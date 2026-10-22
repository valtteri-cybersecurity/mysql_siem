from datetime import datetime, timedelta
from unittest.mock import Mock

import pymysql
import pytest

from detection.common.alerts import AlertStorageError
from detection.ssh_brute_force import main, runner
from detection.ssh_brute_force.db import SSHDetectionError

START = datetime(2026, 10, 22, 12)
END = START + timedelta(minutes=5)
ARGS = ["--start", str(START), "--end", str(END)]


@pytest.fixture
def run_dependencies(monkeypatch, sample_events):
    dependencies = {
        "acquire_lock": Mock(return_value=True), "release_lock": Mock(),
        "get_rule": Mock(return_value=(9, "HIGH", 1)),
        "get_db_data": Mock(return_value=sample_events),
        "store_detection": Mock(return_value="new_alerts_saved"),
    }
    for name, value in dependencies.items():
        monkeypatch.setattr(runner, name, value)
    return dependencies


def test_existing_detector_and_transaction_used(connection, sample_events, run_dependencies):
    summary = runner.run_detection(connection, START, END)
    assert summary == {"events_analyzed": 8, "detections_found": 1, "new_alerts_saved": 1,
                       "alerts_updated": 0, "existing_alerts_skipped": 0, "status": "SUCCESS"}
    run_dependencies["get_db_data"].assert_called_once_with(connection, START, END)
    connection.begin.assert_called_once()
    connection.commit.assert_called_once()
    run_dependencies["release_lock"].assert_called_once_with(connection)
    assert run_dependencies["store_detection"].call_args.args[1]["evidence_ids"] == list(range(1, 9))


def test_disabled_rule_skips_event_read(connection, run_dependencies):
    run_dependencies["get_rule"].return_value = (9, "HIGH", 0)
    assert runner.run_detection(connection, START, END)["status"] == "SKIPPED"
    run_dependencies["get_db_data"].assert_not_called()
    connection.commit.assert_not_called()
    run_dependencies["release_lock"].assert_called_once()


def test_busy_run_does_not_read_or_release_another_runs_lock(connection, run_dependencies):
    run_dependencies["acquire_lock"].return_value = False
    assert runner.run_detection(connection, START, END)["status"] == "SKIPPED"
    run_dependencies["get_rule"].assert_not_called()
    run_dependencies["release_lock"].assert_not_called()


def test_empty_result_does_not_write(connection, run_dependencies):
    run_dependencies["get_db_data"].return_value = []
    assert runner.run_detection(connection, START, END)["detections_found"] == 0
    run_dependencies["store_detection"].assert_not_called()
    connection.commit.assert_not_called()


@pytest.mark.parametrize("failure", [AlertStorageError("failure"), TypeError("programming bug")])
def test_failed_save_rolls_back_and_releases_run_lock(connection, run_dependencies, failure):
    run_dependencies["store_detection"].side_effect = failure
    with pytest.raises(type(failure)):
        runner.run_detection(connection, START, END)
    connection.commit.assert_not_called()
    assert connection.rollback.call_count >= 2
    run_dependencies["release_lock"].assert_called_once()


def test_commit_failure_rolls_back(connection, run_dependencies):
    connection.commit.side_effect = pymysql.OperationalError(2013, "test")
    with pytest.raises(pymysql.OperationalError):
        runner.run_detection(connection, START, END)
    assert connection.rollback.call_count >= 2
    run_dependencies["release_lock"].assert_called_once()


def test_midrun_disabled_rule_rolls_back(connection, run_dependencies):
    run_dependencies["store_detection"].side_effect = SSHDetectionError("disabled")
    with pytest.raises(SSHDetectionError, match="disabled"):
        runner.run_detection(connection, START, END)
    connection.commit.assert_not_called()
    run_dependencies["release_lock"].assert_called_once()


def test_cli_summary_and_cleanup(monkeypatch, capsys, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    run = Mock(return_value={"events_analyzed": 8, "detections_found": 1, "new_alerts_saved": 1,
                            "alerts_updated": 0, "existing_alerts_skipped": 0, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_detection", run)
    assert main.main(ARGS) == 0
    run.assert_called_once_with(connection, START, END)
    assert "New alerts saved: 1" in capsys.readouterr().out
    connection.close.assert_called_once()


@pytest.mark.parametrize("args", [[], ["--start", str(START)], ["--end", str(END)],
    ["--start", "bad", "--end", str(END)], ["--start", str(END), "--end", str(START)],
    ["--start", "2026-10-22T15:00:00+03:00", "--end", str(END)]])
def test_invalid_cli_never_connects(monkeypatch, args):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit) as caught:
        main.main(args)
    assert caught.value.code == 2
    connect.assert_not_called()


def test_connection_failure(monkeypatch, capsys):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=None))
    assert main.main(ARGS) == 1
    assert "connection failed" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [pymysql.OperationalError(1146, "private-payload"), AlertStorageError("private-payload")])
def test_expected_failure_closes_connection_without_sensitive_output(monkeypatch, capsys, connection, failure):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_detection", Mock(side_effect=failure))
    assert main.main(ARGS) == 1
    output = capsys.readouterr()
    assert "private-payload" not in output.out + output.err
    connection.close.assert_called_once()


def test_programming_error_is_visible(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_detection", Mock(side_effect=TypeError("bug")))
    with pytest.raises(TypeError, match="bug"):
        main.main(ARGS)
    connection.close.assert_called_once()
