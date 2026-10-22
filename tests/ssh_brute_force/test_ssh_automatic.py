from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pymysql
import pytest

from detection.ssh_brute_force import config, db, main, runner, state
from detection.ssh_brute_force.db import SSHDetectionError

NOW = datetime(2026, 10, 22, 12)
CONFIG = {"batch_size": 1000, "late_seconds": 600, "max_buffer_events": 10000}


@pytest.fixture
def automatic(monkeypatch, sample_events):
    results = {"acquire_lock": True, "release_lock": None, "get_rule": (9, "HIGH", 1),
               "load_state": (0, []), "get_new_events": sample_events,
               "store_detection": "new_alerts_saved", "save_state": None}
    mocks = {}
    for name, value in results.items():
        mocks[name] = Mock(return_value=value)
        monkeypatch.setattr(runner, name, mocks[name])
    return mocks


def test_alerts_state_and_commit_order(connection, automatic):
    calls = Mock()
    calls.attach_mock(automatic["store_detection"], "alert")
    calls.attach_mock(automatic["save_state"], "state")
    calls.attach_mock(connection.commit, "commit")
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["state_updated"] and result["status"] == "SUCCESS"
    assert result["new_events_fetched"] == 8
    assert result["new_alerts_saved"] == 1
    assert automatic["save_state"].call_args.args[1:3] == (9, 8)
    assert [call[0] for call in calls.mock_calls] == ["alert", "state", "commit"]
    automatic["release_lock"].assert_called_once_with(connection)


@pytest.mark.parametrize("operation", ["store_detection", "save_state", "commit"])
def test_failure_never_commits_checkpoint(connection, automatic, operation):
    target = connection.commit if operation == "commit" else automatic[operation]
    target.side_effect = pymysql.OperationalError(2013, "test")
    with pytest.raises(pymysql.OperationalError):
        runner.run_automatic(connection, CONFIG, now=NOW)
    assert connection.rollback.call_count >= 1
    if operation != "commit":
        connection.commit.assert_not_called()
    if operation == "store_detection":
        automatic["save_state"].assert_not_called()
    automatic["release_lock"].assert_called_once()


def test_cross_run_window_uses_saved_tail(connection, automatic, sample_events):
    records = [{"event": event, "observed_at": NOW - timedelta(seconds=60)} for event in sample_events[:2]]
    automatic["load_state"].return_value = (2, records)
    automatic["get_new_events"].return_value = sample_events[2:5]
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["new_alerts_saved"] == 1
    automatic["get_new_events"].assert_called_once_with(connection, 2, 1000)
    assert automatic["store_detection"].call_args.args[1]["failure_count"] == 5


def test_four_failures_keep_state_without_alert(connection, automatic, sample_events):
    automatic["get_new_events"].return_value = sample_events[:4]
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["detections_found"] == 0
    assert result["state_updated"]
    assert automatic["save_state"].call_args.args[2] == 4
    automatic["store_detection"].assert_not_called()


def test_disabled_rule_never_fetches_or_updates(connection, automatic):
    automatic["get_rule"].return_value = (9, "HIGH", 0)
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["status"] == "SKIPPED" and not result["state_updated"]
    automatic["load_state"].assert_not_called()
    automatic["get_new_events"].assert_not_called()
    automatic["save_state"].assert_not_called()
    connection.commit.assert_not_called()


def test_midrun_disable_rolls_back(connection, automatic):
    automatic["get_rule"].side_effect = [(9, "HIGH", 1), (9, "HIGH", 0)]
    assert not runner.run_automatic(connection, CONFIG, now=NOW)["state_updated"]
    automatic["store_detection"].assert_not_called()
    automatic["save_state"].assert_not_called()
    connection.commit.assert_not_called()


def test_busy_run_is_visible_without_releasing_another_lock(connection, automatic):
    automatic["acquire_lock"].return_value = False
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["status"] == "SKIPPED" and "lock" in result["reason"]
    automatic["get_rule"].assert_not_called()
    automatic["release_lock"].assert_not_called()


@pytest.mark.parametrize("change", [{"event_type": "SSH_AUTH_SUCCESS"}, {"service": "sudo"}, {"event_time": None}])
def test_irrelevant_ids_are_visited_without_poisoning_tail(connection, automatic, sample_events, change):
    automatic["get_new_events"].return_value = [dict(sample_events[0], **change)]
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["events_analyzed"] == 0
    assert automatic["save_state"].call_args.args[2:] == (1, [])


def test_backwards_processing_clock_does_not_advance(connection, automatic, sample_events):
    automatic["load_state"].return_value = (1, [{"event": sample_events[0], "observed_at": NOW + timedelta(seconds=1)}])
    with pytest.raises(SSHDetectionError, match="backwards"):
        runner.run_automatic(connection, CONFIG, now=NOW)
    automatic["save_state"].assert_not_called()
    connection.commit.assert_not_called()


@pytest.mark.parametrize("age,retained", [(660, 1), (660.000001, 0)])
def test_precise_retention_boundary(connection, automatic, sample_events, age, retained):
    automatic["load_state"].return_value = (1, [{"event": sample_events[0], "observed_at": NOW - timedelta(seconds=age)}])
    automatic["get_new_events"].return_value = []
    runner.run_automatic(connection, CONFIG, now=NOW)
    assert len(automatic["save_state"].call_args.args[3]) == retained


def test_restart_processes_tail_before_expiration(connection, automatic, sample_events):
    automatic["load_state"].return_value = (8, [{"event": event, "observed_at": NOW - timedelta(days=1)} for event in sample_events])
    automatic["get_new_events"].return_value = []
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["detections_found"] == 1
    assert automatic["save_state"].call_args.args[3] == []


def test_overflow_fails_without_dropping_records(connection, automatic):
    with pytest.raises(SSHDetectionError, match="buffer limit"):
        runner.run_automatic(connection, dict(CONFIG, max_buffer_events=5), now=NOW)
    automatic["save_state"].assert_not_called()
    connection.commit.assert_not_called()


def test_empty_run_still_commits_durable_state(connection, automatic):
    automatic["get_new_events"].return_value = []
    assert runner.run_automatic(connection, CONFIG, now=NOW)["state_updated"]
    assert automatic["save_state"].call_args.args[2:] == (0, [])


def test_id_read_has_no_timestamp_cutoff(connection, sample_events):
    connection.cursor.return_value.fetchall.return_value = [tuple(sample_events[0][name] for name in db.FIELDS)]
    assert db.get_new_events(connection, 7, 100) == [sample_events[0]]
    sql, params = connection.cursor.return_value.execute.call_args.args
    assert "WHERE id > %s ORDER BY id LIMIT %s" in sql
    assert "event_time >" not in sql
    assert params == (7, 100)


def test_state_round_trip_and_rule_specific_key(connection, sample_events):
    records = [{"event": event, "observed_at": NOW} for event in sample_events[:2]]
    before = deepcopy(records)
    state.save_state(connection, 9, 2, records)
    params = connection.cursor.return_value.execute.call_args.args[1]
    assert params[:2] == (9, 2)
    connection.cursor.return_value.fetchone.return_value = (2, params[2])
    assert state.load_state(connection, 9) == (2, records)
    assert records == before
    connection.commit.assert_not_called()


@pytest.mark.parametrize("payload", ["bad", "null", "[]", "{}", '{"version":2,"events":[]}',
    '{"version":1,"events":[{"event":{},"observed_at":"bad"}]}'])
def test_corrupt_state_is_not_silently_reset(connection, payload):
    connection.cursor.return_value.fetchone.return_value = (2, payload)
    with pytest.raises(SSHDetectionError, match="not reset"):
        state.load_state(connection, 9)


def test_missing_state_starts_at_zero(connection):
    connection.cursor.return_value.fetchone.return_value = None
    assert state.load_state(connection, 9) == (0, [])


@pytest.mark.parametrize("key,value", [("BATCH_SIZE", "bad"), ("BATCH_SIZE", "0"), ("BATCH_SIZE", "10001"),
    ("LATE_SECONDS", "-1"), ("MAX_BUFFER_EVENTS", "100001")])
def test_config_rejects_invalid_values_without_echoing_them(monkeypatch, key, value):
    monkeypatch.setenv("SSH_BRUTE_FORCE_" + key, value)
    with pytest.raises(SSHDetectionError):
        config.load_config()


def test_config_requires_room_for_one_batch(monkeypatch):
    monkeypatch.setenv("SSH_BRUTE_FORCE_BATCH_SIZE", "100")
    monkeypatch.setenv("SSH_BRUTE_FORCE_MAX_BUFFER_EVENTS", "5")
    with pytest.raises(SSHDetectionError, match="batch size"):
        config.load_config()


def test_automatic_cli_reports_state_update(monkeypatch, capsys, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    run = Mock(return_value={"events_analyzed": 5, "detections_found": 1, "new_alerts_saved": 1,
                            "alerts_updated": 0, "existing_alerts_skipped": 0, "state_updated": True,
                            "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_automatic", run)
    assert main.main(["--automatic"]) == 0
    run.assert_called_once()
    assert "Detection state updated: YES" in capsys.readouterr().out
    connection.close.assert_called_once()


def test_automatic_and_manual_arguments_cannot_be_mixed(monkeypatch):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit):
        main.main(["--automatic", "--start", str(NOW)])
    connect.assert_not_called()


def test_file_log_has_bounded_rotation_and_reports_failure(monkeypatch, tmp_path, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_automatic", Mock(side_effect=SSHDetectionError("synthetic failure")))
    target = tmp_path / "cron.log"
    assert main.main(["--automatic", "--log-file", str(target)]) == 1
    output = target.read_text()
    assert "Status: FAILED" in output and "Detection state updated: NO" in output
    assert "Finished:" in output
    from config.run_logging import close_log, open_log

    logger, handler = open_log("test.rotation", str(target))
    assert handler.maxBytes == 1000000 and handler.backupCount == 3
    handler.maxBytes = 200
    for _ in range(30):
        logger.info("x" * 80)
    close_log(logger, handler)
    assert len(list(tmp_path.glob("cron.log*"))) <= 4


def test_aware_processing_clock_is_rejected(connection, automatic):
    with pytest.raises(SSHDetectionError):
        runner.run_automatic(connection, CONFIG, now=NOW.replace(tzinfo=timezone.utc))
