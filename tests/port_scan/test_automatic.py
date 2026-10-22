from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock

import pytest

from detection.port_scan import config, main, runner, state
from detection.port_scan.config import DetectionRunError
from detection.port_scan.db import get_new_events

NOW = datetime(2026, 10, 22, 12)
CONFIG = {"batch_size": 1000, "late_seconds": 600, "max_buffer_events": 10000}


@pytest.fixture
def automatic(monkeypatch, sample_events):
    mocks = {}
    defaults = {
        "acquire_lock": True,
        "release_lock": None,
        "get_rule": (7, 1),
        "load_state": (0, []),
        "get_new_events": sample_events,
        "find_related_alert": None,
        "save_alert": True,
        "save_state": None,
    }
    for name, result in defaults.items():
        mocks[name] = Mock(return_value=result)
        monkeypatch.setattr(runner, name, mocks[name])
    return mocks


def test_first_pass_saves_checkpoint_only_after_alerts(automatic):
    connection = Mock()
    calls = Mock()
    calls.attach_mock(automatic["save_alert"], "alert")
    calls.attach_mock(automatic["save_state"], "state")
    calls.attach_mock(connection.commit, "commit")
    summary = runner.run_automatic(connection, CONFIG, now=NOW)
    assert summary["status"] == "SUCCESS"
    assert summary["state_updated"] is True
    assert summary["new_alerts_saved"] == 1
    assert automatic["save_state"].call_args.args[1:3] == (7, 10)
    assert [call[0] for call in calls.mock_calls] == ["alert", "state", "commit"]
    assert automatic["save_alert"].call_args.kwargs == {"manage_transaction": False}
    automatic["release_lock"].assert_called_once()


@pytest.mark.parametrize("operation", ["save_alert", "save_state"])
def test_failure_never_advances_checkpoint_or_commits(automatic, operation):
    automatic[operation].side_effect = RuntimeError("simulated interruption")
    connection = Mock()
    with pytest.raises(RuntimeError, match="interruption"):
        runner.run_automatic(connection, CONFIG, now=NOW)
    connection.commit.assert_not_called()
    assert connection.rollback.call_count >= 1
    automatic["release_lock"].assert_called_once()
    if operation == "save_alert":
        automatic["save_state"].assert_not_called()


def test_busy_run_does_not_read_or_write(automatic):
    automatic["acquire_lock"].return_value = False
    connection = Mock()
    result = runner.run_automatic(connection, CONFIG)
    assert result["status"] == "SKIPPED"
    assert not result["state_updated"]
    automatic["get_rule"].assert_not_called()
    automatic["release_lock"].assert_not_called()
    connection.begin.assert_not_called()


def test_disabled_rule_does_not_fetch_or_advance(automatic):
    automatic["get_rule"].return_value = (7, 0)
    result = runner.run_automatic(Mock(), CONFIG)
    assert result["status"] == "SKIPPED"
    automatic["load_state"].assert_not_called()
    automatic["get_new_events"].assert_not_called()
    automatic["save_state"].assert_not_called()
    automatic["release_lock"].assert_called_once()


def test_rule_disabled_during_compute_prevents_writes(automatic):
    automatic["get_rule"].side_effect = [(7, 1), (7, 0)]
    connection = Mock()
    result = runner.run_automatic(connection, CONFIG, now=NOW)
    assert result["status"] == "SKIPPED"
    automatic["save_alert"].assert_not_called()
    automatic["save_state"].assert_not_called()
    connection.commit.assert_not_called()


def test_restored_tail_combines_with_new_events(automatic, sample_events):
    records = []
    for event in sample_events[:5]:
        records.append({"event": event, "observed_at": NOW - timedelta(minutes=1)})
    automatic["load_state"].return_value = (5, records)
    automatic["get_new_events"].return_value = sample_events[5:]
    result = runner.run_automatic(Mock(), CONFIG, now=NOW)
    assert automatic["get_new_events"].call_args.args[1:] == (5, 1000)
    assert result["new_alerts_saved"] == 1
    assert len(automatic["save_alert"].call_args.args[2]) == 10


def test_empty_run_still_persists_state(automatic):
    automatic["get_new_events"].return_value = []
    result = runner.run_automatic(Mock(), CONFIG, now=NOW)
    assert result["events_analyzed"] == 0
    assert result["new_alerts_saved"] == 0
    assert result["state_updated"]
    assert automatic["save_state"].call_args.args[2:] == (0, [])


def test_replayed_finding_is_skipped(automatic):
    automatic["save_alert"].return_value = False
    result = runner.run_automatic(Mock(), CONFIG, now=NOW)
    assert result["existing_alerts_skipped"] == 1
    assert result["new_alerts_saved"] == 0


def test_buffer_overflow_does_not_discard_unprocessed_events(automatic, sample_events):
    records = []
    for event in sample_events:
        records.append({"event": event, "observed_at": NOW})
    automatic["load_state"].return_value = (10, records)
    automatic["get_new_events"].return_value = [dict(sample_events[0], id=11)]
    connection = Mock()
    with pytest.raises(DetectionRunError, match="buffer limit"):
        runner.run_automatic(connection, dict(CONFIG, max_buffer_events=10), now=NOW)
    automatic["save_state"].assert_not_called()
    connection.commit.assert_not_called()


def test_id_query_has_no_event_time_cutoff(sample_events):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    event = sample_events[0]
    cursor.fetchall.return_value = [
        tuple(
            event[key]
            for key in (
                "id",
                "event_time",
                "action",
                "src_ip",
                "dst_ip",
                "protocol",
                "dst_port",
            )
        )
    ]
    assert get_new_events(connection, 10, 100) == [event]
    sql, params = cursor.execute.call_args.args
    assert "WHERE id > %s ORDER BY id LIMIT %s" in sql
    assert "event_time >" not in sql
    assert params == (10, 100)


def test_missing_state_starts_at_zero():
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.return_value = None
    assert state.load_state(connection, 7) == (0, [])


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        "{}",
        '{"version": 2, "events": []}',
        '{"version": 1, "events": [{"event": {}, "observed_at": "bad"}]}',
    ],
)
def test_corrupted_state_is_not_silently_reset(payload):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (
        10,
        payload,
    )
    with pytest.raises(DetectionRunError, match="not reset"):
        state.load_state(connection, 7)


@pytest.mark.parametrize("value", ["bad", "0", "10001", "private-secret"])
def test_config_rejects_bad_batch_without_echoing_values(monkeypatch, value):
    monkeypatch.setenv("PORT_SCAN_BATCH_SIZE", value)
    with pytest.raises(DetectionRunError) as caught:
        config.load_config()
    assert value not in str(caught.value)


def test_config_requires_room_for_one_batch(monkeypatch):
    monkeypatch.setenv("PORT_SCAN_BATCH_SIZE", "100")
    monkeypatch.setenv("PORT_SCAN_MAX_BUFFER_EVENTS", "10")
    with pytest.raises(DetectionRunError):
        config.load_config()


def test_default_cli_is_automatic_and_logs_summary(monkeypatch, capsys):
    connection = Mock()
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    run = Mock(
        return_value={
            "events_analyzed": 10,
            "scans_detected": 1,
            "new_alerts_saved": 1,
            "existing_alerts_skipped": 0,
            "state_updated": True,
            "status": "SUCCESS",
        }
    )
    monkeypatch.setattr(main, "run_automatic", run)
    assert main.main([]) == 0
    run.assert_called_once()
    output = capsys.readouterr().out
    for text in (
        "Started:",
        "Finished:",
        "Status: SUCCESS",
        "Detection state updated: YES",
    ):
        assert text in output
    connection.close.assert_called_once()


def test_failed_automatic_cli_exits_nonzero_without_private_payload(
    monkeypatch, capsys
):
    connection = Mock()
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(
        main, "run_automatic", Mock(side_effect=RuntimeError("programming bug"))
    )
    with pytest.raises(RuntimeError, match="programming bug"):
        main.main([])
    connection.close.assert_called_once()


def test_file_log_uses_bounded_rotation(monkeypatch, tmp_path):
    connection = Mock()
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(
        main, "run_automatic", Mock(side_effect=DetectionRunError("safe test error"))
    )
    original = main.RotatingFileHandler
    factory = Mock(side_effect=original)
    monkeypatch.setattr(main, "RotatingFileHandler", factory)
    target = tmp_path / "cron.log"
    assert main.main(["--log-file", str(target)]) == 1
    assert factory.call_args.kwargs["maxBytes"] == 1000000
    assert factory.call_args.kwargs["backupCount"] == 3
    assert "Status: FAILED" in target.read_text()
    assert "Finished:" in target.read_text()


def test_missing_lock_result_is_an_error_not_a_skipped_run():
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (
        None,
    )
    with pytest.raises(DetectionRunError, match="acquire"):
        state.acquire_lock(connection)


def test_invalid_timestamp_is_visited_without_poisoning_buffer(
    automatic, sample_events
):
    automatic["get_new_events"].return_value = [dict(sample_events[0], event_time=None)]
    result = runner.run_automatic(Mock(), CONFIG, now=NOW)
    assert result["new_events_fetched"] == 1
    assert result["events_analyzed"] == 0
    assert automatic["save_state"].call_args.args[2:] == (1, [])
