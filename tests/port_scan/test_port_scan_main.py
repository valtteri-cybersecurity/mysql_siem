from copy import deepcopy
from datetime import datetime, timedelta
from unittest.mock import Mock

import pymysql
import pytest

from detection.common.alerts import AlertStorageError
from detection.port_scan import main

START = datetime(2026, 10, 22, 12)
END = START + timedelta(minutes=10)


@pytest.fixture(autouse=True)
def manual_lock(monkeypatch):
    monkeypatch.setattr(main, "acquire_lock", Mock(return_value=True))
    monkeypatch.setattr(main, "release_lock", Mock())


def test_port_scan_details_and_evidence(finding):
    alert, evidence = main.build_alert(finding)
    assert alert["rule_key"] == "PORT_SCAN_001"
    assert alert["title"] == "Possible Port Scanning"
    assert alert["source_ip"] == finding["source_ip"]
    assert alert["first_seen"] == finding["first_seen"]
    assert alert["last_seen"] == finding["last_seen"]
    assert alert["details"] == {
        "destination_ip": "198.51.100.1",
        "protocol": "TCP",
        "distinct_port_count": 10,
        "destination_ports": list(range(1000, 1010)),
        "window_seconds": 60,
        "threshold": 10,
    }
    assert evidence == [("UFW", index) for index in range(1, 11)]


def test_reordered_evidence_and_ports_have_same_fingerprint(finding):
    first = main.build_alert(finding)[0]
    finding["evidence_ids"].reverse()
    finding["distinct_ports"].reverse()
    assert (
        main.build_alert(finding)[0]["alert_fingerprint"] == first["alert_fingerprint"]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_ip", "192.0.2.2"),
        ("destination_ip", "198.51.100.2"),
        ("protocol", "UDP"),
        ("first_seen", START - timedelta(seconds=1)),
        ("last_seen", START + timedelta(seconds=10)),
        ("evidence_ids", list(range(11, 21))),
    ],
)
def test_different_identity_produces_different_fingerprint(finding, field, value):
    original = main.build_alert(finding)[0]["alert_fingerprint"]
    finding[field] = value
    assert main.build_alert(finding)[0]["alert_fingerprint"] != original


def test_run_uses_existing_detector_and_counts_saved_and_skipped(
    monkeypatch, sample_events
):
    second = deepcopy(sample_events)
    for event in second:
        event["id"] += 10
        event["event_time"] += timedelta(minutes=3)
    read = Mock(return_value=sample_events + second)
    save = Mock(side_effect=["new_alerts_saved", "existing_alerts_skipped"])
    monkeypatch.setattr(main, "get_db_data", read)
    monkeypatch.setattr(main, "store_detection", save)
    connection = Mock()
    assert main.run_detection(connection, START, END) == {
        "events_analyzed": 20,
        "scans_detected": 2,
        "new_alerts_saved": 1,
        "existing_alerts_skipped": 1,
        "alerts_updated": 0,
    }
    read.assert_called_once_with(connection, START, END)
    connection.rollback.assert_called_once()
    assert save.call_count == 2
    first = main.build_alert(save.call_args_list[0].args[1])[0]["alert_fingerprint"]
    second = main.build_alert(save.call_args_list[1].args[1])[0]["alert_fingerprint"]
    assert first != second


def test_empty_read_does_not_write(monkeypatch):
    monkeypatch.setattr(main, "get_db_data", Mock(return_value=[]))
    save = Mock()
    monkeypatch.setattr(main, "store_detection", save)
    summary = main.run_detection(Mock(), START, END)
    assert all(value == 0 for value in summary.values())
    save.assert_not_called()


def test_main_summary_and_connection_cleanup(monkeypatch, capsys):
    connection = Mock()
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    run = Mock(
        return_value={
            "events_analyzed": 20,
            "scans_detected": 2,
            "new_alerts_saved": 1,
            "existing_alerts_skipped": 1,
        }
    )
    monkeypatch.setattr(main, "run_detection", run)
    assert main.main(["--start", str(START), "--end", str(END)]) == 0
    run.assert_called_once_with(connection, START, END)
    output = capsys.readouterr().out
    assert "UFW events analyzed: 20" in output
    assert "New alerts saved: 1" in output
    assert "Existing alerts skipped: 1" in output
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "args",
    [
        ["--unknown-option"],
        ["--start", str(START)],
        ["--start", "bad", "--end", str(END)],
        ["--start", str(END), "--end", str(START)],
        ["--start", str(START), "--end", str(START)],
        ["--start", "2026-10-22T12:00:00+03:00", "--end", str(END)],
    ],
)
def test_bad_arguments_fail_before_connecting(monkeypatch, args):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit) as caught:
        main.main(args)
    assert caught.value.code == 2
    connect.assert_not_called()


def test_failed_connection_returns_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=None))
    assert main.main(["--start", str(START), "--end", str(END)]) == 1
    assert "connection failed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "error",
    [pymysql.OperationalError(1146, "private-data"), AlertStorageError("private-data")],
)
def test_failure_closes_connection_and_prints_no_database_payload(
    monkeypatch, capsys, error
):
    connection = Mock()
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_detection", Mock(side_effect=error))
    assert main.main(["--start", str(START), "--end", str(END)]) == 1
    output = capsys.readouterr()
    assert "private-data" not in output.out + output.err
    assert "failed" in output.err
    connection.close.assert_called_once()
