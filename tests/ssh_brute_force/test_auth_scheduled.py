from unittest.mock import Mock

import pytest

from ingestion.auth import main
from ingestion.auth.collector import AuthCollectionBusy, process_file

LINE = b"2026-10-22T12:00:00Z server-a sshd[12]: Failed password for alice from 192.0.2.1 port 22 ssh2\n"


def test_missing_source_is_logged_and_never_connects(monkeypatch, tmp_path):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    logfile = tmp_path / "missing-auth.log"
    target = tmp_path / "collector.log"
    assert main.main(["--allow-missing-source", "--logfile", str(logfile), "--log-file", str(target)]) == 0
    assert "Status: SKIPPED" in target.read_text()
    assert "state unchanged" in target.read_text()
    connect.assert_not_called()


def test_unreadable_source_reports_failure_without_raw_payload(monkeypatch, tmp_path, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "collect_auth_events", Mock(side_effect=PermissionError("private-path")))
    target = tmp_path / "collector.log"
    assert main.main(["--log-file", str(target)]) == 1
    assert "Status: FAILED" in target.read_text()
    assert "private-path" not in target.read_text()
    connection.close.assert_called_once()


def test_busy_collection_is_visible_and_skipped(monkeypatch, capsys, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "collect_auth_events", Mock(side_effect=AuthCollectionBusy("busy")))
    assert main.main([]) == 0
    assert "SKIPPED" in capsys.readouterr().out
    connection.close.assert_called_once()


def test_batch_stops_at_complete_line_and_reports_counts(tmp_path, connection):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE * 3)
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = None
    stats = {"lines_read": 0, "failures_recognized": 0, "duplicates": 0}
    assert process_file(cursor, str(logfile), "test", stats=stats, line_limit=2) == (2, 0)
    assert stats["lines_read"] == 2
    assert stats["failures_recognized"] == 2
    assert stats["duplicates"] == 0
    assert stats["budget_exhausted"] is True
    assert stats["remaining_bytes"] == len(LINE)
    assert cursor.execute.call_args.args[1][4] == len(LINE) * 2


def test_duplicate_count_is_separate_from_unsupported_lines(tmp_path, connection, monkeypatch):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(b"not supported\n" + LINE)
    connection.cursor.return_value.fetchone.return_value = None
    monkeypatch.setattr("ingestion.auth.collector.save_event", Mock(return_value=0))
    stats = {"lines_read": 0, "failures_recognized": 0, "duplicates": 0}
    assert process_file(connection.cursor.return_value, str(logfile), "test", stats=stats) == (0, 1)
    assert stats["lines_read"] == 2
    assert stats["failures_recognized"] == 1
    assert stats["duplicates"] == 1
    assert stats["unrecognized_lines"] == 1


def test_collection_summary(monkeypatch, capsys, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))

    def collect(*args, **kwargs):
        kwargs["stats"].update(lines_read=10, failures_recognized=5, duplicates=2)
        return {"inserted": 3, "skipped": 5}

    monkeypatch.setattr(main, "collect_auth_events", collect)
    assert main.main([]) == 0
    output = capsys.readouterr().out
    for message in ("Log lines read: 10", "SSH failures recognized: 5", "New auth events: 3",
                    "Duplicate events skipped: 2", "Collection state updated: YES", "Status: SUCCESS"):
        assert message in output


@pytest.mark.parametrize("limit", ["0", "100001"])
def test_bad_collection_limit_never_connects(monkeypatch, limit):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit):
        main.main(["--max-lines", limit])
    connect.assert_not_called()


def test_unknown_writer_lock_result_is_a_failure(connection, monkeypatch, capsys):
    connection.cursor.return_value.fetchone.return_value = (None,)
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    assert main.main([]) == 1
    assert "Status: FAILED" in capsys.readouterr().out
    connection.commit.assert_not_called()


def test_partial_status_after_bounded_committed_batch(monkeypatch, tmp_path, connection, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE * 2)
    connection.cursor.return_value.fetchone.side_effect = [(1,), None]
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    assert main.main(["--logfile", str(logfile), "--max-lines", "1"]) == 0
    output = capsys.readouterr().out
    assert "Status: PARTIAL" in output
    assert "Status: SUCCESS" not in output
    assert f"Remaining observed bytes: {len(LINE)}" in output
    connection.commit.assert_called_once()


def test_known_format_gap_fails_without_private_payload(monkeypatch, tmp_path, connection, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE.replace(b"2026-10-22T12:00:00Z", b"Oct 22 12:00:00"))
    connection.cursor.return_value.fetchone.side_effect = [(1,), None]
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    assert main.main(["--logfile", str(logfile)]) == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Status: FAILED" in output
    assert "Auth coverage gap:" in output
    assert "confirmed source interval" in output
    assert "alice" not in output
    assert "192.0.2.1" not in output
    connection.commit.assert_not_called()


@pytest.mark.parametrize("value", ["0", "-1", "51", "nan", "inf"])
def test_bad_time_budget_never_connects(monkeypatch, value):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit):
        main.main(["--max-seconds", value])
    connect.assert_not_called()


@pytest.mark.parametrize("arguments", [
    ["--syslog-timezone", "UTC"],
    ["--syslog-start", "2026-10-22T00:00:00", "--syslog-end", "2026-10-23T00:00:00Z", "--syslog-timezone", "UTC"],
    ["--syslog-start", "2026-10-22T00:00:00Z", "--syslog-end", "2026-10-21T00:00:00Z", "--syslog-timezone", "UTC"],
    ["--syslog-start", "2026-10-22T00:00:00Z", "--syslog-end", "2026-10-23T00:00:00Z", "--syslog-timezone", "Unknown/Zone"],
])
def test_invalid_syslog_context_never_connects(monkeypatch, arguments):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit):
        main.main(arguments)
    connect.assert_not_called()


def test_explicit_syslog_context_collects_success(monkeypatch, tmp_path, connection, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE.replace(b"2026-10-22T12:00:00Z", b"Oct 22 12:00:00").replace(b"Failed", b"Accepted"))
    connection.cursor.return_value.fetchone.side_effect = [(1,), None]
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    assert main.main(["--logfile", str(logfile), "--syslog-start", "2026-10-22T00:00:00Z",
                      "--syslog-end", "2026-10-23T00:00:00Z", "--syslog-timezone", "UTC"]) == 0
    output = capsys.readouterr().out
    assert "Status: SUCCESS" in output
    assert "SSH successes recognized: 1" in output
    assert "SSH failures recognized: 0" in output


def test_termination_reports_failure_and_restores_signal_handler(monkeypatch, tmp_path, connection):
    import signal

    previous = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))

    def stop(*args, **kwargs):
        signal.raise_signal(signal.SIGTERM)

    monkeypatch.setattr(main, "collect_auth_events", stop)
    target = tmp_path / "collector.log"
    assert main.main(["--log-file", str(target)]) == 1
    output = target.read_text()
    assert "Status: FAILED" in output
    assert "interrupted" in output
    assert signal.getsignal(signal.SIGTERM) == previous


@pytest.mark.parametrize("confirmed", ["YES", "UNKNOWN"])
def test_failure_reports_actual_commit_certainty(monkeypatch, connection, capsys, confirmed):
    import pymysql

    def fail(*args, **kwargs):
        kwargs["stats"]["state_updated"] = confirmed
        raise pymysql.OperationalError(2013, "private SQL text")

    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "collect_auth_events", fail)
    assert main.main([]) == 1
    captured = capsys.readouterr()
    assert f"Collection state updated: {confirmed}" in captured.out
    assert "Status: FAILED" in captured.out
    assert "private SQL text" not in captured.out + captured.err


def test_compressed_history_reports_partial(monkeypatch, tmp_path, connection, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE)
    (tmp_path / "auth.log.2.gz").write_bytes(b"unread archive")
    connection.cursor.return_value.fetchone.side_effect = [(1,), None]
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    assert main.main(["--logfile", str(logfile)]) == 0
    captured = capsys.readouterr()
    assert "Status: PARTIAL" in captured.out
    assert "Auth coverage gap:" in captured.err
    assert "compressed rotations: 1" in captured.out
    assert "Status: SUCCESS" not in captured.out


def test_source_preflight_uses_no_database(monkeypatch, tmp_path, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE)
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    assert main.main(["--check-source", "--logfile", str(logfile)]) == 0
    assert "Source timestamp check: SUCCESS" in capsys.readouterr().out
    connect.assert_not_called()


def test_source_preflight_rejects_yearless_cron_record_without_context(monkeypatch, tmp_path, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(b"Oct 22 12:00:00 host CRON[1]: pam_unix(cron:session): session opened\n")
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    assert main.main(["--check-source", "--logfile", str(logfile)]) == 1
    captured = capsys.readouterr()
    assert "confirmed source interval" in captured.err
    assert "Status: FAILED" in captured.out
    connect.assert_not_called()


def test_source_preflight_accepts_explicit_yearless_context(monkeypatch, tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE.replace(b"2026-10-22T12:00:00Z", b"Oct 22 12:00:00"))
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    assert main.main(["--check-source", "--logfile", str(logfile),
                      "--syslog-start", "2026-10-22T00:00:00Z",
                      "--syslog-end", "2026-10-23T00:00:00Z", "--syslog-timezone", "UTC"]) == 0
    connect.assert_not_called()


def test_source_preflight_is_bounded(monkeypatch, tmp_path, capsys):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE * 100 + b"\xff\n")
    monkeypatch.setattr(main, "get_connection", Mock())
    assert main.main(["--check-source", "--logfile", str(logfile)]) == 0
    assert "100 complete lines" in capsys.readouterr().out
    main.get_connection.assert_not_called()
