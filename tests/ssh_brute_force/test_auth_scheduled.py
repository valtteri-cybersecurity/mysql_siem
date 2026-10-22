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
    assert stats == {"lines_read": 2, "failures_recognized": 2, "duplicates": 0}
    assert cursor.execute.call_args.args[1][4] == len(LINE) * 2


def test_duplicate_count_is_separate_from_unsupported_lines(tmp_path, connection, monkeypatch):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(b"not supported\n" + LINE)
    connection.cursor.return_value.fetchone.return_value = None
    monkeypatch.setattr("ingestion.auth.collector.save_event", Mock(return_value=0))
    stats = {"lines_read": 0, "failures_recognized": 0, "duplicates": 0}
    assert process_file(connection.cursor.return_value, str(logfile), "test", stats=stats) == (0, 1)
    assert stats == {"lines_read": 2, "failures_recognized": 1, "duplicates": 1}


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
