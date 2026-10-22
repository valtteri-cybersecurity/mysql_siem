from unittest.mock import MagicMock

import pytest

from ingestion.auth import main


def test_manual_entry_point(monkeypatch):
    connection = MagicMock()
    collect = MagicMock(return_value={"inserted": 1, "skipped": 2})
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "collect_auth_events", collect)
    assert main.main(["--logfile", "/tmp/example.log", "--collector-id", "test"]) == 0
    collect.assert_called_once_with(connection, "/tmp/example.log", collector_id="test",
                                    stats={"lines_read": 0, "failures_recognized": 0, "duplicates": 0},
                                    max_lines=5000)
    connection.close.assert_called_once()


def test_connection_failure(monkeypatch):
    monkeypatch.setattr(main, "get_connection", lambda: None)
    assert main.main([]) == 1


def test_programming_error_is_not_hidden(monkeypatch):
    connection = MagicMock()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "collect_auth_events", MagicMock(side_effect=TypeError("bug")))
    with pytest.raises(TypeError, match="bug"):
        main.main([])
    connection.close.assert_called_once()


def test_unexpected_runtime_error_is_not_hidden(monkeypatch):
    connection = MagicMock()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "collect_auth_events", MagicMock(side_effect=RuntimeError("bug")))
    with pytest.raises(RuntimeError, match="bug"):
        main.main([])
    connection.close.assert_called_once()
