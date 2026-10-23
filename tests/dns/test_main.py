from unittest.mock import MagicMock

import pytest

from ingestion.dns import db
from ingestion.dns import main as entrypoint
from ingestion.dns.collector import DNSCollectionError, DNSCollectionIncomplete
from ingestion.dns.config import AdGuardConfig, CollectorConfig
from ingestion.dns.db import DNSCollectionBusy, DNSStorageError


@pytest.fixture
def runtime(monkeypatch):
    config = AdGuardConfig(
        "https://dns.example.net", "fixture-user", "fixture-password"
    )
    monkeypatch.setattr(entrypoint, "load_adguard_config", lambda: config)
    monkeypatch.setattr(entrypoint, "load_collector_config", CollectorConfig)
    mocks = {}
    for name in (
        "get_connection",
        "find_source",
        "collect",
        "register_source",
        "AdGuardAdapter",
    ):
        mocks[name] = MagicMock()
        monkeypatch.setattr(entrypoint, name, mocks[name])
    mocks["get_connection"].return_value = MagicMock()
    mocks["find_source"].return_value = 7
    mocks["collect"].return_value = {
        "inserted": 2,
        "pages": 3,
        "fetched": 7,
        "excluded": 4,
    }
    mocks["purge_events"] = MagicMock()
    monkeypatch.setattr(db, "purge_events", mocks["purge_events"])
    # Catch a future module-level import too, without requiring one at runtime.
    monkeypatch.setattr(entrypoint, "purge_events", mocks["purge_events"], raising=False)
    return mocks


def test_cli_success_keeps_history_and_reports_counts(runtime, capsys):
    assert entrypoint.main([]) == 0
    output = capsys.readouterr().out
    for text in ("inserted=2", "fetched=7", "excluded=4", "status=SUCCESS"):
        assert text in output
    runtime["get_connection"].return_value.close.assert_called_once()
    runtime["purge_events"].assert_not_called()
    assert "expired_deleted" not in output


@pytest.mark.parametrize(
    "error,status",
    [
        (DNSCollectionBusy("busy"), 0),
        (DNSCollectionIncomplete("pending"), 2),
        (DNSCollectionError("invalid checkpoint"), 1),
        (DNSStorageError("DNS database operation failed."), 1),
        (RuntimeError("secret-value"), 1),
    ],
)
def test_cli_failure_codes_and_no_purge(runtime, capsys, error, status):
    runtime["collect"].side_effect = error
    assert entrypoint.main([]) == status
    runtime["purge_events"].assert_not_called()
    runtime["get_connection"].return_value.close.assert_called_once()
    output = capsys.readouterr().out
    assert "secret-value" not in output
    assert "status=SUCCESS" not in output


def test_register_command_does_not_fetch_or_enable(runtime):
    assert entrypoint.main(["--register-source"]) == 0
    runtime["register_source"].assert_called_once()
    assert "enabled" not in runtime["register_source"].call_args.kwargs
    runtime["collect"].assert_not_called()
    runtime["AdGuardAdapter"].assert_not_called()
    runtime["purge_events"].assert_not_called()


def test_no_connection_returns_failure(runtime):
    runtime["get_connection"].return_value = None
    assert entrypoint.main([]) == 1
    runtime["collect"].assert_not_called()


@pytest.mark.parametrize("days", [1, 30, 36500])
def test_source_history_window_never_enables_automatic_purge(runtime, monkeypatch, days):
    monkeypatch.setattr(
        entrypoint, "load_collector_config", lambda: CollectorConfig(retention_days=days)
    )
    assert entrypoint.main([]) == 0
    runtime["purge_events"].assert_not_called()
    assert runtime["collect"].call_args.args[3].retention_days == days
