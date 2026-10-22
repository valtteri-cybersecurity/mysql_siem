from unittest.mock import MagicMock

import pytest

from ingestion.dns import main as entrypoint
from ingestion.dns.collector import DNSCollectionError, DNSCollectionIncomplete
from ingestion.dns.config import AdGuardConfig, CollectorConfig
from ingestion.dns.db import DNSCollectionBusy


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
        "purge_events",
        "register_source",
        "AdGuardAdapter",
    ):
        mocks[name] = MagicMock()
        monkeypatch.setattr(entrypoint, name, mocks[name])
    mocks["get_connection"].return_value = MagicMock()
    mocks["find_source"].return_value = 7
    mocks["collect"].return_value = {"inserted": 2, "pages": 3}
    mocks["purge_events"].return_value = 0
    return mocks


def test_cli_success_cleans_up_and_reports_counts(runtime, capsys):
    assert entrypoint.main([]) == 0
    assert "inserted=2" in capsys.readouterr().out
    runtime["get_connection"].return_value.close.assert_called_once()
    runtime["purge_events"].assert_called_once()


@pytest.mark.parametrize(
    "error,status",
    [
        (DNSCollectionBusy("busy"), 0),
        (DNSCollectionIncomplete("pending"), 2),
        (DNSCollectionError("invalid checkpoint"), 1),
        (RuntimeError("secret-value"), 1),
    ],
)
def test_cli_failure_codes_and_no_purge(runtime, capsys, error, status):
    runtime["collect"].side_effect = error
    assert entrypoint.main([]) == status
    runtime["purge_events"].assert_not_called()
    runtime["get_connection"].return_value.close.assert_called_once()
    assert "secret-value" not in capsys.readouterr().out


def test_register_command_does_not_fetch_or_enable(runtime):
    assert entrypoint.main(["--register-source"]) == 0
    runtime["register_source"].assert_called_once()
    assert "enabled" not in runtime["register_source"].call_args.kwargs
    runtime["collect"].assert_not_called()
    runtime["AdGuardAdapter"].assert_not_called()


def test_no_connection_returns_failure(runtime):
    runtime["get_connection"].return_value = None
    assert entrypoint.main([]) == 1
    runtime["collect"].assert_not_called()


def test_retention_cleanup_is_bounded_and_source_scoped(runtime):
    runtime["purge_events"].return_value = 10000
    assert entrypoint.main([]) == 0
    assert runtime["purge_events"].call_count == 10
    assert runtime["purge_events"].call_args.kwargs["source_id"] == 7
