"""Fail closed for unknown UFW history and incompatible precision."""

import json
from unittest.mock import MagicMock

import pytest

from database import migrate


@pytest.mark.parametrize("column", [None, ("timestamp", 0, "YES", None),
                                    ("datetime", 3, "YES", None),
                                    ("datetime", 0, "NO", None),
                                    ("datetime", 0, "YES", "CURRENT_TIMESTAMP")])
def test_precision_upgrade_rejects_incompatible_schema_before_ddl(monkeypatch, column):
    connection = MagicMock()
    monkeypatch.setattr(migrate, "ufw_timestamp_schema", lambda _: column)
    with pytest.raises(migrate.MigrationError):
        migrate.upgrade_ufw_timestamp_precision(connection)
    connection.cursor.assert_not_called()


@pytest.mark.parametrize("counts", [{}, {"ufw_log": -1}, {"ufw_log": True},
                                    {"ufw_log": "0"}, {"ufw_log": 1}])
def test_utc_check_rejects_unknown_or_existing_history(monkeypatch, counts):
    connection = MagicMock()
    monkeypatch.setattr(migrate, "ufw_timestamp_schema", lambda _: ("datetime", 6, "YES", None))
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (json.dumps(counts),)
    with pytest.raises(migrate.MigrationError):
        migrate.check_ufw_utc_readiness(connection)
    assert all(call.args[0].startswith("SELECT") for call in cursor.execute.call_args_list)


@pytest.mark.parametrize("table", migrate.ANALYSIS_TABLES + ("detection_state", "detection_alerts", "alert_evidence"))
def test_removed_raw_history_does_not_hide_old_summaries_or_state(monkeypatch, table):
    connection = MagicMock()
    monkeypatch.setattr(migrate, "ufw_timestamp_schema", lambda _: ("datetime", 6, "YES", None))
    counts = {name: 0 for name in ("ufw_log",) + migrate.ANALYSIS_TABLES +
              ("detection_state", "detection_alerts", "alert_evidence")}
    counts[table] = 1
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (json.dumps(counts),)
    with pytest.raises(migrate.MigrationError, match="Legacy UFW history"):
        migrate.check_ufw_utc_readiness(connection)
