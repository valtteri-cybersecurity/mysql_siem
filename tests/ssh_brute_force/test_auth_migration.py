"""Auth schema upgrade safety and metadata writes without a running database."""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from database.auth_migrations import upgrade_auth_events
from database.identity import EventIdentity
from database.migrate import MIGRATIONS, apply_one
from database.schema import SchemaError
from ingestion.auth.db import save_event

MIGRATION = Path(__file__).resolve().parents[2] / "database/migrations/021_auth_logins.sql"
SOURCE_IP = ("source_ip", "varchar(45)", "YES", None, "ascii_bin", "")
AUTH_METHOD = ("auth_method", "varchar(32)", "YES", None, "ascii_bin", "")
SOURCE_PORT = ("source_port", "smallint unsigned", "YES", None, None, "")
LEGACY_IP = ("source_ip", "varchar(45)", "NO", None, "ascii_bin", "")


def migration_connection(rows):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.side_effect = rows
    return connection, cursor


def alter_statements(cursor):
    statements = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith("ALTER"):
            statements.append(call.args[0])
    return statements


def test_auth_upgrade_is_registered_and_only_additive():
    assert ("021", "auth_logins", MIGRATION) in MIGRATIONS
    connection, cursor = migration_connection([
        [LEGACY_IP], [SOURCE_IP], [SOURCE_IP, AUTH_METHOD],
        [SOURCE_IP, AUTH_METHOD, SOURCE_PORT],
    ])
    apply_one(connection, "021")
    statements = alter_statements(cursor)
    assert len(statements) == 3
    assert "MODIFY COLUMN source_ip" in statements[0]
    assert "ADD COLUMN auth_method" in statements[1]
    assert "ADD COLUMN source_port" in statements[2]
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith(("SELECT", "ALTER TABLE auth_events"))
    connection.commit.assert_not_called()
    connection.rollback.assert_not_called()


def test_auth_upgrade_repeated_on_current_schema_does_no_writes():
    connection, cursor = migration_connection([[SOURCE_IP, AUTH_METHOD, SOURCE_PORT]])
    upgrade_auth_events(connection, MIGRATION)
    assert alter_statements(cursor) == []


@pytest.mark.parametrize("committed", [1, 2])
def test_auth_upgrade_resumes_after_partial_ddl(committed):
    if committed == 1:
        rows = [[SOURCE_IP], [SOURCE_IP, AUTH_METHOD], [SOURCE_IP, AUTH_METHOD, SOURCE_PORT]]
    else:
        rows = [[SOURCE_IP, AUTH_METHOD], [SOURCE_IP, AUTH_METHOD, SOURCE_PORT]]
    connection, cursor = migration_connection(rows)
    upgrade_auth_events(connection, MIGRATION)
    assert len(alter_statements(cursor)) == 3 - committed
    assert "MODIFY" not in " ".join(alter_statements(cursor))


@pytest.mark.parametrize("columns", [
    [],
    [("source_ip", "varchar(128)", "NO", None, "ascii_bin", "")],
    [("source_ip", "varchar(45)", "NO", None, "utf8mb4_bin", "")],
    [LEGACY_IP, ("auth_method", "varchar(32)", "NO", None, "ascii_bin", "")],
    [LEGACY_IP, ("source_port", "smallint unsigned", "YES", "0", None, "")],
])
def test_auth_upgrade_rejects_incompatible_schema_before_any_write(columns):
    connection, cursor = migration_connection([columns])
    with pytest.raises(SchemaError):
        upgrade_auth_events(connection, MIGRATION)
    assert alter_statements(cursor) == []


def test_auth_upgrade_checks_the_result_of_each_alter():
    connection, cursor = migration_connection([[LEGACY_IP], [LEGACY_IP]])
    with pytest.raises(SchemaError, match="not verified"):
        upgrade_auth_events(connection, MIGRATION)
    assert len(alter_statements(cursor)) == 1


def test_auth_write_preserves_raw_message_nullable_ip_metadata_and_identity():
    event = {
        "event_time": datetime(2026, 10, 27, 12), "hostname": "server",
        "source_ip": None, "username": "alice", "event_type": "LOCAL_LOGIN_SUCCESS",
        "service": "login", "raw_message": "original supported login message",
        "event_hash": "a" * 64, "auth_method": "pam", "source_port": None,
    }
    cursor = MagicMock()
    assert save_event(cursor, event, identity=EventIdentity(1, 2, 3)) == 1
    sql, values = cursor.execute.call_args.args
    assert "auth_method, source_port, host_id, source_id, collector_id, sender_id, source_scope" in sql
    assert values == (datetime(2026, 10, 27, 12), "server", None, "alice",
                      "LOCAL_LOGIN_SUCCESS", "login", "original supported login message",
                      "a" * 64, "pam", None, 1, 2, 3, None, 2)
