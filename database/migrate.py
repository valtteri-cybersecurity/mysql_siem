"""Versioned MySQL migrations. Run status first, then apply during maintenance.

The old 001..012 scripts predate migration tracking and are not replayed. Version
013 establishes their current CREATE-only baseline, retaining existing tables.
014..016 add the host model. DDL is resumed using schema introspection, not by
pretending that rollback can undo MySQL DDL.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

import pymysql

from database.connection import get_connection
from database.migration_steps import (
    ANALYSIS_TABLES,
    EVENT_TABLES,
    event_identity,
    scoped_keys,
)
from database.schema import ensure_tables, read_schema

ROOT = Path(__file__).parent
BASELINE = ROOT / "schema.sql"
REGISTRY = ROOT / "migrations/014_host_registry.sql"
LOCK_NAME = "mysql_siem_schema_migrations"
MIGRATIONS = (
    ("013", "current_baseline", BASELINE),
    ("014", "host_registry", REGISTRY),
    ("015", "event_identity", ROOT / "migration_steps.py"),
    ("016", "scoped_keys", ROOT / "migration_steps.py"),
)


class MigrationError(RuntimeError):
    """A migration needs attention before runtime jobs can resume."""


HISTORY_TABLES = EVENT_TABLES + ANALYSIS_TABLES + (
    "dns_events", "dns_sources", "dns_collection_state", "dns_client_filters", "dns_domain_filters",
    "detection_alerts", "alert_evidence", "detection_state", "ufw_state", "auth_ingestion_state",
)


def history_counts(connection):
    """Record exact counts during the documented maintenance window."""
    result = {}
    with connection.cursor() as cursor:
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
        existing = {row[0] for row in cursor.fetchall()}
        for table in HISTORY_TABLES:
            if table in existing:
                cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                result[table] = cursor.fetchone()[0]
    return result


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def migration_status(connection):
    """Read only: status does not create the tracking table."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT table_name FROM information_schema.tables "
                       "WHERE table_schema = DATABASE() AND table_name = 'schema_migrations'")
        if cursor.fetchone() is None:
            return {}
        cursor.execute("SELECT version, checksum, status FROM schema_migrations ORDER BY version")
        return {version: (digest, state) for version, digest, state in cursor.fetchall()}


def apply_one(connection, version):
    if version == "013":
        tables, rules = read_schema(BASELINE)
        ensure_tables(connection, tuple(tables), rule_keys=tuple(rules), schema_file=BASELINE)
    elif version == "014":
        tables, _ = read_schema(REGISTRY)
        ensure_tables(connection, tuple(tables), schema_file=REGISTRY)
    elif version == "015":
        event_identity(connection)
    elif version == "016":
        scoped_keys(connection)
    else:
        raise MigrationError("Unknown migration version.")


def migrate(connection):
    """Use a dedicated administrator connection, with collectors stopped.

    A RUNNING record is committed before any DDL. Only a fully completed version
    becomes APPLIED. A crash may leave RUNNING; a rerun resumes that same version.
    FAILED is committed after an ordinary exception. Driver payloads are never
    copied into the migration ledger or displayed by the CLI.
    """
    locked = False
    applied = []
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
            if cursor.fetchone() != (1,):
                raise MigrationError("Another migration process holds the schema lock.")
            locked = True
            cursor.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                name VARCHAR(128) NOT NULL,
                checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                status VARCHAR(16) NOT NULL,
                row_counts JSON NOT NULL,
                started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                finished_at TIMESTAMP(6) NULL,
                PRIMARY KEY (version),
                CONSTRAINT chk_migration_status CHECK (status IN ('RUNNING', 'FAILED', 'APPLIED'))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin""")
        records = migration_status(connection)
        known_versions = {version for version, _, _ in MIGRATIONS}
        if records.keys() - known_versions:
            raise MigrationError("Database contains unknown migration versions; use matching application code.")
        # Validate every checksum before performing any schema upgrade.
        for version, _, path in MIGRATIONS:
            if version in records and records[version][0] != checksum(path):
                raise MigrationError(f"Migration {version} checksum differs; restore its original source.")
        for version, name, path in MIGRATIONS:
            if records.get(version, (None, None))[1] == "APPLIED":
                continue
            counts = history_counts(connection)
            with connection.cursor() as cursor:
                cursor.execute("SELECT row_counts FROM schema_migrations WHERE version = %s", (version,))
                previous = cursor.fetchone()
                if previous is not None:
                    counts = json.loads(previous[0])
                cursor.execute("""INSERT INTO schema_migrations (version, name, checksum, status, row_counts)
                    VALUES (%s, %s, %s, 'RUNNING', %s)
                    ON DUPLICATE KEY UPDATE status = 'RUNNING', finished_at = NULL""",
                               (version, name, checksum(path), json.dumps(counts, sort_keys=True)))
            connection.commit()
            try:
                apply_one(connection, version)
                actual_counts = history_counts(connection)
                if any(actual_counts.get(table) != count for table, count in counts.items()):
                    raise MigrationError("Historical row counts changed; inspect the database before resuming jobs.")
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE schema_migrations SET status = 'APPLIED', "
                                   "finished_at = CURRENT_TIMESTAMP(6) WHERE version = %s", (version,))
                connection.commit()
            except Exception:
                connection.rollback()
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE schema_migrations SET status = 'FAILED' WHERE version = %s", (version,))
                connection.commit()
                raise
            applied.append(version)
        return applied
    finally:
        connection.__dict__.pop("_siem_identity_ready", None)
        if locked:
            with connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect/apply versioned SIEM migrations using DB_* settings.")
    parser.add_argument("command", choices=("status", "check", "apply"))
    parser.add_argument("--admin-socket", help="Use the local root socket account, for installer/admin use only.")
    args = parser.parse_args(argv)
    if args.admin_socket:
        try:
            connection = pymysql.connect(unix_socket=args.admin_socket, user="root", database=os.environ["DB_NAME"],
                                         charset="utf8mb4", autocommit=False)
        except (pymysql.MySQLError, KeyError):
            print("Administrator database connection failed.")
            return 1
    else:
        connection = get_connection()
    if connection is None:
        return 1
    try:
        if args.command == "apply":
            versions = migrate(connection)
            print("Applied: " + (", ".join(versions) or "none"))
        else:
            records = migration_status(connection)
            known_versions = {version for version, _, _ in MIGRATIONS}
            ready = not (records.keys() - known_versions)
            if not ready:
                print("Unknown migration versions are present; use matching application code.")
            for version, name, path in MIGRATIONS:
                digest, state = records.get(version, (None, "PENDING"))
                if digest is not None and digest != checksum(path):
                    state = "CHECKSUM_MISMATCH"
                if state != "APPLIED":
                    ready = False
                print(f"{version} {name}: {state}")
            if args.command == "check" and not ready:
                return 1
        return 0
    except (pymysql.MySQLError, OSError, MigrationError):
        print("Migration failed. Inspect migration status/schema with administrator access; keep jobs stopped.")
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
