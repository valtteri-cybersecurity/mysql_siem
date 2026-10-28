
"""Versioned MySQL migrations.

Versions 013-016 preserve the existing schema and add host identities.
Version 017 upgrades UFW event timestamps to microsecond precision.
Version 021 adds nullable Auth login metadata and local source addresses.
MySQL DDL is resumed through schema inspection, not transaction rollback.
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
UFW_TIME_MIGRATION = ROOT / "migrations/017_ufw_datetime_precision.sql"
LOCK_NAME = "mysql_siem_schema_migrations"

MIGRATIONS = (
    ("013", "current_baseline", BASELINE),
    ("014", "host_registry", REGISTRY),
    ("015", "event_identity", ROOT / "migration_steps.py"),
    ("016", "scoped_keys", ROOT / "migration_steps.py"),
    ("017", "ufw_datetime_precision", UFW_TIME_MIGRATION),
    ("018", "processes", ROOT / "migrations/018_processes.sql"),
    ("019", "services", ROOT / "migrations/019_services.sql"),
    ("020", "audit", ROOT / "migrations/020_audit.sql"),
    ("021", "auth_logins", ROOT / "migrations/021_auth_logins.sql"),
)


class MigrationError(RuntimeError):
    """A migration needs attention before runtime jobs can resume."""


HISTORY_TABLES = EVENT_TABLES + ANALYSIS_TABLES + (
    "dns_events",
    "dns_sources",
    "dns_collection_state",
    "dns_client_filters",
    "dns_domain_filters",
    "detection_alerts",
    "alert_evidence",
    "detection_state",
    "ufw_state",
    "auth_ingestion_state",
    "process_events", "process_state", "service_events", "service_state", "collector_snapshots",
    "audit_events", "audit_checkpoints", "audit_targets",
)


def history_counts(connection):
    """Record table row counts during the maintenance window."""

    result = {}
    existing = set()

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT table_name "
            "FROM information_schema.tables "
            "WHERE table_schema = DATABASE()"
        )

        rows = cursor.fetchall()

        for row in rows:
            existing.add(row[0])

        for table in HISTORY_TABLES:
            if table in existing:
                cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                result[table] = cursor.fetchone()[0]

    return result


def checksum(path):
    """Calculate a migration file checksum."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def migration_status(connection):
    """Read migration status without changing the database."""

    records = {}

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT table_name "
            "FROM information_schema.tables "
            "WHERE table_schema = DATABASE() "
            "AND table_name = 'schema_migrations'"
        )

        if cursor.fetchone() is None:
            return records

        cursor.execute(
            "SELECT version, checksum, status "
            "FROM schema_migrations "
            "ORDER BY version"
        )

        rows = cursor.fetchall()

        for row in rows:
            version = row[0]
            digest = row[1]
            state = row[2]

            records[version] = (digest, state)

    return records


def check_migration_history(connection):
    """Validate known versions and source checksums using SELECT queries only."""
    records = migration_status(connection)
    known_versions = set()

    for version, name, path in MIGRATIONS:
        known_versions.add(version)

    for version in records:
        if version not in known_versions:
            raise MigrationError(
                "Database contains unknown migration versions; "
                "use matching application code."
            )

    # Check existing migrations before changing the schema.
    for version, name, path in MIGRATIONS:
        if version in records:
            saved_checksum = records[version][0]
            current_checksum = checksum(path)

            if saved_checksum != current_checksum:
                raise MigrationError(
                    f"Migration {version} checksum differs; "
                    "restore its original source."
                )

    return records


def ufw_timestamp_schema(connection):
    """Inspect the UFW event_time column without changing it."""

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT DATA_TYPE, DATETIME_PRECISION, "
            "IS_NULLABLE, COLUMN_DEFAULT "
            "FROM information_schema.columns "
            "WHERE TABLE_SCHEMA = DATABASE() "
            "AND TABLE_NAME = %s "
            "AND COLUMN_NAME = %s",
            ("ufw_log", "event_time"),
        )

        return cursor.fetchone()


def upgrade_ufw_timestamp_precision(connection):
    """Upgrade UFW timestamps to microsecond precision.

    Existing timestamp values are preserved.
    Historical local times are not converted into UTC.
    """

    column = ufw_timestamp_schema(connection)

    if column is None:
        raise MigrationError(
            "UFW event_time column is missing."
        )

    data_type = column[0]
    precision = column[1]
    nullable = column[2]
    default = column[3]

    if data_type != "datetime":
        raise MigrationError(
            "UFW event_time must be DATETIME."
        )

    if nullable != "YES":
        raise MigrationError(
            "Unexpected UFW event_time NULL setting."
        )

    if default is not None:
        raise MigrationError(
            "Unexpected UFW event_time default value."
        )

    if precision == 6:
        return

    if precision != 0:
        raise MigrationError(
            "Unsupported UFW timestamp precision."
        )

    sql = UFW_TIME_MIGRATION.read_text(
        encoding="utf-8"
    ).strip()

    with connection.cursor() as cursor:
        cursor.execute(sql)

    updated_schema = ufw_timestamp_schema(connection)

    if updated_schema != ("datetime", 6, "YES", None):
        raise MigrationError(
            "UFW DATETIME(6) upgrade was not verified."
        )


def check_ufw_utc_readiness(connection):
    """Fail the deployment check for ambiguous history; never convert old rows.

    A 017 ledger with pre-existing UFW rows is an offline historical database.
    New UTC collection must use a fresh migrated database (see the runbook).
    """
    if ufw_timestamp_schema(connection) != ("datetime", 6, "YES", None):
        raise MigrationError("UFW UTC deployment requires DATETIME(6).")
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version = '017' AND status = 'APPLIED'")
        row = cursor.fetchone()
    if row is None:
        raise MigrationError("UFW UTC migration 017 is not complete.")
    try:
        counts = json.loads(row[0])
        tables = ("ufw_log",) + ANALYSIS_TABLES + (
            "detection_state", "detection_alerts", "alert_evidence",
        )
        values = [counts[table] for table in tables]
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise MigrationError("Cannot verify the UFW historical time basis.") from None
    if any(values):
        raise MigrationError(
            "Legacy UFW history has an unverified time basis; keep this database offline. "
            "Use a fresh migrated database for UTC collection. The development installer recreates mysql_siem only after explicit RESET confirmation."
        )


def apply_one(connection, version):
    """Apply one database migration."""

    if version == "013":
        tables, rules = read_schema(BASELINE)

        ensure_tables(
            connection,
            tuple(tables),
            rule_keys=tuple(rules),
            schema_file=BASELINE,
        )

    elif version == "014":
        tables, _ = read_schema(REGISTRY)

        ensure_tables(
            connection,
            tuple(tables),
            schema_file=REGISTRY,
        )

    elif version == "015":
        event_identity(connection)

    elif version == "016":
        scoped_keys(connection)

    elif version == "017":
        upgrade_ufw_timestamp_precision(connection)

    elif version in ("018", "019"):
        from database.snapshot_migrations import upgrade_snapshots
        path = ROOT / ("migrations/018_processes.sql" if version == "018" else "migrations/019_services.sql")
        upgrade_snapshots(connection, path, services=version == "019")

    elif version == "020":
        from database.audit_migrations import upgrade_audit
        upgrade_audit(connection, ROOT / "migrations/020_audit.sql")

    elif version == "021":
        from database.auth_migrations import upgrade_auth_events
        upgrade_auth_events(connection, ROOT / "migrations/021_auth_logins.sql")

    else:
        raise MigrationError(
            "Unknown migration version."
        )


def migrate(connection):
    """Apply pending migrations with collectors stopped.

    RUNNING is committed before DDL.
    Completed migrations become APPLIED.

    MySQL DDL cannot be reliably rolled back.
    An interrupted migration can be resumed.
    """

    locked = False
    applied = []

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT GET_LOCK(%s, 0)",
                (LOCK_NAME,),
            )

            if cursor.fetchone() != (1,):
                raise MigrationError(
                    "Another migration process holds the schema lock."
                )

            locked = True

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(16)
                        CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                    name VARCHAR(128) NOT NULL,
                    checksum CHAR(64)
                        CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                    status VARCHAR(16) NOT NULL,
                    row_counts JSON NOT NULL,
                    started_at TIMESTAMP(6)
                        NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                    finished_at TIMESTAMP(6) NULL,
                    PRIMARY KEY (version),
                    CONSTRAINT chk_migration_status
                        CHECK (status IN ('RUNNING', 'FAILED', 'APPLIED'))
                ) ENGINE=InnoDB
                  DEFAULT CHARSET=utf8mb4
                  COLLATE=utf8mb4_bin
                """
            )

        records = check_migration_history(connection)

        for version, name, path in MIGRATIONS:
            if version in records:
                state = records[version][1]

                if state == "APPLIED":
                    continue

            counts = history_counts(connection)

            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT row_counts "
                    "FROM schema_migrations "
                    "WHERE version = %s",
                    (version,),
                )

                previous = cursor.fetchone()

                if previous is not None:
                    counts = json.loads(previous[0])

                cursor.execute(
                    """
                    INSERT INTO schema_migrations
                        (version, name, checksum, status, row_counts)
                    VALUES (%s, %s, %s, 'RUNNING', %s)
                    ON DUPLICATE KEY UPDATE
                        status = 'RUNNING',
                        finished_at = NULL
                    """,
                    (
                        version,
                        name,
                        checksum(path),
                        json.dumps(counts, sort_keys=True),
                    ),
                )

            connection.commit()

            try:
                apply_one(connection, version)

                actual_counts = history_counts(connection)

                for table in counts:
                    original_count = counts[table]
                    current_count = actual_counts.get(table)

                    if current_count is None or current_count < original_count:
                        raise MigrationError(
                            "Historical row counts decreased; "
                            "inspect the database before resuming jobs."
                        )

                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE schema_migrations "
                        "SET status = 'APPLIED', "
                        "finished_at = CURRENT_TIMESTAMP(6) "
                        "WHERE version = %s",
                        (version,),
                    )

                connection.commit()

            except Exception:
                connection.rollback()

                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE schema_migrations "
                        "SET status = 'FAILED' "
                        "WHERE version = %s",
                        (version,),
                    )

                connection.commit()
                raise

            applied.append(version)

        return applied

    finally:
        connection.__dict__.pop(
            "_siem_identity_ready",
            None,
        )

        if locked:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT RELEASE_LOCK(%s)",
                    (LOCK_NAME,),
                )


def main(argv=None):
    """Command-line interface for database migrations."""

    parser = argparse.ArgumentParser(
        description=(
            "Inspect or apply versioned SIEM migrations "
            "using DB_* settings."
        )
    )

    parser.add_argument(
        "command",
        choices=("status", "check", "apply"),
    )

    parser.add_argument(
        "--admin-socket",
        help=(
            "Use the local root socket account, "
            "for installer/admin use only."
        ),
    )

    args = parser.parse_args(argv)

    if args.admin_socket:
        try:
            connection = pymysql.connect(
                unix_socket=args.admin_socket,
                user="root",
                database=os.environ["DB_NAME"],
                charset="utf8mb4",
                autocommit=False,
                init_command="SET time_zone = '+00:00'",
            )

        except (pymysql.MySQLError, KeyError):
            print(
                "Administrator database connection failed."
            )
            return 1

    else:
        connection = get_connection()

    if connection is None:
        return 1

    try:
        if args.command == "apply":
            versions = migrate(connection)

            if versions:
                print("Applied: " + ", ".join(versions))
            else:
                print("Applied: none")

        else:
            records = migration_status(connection)

            known_versions = set()

            for version, name, path in MIGRATIONS:
                known_versions.add(version)

            ready = True

            for version in records:
                if version not in known_versions:
                    ready = False

            if not ready:
                print(
                    "Unknown migration versions are present; "
                    "use matching application code."
                )

            for version, name, path in MIGRATIONS:
                digest, state = records.get(
                    version,
                    (None, "PENDING"),
                )

                if digest is not None and digest != checksum(path):
                    state = "CHECKSUM_MISMATCH"

                if state != "APPLIED":
                    ready = False

                print(f"{version} {name}: {state}")

            if args.command == "check":
                if not ready:
                    return 1
                check_ufw_utc_readiness(connection)

        return 0

    except MigrationError as error:
        print(str(error))
        return 1

    except (pymysql.MySQLError, OSError):
        print(
            "Migration failed. Inspect migration status/schema "
            "with administrator access; keep jobs stopped."
        )
        return 1

    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
