
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
import time
from datetime import datetime, timedelta
from decimal import Decimal
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
    ("022", "ufw_history_isolation", ROOT / "migrations/022_ufw_history_isolation.sql"),
    ("023", "ufw_analysis_history", ROOT / "migrations/023_ufw_analysis_history.sql"),
    ("024", "ufw_quarantine_archives", ROOT / "migrations/024_ufw_quarantine_archives.sql"),
    ("025", "ufw_continuity", ROOT / "migrations/025_ufw_continuity.sql"),
    ("026", "ufw_filtering", ROOT / "migrations/026_ufw_filtering.sql"),
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
    "ufw_state", "ufw_archive_failures", "ufw_quarantine", "ufw_quarantine_origins", "ufw_archives",
    "ufw_file_checkpoints", "ufw_collection_gaps", "ufw_archive_proofs", "ufw_collection_health",
    "ufw_filter_rules", "ufw_filter_audit", "ufw_filter_seen", "ufw_filter_stats",
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


UFW_HISTORY_TABLES = ("ufw_log",) + ANALYSIS_TABLES
SHARED_HISTORY_TABLES = ("detection_state", "detection_alerts", "alert_evidence")

UFW_UTC_PROOF = "_ufw_utc_proof"
UFW_HISTORY_SECONDS = 120
UFW_HISTORY_BATCH = 256


def check_ufw_raw_history(connection, count, *, saved=None):
    """Prove UTC without rewriting rows; return bounded-size ledger evidence.

    TIMESTAMP provenance uses epoch seconds, independent of session timezone.
    Count-only ledgers cannot prove original IDs and require 022 isolation.
    A recorded digest allows gaps and preserves pre-ALTER precision.
    """
    from ingestion.splitter import parse_ufw_line
    from ingestion.ufw_to_mysql import convert_timestamp

    if type(count) is not int or count < 0:
        raise MigrationError("Legacy UFW history row count is invalid.")
    deadline = time.monotonic() + UFW_HISTORY_SECONDS
    proof = None
    previous = 0
    if saved is not None:
        previous = saved.get("ufw_log", 0)
        proof = saved.get(UFW_UTC_PROOF)
        if previous != count:
            raise MigrationError("Legacy UFW history counts no longer identify the original rows.")
    if count == 0:
        if proof is not None:
            raise MigrationError("Legacy UFW history proof contradicts the row count.")
        return None
    column = ufw_timestamp_schema(connection)
    if (not isinstance(column, tuple) or len(column) != 4
            or column[0] != "datetime" or column[1] not in (0, 6)
            or column[2:] != ("YES", None)):
        raise MigrationError("Legacy UFW history has unsupported timestamp precision.")
    precision = column[1]
    upper = None
    if proof is not None:
        if (not isinstance(proof, dict) or set(proof) != {"version", "precision", "count", "max_id", "sha256"}
                or type(proof["version"]) is not int or proof["version"] != 1
                or type(proof["precision"]) is not int or proof["precision"] not in (0, 6)
                or proof["precision"] > precision
                or type(proof["count"]) is not int or proof["count"] != count
                or type(proof["max_id"]) is not int or not 0 < proof["max_id"] < 2**64
                or not isinstance(proof["sha256"], str)
                or len(proof["sha256"]) != 64):
            raise MigrationError("Legacy UFW history proof is invalid.")
        for character in proof["sha256"]:
            if character not in "0123456789abcdef":
                raise MigrationError("Legacy UFW history proof digest is invalid.")
        precision = proof["precision"]
        upper = proof["max_id"]
    elif previous:
        raise MigrationError('Legacy UFW history has count-only provenance; migration 022 isolation is required.')
    else:
        with connection.cursor() as cursor:
            cursor.execute("SELECT /*+ MAX_EXECUTION_TIME(5000) */ MAX(id) FROM ufw_log")
            row = cursor.fetchone()
        if row is None or type(row[0]) is not int or not 0 < row[0] < 2**64:
            raise MigrationError("Legacy UFW history rows cannot be identified.")
        upper = row[0]
    digest = hashlib.sha256()
    last_id = 0
    seen = 0
    while last_id < upper:
        if time.monotonic() >= deadline:
            raise MigrationError("Legacy UFW history verification exceeded its time budget.")
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT /*+ MAX_EXECUTION_TIME(5000) */ id, event_time, raw_line, UNIX_TIMESTAMP(created_at) "
                "FROM ufw_log WHERE id > %s AND id <= %s ORDER BY id LIMIT %s",
                (last_id, upper, UFW_HISTORY_BATCH),
            )
            rows = cursor.fetchall()
        if not rows:
            break
        for event_id, stored, raw_line, created in rows:
            if time.monotonic() >= deadline:
                raise MigrationError("Legacy UFW history verification exceeded its time budget.")
            if type(event_id) is not int or not last_id < event_id <= upper:
                raise MigrationError("Legacy UFW history IDs are inconsistent.")
            if (not isinstance(stored, datetime) or stored.tzinfo is not None
                    or not isinstance(created, (int, Decimal))
                    or not isinstance(raw_line, str) or len(raw_line) > 65536):
                raise MigrationError("Legacy UFW history has invalid timestamp evidence.")
            timestamp = parse_ufw_line(raw_line)["timestamp"]
            if not isinstance(timestamp, str):
                raise MigrationError("Legacy UFW history has no timestamp evidence.")
            if timestamp.endswith("Z"):
                local_time = timestamp[:-1]
            else:
                zone = timestamp[-6:]
                if (len(zone) != 6 or zone[0] not in ("+", "-") or zone[3] != ":"
                        or not zone[1:3].isascii() or not zone[1:3].isdigit()
                        or not zone[4:6].isascii() or not zone[4:6].isdigit()
                        or zone == "-00:00"):
                    raise MigrationError("Legacy UFW history has no unambiguous timezone evidence.")
                if int(zone[1:3]) > 23 or int(zone[4:6]) > 59:
                    raise MigrationError("Legacy UFW history has invalid timezone evidence.")
                local_time = timestamp[:-6]
            base_time, point, fraction = local_time.partition(".")
            if len(base_time) != 19 or base_time[10] != "T":
                raise MigrationError("Legacy UFW history has invalid timestamp evidence.")
            if point:
                if not 1 <= len(fraction) <= 6:
                    raise MigrationError("Legacy UFW history has unsupported fractional precision.")
                if not fraction.isascii() or not fraction.isdigit():
                    raise MigrationError("Legacy UFW history has invalid fractional seconds.")
            try:
                utc = convert_timestamp(timestamp)
            except ValueError:
                raise MigrationError("Legacy UFW history has invalid timestamp evidence.") from None
            matches = stored == utc
            if precision == 0:
                # MySQL DATETIME(0) either truncates or rounds fractional seconds,
                # depending on the writer's TIME_TRUNCATE_FRACTIONAL SQL mode.
                truncated = utc.replace(microsecond=0)
                rounded = truncated
                if utc.microsecond >= 500000:
                    try:
                        rounded += timedelta(seconds=1)
                    except OverflowError:
                        raise MigrationError("Legacy UFW history rounding is outside the MySQL range.") from None
                matches = stored in (truncated, rounded)
            if not matches:
                raise MigrationError("Legacy UFW history event_time does not match proven UTC.")
            payload = (event_id, stored.isoformat(timespec="microseconds"), raw_line,
                       str(created))
            digest.update(json.dumps(payload, ensure_ascii=True).encode("ascii") + b"\n")
            last_id = event_id
            seen += 1
    if seen != count or last_id != upper:
        raise MigrationError("Legacy UFW history original rows are missing or replaced.")
    verified = {"version": 1, "precision": precision, "count": seen,
                "max_id": upper, "sha256": digest.hexdigest()}
    if proof is not None and verified != proof:
        raise MigrationError("Legacy UFW history no longer matches its verified original rows.")
    return verified


def check_ufw_history(connection, counts, *, saved=None):
    """Read-only classification; aggregate legacy counts are never provenance.

    Shared detection totals require surviving SSH rows from before 017 started.
    Older evidence needs surviving old SSH parents. A 022 baseline records
    actual immutable IDs independently of the count-only 017 provenance.
    """
    for source in (counts, saved):
        if source is None:
            continue
        if not isinstance(source, dict):
            raise MigrationError("Historical counts are invalid.")
        for table in UFW_HISTORY_TABLES + SHARED_HISTORY_TABLES:
            value = source.get(table, 0)
            if type(value) is not int or value < 0:
                raise MigrationError("Historical counts are invalid.")
            if table in ANALYSIS_TABLES and value:
                raise MigrationError("Legacy UFW history predates a verified UTC migration.")
    proof = check_ufw_raw_history(connection, counts.get("ufw_log", 0), saved=saved)
    relevant = False
    for table in SHARED_HISTORY_TABLES:
        if counts.get(table, 0) or saved is not None and saved.get(table, 0):
            relevant = True
    if not relevant:
        return proof
    cutoff = "(SELECT started_at FROM schema_migrations WHERE version = '017')"
    queries = (
        ("detection_state", "SELECT COUNT(*), COALESCE(SUM(CASE WHEN r.rule_key = 'SSH_BRUTE_FORCE_001' "
         "THEN 0 ELSE 1 END),0), COALESCE(SUM(CASE WHEN s.updated_at <= " + cutoff +
         " THEN 1 ELSE 0 END),0) FROM detection_state s LEFT JOIN detection_rules r ON r.id=s.rule_id"),
        ("detection_alerts", "SELECT COUNT(*), COALESCE(SUM(CASE WHEN r.rule_key = 'SSH_BRUTE_FORCE_001' "
         "THEN 0 ELSE 1 END),0), COALESCE(SUM(CASE WHEN a.detected_at <= " + cutoff +
         " THEN 1 ELSE 0 END),0) FROM detection_alerts a LEFT JOIN detection_rules r ON r.id=a.rule_id"),
        ("alert_evidence", "SELECT COUNT(*), COALESCE(SUM(CASE WHEN r.rule_key = 'SSH_BRUTE_FORCE_001' "
         "AND e.event_type = 'AUTH' AND h.id IS NOT NULL AND h.event_type = 'SSH_AUTH_FAILURE' "
         "AND h.service = 'sshd' THEN 0 ELSE 1 END),0), COALESCE(SUM(CASE WHEN a.detected_at <= " + cutoff +
         " AND h.created_at <= " + cutoff + " THEN 1 ELSE 0 END),0), COALESCE(MAX(e.id),0) "
         "FROM alert_evidence e LEFT JOIN detection_alerts a ON a.id=e.alert_id "
         "LEFT JOIN detection_rules r ON r.id=a.rule_id LEFT JOIN auth_events h ON h.id=e.event_id"),
    )
    with connection.cursor() as cursor:
        for table, query in queries:
            cursor.execute(query)
            row = cursor.fetchone()
            if (not isinstance(row, tuple) or len(row) < 3 or type(row[0]) is not int
                    or row[1] != 0):
                raise MigrationError("Legacy UFW history or unclassifiable detection history blocks migration 017.")
            previous = 0
            if saved is not None:
                previous = saved.get(table, 0)
            if previous and (row[0] < previous or (table != "detection_state" and row[2] < previous)):
                raise MigrationError("Legacy UFW history provenance cannot be established from the migration ledger.")
        cursor.execute("SELECT s.rule_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "WHERE r.rule_key = 'SSH_BRUTE_FORCE_001'")
        rules = cursor.fetchall()
    from detection.ssh_brute_force.state import load_state
    try:
        for rule in rules:
            _last_id, records = load_state(connection, rule[0])
            with connection.cursor() as cursor:
                for record in records:
                    event = record['event']
                    cursor.execute("SELECT id FROM auth_events WHERE id=%s AND event_hash=%s "
                                   "AND event_type='SSH_AUTH_FAILURE' AND service='sshd'",
                                   (event['id'], event['event_hash']))
                    if cursor.fetchone() != (event['id'],):
                        raise MigrationError("Legacy UFW history: SSH state references an unverified event.")
    except (ValueError, RuntimeError, TypeError, KeyError):
        raise MigrationError("Legacy UFW history: detection state cannot be classified safely.") from None

    return proof


def check_ufw_utc_readiness(connection):
    """Require completed precision migration and proven historical UTC values."""
    if ufw_timestamp_schema(connection) != ("datetime", 6, "YES", None):
        raise MigrationError("UFW UTC deployment requires DATETIME(6).")
    if migration_status(connection).get("022", (None, None))[1] == "APPLIED":
        from database.ufw_history import preflight
        preflight(connection)
        return
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
        for table in tables:
            value = counts[table]
            if type(value) is not int or value < 0:
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise MigrationError("Cannot verify the UFW historical time basis.") from None
    check_ufw_history(connection, counts, saved=counts)


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

    elif version == "026":
        path = ROOT / "migrations/026_ufw_filtering.sql"
        tables, _rules = read_schema(path)
        ensure_tables(connection, tuple(tables), schema_file=path)
        from database.ufw_collection_schema import verify
        verify(connection, continuity=True, filtering=True)

    elif version == "025":
        path = ROOT / "migrations/025_ufw_continuity.sql"
        tables, _rules = read_schema(path)
        ensure_tables(connection, tuple(tables), schema_file=path)
        from database.ufw_collection_schema import verify
        verify(connection, continuity=True)

    elif version == "024":
        tables, _rules = read_schema(ROOT / 'migrations/024_ufw_quarantine_archives.sql')
        ensure_tables(connection, tuple(tables), schema_file=ROOT / 'migrations/024_ufw_quarantine_archives.sql')
        from database.ufw_collection_schema import verify
        verify(connection)

    elif version == "023":
        from database.ufw_analysis_history import upgrade
        upgrade(connection)

    elif version == "022":
        from database.ufw_history import isolate
        isolate(connection)

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

                from database.ufw_history import (
                    KEY,
                    SSH_KEY,
                    raw_baseline,
                    ssh_baseline,
                )
                if version == "017" and KEY not in counts:
                    counts[KEY] = raw_baseline(connection)
                    if (counts[KEY]['all_utc'] and counts.get('ufw_log', 0)
                            and counts['ufw_log'] == counts[KEY]['count']):
                        saved = None
                        if UFW_UTC_PROOF in counts:
                            saved = counts
                        counts[UFW_UTC_PROOF] = check_ufw_raw_history(connection, counts['ufw_log'], saved=saved)
                if version == "022" and KEY not in counts:
                    cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='017'")
                    original = json.loads(cursor.fetchone()[0])
                    baseline = original.get(KEY)
                    if baseline is None:
                        baseline = raw_baseline(connection)
                        old_proof = original.get(UFW_UTC_PROOF)
                        if old_proof is not None:
                            check_ufw_raw_history(connection, original['ufw_log'], saved=original)
                            baseline['previous_max_id'] = old_proof['max_id']
                            baseline['previous_precision'] = old_proof['precision']
                    counts[KEY] = baseline
                    counts[SSH_KEY] = ssh_baseline(connection)

                if version == "023" and "_analysis_baseline" not in counts:
                    from database.ufw_analysis_history import capture
                    counts["_analysis_baseline"] = capture(connection)
                cursor.execute(
                    """
                    INSERT INTO schema_migrations
                        (version, name, checksum, status, row_counts)
                    VALUES (%s, %s, %s, 'RUNNING', %s)
                    ON DUPLICATE KEY UPDATE
                        status = 'RUNNING',
                        row_counts = VALUES(row_counts),
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
                    if table in ("_ufw_compatibility", "_ssh_baseline", "_analysis_baseline", UFW_UTC_PROOF):
                        continue
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
