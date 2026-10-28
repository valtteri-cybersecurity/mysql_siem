"""Fail closed for unknown UFW history and incompatible precision."""

import json
from datetime import datetime
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


@pytest.mark.parametrize('actual', [4, 5, 6])
def test_migrations_allow_added_rows_but_reject_disappearing_history(monkeypatch, tmp_path, actual):
    source = tmp_path / 'approved.sql'
    source.write_text('SELECT 1;')
    monkeypatch.setattr(migrate, 'MIGRATIONS', (('999', 'synthetic_additive', source),))
    monkeypatch.setattr(migrate, 'check_migration_history', lambda connection: {})
    counts = iter([{'auth_events': 5}, {'auth_events': actual}])
    monkeypatch.setattr(migrate, 'history_counts', lambda connection: next(counts))
    monkeypatch.setattr(migrate, 'apply_one', lambda connection, version: None)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(1,), None]
    if actual < 5:
        with pytest.raises(migrate.MigrationError, match='decreased'):
            migrate.migrate(connection)
    else:
        assert migrate.migrate(connection) == ['999']


class ReadOnlyConnection:
    """Reject mutations and transaction changes made by either preflight."""

    def __init__(self, connection):
        self.connection = connection

    def cursor(self):
        return ReadOnlyCursor(self.connection.cursor())


class ReadOnlyCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cursor.close()

    def execute(self, sql, args=None):
        assert sql.lstrip().startswith("SELECT")
        return self.cursor.execute(sql, args)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


@pytest.mark.parametrize("status", [None, "RUNNING", "FAILED", "APPLIED"])
@pytest.mark.parametrize("scenario", [
    "ssh", "ufw_log", "analysis_ufw_traffic", "port_scan", "unknown_rule",
    "orphan_rule", "ufw_evidence", "orphan_alert", "orphan_auth",
    "wrong_auth", "invalid_state", "missing_history", "newer_history", "evidence_gap",
])
def test_detection_history_classification_mysql(empty_mysql, monkeypatch, status, scenario):
    """Exercise actual MySQL SELECTs in a fresh socket-only test database."""
    from config import reset_installation as setup

    connection = empty_mysql
    with connection.cursor() as cursor:
        cursor.execute("CREATE TABLE schema_migrations "
                       "(version VARCHAR(16), status VARCHAR(16), row_counts JSON, started_at TIMESTAMP(6))")
        cursor.execute("CREATE TABLE ufw_log (id BIGINT PRIMARY KEY, event_time DATETIME(6), "
                       "raw_line TEXT, created_at TIMESTAMP)")
        cursor.execute("CREATE TABLE detection_rules (id INT PRIMARY KEY, rule_key VARCHAR(64))")
        cursor.execute("CREATE TABLE detection_state (rule_id INT PRIMARY KEY, last_event_id BIGINT, "
                       "state_data JSON, updated_at TIMESTAMP(6))")
        cursor.execute("CREATE TABLE detection_alerts (id INT PRIMARY KEY, rule_id INT, detected_at TIMESTAMP(6))")
        cursor.execute("CREATE TABLE alert_evidence (id INT PRIMARY KEY, alert_id INT, event_type VARCHAR(32), event_id INT)")
        cursor.execute("CREATE TABLE auth_events (id INT PRIMARY KEY, event_type VARCHAR(64), "
                       "service VARCHAR(32), event_hash VARCHAR(64), created_at TIMESTAMP(6))")
        cursor.execute("INSERT INTO detection_rules VALUES (1, 'SSH_BRUTE_FORCE_001')")
        cursor.execute("INSERT INTO detection_state VALUES (1, 1, %s, '2026-01-01')",
                       (json.dumps({"version": 1, "events": []}),))
        cursor.execute("INSERT INTO detection_alerts VALUES (1, 1, '2026-01-01')")
        cursor.execute("INSERT INTO auth_events VALUES (1, 'SSH_AUTH_FAILURE', 'sshd', 'hash', '2026-01-01')")
        cursor.execute("INSERT INTO alert_evidence VALUES (1, 1, 'AUTH', 1)")
        changes = {
            "port_scan": "UPDATE detection_rules SET rule_key='PORT_SCAN_001'",
            "unknown_rule": "UPDATE detection_rules SET rule_key='UNKNOWN'",
            "orphan_rule": "DELETE FROM detection_rules",
            "ufw_evidence": "UPDATE alert_evidence SET event_type='UFW'",
            "orphan_alert": "UPDATE alert_evidence SET alert_id=99",
            "orphan_auth": "UPDATE alert_evidence SET event_id=99",
            "wrong_auth": "UPDATE auth_events SET event_type='SSH_AUTH_SUCCESS'",
            "invalid_state": "UPDATE detection_state SET state_data=JSON_OBJECT()",
            "missing_history": "DELETE FROM alert_evidence",
            "newer_history": "UPDATE detection_state SET updated_at='2026-03-01'",
            "evidence_gap": "UPDATE alert_evidence SET id=10",
        }
        if scenario in changes:
            cursor.execute(changes[scenario])
        saved = {}
        for table in migrate.UFW_HISTORY_TABLES + migrate.SHARED_HISTORY_TABLES:
            saved[table] = 0
        for table in migrate.SHARED_HISTORY_TABLES:
            saved[table] = 1
        current = dict(saved)
        if scenario == "missing_history":
            current["alert_evidence"] = 0
        if scenario in ("ufw_log", "analysis_ufw_traffic"):
            saved[scenario] = 1
            current[scenario] = 1
        if status is not None:
            cursor.execute("INSERT INTO schema_migrations VALUES ('017', %s, %s, '2026-02-01')",
                           (status, json.dumps(saved)))
    monkeypatch.setattr(migrate, "migration_status", lambda _: {"017": ("checksum", status)})
    monkeypatch.setattr(migrate, "history_counts", lambda _: current)
    monkeypatch.setattr(migrate, "ufw_timestamp_schema", lambda _: ("datetime", 6, "YES", None))
    tables = ("schema_migrations", "detection_rules", "detection_state",
              "detection_alerts", "alert_evidence", "auth_events")
    before = {}
    with connection.cursor() as cursor:
        for table in tables:
            cursor.execute("SELECT * FROM " + table)
            before[table] = cursor.fetchall()
    allowed = scenario == "ssh"
    # With no earlier ledger there is no historical snapshot to contradict.
    if status is None and scenario in ("missing_history", "newer_history", "evidence_gap"):
        allowed = True
    readonly = ReadOnlyConnection(connection)
    if allowed:
        setup.check_ufw_before_upgrade(readonly)
    else:
        with pytest.raises((setup.ResetError, migrate.MigrationError)):
            setup.check_ufw_before_upgrade(readonly)
    with connection.cursor() as cursor:
        for table in tables:
            cursor.execute("SELECT * FROM " + table)
            assert cursor.fetchall() == before[table]


@pytest.fixture
def raw_history(monkeypatch):
    """A keyset-query fake that rejects writes and enforces the batch size."""
    def prepare(rows, precision=0):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        current = [None, None]

        def execute(sql, args=None):
            assert sql.startswith("SELECT")
            current[:] = [sql, args]

        def fetchone():
            if "started_at" in current[0]:
                return (1769904000,)
            maximum = None
            for row in rows:
                if maximum is None or row[0] > maximum:
                    maximum = row[0]
            return (maximum,)

        def fetchall():
            last_id, upper, limit = current[1]
            assert limit == migrate.UFW_HISTORY_BATCH
            batch = []
            for row in rows:
                if last_id < row[0] <= upper and len(batch) < limit:
                    batch.append(row)
            return batch

        cursor.execute.side_effect = execute
        cursor.fetchone.side_effect = fetchone
        cursor.fetchall.side_effect = fetchall
        monkeypatch.setattr(migrate, "ufw_timestamp_schema", lambda _: ("datetime", precision, "YES", None))
        return connection
    return prepare


def old_ufw_row(timestamp, stored, event_id=1):
    return (event_id, stored, timestamp + " host kernel: [UFW BLOCK] SRC=192.0.2.1", 1767225600)


@pytest.mark.parametrize("timestamp,stored,precision,accepted", [
    ("2026-01-01T14:00:00+02:00", datetime(2026, 1, 1, 12), 0, True),
    ("2026-01-01T14:00:00+02:00", datetime(2026, 1, 1, 14), 0, False),
    ("2026-01-01T12:00:00", datetime(2026, 1, 1, 12), 0, False),
    ("2026-01-01T12:00:00Z", datetime(2026, 1, 1, 12), 6, True),
    ("2026-01-01T12:00:00.123456Z", datetime(2026, 1, 1, 12), 0, True),
    ("2026-01-01T12:00:00.800000Z", datetime(2026, 1, 1, 12, 0, 1), 0, True),
    ("2026-01-01T12:00:00.800000Z", datetime(2026, 1, 1, 12), 0, True),
    ("2026-01-01T12:00:00.123456Z", datetime(2026, 1, 1, 12), 6, False),
    ("2026-01-01T12:00:00.123456Z", datetime(2026, 1, 1, 12, 0, 0, 123456), 6, True),
    ("2026-01-01T12:00:00.123456Z", datetime(2026, 1, 1, 12, 0, 1), 0, False),
    ("2026-01-01T23:59:59.900000Z", datetime(2026, 1, 2), 0, True),
    ("2026-01-01T12:00:00-00:00", datetime(2026, 1, 1, 12), 0, False),
    ("2026-01-01T12:00:00+00:60", datetime(2026, 1, 1, 11), 0, False),
    ("2026-02-31T12:00:00Z", datetime(2026, 1, 1, 12), 0, False),
    ("Jan 1 12:00:00", datetime(2026, 1, 1, 12), 0, False),
    ("2026-01-01T12:00:00.1234567Z", datetime(2026, 1, 1, 12, 0, 0, 123456), 6, False),
    ("2026-01-01T12:00:00Z", None, 0, False),
])
def test_raw_utc_evidence(raw_history, timestamp, stored, precision, accepted):
    connection = raw_history([old_ufw_row(timestamp, stored)], precision)
    if accepted:
        proof = migrate.check_ufw_history(connection, {"ufw_log": 1})
        assert proof["precision"] == precision
        assert proof["count"] == 1
    else:
        with pytest.raises(migrate.MigrationError, match="Legacy UFW history"):
            migrate.check_ufw_history(connection, {"ufw_log": 1})
    connection.commit.assert_not_called()


def test_mixed_history_fails_even_when_first_batch_is_valid(raw_history, monkeypatch):
    monkeypatch.setattr(migrate, "UFW_HISTORY_BATCH", 1)
    rows = [old_ufw_row("2026-01-01T12:00:00Z", datetime(2026, 1, 1, 12)),
            old_ufw_row("2026-01-01T14:00:00+02:00", datetime(2026, 1, 1, 14), 2)]
    connection = raw_history(rows)
    with pytest.raises(migrate.MigrationError, match="does not match proven UTC"):
        migrate.check_ufw_history(connection, {"ufw_log": 2})


def test_raw_history_is_batched_and_time_bounded(raw_history, monkeypatch):
    monkeypatch.setattr(migrate, "UFW_HISTORY_BATCH", 2)
    rows = []
    for event_id in range(1, 8):
        rows.append(old_ufw_row("2026-01-01T12:00:00Z", datetime(2026, 1, 1, 12), event_id))
    connection = raw_history(rows)
    assert migrate.check_ufw_history(connection, {"ufw_log": 7})["count"] == 7
    cursor = connection.cursor.return_value.__enter__.return_value
    assert cursor.fetchall.call_count == 4
    for call in cursor.execute.call_args_list:
        if "FROM ufw_log" in call.args[0]:
            assert "MAX_EXECUTION_TIME(5000)" in call.args[0]
    clock = iter([0, 121])
    monkeypatch.setattr(migrate.time, "monotonic", lambda: next(clock))
    with pytest.raises(migrate.MigrationError, match="time budget"):
        migrate.check_ufw_history(connection, {"ufw_log": 7})


@pytest.mark.parametrize("fault", ["missing", "changed", "corrupt_proof", "count", "precision"])
def test_recorded_proof_rejects_changed_or_missing_originals(raw_history, fault):
    row = old_ufw_row("2026-01-01T12:00:00.123456Z", datetime(2026, 1, 1, 12), 20)
    connection = raw_history([row])
    proof = migrate.check_ufw_history(connection, {"ufw_log": 1})
    saved = {"ufw_log": 1, migrate.UFW_UTC_PROOF: proof}
    rows = [row]
    count = 1
    if fault == "missing":
        rows = []
    elif fault == "changed":
        rows = [old_ufw_row("2026-01-01T12:00:00.987654Z", datetime(2026, 1, 1, 12), 20)]
    elif fault == "corrupt_proof":
        proof["sha256"] = "0" * 64
    elif fault == "count":
        count = 2
    else:
        proof["precision"] = True
    connection = raw_history(rows, 6)
    with pytest.raises(migrate.MigrationError, match="Legacy UFW history"):
        migrate.check_ufw_history(connection, {"ufw_log": count}, saved=saved)


def test_count_only_ledger_cannot_invent_lost_precision_or_original_ids(raw_history):
    row = old_ufw_row("2026-01-01T12:00:00.123456Z", datetime(2026, 1, 1, 12))
    connection = raw_history([row], 6)
    with pytest.raises(migrate.MigrationError, match="does not match proven UTC"):
        migrate.check_ufw_history(connection, {"ufw_log": 1}, saved={"ufw_log": 1})
    row = old_ufw_row("2026-01-01T12:00:00Z", datetime(2026, 1, 1, 12), 2)
    connection = raw_history([row], 6)
    with pytest.raises(migrate.MigrationError, match="missing or replaced"):
        migrate.check_ufw_history(connection, {"ufw_log": 1}, saved={"ufw_log": 1})


@pytest.mark.parametrize("analysis", migrate.ANALYSIS_TABLES)
def test_verified_ufw_does_not_authorize_old_analysis(raw_history, analysis):
    connection = raw_history([old_ufw_row("2026-01-01T12:00:00Z", datetime(2026, 1, 1, 12))])
    with pytest.raises(migrate.MigrationError, match="Legacy UFW history"):
        migrate.check_ufw_history(connection, {"ufw_log": 1, analysis: 1})


@pytest.mark.parametrize("state", [None, "RUNNING", "FAILED", "APPLIED"])
@pytest.mark.parametrize("kind", ["utc", "local", "no_zone", "mixed", "missing_original"])
def test_utc_history_preflight_mysql(empty_mysql, state, kind):
    from config import reset_installation as setup

    connection = empty_mysql
    tables, rules = migrate.read_schema()
    migrate.ensure_tables(connection, tuple(tables), rule_keys=tuple(rules))
    with connection.cursor() as cursor:
        cursor.execute("CREATE TABLE schema_migrations (version VARCHAR(16), checksum CHAR(64), "
                       "status VARCHAR(16), row_counts JSON, started_at TIMESTAMP(6))")
        if state == "APPLIED":
            cursor.execute("ALTER TABLE ufw_log MODIFY event_time DATETIME(6) NULL DEFAULT NULL")
        timestamp = "2026-01-01T14:00:00+02:00"
        stored = datetime(2026, 1, 1, 12)
        if kind == "local":
            stored = datetime(2026, 1, 1, 14)
        if kind == "no_zone":
            timestamp = "2026-01-01T12:00:00"
        cursor.execute("INSERT INTO ufw_log (id,event_time,raw_line,event_hash,created_at) "
                       "VALUES (1,%s,%s,%s,'2026-01-01')",
                       (stored, timestamp + " host kernel: [UFW BLOCK]", "a" * 64))
        if kind == "mixed":
            cursor.execute("INSERT INTO ufw_log (id,event_time,raw_line,event_hash,created_at) "
                           "VALUES (2,'2026-01-01 14:00:00',%s,%s,'2026-01-01')",
                           (timestamp + " host kernel: [UFW BLOCK]", "b" * 64))
    counts = migrate.history_counts(connection)
    with connection.cursor() as cursor:
        if state is not None:
            cursor.execute("INSERT INTO schema_migrations VALUES ('017',%s,%s,%s,'2026-02-01')",
                           (migrate.checksum(migrate.UFW_TIME_MIGRATION), state, json.dumps(counts)))
        if kind == "missing_original":
            cursor.execute("UPDATE ufw_log SET id=99")
    connection.commit()
    readonly = ReadOnlyConnection(connection)
    if kind == "utc" or kind == "missing_original" and state is None:
        setup.check_ufw_before_upgrade(readonly)
    else:
        with pytest.raises((setup.ResetError, migrate.MigrationError)):
            setup.check_ufw_before_upgrade(readonly)


@pytest.mark.parametrize("interruption", [None, "RUNNING", "FAILED"])
def test_precision_proof_survives_ddl_and_preserves_history_mysql(empty_mysql, monkeypatch, interruption):
    from config import reset_installation as setup

    connection = empty_mysql
    complete = migrate.MIGRATIONS
    monkeypatch.setattr(migrate, "MIGRATIONS", complete[:4])
    migrate.migrate(connection)
    monkeypatch.setattr(migrate, "MIGRATIONS", complete)
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO ufw_log (id,event_time,raw_line,event_hash) VALUES "
                       "(42,'2026-01-01 12:00:00',%s,%s)",
                       ("2026-01-01T14:00:00.123456+02:00 host kernel: [UFW BLOCK]", "a" * 64))
        cursor.execute("INSERT INTO ufw_state (logfile,last_position,file_device,file_inode) "
                       "VALUES ('/synthetic/ufw.log',12345,1,2)")
    connection.commit()
    original = {}
    with connection.cursor() as cursor:
        for table in ("ufw_log", "ufw_state"):
            cursor.execute("SELECT * FROM " + table)
            original[table] = cursor.fetchall()
    setup.check_ufw_before_upgrade(ReadOnlyConnection(connection))
    apply = migrate.apply_one

    def interrupted(connection, version):
        apply(connection, version)
        if version == "017":
            if interruption == "RUNNING":
                raise SystemExit("Simulated exit after DDL")
            raise RuntimeError("Simulated failure after DDL")

    if interruption is not None:
        monkeypatch.setattr(migrate, "apply_one", interrupted)
        with pytest.raises((SystemExit, RuntimeError), match="Simulated"):
            migrate.migrate(connection)
        assert migrate.migration_status(connection)["017"][1] == interruption
        setup.check_ufw_before_upgrade(ReadOnlyConnection(connection))
        monkeypatch.setattr(migrate, "apply_one", apply)
    migrate.migrate(connection)
    readonly = ReadOnlyConnection(connection)
    setup.check_ufw_before_upgrade(readonly)
    migrate.check_ufw_utc_readiness(readonly)
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='017'")
        counts = json.loads(cursor.fetchone()[0])
        assert counts[migrate.UFW_UTC_PROOF]["precision"] == 0
        assert counts[migrate.UFW_UTC_PROOF]["max_id"] == 42
        for table in ("ufw_log", "ufw_state"):
            cursor.execute("SELECT * FROM " + table)
            assert cursor.fetchall() == original[table]
        # Rows collected after 017 do not change the original-history proof.
        cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash) VALUES "
                       "('2026-01-01 12:00:01.654321',%s,%s)",
                       ("2026-01-01T12:00:01.654321Z host kernel: [UFW BLOCK]", "b" * 64))
    migrate.check_ufw_utc_readiness(readonly)

    # Admin preflight sessions may inherit the server's non-UTC timezone.
    with connection.cursor() as cursor:
        cursor.execute("SET time_zone = '+02:00'")
    setup.check_ufw_before_upgrade(readonly)
    migrate.check_ufw_utc_readiness(readonly)
