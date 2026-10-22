"""Opt-in tests using a new private server; never use configured DB settings.

PORT_SCAN_TEST_MYSQL=1 enables the tests. Networking is disabled, and the
production schema dump is never imported: only its ufw_log CREATE is used.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import pymysql
import pytest

from detection.common.alerts import AlertStorageError, save_alert
from detection.port_scan.db import get_db_data
from detection.port_scan.main import build_alert, run_detection
from detection.port_scan.runner import run_automatic
from detection.port_scan.state import acquire_lock, load_state

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "database/migrations/003_detection_alerts.sql"
START = datetime(2026, 10, 22, 12)
END = START + timedelta(minutes=10)


def apply_migration(connection):
    lines = []
    for line in MIGRATION.read_text().splitlines():
        if not line.lstrip().startswith("--"):
            lines.append(line)
    with connection.cursor() as cursor:
        for statement in "\n".join(lines).split(";"):
            if statement.strip():
                cursor.execute(statement)
    connection.commit()


@pytest.fixture(scope="module")
def private_server():
    if os.getenv("PORT_SCAN_TEST_MYSQL") != "1":
        pytest.skip("Set PORT_SCAN_TEST_MYSQL=1 for an isolated MySQL server.")
    executable = shutil.which("mysqld")
    if executable is None:
        pytest.fail("Explicitly requested integration tests require mysqld.")
    with tempfile.TemporaryDirectory(prefix="pscan-mysql-") as folder:
        root = Path(folder)
        data = root / "data"
        data.mkdir()
        log = root / "server.log"
        subprocess.run(
            [
                executable,
                "--no-defaults",
                "--initialize-insecure",
                f"--datadir={data}",
                f"--log-error={log}",
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        socket = root / "mysql.sock"
        process = subprocess.Popen(
            [
                executable,
                "--no-defaults",
                f"--datadir={data}",
                f"--socket={socket}",
                f"--pid-file={root / 'mysql.pid'}",
                f"--log-error={log}",
                "--skip-networking",
                "--mysqlx=OFF",
                "--performance-schema=OFF",
                "--innodb-buffer-pool-size=32M",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        admin = None
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail("Private MySQL startup failed: " + log.read_text())
                try:
                    admin = pymysql.connect(
                        unix_socket=str(socket),
                        user="root",
                        connect_timeout=2,
                        read_timeout=5,
                        write_timeout=5,
                    )
                    break
                except pymysql.OperationalError:
                    time.sleep(0.1)
            if admin is None:
                pytest.fail("Private MySQL startup timed out.")
            yield str(socket)
        finally:
            if process.poll() is None:
                if admin is None:
                    admin = pymysql.connect(unix_socket=str(socket), user="root")
                try:
                    with admin.cursor() as cursor:
                        cursor.execute("SHUTDOWN")
                finally:
                    admin.close()
                process.wait(timeout=20)
            elif admin is not None:
                admin.close()


@pytest.fixture
def mysql(private_server):
    connection = pymysql.connect(
        unix_socket=private_server,
        user="root",
        charset="utf8mb4",
        autocommit=False,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
    )
    try:
        # Generated locally, never taken from configuration or user input.
        schema_name = f"detection_test_{time.monotonic_ns()}"
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{schema_name}` CHARACTER SET utf8mb4")
        connection.select_db(schema_name)
        schema = (ROOT / "database/schema.sql").read_text()
        start = schema.index("CREATE TABLE `ufw_log`")
        end = schema.index(";", start) + 1
        with connection.cursor() as cursor:
            cursor.execute(schema[start:end])
            cursor.execute(
                """
                INSERT INTO ufw_log (id, event_time, action, raw_line, event_hash)
                VALUES (999, '2000-01-01 00:00:00', 'BLOCK', 'preserve-me', %s)
                """,
                ("a" * 64,),
            )
        connection.commit()
        apply_migration(connection)
        yield connection
    finally:
        connection.close()


def insert_events(connection, events):
    fields = ("id", "event_time", "action", "src_ip", "dst_ip", "protocol", "dst_port")
    rows = []
    for event in events:
        values = tuple(event[field] for field in fields)
        raw = f"synthetic UFW test {event['id']}"
        rows.append(values + (raw, hashlib.sha256(raw.encode()).hexdigest()))
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            INSERT INTO ufw_log (
                id, event_time, action, src_ip, dst_ip, protocol, dst_port, raw_line, event_hash
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )
    connection.commit()


def counts(connection):
    result = []
    with connection.cursor() as cursor:
        for table in ("detection_alerts", "alert_evidence"):
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            result.append(cursor.fetchone()[0])
    return tuple(result)


def test_migration_is_repeatable_preserves_telemetry_and_rule_settings(mysql):
    with mysql.cursor() as cursor:
        cursor.execute("SELECT name, severity, enabled FROM detection_rules")
        assert cursor.fetchall() == (("Possible Port Scanning", "HIGH", 1),)
        cursor.execute(
            "UPDATE detection_rules SET enabled = FALSE, name = 'Custom', severity = 'LOW'"
        )
    mysql.commit()
    apply_migration(mysql)
    apply_migration(mysql)
    with mysql.cursor() as cursor:
        cursor.execute("SELECT rule_key, name, severity, enabled FROM detection_rules")
        assert cursor.fetchall() == (("PORT_SCAN_001", "Custom", "LOW", 0),)
        cursor.execute("SELECT id, raw_line, event_hash FROM ufw_log")
        assert cursor.fetchall() == ((999, "preserve-me", "a" * 64),)
        cursor.execute("SHOW TABLES")
        assert {row[0] for row in cursor.fetchall()} == {
            "ufw_log",
            "detection_rules",
            "detection_alerts",
            "alert_evidence",
        }


def test_real_query_filters_time_action_protocol_and_orders_ties(mysql, sample_events):
    events = list(reversed(sample_events))
    events[0] = dict(events[0], event_time=START)
    events += [
        dict(sample_events[0], id=20, event_time=START - timedelta(seconds=1)),
        dict(sample_events[0], id=21, event_time=END),
        dict(sample_events[0], id=22, action="UNKNOWN"),
        dict(sample_events[0], id=23, protocol="ICMP"),
    ]
    insert_events(mysql, events)
    fetched = get_db_data(mysql, START, END)
    assert len(fetched) == 10
    assert [event["id"] for event in fetched[:2]] == [1, 10]
    assert any(event["action"] == "ALLOW" for event in fetched)
    assert fetched == sorted(
        fetched, key=lambda event: (event["event_time"], event["id"])
    )


def test_complete_run_replay_details_and_evidence(mysql, sample_events):
    insert_events(mysql, sample_events)
    first = run_detection(mysql, START, END)
    assert first == {
        "events_analyzed": 10,
        "scans_detected": 1,
        "new_alerts_saved": 1,
        "existing_alerts_skipped": 0,
        "alerts_updated": 0,
    }
    second = run_detection(mysql, START, END)
    assert second["new_alerts_saved"] == 0
    assert second["existing_alerts_skipped"] == 1
    assert counts(mysql) == (1, 10)
    with mysql.cursor() as cursor:
        cursor.execute("""
            SELECT r.rule_key, a.severity, a.status, a.title, a.details,
                   a.first_seen, a.last_seen, a.detected_at
            FROM detection_alerts a JOIN detection_rules r ON r.id = a.rule_id
            """)
        row = cursor.fetchone()
        assert row[:4] == ("PORT_SCAN_001", "HIGH", "NEW", "Possible Port Scanning")
        details = json.loads(row[4])
        assert details["destination_ip"] == "198.51.100.1"
        assert details["protocol"] == "TCP"
        assert details["distinct_port_count"] == 10
        assert details["destination_ports"] == list(range(1000, 1010))
        assert details["window_seconds"] == 60 and details["threshold"] == 10
        assert row[5] == START and row[6] == START + timedelta(seconds=9)
        assert isinstance(row[7], datetime)
        cursor.execute(
            "SELECT event_type, event_id FROM alert_evidence ORDER BY event_id"
        )
        assert cursor.fetchall() == tuple(("UFW", index) for index in range(1, 11))


def test_separate_scans_make_separate_alerts(mysql, sample_events):
    second = []
    for event in sample_events:
        second.append(
            dict(
                event,
                id=event["id"] + 10,
                event_time=event["event_time"] + timedelta(minutes=3),
            )
        )
    insert_events(mysql, sample_events + second)
    assert run_detection(mysql, START, END)["new_alerts_saved"] == 2
    assert counts(mysql) == (2, 20)


def test_evidence_error_rolls_back_the_alert(mysql, sample_events):
    insert_events(mysql, sample_events)
    with mysql.cursor() as cursor:
        cursor.execute("""
            CREATE TRIGGER reject_test_evidence BEFORE INSERT ON alert_evidence
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic test error'
            """)
    with pytest.raises(AlertStorageError):
        run_detection(mysql, START, END)
    assert counts(mysql) == (0, 0)


def test_alert_insert_error_rolls_back(mysql, sample_events):
    insert_events(mysql, sample_events)
    with mysql.cursor() as cursor:
        cursor.execute("""
            CREATE TRIGGER reject_test_alert BEFORE INSERT ON detection_alerts
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic test error'
            """)
    with pytest.raises(AlertStorageError):
        run_detection(mysql, START, END)
    assert counts(mysql) == (0, 0)


def test_disabled_rule_does_not_save(mysql, sample_events):
    insert_events(mysql, sample_events)
    with mysql.cursor() as cursor:
        cursor.execute("UPDATE detection_rules SET enabled = FALSE")
    mysql.commit()
    with pytest.raises(AlertStorageError, match="disabled"):
        run_detection(mysql, START, END)
    assert counts(mysql) == (0, 0)


def test_evidence_unique_constraint(mysql, finding):
    alert, evidence = build_alert(finding)
    assert save_alert(mysql, alert, evidence + evidence)
    assert counts(mysql) == (1, 10)
    with mysql.cursor() as cursor:
        cursor.execute("SELECT id FROM detection_alerts")
        alert_id = cursor.fetchone()[0]
        with pytest.raises(pymysql.IntegrityError) as caught:
            cursor.execute(
                "INSERT INTO alert_evidence (alert_id, event_type, event_id) VALUES (%s, 'UFW', 1)",
                (alert_id,),
            )
    assert caught.value.args[0] == 1062
    mysql.rollback()


def test_concurrent_runs_create_only_one_alert(mysql, finding, private_server):
    with mysql.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        schema_name = cursor.fetchone()[0]
    alert, evidence = build_alert(finding)

    def save_once():
        connection = pymysql.connect(
            unix_socket=private_server,
            user="root",
            database=schema_name,
            autocommit=False,
            read_timeout=10,
            write_timeout=10,
        )
        try:
            return save_alert(connection, alert, evidence)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda unused: save_once(), range(2)))
    assert sorted(results) == [False, True]
    mysql.rollback()
    assert counts(mysql) == (1, 10)


def test_minimal_application_permissions(mysql, sample_events, private_server):
    insert_events(mysql, sample_events)
    with mysql.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        schema_name = cursor.fetchone()[0]
        cursor.execute(
            "CREATE USER 'port_scan_test'@'localhost' IDENTIFIED BY 'test-only-password'"
        )
        for table, privileges in (
            ("ufw_log", "SELECT"),
            ("detection_rules", "SELECT"),
            ("detection_alerts", "SELECT, INSERT, UPDATE"),
            ("alert_evidence", "SELECT, INSERT"),
        ):
            cursor.execute(
                f"GRANT {privileges} ON `{schema_name}`.`{table}` TO 'port_scan_test'@'localhost'"
            )
    connection = pymysql.connect(
        unix_socket=private_server,
        user="port_scan_test",
        password="test-only-password",
        database=schema_name,
        autocommit=False,
    )
    try:
        assert run_detection(connection, START, END)["new_alerts_saved"] == 1
        assert run_detection(connection, START, END)["existing_alerts_skipped"] == 1
    finally:
        connection.close()


AUTO_CONFIG = {"batch_size": 1000, "late_seconds": 600, "max_buffer_events": 10000}


def apply_state_migration(connection):
    content = (ROOT / "database/migrations/004_detection_state.sql").read_text()
    lines = []
    for line in content.splitlines():
        if not line.lstrip().startswith("--"):
            lines.append(line)
    with connection.cursor() as cursor:
        for statement in "\n".join(lines).split(";"):
            if statement.strip():
                cursor.execute(statement)
    connection.commit()


@pytest.fixture
def automatic_mysql(mysql):
    # Remove only this private test fixture's sentinel so later synthetic IDs
    # increase in the same order as the actual serialized UFW collector.
    with mysql.cursor() as cursor:
        cursor.execute("DELETE FROM ufw_log WHERE id = 999")
    mysql.commit()
    apply_state_migration(mysql)
    return mysql


def checkpoint(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id FROM detection_rules WHERE rule_key = 'PORT_SCAN_001'"
        )
        rule_id = cursor.fetchone()[0]
    return load_state(connection, rule_id)


def test_automatic_scan_crosses_two_passes_and_calendar_minute(
    automatic_mysql, sample_events
):
    connection = automatic_mysql
    for index, event in enumerate(sample_events):
        event["event_time"] = START + timedelta(seconds=45 + index * 4)
    insert_events(connection, sample_events[:5])
    first = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=1))
    assert first["new_alerts_saved"] == 0
    assert checkpoint(connection)[0] == 5
    connection.rollback()
    insert_events(connection, sample_events[5:])
    second = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=2))
    assert second["new_alerts_saved"] == 1
    assert checkpoint(connection)[0] == 10
    assert counts(connection) == (1, 10)


def test_automatic_batches_preserve_window(automatic_mysql, sample_events):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    config = dict(AUTO_CONFIG, batch_size=5)
    first = run_automatic(connection, config, now=START)
    assert first["events_analyzed"] == 5
    assert checkpoint(connection)[0] == 5
    connection.rollback()
    second = run_automatic(connection, config, now=START + timedelta(minutes=1))
    assert second["new_alerts_saved"] == 1
    assert checkpoint(connection)[0] == 10
    assert counts(connection) == (1, 10)


def test_continuing_scan_keeps_identity_and_analyst_status(
    automatic_mysql, sample_events
):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    assert run_automatic(connection, AUTO_CONFIG, now=START)["new_alerts_saved"] == 1
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, alert_fingerprint FROM detection_alerts")
        identity = cursor.fetchone()
        cursor.execute(
            "UPDATE detection_alerts SET status = 'TRIAGED', severity = 'MEDIUM'"
        )
    connection.commit()
    more = []
    for event in sample_events:
        more.append(
            dict(
                event,
                id=event["id"] + 10,
                event_time=event["event_time"] + timedelta(seconds=10),
                dst_port=event["dst_port"] + 10,
            )
        )
    insert_events(connection, more)
    result = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=1))
    assert result["new_alerts_saved"] == 0
    assert result["alerts_updated"] == 1
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, alert_fingerprint, status, severity, details FROM detection_alerts"
        )
        row = cursor.fetchone()
        assert row[:2] == identity
        assert row[2:4] == ("TRIAGED", "MEDIUM")
        assert json.loads(row[4])["distinct_port_count"] == 20
    assert counts(connection) == (1, 20)


def test_late_event_can_complete_a_scan(automatic_mysql, sample_events):
    connection = automatic_mysql
    insert_events(connection, sample_events[:9])
    assert run_automatic(connection, AUTO_CONFIG, now=START)["new_alerts_saved"] == 0
    insert_events(connection, sample_events[9:])
    result = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=5))
    assert result["new_alerts_saved"] == 1
    assert counts(connection) == (1, 10)


def test_late_event_extends_existing_alert_without_duplicate(
    automatic_mysql, sample_events
):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    run_automatic(connection, AUTO_CONFIG, now=START)
    late = dict(
        sample_events[0], id=11, dst_port=443, event_time=START - timedelta(seconds=1)
    )
    insert_events(connection, [late])
    result = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=5))
    assert result["alerts_updated"] == 1
    assert result["new_alerts_saved"] == 0
    assert counts(connection) == (1, 11)
    with connection.cursor() as cursor:
        cursor.execute("SELECT first_seen FROM detection_alerts")
        assert cursor.fetchone()[0] == START - timedelta(seconds=1)


def test_automatic_replay_and_two_separate_scans(automatic_mysql, sample_events):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    run_automatic(connection, AUTO_CONFIG, now=START)
    replay = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=1))
    assert replay["new_alerts_saved"] == 0
    assert replay["existing_alerts_skipped"] == 1
    second = []
    for event in sample_events:
        second.append(
            dict(
                event,
                id=event["id"] + 10,
                event_time=event["event_time"] + timedelta(minutes=3),
            )
        )
    insert_events(connection, second)
    result = run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=3))
    assert result["new_alerts_saved"] == 1
    assert counts(connection) == (2, 20)


def test_state_failure_rolls_back_alert_evidence_and_can_retry(
    automatic_mysql, sample_events
):
    connection = automatic_mysql
    insert_events(connection, sample_events[:5])
    run_automatic(connection, AUTO_CONFIG, now=START)
    insert_events(connection, sample_events[5:])
    with connection.cursor() as cursor:
        cursor.execute("SET @fail_detection_state = 1")
        cursor.execute("""
            CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON detection_state
            FOR EACH ROW SET NEW.state_data = IF(@fail_detection_state = 1, NULL, NEW.state_data)
            """)
    with pytest.raises(pymysql.MySQLError):
        run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=1))
    assert checkpoint(connection)[0] == 5
    assert counts(connection) == (0, 0)
    with connection.cursor() as cursor:
        cursor.execute("SET @fail_detection_state = 0")
    connection.rollback()
    assert (
        run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=2))[
            "new_alerts_saved"
        ]
        == 1
    )
    assert checkpoint(connection)[0] == 10
    assert counts(connection) == (1, 10)


def test_extension_failure_also_rolls_back_updated_alert(
    automatic_mysql, sample_events
):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    run_automatic(connection, AUTO_CONFIG, now=START)
    insert_events(connection, [dict(sample_events[0], id=11, dst_port=443)])
    with connection.cursor() as cursor:
        cursor.execute(
            "CREATE TRIGGER fail_update BEFORE UPDATE ON detection_state "
            "FOR EACH ROW SET NEW.state_data = NULL"
        )
    with pytest.raises(pymysql.MySQLError):
        run_automatic(connection, AUTO_CONFIG, now=START + timedelta(minutes=1))
    assert checkpoint(connection)[0] == 10
    assert counts(connection) == (1, 10)
    with connection.cursor() as cursor:
        cursor.execute("SELECT details FROM detection_alerts")
        assert json.loads(cursor.fetchone()[0])["distinct_port_count"] == 10


def test_restart_reads_durable_state(automatic_mysql, sample_events, private_server):
    connection = automatic_mysql
    insert_events(connection, sample_events[:5])
    run_automatic(connection, AUTO_CONFIG, now=START)
    insert_events(connection, sample_events[5:])
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        schema_name = cursor.fetchone()[0]
    restarted = pymysql.connect(
        unix_socket=private_server, user="root", database=schema_name, autocommit=False
    )
    try:
        result = run_automatic(restarted, AUTO_CONFIG, now=START + timedelta(minutes=1))
        assert result["new_alerts_saved"] == 1
        assert checkpoint(restarted)[0] == 10
    finally:
        restarted.close()


def test_lock_blocks_second_run_and_connection_close_releases_it(
    automatic_mysql, private_server
):
    connection = automatic_mysql
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        schema_name = cursor.fetchone()[0]
    owner = pymysql.connect(
        unix_socket=private_server, user="root", database=schema_name
    )
    assert acquire_lock(owner)
    try:
        result = run_automatic(connection, AUTO_CONFIG, now=START)
        assert result["status"] == "SKIPPED"
        assert not result["state_updated"]
        assert checkpoint(connection) == (0, [])
    finally:
        owner.close()
    connection.rollback()
    assert run_automatic(connection, AUTO_CONFIG, now=START)["status"] == "SUCCESS"


def test_empty_run_creates_checkpoint_and_expires_tail(automatic_mysql, sample_events):
    connection = automatic_mysql
    empty = run_automatic(connection, AUTO_CONFIG, now=START)
    assert empty["state_updated"]
    assert checkpoint(connection) == (0, [])
    connection.rollback()
    insert_events(connection, sample_events[:5])
    run_automatic(connection, AUTO_CONFIG, now=START)
    run_automatic(connection, AUTO_CONFIG, now=START + timedelta(seconds=660))
    assert len(checkpoint(connection)[1]) == 5
    connection.rollback()
    run_automatic(connection, AUTO_CONFIG, now=START + timedelta(seconds=661))
    assert checkpoint(connection) == (5, [])


def test_state_migration_is_repeatable_and_preserves_checkpoint(automatic_mysql):
    connection = automatic_mysql
    run_automatic(connection, AUTO_CONFIG, now=START)
    before = checkpoint(connection)
    connection.rollback()
    apply_state_migration(connection)
    apply_state_migration(connection)
    assert checkpoint(connection) == before
    with connection.cursor() as cursor:
        cursor.execute(
            "SHOW INDEX FROM alert_evidence WHERE Key_name = 'idx_evidence_event'"
        )
        assert [row[4] for row in cursor.fetchall()] == ["event_type", "event_id"]


def test_automatic_minimal_permissions(automatic_mysql, sample_events, private_server):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        schema_name = cursor.fetchone()[0]
        cursor.execute(
            "CREATE USER 'port_scan_auto_test'@'localhost' IDENTIFIED BY 'test-only-password'"
        )
        for table, privileges in (
            ("ufw_log", "SELECT"),
            ("detection_rules", "SELECT"),
            ("detection_alerts", "SELECT, INSERT, UPDATE"),
            ("alert_evidence", "SELECT, INSERT"),
            ("detection_state", "SELECT, INSERT, UPDATE"),
        ):
            cursor.execute(
                f"GRANT {privileges} ON `{schema_name}`.`{table}` TO 'port_scan_auto_test'@'localhost'"
            )
    app = pymysql.connect(
        unix_socket=private_server,
        user="port_scan_auto_test",
        password="test-only-password",
        database=schema_name,
        autocommit=False,
    )
    try:
        assert run_automatic(app, AUTO_CONFIG, now=START)["new_alerts_saved"] == 1
        assert (
            run_automatic(app, AUTO_CONFIG, now=START)["existing_alerts_skipped"] == 1
        )
    finally:
        app.close()


def test_manual_run_extends_automatic_alert_without_changing_state(
    automatic_mysql, sample_events
):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    run_automatic(connection, AUTO_CONFIG, now=START)
    before = checkpoint(connection)
    connection.rollback()
    insert_events(connection, [dict(sample_events[0], id=11, dst_port=443)])
    result = run_detection(connection, START, END)
    assert result["new_alerts_saved"] == 0
    assert result["alerts_updated"] == 1
    assert checkpoint(connection) == before
    assert counts(connection) == (1, 11)


def test_continuous_identity_survives_buffer_pruning(automatic_mysql, sample_events):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    run_automatic(connection, AUTO_CONFIG, now=START)
    for batch, observed_second in ((1, 700), (2, 760)):
        events = []
        for event in sample_events:
            events.append(
                dict(
                    event,
                    id=event["id"] + batch * 10,
                    event_time=event["event_time"] + timedelta(seconds=batch * 10),
                )
            )
        insert_events(connection, events)
        result = run_automatic(
            connection, AUTO_CONFIG, now=START + timedelta(seconds=observed_second)
        )
        assert result["alerts_updated"] == 1
        assert result["new_alerts_saved"] == 0
    assert counts(connection) == (1, 30)


def test_disabled_rule_also_blocks_manual_extension(automatic_mysql, sample_events):
    connection = automatic_mysql
    insert_events(connection, sample_events)
    run_automatic(connection, AUTO_CONFIG, now=START)
    insert_events(connection, [dict(sample_events[0], id=11, dst_port=443)])
    with connection.cursor() as cursor:
        cursor.execute("UPDATE detection_rules SET enabled = FALSE")
    connection.commit()
    with pytest.raises(AlertStorageError, match="disabled"):
        run_detection(connection, START, END)
    assert counts(connection) == (1, 10)
