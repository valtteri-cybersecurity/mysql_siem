"""SOC integration against the shared private server, never the collection DB."""

import json
from datetime import datetime, timedelta

import pymysql
import pytest

from detection.common.alerts import AlertStorageError
from detection.port_scan.main import run_detection as run_port_scan_detection
from detection.ssh_brute_force import db
from detection.ssh_brute_force.detector import detect_ssh_brute_force
from detection.ssh_brute_force.runner import run_detection, store_detection
from ingestion.auth.db import save_event
from ingestion.auth.parser import parse_auth_line

START = datetime(2026, 10, 22, 12)
END = START + timedelta(minutes=10)


@pytest.fixture
def soc_mysql(mysql, apply_migration):
    apply_migration(mysql, "003_detection_alerts.sql")
    apply_migration(mysql, "008_ssh_brute_force_rule.sql")
    return mysql


def insert_events(connection, count=8, *, start=START, step=10, hostname="server-a",
                  source_ip="192.0.2.1", first_pid=100, **changes):
    with connection.cursor() as cursor:
        for index in range(count):
            timestamp = (start + timedelta(seconds=index * step)).isoformat(timespec="microseconds")
            raw = (f"{timestamp}Z {hostname} sshd[{first_pid + index}]: "
                   f"Failed password for user{index} from {source_ip} port 54321 ssh2")
            event = parse_auth_line(raw)
            event.update(changes)
            assert save_event(cursor, event) == 1
    connection.commit()


def alerts(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT a.*, r.rule_key FROM detection_alerts a "
                       "JOIN detection_rules r ON r.id = a.rule_id ORDER BY a.id")
        rows = cursor.fetchall()
    for row in rows:
        row["details"] = json.loads(row["details"])
    return rows


def evidence(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT alert_id, event_type, event_id FROM alert_evidence ORDER BY alert_id, event_id")
        return cursor.fetchall()


def test_rule_registration_is_repeatable_and_preserves_operator_settings(soc_mysql, apply_migration):
    with soc_mysql.cursor() as cursor:
        cursor.execute("SELECT id, name, severity, enabled FROM detection_rules WHERE rule_key = %s",
                       ("SSH_BRUTE_FORCE_001",))
        original = cursor.fetchone()
        assert original[1:] == ("SSH Brute Force Attempt", "HIGH", 1)
        cursor.execute("UPDATE detection_rules SET enabled = FALSE, name = %s WHERE rule_key = %s",
                       ("Operator label", "SSH_BRUTE_FORCE_001"))
        cursor.execute("UPDATE detection_rules SET severity = %s WHERE rule_key = %s", ("LOW", "PORT_SCAN_001"))
    soc_mysql.commit()
    apply_migration(soc_mysql, "008_ssh_brute_force_rule.sql")
    apply_migration(soc_mysql, "008_ssh_brute_force_rule.sql")
    with soc_mysql.cursor() as cursor:
        cursor.execute("SELECT id, name, severity, enabled FROM detection_rules WHERE rule_key = %s",
                       ("SSH_BRUTE_FORCE_001",))
        assert cursor.fetchone() == (original[0], "Operator label", "HIGH", 0)
        cursor.execute("SELECT COUNT(*) FROM detection_rules")
        assert cursor.fetchone() == (2,)
        cursor.execute("SELECT severity FROM detection_rules WHERE rule_key = %s", ("PORT_SCAN_001",))
        assert cursor.fetchone() == ("LOW",)


def test_read_range_is_half_open_sorted_and_excludes_other_services(soc_mysql):
    insert_events(soc_mysql, 1, start=START - timedelta(seconds=1), first_pid=90)
    insert_events(soc_mysql, 2, step=60)
    insert_events(soc_mysql, 1, start=START + timedelta(seconds=10), first_pid=200,
                  event_type="SSH_AUTH_SUCCESS")
    insert_events(soc_mysql, 1, start=START + timedelta(seconds=20), first_pid=201, service="sudo")
    result = db.get_db_data(soc_mysql, START, START + timedelta(seconds=60))
    assert len(result) == 1
    assert result[0]["event_time"] == START
    assert result[0]["event_type"] == "SSH_AUTH_FAILURE"
    assert result[0]["service"] == "sshd"


def test_wrong_types_cannot_complete_threshold(soc_mysql):
    insert_events(soc_mysql, 4)
    insert_events(soc_mysql, 1, first_pid=200, event_type="SSH_AUTH_SUCCESS")
    insert_events(soc_mysql, 1, first_pid=201, service="sudo")
    summary = run_detection(soc_mysql, START, END)
    assert summary["events_analyzed"] == 4
    assert summary["new_alerts_saved"] == 0
    assert not alerts(soc_mysql)


def test_detection_creates_high_soc_alert_with_auth_evidence(soc_mysql):
    insert_events(soc_mysql)
    summary = run_detection(soc_mysql, START, END)
    assert summary["new_alerts_saved"] == 1
    row = alerts(soc_mysql)[0]
    assert row["rule_key"] == "SSH_BRUTE_FORCE_001"
    assert row["severity"] == "HIGH" and row["status"] == "NEW"
    assert row["source_ip"] == "192.0.2.1"
    assert row["title"] == "SSH Brute Force Attempt"
    assert row["details"] == {"hostname": "server-a", "failure_count": 8,
                              "window_seconds": 60, "threshold": 5,
                              "usernames": [f"user{i}" for i in range(8)]}
    assert row["first_seen"] == START
    assert row["last_seen"] == START + timedelta(seconds=70)
    assert row["detected_at"] is not None
    assert len(row["alert_fingerprint"]) == 64
    assert evidence(soc_mysql) == tuple((row["id"], "AUTH", i) for i in range(1, 9))
    assert "Failed password" not in json.dumps(row["details"])


def test_exact_replay_changes_nothing(soc_mysql):
    insert_events(soc_mysql)
    run_detection(soc_mysql, START, END)
    before = alerts(soc_mysql)
    before_evidence = evidence(soc_mysql)
    summary = run_detection(soc_mysql, START, END)
    assert summary["new_alerts_saved"] == 0
    assert summary["existing_alerts_skipped"] == 1
    assert alerts(soc_mysql) == before
    assert evidence(soc_mysql) == before_evidence


@pytest.mark.parametrize("reverse", [False, True])
def test_overlapping_runs_extend_one_alert_preserving_identity_and_status(soc_mysql, reverse):
    insert_events(soc_mysql)
    ranges = [(START, START + timedelta(seconds=41)),
              (START + timedelta(seconds=30), START + timedelta(seconds=71))]
    if reverse:
        ranges.reverse()
    run_detection(soc_mysql, *ranges[0])
    before = alerts(soc_mysql)[0]
    with soc_mysql.cursor() as cursor:
        cursor.execute("UPDATE detection_alerts SET status = %s WHERE id = %s", ("ACKNOWLEDGED", before["id"]))
    soc_mysql.commit()
    summary = run_detection(soc_mysql, *ranges[1])
    assert summary["alerts_updated"] == 1
    assert summary["new_alerts_saved"] == 0
    rows = alerts(soc_mysql)
    assert len(rows) == 1
    assert rows[0]["alert_fingerprint"] == before["alert_fingerprint"]
    assert rows[0]["status"] == "ACKNOWLEDGED"
    assert rows[0]["first_seen"] == START
    assert rows[0]["last_seen"] == START + timedelta(seconds=70)
    assert rows[0]["details"]["failure_count"] == 8
    assert len(rows[0]["details"]["usernames"]) == 8
    assert len(evidence(soc_mysql)) == 8
    assert run_detection(soc_mysql, START, END)["existing_alerts_skipped"] == 1
    assert len(evidence(soc_mysql)) == 8


def test_two_separate_episodes_create_two_alerts(soc_mysql):
    insert_events(soc_mysql, 5)
    insert_events(soc_mysql, 5, start=START + timedelta(seconds=180))
    summary = run_detection(soc_mysql, START, END)
    assert summary["new_alerts_saved"] == 2
    rows = alerts(soc_mysql)
    assert len(rows) == 2
    assert rows[0]["alert_fingerprint"] != rows[1]["alert_fingerprint"]
    assert [row["details"]["failure_count"] for row in rows] == [5, 5]


@pytest.mark.parametrize("changes", [{"hostname": "server-b"}, {"source_ip": "2001:db8::1"}])
def test_different_hosts_or_ips_are_separate(soc_mysql, changes):
    insert_events(soc_mysql, 5)
    insert_events(soc_mysql, 5, **changes)
    summary = run_detection(soc_mysql, START, END)
    assert summary["new_alerts_saved"] == 2
    assert len(alerts(soc_mysql)) == 2
    assert len(evidence(soc_mysql)) == 10


def test_empty_database_is_successful_without_writes(soc_mysql):
    summary = run_detection(soc_mysql, START, END)
    assert summary["status"] == "SUCCESS"
    assert summary["events_analyzed"] == summary["new_alerts_saved"] == 0
    assert not alerts(soc_mysql)


def test_disabled_rule_does_not_create_alerts(soc_mysql):
    insert_events(soc_mysql)
    with soc_mysql.cursor() as cursor:
        cursor.execute("UPDATE detection_rules SET enabled = FALSE WHERE rule_key = %s", ("SSH_BRUTE_FORCE_001",))
    soc_mysql.commit()
    assert run_detection(soc_mysql, START, END)["status"] == "SKIPPED"
    assert not alerts(soc_mysql)


@pytest.mark.parametrize("existing", [False, True])
def test_evidence_failure_rolls_back_new_alert_or_extension_and_allows_retry(soc_mysql, existing):
    insert_events(soc_mysql)
    if existing:
        run_detection(soc_mysql, START, START + timedelta(seconds=41))
    before_alerts, before_evidence = alerts(soc_mysql), evidence(soc_mysql)
    with soc_mysql.cursor() as cursor:
        cursor.execute("""
            CREATE TRIGGER fail_ssh_evidence BEFORE INSERT ON alert_evidence FOR EACH ROW
            BEGIN
                IF NEW.event_type = 'AUTH' AND NEW.event_id = 8 THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure';
                END IF;
            END
        """)
    with pytest.raises((pymysql.MySQLError, AlertStorageError)):
        run_detection(soc_mysql, START, END)
    assert alerts(soc_mysql) == before_alerts
    assert evidence(soc_mysql) == before_evidence
    with soc_mysql.cursor() as cursor:
        cursor.execute("DROP TRIGGER fail_ssh_evidence")
    summary = run_detection(soc_mysql, START, END)
    assert summary["alerts_updated" if existing else "new_alerts_saved"] == 1
    assert len(evidence(soc_mysql)) == 8


@pytest.mark.parametrize("change", ["missing", "wrong_type", "wrong_host"])
def test_stale_or_inconsistent_source_evidence_is_rejected(soc_mysql, change):
    insert_events(soc_mysql)
    finding = detect_ssh_brute_force(db.get_db_data(soc_mysql, START, END))[0]
    with soc_mysql.cursor() as cursor:
        if change == "missing":
            cursor.execute("DELETE FROM auth_events WHERE id = %s", (1,))
        elif change == "wrong_type":
            cursor.execute("UPDATE auth_events SET event_type = %s WHERE id = %s", ("SSH_AUTH_SUCCESS", 1))
        else:
            cursor.execute("UPDATE auth_events SET hostname = %s WHERE id = %s", ("server-b", 1))
    soc_mysql.commit()
    assert db.acquire_lock(soc_mysql)
    try:
        soc_mysql.begin()
        with pytest.raises(db.SSHDetectionError):
            store_detection(soc_mysql, finding)
    finally:
        soc_mysql.rollback()
        db.release_lock(soc_mysql)
    assert not alerts(soc_mysql)
    assert not evidence(soc_mysql)


def test_competing_ssh_run_is_skipped(soc_mysql, private_server):
    insert_events(soc_mysql)
    with (pymysql.connect(unix_socket=private_server, user="root") as other,
          other.cursor() as cursor):
        cursor.execute("SELECT GET_LOCK(%s, 0)", (db.LOCK_NAME,))
        assert cursor.fetchone() == (1,)
        assert run_detection(soc_mysql, START, END)["status"] == "SKIPPED"
        cursor.execute("SELECT RELEASE_LOCK(%s)", (db.LOCK_NAME,))
    assert not alerts(soc_mysql)
    assert run_detection(soc_mysql, START, END)["new_alerts_saved"] == 1


def test_late_bridge_between_saved_alerts_fails_without_partial_merging(soc_mysql):
    insert_events(soc_mysql, 5)
    insert_events(soc_mysql, 5, start=START + timedelta(seconds=120))
    run_detection(soc_mysql, START, END)
    before = alerts(soc_mysql), evidence(soc_mysql)
    insert_events(soc_mysql, 7, start=START + timedelta(seconds=50))
    with pytest.raises(db.SSHDetectionError, match="multiple saved SSH alerts"):
        run_detection(soc_mysql, START, END)
    assert (alerts(soc_mysql), evidence(soc_mysql)) == before


def test_ssh_storage_preserves_port_scan_alerts_and_identity(soc_mysql):
    # Import only the UFW CREATE statement, never the destructive schema dump.
    from pathlib import Path

    schema = (Path(__file__).resolve().parents[2] / "database/schema.sql").read_text()
    start = schema.index("CREATE TABLE `ufw_log`")
    with soc_mysql.cursor() as cursor:
        cursor.execute(schema[start:schema.index(";", start) + 1])
        for index in range(10):
            cursor.execute("""
                INSERT INTO ufw_log (event_time, action, src_ip, dst_ip, protocol,
                                     dst_port, raw_line, event_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (START + timedelta(seconds=index), "BLOCK", "192.0.2.1", "198.51.100.1",
                  "TCP", 1000 + index, f"synthetic-{index}", f"{index:064x}"))
    soc_mysql.commit()
    assert run_port_scan_detection(soc_mysql, START, END)["new_alerts_saved"] == 1
    port_before = alerts(soc_mysql)
    evidence_before = evidence(soc_mysql)
    insert_events(soc_mysql)
    assert run_detection(soc_mysql, START, END)["new_alerts_saved"] == 1
    assert alerts(soc_mysql)[0] == port_before[0]
    assert evidence(soc_mysql)[:10] == evidence_before
    assert run_port_scan_detection(soc_mysql, START, END)["existing_alerts_skipped"] == 1
    rows = alerts(soc_mysql)
    assert [row["rule_key"] for row in rows] == ["PORT_SCAN_001", "SSH_BRUTE_FORCE_001"]
    assert rows[0]["alert_fingerprint"] != rows[1]["alert_fingerprint"]
