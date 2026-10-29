"""Port aggregation and additive migration only in the private test database."""

import hashlib
from datetime import datetime, timedelta
from pathlib import Path

import pymysql
import pytest

from analysis.ufw import ports
from analysis.ufw.source_ips import run_source_ip_analysis

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)
MIGRATION = "011_analysis_ufw_ports.sql"


@pytest.fixture
def mysql(unmigrated_mysql, migrate_analysis):
    migrate_analysis(unmigrated_mysql, MIGRATION)
    from database.migrate import migrate
    migrate(unmigrated_mysql)
    return unmigrated_mysql


def seed(connection, events):
    with connection.cursor() as cursor:
        for index, event in enumerate(events):
            event.setdefault("host_id", None)
            cursor.execute("""INSERT INTO ufw_log
                (event_time, src_ip, dst_ip, dst_port, protocol, action, raw_line, event_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (event["event_time"], event["src_ip"], event["dst_ip"], event["dst_port"],
                 event["protocol"], event["action"], "synthetic only",
                 hashlib.sha256(f"ports-{index}-{event}".encode()).hexdigest()))
    connection.commit()


def saved(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("""SELECT * FROM analysis_ufw_ports ORDER BY
                       period_start, period_end, destination_ip, destination_port, protocol""")
        results = []
        for row in cursor.fetchall():
            result = {}
            for field in ports.RESULT_FIELDS + ("host_id", "host_scope"):
                result[field] = row[field]
            results.append(result)
        return results


def create_legacy(connection):
    with connection.cursor() as cursor:
        cursor.execute("""CREATE TABLE top_targeted_ports (
                       metric_date DATE NOT NULL, dst_port INT UNSIGNED NOT NULL,
                       hits BIGINT UNSIGNED NOT NULL DEFAULT 0,
                       PRIMARY KEY (metric_date, dst_port)) ENGINE=InnoDB""")
        cursor.execute("INSERT INTO top_targeted_ports VALUES (%s, %s, %s)", ("2025-01-01", 22, 77))
    connection.commit()


def test_mysql_matches_pure_metrics_with_ip_protocol_and_time_boundaries(mysql, events):
    extra = [dict(events[0], protocol="UDP"), dict(events[0], dst_ip="2001:0DB8::1"),
             dict(events[0], dst_ip="2001:db8::1"), dict(events[0], dst_ip=None),
             dict(events[0], event_time=END), dict(events[0], src_ip=None, action="OTHER")]
    seed(mysql, events + extra)
    expected = ports.aggregate_ports(events + extra, START, END)
    assert ports.analyze_ports(mysql, START, END) == expected
    assert ports.run_port_analysis(mysql, START, END)["status"] == "SUCCESS"
    assert saved(mysql) == expected


def test_rerun_updates_late_events_without_duplicate_groups(mysql, events):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    before = saved(mysql)
    ports.run_port_analysis(mysql, START, END)
    assert saved(mysql) == before
    late = dict(events[0], event_time=START + timedelta(minutes=10), src_ip="10.88.0.1")
    seed(mysql, [late])
    ports.run_port_analysis(mysql, START, END)
    target = next(row for row in saved(mysql) if row["destination_port"] == 22)
    assert target["total_events"] == 2 and target["unique_source_ips"] == 2
    assert target["last_seen"] == late["event_time"]


def test_stale_and_empty_groups_are_removed_only_for_exact_interval(mysql, events):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    ports.run_port_analysis(mysql, START, END + timedelta(hours=1))
    other = [row for row in saved(mysql) if row["period_end"] != END]
    with mysql.cursor() as cursor:
        cursor.execute("DELETE FROM ufw_log WHERE dst_port = 22")
    mysql.commit()
    ports.run_port_analysis(mysql, START, END)
    assert all(row["destination_port"] != 22 for row in saved(mysql) if row["period_end"] == END)
    with mysql.cursor() as cursor:
        cursor.execute("DELETE FROM ufw_log")
    mysql.commit()
    ports.run_port_analysis(mysql, START, END)
    assert saved(mysql) == other


def test_database_error_after_delete_rolls_back(mysql, events):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    before = saved(mysql)
    with mysql.cursor() as cursor:
        cursor.execute("""CREATE TRIGGER reject_ports BEFORE INSERT ON analysis_ufw_ports
                       FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'""")
    with pytest.raises(pymysql.MySQLError):
        ports.run_port_analysis(mysql, START, END)
    assert saved(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("SELECT IS_FREE_LOCK(%s)", (ports.LOCK_NAME,))
        assert cursor.fetchone()[0] == 1


def test_limit_error_preserves_existing_metrics(mysql, events):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    before = saved(mysql)
    with pytest.raises(ports.PortAnalysisError):
        ports.run_port_analysis(mysql, START, END, max_events=4)
    assert saved(mysql) == before


def test_lock_contention_skips_without_changing_data(mysql, events, analysis_private_server):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    before = saved(mysql)
    other = pymysql.connect(unix_socket=analysis_private_server, user="root")
    try:
        with other.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (ports.LOCK_NAME,))
            assert cursor.fetchone()[0] == 1
        assert ports.run_port_analysis(mysql, START, END)["status"] == "SKIPPED"
        assert saved(mysql) == before
    finally:
        other.close()


def test_additive_migration_preserves_legacy_raw_and_new_results_and_can_repeat(mysql, events, migrate_analysis):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    before = saved(mysql)
    run_source_ip_analysis(mysql, START, END)
    with mysql.cursor() as cursor:
        cursor.execute("SELECT source_ip, total_events FROM analysis_source_ips ORDER BY source_ip")
        source_before = cursor.fetchall()
    assert source_before
    ports.validate_ports_schema(mysql)
    create_legacy(mysql)
    # The legacy 011 validator intentionally rejects the expanded modern schema.
    with pytest.raises(pymysql.MySQLError):
        migrate_analysis(mysql, MIGRATION)
    from database.migrate import migrate
    assert migrate(mysql) == []
    assert saved(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("SELECT hits FROM top_targeted_ports")
        assert cursor.fetchone()[0] == 77
        cursor.execute("SELECT COUNT(*) FROM ufw_log")
        assert cursor.fetchone()[0] == len(events)
        cursor.execute("SELECT source_ip, total_events FROM analysis_source_ips ORDER BY source_ip")
        assert cursor.fetchall() == source_before


@pytest.mark.parametrize("alter", [
    "MODIFY destination_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NULL",
    "MODIFY total_events BIGINT NOT NULL", "ADD unexpected INT NULL",
    "DROP INDEX uq_ufw_ports_period", "DROP INDEX idx_ufw_ports_history",
    "ALTER INDEX idx_ufw_ports_history INVISIBLE",
    "ALTER CHECK chk_ufw_ports_port NOT ENFORCED",
    "DROP CHECK chk_ufw_ports_protocol, ADD CONSTRAINT chk_ufw_ports_protocol CHECK (protocol IN ('TCP', 'UDP', 'X'))",
])
def test_wrong_existing_schema_aborts_without_retiring_legacy(unmigrated_mysql, events, migrate_analysis, alter):
    connection = unmigrated_mysql
    create_legacy(connection)
    # Create the replacement without running the retirement portion.
    sql = (ROOT / "database/migrations" / MIGRATION).read_text()
    ddl = "CREATE TABLE" + sql.split("CREATE TABLE", 1)[1].split(";", 1)[0]
    with connection.cursor() as cursor:
        cursor.execute(ddl)
    seed(connection, events)
    ports.run_port_analysis(connection, START, END)
    before = saved(connection)
    with connection.cursor() as cursor:
        cursor.execute("ALTER TABLE analysis_ufw_ports " + alter)
    with pytest.raises(ports.PortAnalysisError):
        ports.validate_ports_schema(connection)
    with pytest.raises(pymysql.MySQLError):
        migrate_analysis(connection, MIGRATION)
    assert saved(connection) == before
    with connection.cursor() as cursor:
        cursor.execute("SELECT hits FROM top_targeted_ports")
        assert cursor.fetchone()[0] == 77
        cursor.execute("SELECT COUNT(*) FROM ufw_log")
        assert cursor.fetchone()[0] == len(events)


def test_schema_unique_key_and_not_null_reject_invalid_grains(mysql, events):
    seed(mysql, events)
    ports.run_port_analysis(mysql, START, END)
    row = saved(mysql)[0]
    sql = "INSERT INTO analysis_ufw_ports (" + ",".join(ports.RESULT_FIELDS) + ") VALUES (" + ",".join(["%s"] * len(ports.RESULT_FIELDS)) + ")"
    for destination in (row["destination_ip"], None):
        with mysql.cursor() as cursor, pytest.raises(pymysql.IntegrityError):
            cursor.execute(sql, tuple(destination if field == "destination_ip" else row[field] for field in ports.RESULT_FIELDS))
        mysql.rollback()
