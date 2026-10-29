"""Only the opt-in temporary MySQL server; never the application database."""

import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path

import pymysql
import pytest

from analysis.ufw.source_ips import (
    LOCK_NAME,
    RESULT_FIELDS,
    SourceIPAnalysisError,
    aggregate_source_ips,
    analyze_source_ips,
    run_source_ip_analysis,
)

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)


@pytest.fixture
def mysql(unmigrated_mysql):
    from database.migrate import migrate
    migrate(unmigrated_mysql)
    return unmigrated_mysql


def insert_events(connection, events):
    with connection.cursor() as cursor:
        for index, event in enumerate(events):
            event.setdefault("host_id", None)
            digest = hashlib.sha256(f"{index}-{event}".encode()).hexdigest()
            cursor.execute(
                """INSERT INTO ufw_log
                (event_time, src_ip, dst_ip, action, protocol, dst_port, raw_line, event_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (event["event_time"], event["src_ip"], event["dst_ip"], event["action"],
                 event["protocol"], event["dst_port"], "synthetic only", digest),
            )
    connection.commit()


def saved(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT * FROM analysis_source_ips ORDER BY period_start, period_end, source_ip")
        results = []
        for row in cursor.fetchall():
            result = {}
            for field in RESULT_FIELDS + ("host_id", "host_scope"):
                result[field] = row[field]
            results.append(result)
        return results


def test_real_mysql_matches_all_metrics_and_interval_boundaries(mysql, events):
    # Include IPv6, private IPs, a missing source, and the exclusive upper bound.
    extra = [dict(events[0], src_ip=ip) for ip in ("10.88.0.1", "fe80::1", "2001:0DB8::1", None, "invalid")]
    extra.append(dict(events[0], event_time=END))
    extra.append(dict(events[0], event_time=START - timedelta(seconds=1)))
    insert_events(mysql, events + extra)
    expected = aggregate_source_ips(events + extra, START, END)
    assert analyze_source_ips(mysql, START, END) == expected
    assert run_source_ip_analysis(mysql, START, END)["status"] == "SUCCESS"
    assert saved(mysql) == expected


def test_repeat_run_updates_late_events_without_duplicates(mysql, events):
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    assert run_source_ip_analysis(mysql, START, END)["total_events"] == 5
    assert len(saved(mysql)) == 1
    late = dict(events[0], event_time=START + timedelta(minutes=10))
    insert_events(mysql, [late])
    run_source_ip_analysis(mysql, START, END)
    assert saved(mysql)[0]["total_events"] == 6
    assert saved(mysql)[0]["last_seen"] == late["event_time"]


def test_exact_replacement_removes_stale_sources_and_preserves_other_periods(mysql, events):
    events[-1]["src_ip"] = "10.2.0.1"
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    run_source_ip_analysis(mysql, START, END + timedelta(hours=1))
    other = [row for row in saved(mysql) if row["period_end"] != END]
    # Simulate source corrections only in the private test database.
    with mysql.cursor() as cursor:
        cursor.execute("DELETE FROM ufw_log WHERE src_ip = %s", ("10.2.0.1",))
    mysql.commit()
    run_source_ip_analysis(mysql, START, END)
    assert len(saved(mysql)) == 3
    assert [row for row in saved(mysql) if row["period_end"] != END] == other
    with mysql.cursor() as cursor:
        cursor.execute("DELETE FROM ufw_log")
    mysql.commit()
    run_source_ip_analysis(mysql, START, END)
    assert saved(mysql) == other


def test_failure_after_deletion_rolls_back_previous_summary(mysql, events):
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    before = saved(mysql)
    with mysql.cursor() as cursor:
        cursor.execute("""CREATE TRIGGER reject_summary BEFORE INSERT ON analysis_source_ips
                       FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'""")
    with pytest.raises(pymysql.MySQLError):
        run_source_ip_analysis(mysql, START, END)
    assert saved(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("SELECT IS_FREE_LOCK(%s)", (LOCK_NAME,))
        assert cursor.fetchone()[0] == 1


def test_row_limit_failure_preserves_previous_summary(mysql, events):
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    before = saved(mysql)
    with pytest.raises(SourceIPAnalysisError, match="Too many"):
        run_source_ip_analysis(mysql, START, END, max_events=4)
    assert saved(mysql) == before


def test_competing_connection_skips_without_changes(mysql, events, analysis_private_server):
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    before = saved(mysql)
    other = pymysql.connect(unix_socket=analysis_private_server, user="root")
    try:
        with other.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
            assert cursor.fetchone()[0] == 1
        assert run_source_ip_analysis(mysql, START, END)["status"] == "SKIPPED"
        assert saved(mysql) == before
    finally:
        other.close()


@pytest.mark.parametrize("days", [1, 7, 30, 90, 365])
def test_arbitrary_historical_intervals_no_current_date_cutoff(mysql, events, days):
    historical = [dict(event, event_time=event["event_time"].replace(year=2025)) for event in events]
    insert_events(mysql, historical)
    start = START.replace(year=2025)
    assert run_source_ip_analysis(mysql, start, start + timedelta(days=days))["total_events"] == 5
    assert saved(mysql)[0]["period_end"] == start + timedelta(days=days)


def test_repeatable_migration_preserves_raw_and_new_history(mysql, events, migrate_analysis):
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    before = saved(mysql)
    migrate_analysis(mysql)
    assert saved(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_log")
        assert cursor.fetchone()[0] == 5
        cursor.execute("SHOW INDEX FROM analysis_source_ips")
        indexes = cursor.fetchall()
        assert [row[4] for row in indexes if row[2] == "PRIMARY"] == ["period_start", "period_end", "source_ip", "host_scope", "time_basis"]
        assert [row[4] for row in indexes if row[2] == "idx_analysis_source_history"] == ["source_ip", "period_start", "period_end"]


def test_real_unique_key_prevents_duplicate_period_and_ip(mysql, events):
    insert_events(mysql, events)
    run_source_ip_analysis(mysql, START, END)
    row = saved(mysql)[0]
    with mysql.cursor() as cursor, pytest.raises(pymysql.IntegrityError):
        cursor.execute("INSERT INTO analysis_source_ips (" + ",".join(RESULT_FIELDS) + ") VALUES ("
                       + ",".join(["%s"] * len(RESULT_FIELDS)) + ")",
                       tuple(row[field] for field in RESULT_FIELDS))
    mysql.rollback()
    assert len(saved(mysql)) == 1


def test_bootstrap_schema_never_recreates_retired_table(unmigrated_mysql, migrate_analysis):
    mysql = unmigrated_mysql
    root = Path(__file__).resolve().parents[2]
    schema = (root / "database/schema.sql").read_text()
    # The fixture has already created ufw_log and applied 009. Create every
    # other bootstrap table, as on a fresh install, without running the dump's DROP statements.
    with mysql.cursor() as cursor:
        for match in re.finditer(r"CREATE TABLE (?:IF NOT EXISTS )?`?(\w+)`? \(.*?;", schema, re.DOTALL):
            if match.group(1) != "ufw_log":
                cursor.execute(match.group(0))
    migrate_analysis(mysql)
    migrate_analysis(mysql, "011_analysis_ufw_ports.sql")
    with mysql.cursor() as cursor:
        cursor.execute("SHOW TABLES")
        assert {row[0] for row in cursor.fetchall()} == {
            "filesystem_metrics", "security_metrics", "system_metrics", "analysis_ufw_ports",
            "analysis_ufw_traffic", "analysis_ufw_traffic_daily", "ufw_log", "ufw_state", "analysis_source_ips",
            "dns_sources", "dns_events", "dns_collection_state", "dns_client_filters", "dns_domain_filters",
            "detection_rules", "detection_alerts", "alert_evidence", "detection_state", "auth_events", "auth_ingestion_state",
        }
