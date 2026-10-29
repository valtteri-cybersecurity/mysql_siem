"""Real SQL on an opt-in private MySQL server; never the collection database."""

import hashlib
from datetime import datetime, timedelta

import pymysql
import pytest

from analysis.ufw import traffic
from analysis.ufw.ports import run_port_analysis
from analysis.ufw.source_ips import run_source_ip_analysis

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)
MIGRATION = "012_analysis_ufw_traffic.sql"


@pytest.fixture
def mysql(unmigrated_mysql, migrate_analysis):
    migrate_analysis(unmigrated_mysql, MIGRATION)
    from database.migrate import migrate
    migrate(unmigrated_mysql)
    return unmigrated_mysql


def seed(connection, events):
    with connection.cursor() as cursor:
        for index, event in enumerate(events):
            cursor.execute("""INSERT INTO ufw_log
                (event_time, src_ip, dst_ip, dst_port, protocol, action, raw_line, event_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (event["event_time"], event["src_ip"], event["dst_ip"], event["dst_port"],
                 event["protocol"], event["action"], "synthetic only",
                 hashlib.sha256(f"traffic-{index}-{event}".encode()).hexdigest()))
    connection.commit()


def saved(connection, daily=False):
    table = "analysis_ufw_traffic_daily" if daily else "analysis_ufw_traffic"
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute(f"SELECT * FROM {table} ORDER BY id")
        return cursor.fetchall()


def run(connection, start=START, end=END, **kwargs):
    return traffic.run_traffic_analysis(connection, start, end, now=end, **kwargs)


def test_actions_protocols_distinct_ipv4_ipv6_and_missing_fields(mysql, events):
    extra = [dict(events[0], src_ip=None, dst_ip=None, protocol=None, dst_port=0, action="REJECT"),
             dict(events[0], src_ip="bad", dst_ip="bad", protocol="TCP", dst_port=53, action=None),
             dict(events[0], src_ip="2001:0DB8::1", dst_ip="2001:0DB8::1", action="block"),
             dict(events[0], src_ip="2001:db8::1", dst_ip="2001:db8::1", action="AUDIT")]
    seed(mysql, events + extra)
    run(mysql)
    row = saved(mysql)[0]
    assert {name: row[name] for name in traffic.METRICS} == {
        "total_events": 9, "blocked_events": 2, "allowed_events": 1, "audited_events": 2,
        "other_events": 4, "tcp_events": 5, "udp_events": 2,
        "unique_source_ips": 2, "unique_destination_ips": 2, "unique_destination_ports": 4}
    assert row["first_seen"] == START and row["last_seen"] == START + timedelta(seconds=4)
    assert row["coverage_status"] == "UNKNOWN" and row["period_status"] == "CLOSED"


def test_hour_and_day_boundaries_exclude_null_timestamp(mysql, events):
    midnight = START.replace(hour=0)
    seed(mysql, [dict(events[0], event_time=stamp) for stamp in (
        midnight - timedelta(seconds=1), midnight, START, END,
        midnight + timedelta(days=1), None)])
    run(mysql)
    assert saved(mysql)[0]["total_events"] == 1
    assert saved(mysql, True)[0]["total_events"] == 3


def test_empty_hour_and_day_have_zero_counts_unknown_coverage_and_open_state(mysql):
    traffic.run_traffic_analysis(mysql, START, END, now=START + timedelta(minutes=5))
    for daily in (False, True):
        row = saved(mysql, daily)[0]
        assert all(row[name] == 0 for name in traffic.METRICS)
        assert row["coverage_status"] == "UNKNOWN" and row["period_status"] == "OPEN"
    assert saved(mysql)[0]["first_seen"] is None and saved(mysql)[0]["last_seen"] is None
    run(mysql)
    assert saved(mysql)[0]["period_status"] == "CLOSED"
    assert saved(mysql)[0]["coverage_status"] == "UNKNOWN"


def test_daily_uniques_are_computed_from_raw_events_not_summed_hours(mysql, events):
    seed(mysql, [dict(events[0], event_time=stamp) for stamp in (START, END)])
    run(mysql, end=END + timedelta(hours=1))
    hourly, daily = saved(mysql), saved(mysql, True)[0]
    assert sum(row["unique_source_ips"] for row in hourly) == 2
    assert daily["total_events"] == 2
    for metric in ("unique_source_ips", "unique_destination_ips", "unique_destination_ports"):
        assert daily[metric] == 1


def test_rerun_is_idempotent_and_repairs_late_arrivals(mysql, events):
    seed(mysql, events)
    run(mysql)
    old = saved(mysql)[0]
    run(mysql)
    assert saved(mysql)[0]["id"] == old["id"]
    assert saved(mysql)[0]["total_events"] == 5
    seed(mysql, [dict(events[0], event_time=START + timedelta(minutes=40), src_ip="2001:db8::5")])
    run(mysql)
    assert len(saved(mysql)) == 1 and len(saved(mysql, True)) == 1
    assert saved(mysql)[0]["total_events"] == saved(mysql, True)[0]["total_events"] == 6
    assert saved(mysql)[0]["unique_source_ips"] == 2
    assert saved(mysql)[0]["last_seen"] == START + timedelta(minutes=40)


def test_failed_update_rolls_back_and_releases_lock(mysql, events):
    seed(mysql, events)
    run(mysql)
    before = saved(mysql)
    with mysql.cursor() as cursor:
        cursor.execute("""CREATE TRIGGER reject_traffic BEFORE UPDATE ON analysis_ufw_traffic
                       FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'""")
    seed(mysql, [dict(events[0], event_time=START + timedelta(minutes=10))])
    with pytest.raises(pymysql.MySQLError):
        run(mysql)
    assert saved(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("SELECT IS_FREE_LOCK(%s)", (traffic.LOCK_NAME,))
        assert cursor.fetchone()[0] == 1


def test_busy_lock_skips_all_writes(mysql, events, analysis_private_server):
    other = pymysql.connect(unix_socket=analysis_private_server, user="root")
    try:
        with other.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (traffic.LOCK_NAME,))
            assert cursor.fetchone()[0] == 1
        assert run(mysql)["status"] == "SKIPPED"
        assert not saved(mysql) and not saved(mysql, True)
    finally:
        other.close()


def test_scheduled_window_and_previous_day_are_bounded(mysql, events):
    seed(mysql, events)
    result = run(mysql, start=START - timedelta(hours=2), previous_day=True)
    assert result["hour_count"] == 3 and result["day_count"] == 2
    assert sum(row["total_events"] for row in saved(mysql)) == 5
    assert saved(mysql, True)[0]["analysis_date"] == START.date() - timedelta(days=1)


@pytest.mark.parametrize("stamp", [datetime(2026, 3, 29), datetime(2026, 10, 25), datetime(2025, 1, 1)])
def test_naive_calendar_days_follow_ufw_basis_even_on_dst_dates(mysql, events, stamp):
    seed(mysql, [dict(events[0], event_time=stamp + timedelta(hours=23, minutes=59))])
    result = run(mysql, stamp, stamp + timedelta(days=1))
    assert result["hour_count"] == 24
    assert saved(mysql, True)[0]["analysis_date"] == stamp.date()
    assert saved(mysql, True)[0]["total_events"] == 1


def test_additive_repeatable_migration_and_other_analyses(mysql, events, migrate_analysis):
    seed(mysql, events)
    from database.migrate import migrate
    assert migrate(mysql) == []
    source = run_source_ip_analysis(mysql, START, END)
    ports = run_port_analysis(mysql, START, END)
    assert source["total_events"] == 5 and ports["total_events"] == 4
    run(mysql)
    before = saved(mysql)
    migrate_analysis(mysql, MIGRATION)
    migrate_analysis(mysql, MIGRATION)
    traffic.validate_traffic_schema(mysql)
    assert saved(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_log")
        assert cursor.fetchone()[0] == 5
        cursor.execute("SELECT SUM(total_events) FROM analysis_source_ips")
        assert cursor.fetchone()[0] == 5
        cursor.execute("SELECT SUM(total_events) FROM analysis_ufw_ports")
        assert cursor.fetchone()[0] == 4


@pytest.mark.parametrize("alter", ["DROP INDEX uq_traffic_period", "MODIFY total_events BIGINT NOT NULL",
    "MODIFY first_seen DATETIME(6) NOT NULL", "ENGINE=MyISAM"])
def test_installer_rejects_incompatible_traffic_schema(mysql, alter):
    with mysql.cursor() as cursor:
        cursor.execute("ALTER TABLE analysis_ufw_traffic " + alter)
    with pytest.raises(traffic.TrafficAnalysisError):
        traffic.validate_traffic_schema(mysql)


def test_mysql_session_timezone_does_not_shift_naive_ufw_days(mysql, events):
    midnight = START.replace(hour=0)
    seed(mysql, [dict(events[0], event_time=midnight), dict(events[0], event_time=midnight - timedelta(seconds=1))])
    for offset in ("+00:00", "+03:00", "-07:00"):
        with mysql.cursor() as cursor:
            cursor.execute("SET time_zone = %s", (offset,))
        run(mysql, midnight, midnight + timedelta(hours=1))
        assert saved(mysql)[0]["total_events"] == saved(mysql, True)[0]["total_events"] == 1


def test_daily_write_failure_rolls_back_previous_daily_row(mysql, events):
    seed(mysql, events)
    run(mysql)
    before = saved(mysql, True)
    with mysql.cursor() as cursor:
        cursor.execute("""CREATE TRIGGER reject_daily BEFORE UPDATE ON analysis_ufw_traffic_daily
                       FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'""")
    seed(mysql, [dict(events[0], event_time=START + timedelta(minutes=10))])
    with pytest.raises(pymysql.MySQLError):
        run(mysql)
    assert saved(mysql, True) == before
    # Earlier buckets can commit; a failed daily bucket never becomes partial.
    assert saved(mysql)[0]["total_events"] == 6


def test_historical_correction_preserves_other_hours_and_days(mysql, events):
    seed(mysql, events)
    run(mysql)
    run(mysql, START - timedelta(days=400), END - timedelta(days=400))
    assert len(saved(mysql)) == 2 and len(saved(mysql, True)) == 2
    assert sorted(row["total_events"] for row in saved(mysql)) == [0, 5]
