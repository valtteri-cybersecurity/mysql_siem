from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pymysql
import pytest

from analysis.ufw import ports

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)


@pytest.fixture
def port_events():
    return [{"event_time": START + timedelta(seconds=index), "src_ip": source,
             "dst_ip": "192.168.1.10", "dst_port": 443, "protocol": "TCP", "action": action}
            for index, (action, source) in enumerate([
                ("BLOCK", "10.2.0.1"), ("ALLOW", "10.2.0.1"), ("AUDIT", "2001:db8::1"),
                ("OTHER", None), (None, "invalid"),
            ])]


def test_all_metrics_unknown_actions_and_missing_sources(port_events):
    assert ports.aggregate_ports(port_events, START, END) == [{
        "period_start": START, "period_end": END, "destination_ip": "192.168.1.10",
        "destination_port": 443, "protocol": "TCP", "total_events": 5,
        "blocked_events": 1, "allowed_events": 1, "audited_events": 1, "unique_source_ips": 2,
        "first_seen": START, "last_seen": START + timedelta(seconds=4),
    }]


def test_ports_protocols_and_destinations_are_separate(port_events):
    port_events[1]["protocol"] = "UDP"
    port_events[2]["dst_port"] = 22
    port_events[3]["dst_ip"] = "192.168.1.20"
    port_events[4]["dst_ip"] = "2001:db8::1"
    rows = ports.aggregate_ports(port_events, START, END)
    assert len(rows) == 5
    assert {tuple(row[field] for field in ("destination_ip", "destination_port", "protocol")) for row in rows} == {
        ("192.168.1.10", 443, "TCP"), ("192.168.1.10", 443, "UDP"), ("192.168.1.10", 22, "TCP"),
        ("192.168.1.20", 443, "TCP"), ("2001:db8::1", 443, "TCP"),
    }


def test_ipv6_spellings_normalize_and_private_sources_count(port_events):
    for event in port_events:
        event.update(dst_ip="2001:db8::1", src_ip="fe80::1")
    port_events[0].update(dst_ip="2001:0DB8:0:0:0:0:0:1", src_ip="fe80:0:0:0:0:0:0:1")
    rows = ports.aggregate_ports(port_events, START, END)
    assert len(rows) == 1
    assert rows[0]["destination_ip"] == "2001:db8::1"
    assert rows[0]["unique_source_ips"] == 1


@pytest.mark.parametrize("field,value", [
    ("dst_port", 0), ("dst_port", -1), ("dst_port", 65536), ("dst_port", None), ("dst_port", True),
    ("dst_port", "22"), ("dst_port", 22.5), ("dst_port", []),
    ("protocol", None), ("protocol", ""), ("protocol", "ICMP"), ("protocol", "tcp"),
    ("dst_ip", None), ("dst_ip", ""), ("dst_ip", "invalid"), ("dst_ip", "fe80::1%eth0"),
])
def test_rejected_targets_do_not_create_rows(port_events, field, value):
    for event in port_events:
        event[field] = value
    assert ports.aggregate_ports(port_events, START, END) == []


@pytest.mark.parametrize("port", [1, 65535])
def test_valid_port_boundaries(port_events, port):
    port_events[0]["dst_port"] = port
    assert ports.aggregate_ports(port_events[:1], START, END)[0]["destination_port"] == port


def test_half_open_boundaries_and_no_input_mutation(port_events):
    port_events[0]["event_time"] = START - timedelta(microseconds=1)
    port_events[1]["event_time"] = START
    port_events[2]["event_time"] = END - timedelta(microseconds=1)
    port_events[3]["event_time"] = END
    port_events[4]["event_time"] = None
    port_events.reverse()
    before = deepcopy(port_events)
    row = ports.aggregate_ports(port_events, START, END)[0]
    assert row["total_events"] == 2
    assert (row["first_seen"], row["last_seen"]) == (START, END - timedelta(microseconds=1))
    assert port_events == before


def test_empty_and_malformed_input():
    assert ports.aggregate_ports([], START, END) == []
    assert ports.aggregate_ports([None, {}, "bad"], START, END) == []


@pytest.mark.parametrize("days", [1, 7, 30, 90, 180, 365])
def test_historical_ranges_have_no_rolling_cutoff(port_events, days):
    historical = [dict(event, event_time=event["event_time"].replace(year=2025)) for event in port_events]
    start = START.replace(year=2025)
    assert ports.aggregate_ports(historical, start, start + timedelta(days=days))[0]["total_events"] == 5


def test_raw_row_limit_includes_rejected_rows(port_events):
    port_events[-1]["dst_port"] = 0
    with pytest.raises(ports.PortAnalysisError, match="Too many"):
        ports.aggregate_ports(port_events, START, END, max_events=4)
    assert ports.aggregate_ports(port_events, START, END, max_events=5)[0]["total_events"] == 4


@pytest.mark.parametrize("start,end", [(START, START), (END, START), (None, END),
    (START, None), (START.replace(tzinfo=timezone.utc), END)])
def test_invalid_ranges_do_not_query(connection, start, end):
    with pytest.raises(ValueError):
        ports.analyze_ports(connection, start, end)
    connection.cursor.assert_not_called()


def test_streaming_query_is_bounded_and_parameterized(connection, port_events):
    cursor = connection.cursor.return_value
    cursor.__iter__.return_value = iter(tuple(event[field] for field in ports.EVENT_FIELDS) for event in port_events)
    assert ports.analyze_ports(connection, START, END)[0]["total_events"] == 5
    assert connection.cursor.call_count == 2
    assert connection.cursor.call_args.args == (pymysql.cursors.SSCursor,)
    sql, parameters = cursor.execute.call_args.args
    assert parameters == (START, END, ports.MAX_EVENTS + 1)
    assert "event_time >= %s AND event_time < %s" in sql
    assert "ORDER BY event_time, id LIMIT %s" in sql
    assert "CURDATE" not in sql and "raw_line" not in sql
    connection.commit.assert_not_called()


def test_exact_period_replacement_commits(connection, port_events, monkeypatch):
    rows = ports.aggregate_ports(port_events, START, END)
    monkeypatch.setattr(ports, "analyze_ports", Mock(return_value=rows))
    summary = ports.run_port_analysis(connection, START, END)
    assert summary["status"] == "SUCCESS" and summary["group_count"] == 1
    cursor = connection.cursor.return_value
    delete = next(call.args for call in cursor.execute.call_args_list if "DELETE" in call.args[0])
    assert delete == ("DELETE FROM analysis_ufw_ports WHERE period_start = %s AND period_end = %s AND time_basis = 'UTC_VERIFIED'", (START, END))
    expected_values = []
    for field in ports.RESULT_FIELDS:
        expected_values.append(rows[0][field])
    expected_values.append("UTC_VERIFIED")
    assert cursor.executemany.call_args.args[1] == [tuple(expected_values)]
    connection.begin.assert_called_once()
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()


@pytest.mark.parametrize("operation", ["read", "delete", "insert", "commit"])
def test_failure_rolls_back_and_releases_lock(connection, port_events, monkeypatch, operation):
    rows = ports.aggregate_ports(port_events, START, END)
    monkeypatch.setattr(ports, "analyze_ports", Mock(return_value=rows))
    error = pymysql.OperationalError(2013, "synthetic error")
    cursor = connection.cursor.return_value
    if operation == "read":
        monkeypatch.setattr(ports, "analyze_ports", Mock(side_effect=error))
    elif operation == "delete":
        def execute(sql, params):
            if sql.startswith("DELETE"):
                raise error
        cursor.execute.side_effect = execute
    elif operation == "insert":
        cursor.executemany.side_effect = error
    else:
        connection.commit.side_effect = error
    with pytest.raises(pymysql.MySQLError):
        ports.run_port_analysis(connection, START, END)
    connection.rollback.assert_called_once()
    assert "RELEASE_LOCK" in cursor.execute.call_args.args[0]


def test_busy_analysis_does_not_replace_results(connection):
    connection.cursor.return_value.fetchone.side_effect = [(0,)]
    assert ports.run_port_analysis(connection, START, END)["status"] == "SKIPPED"
    connection.begin.assert_not_called()
    connection.cursor.return_value.executemany.assert_not_called()


def test_missing_lock_is_failure(connection):
    connection.cursor.return_value.fetchone.side_effect = [(None,)]
    with pytest.raises(ports.PortAnalysisError):
        ports.run_port_analysis(connection, START, END)
