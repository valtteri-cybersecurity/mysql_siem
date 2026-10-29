from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pymysql
import pytest

from analysis.ufw import source_ips

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)


def test_all_metrics(events):
    result = source_ips.aggregate_source_ips(events, START, END)
    assert result == [{
        "period_start": START, "period_end": END, "source_ip": "192.0.2.1",
        "total_events": 5, "blocked_events": 2, "allowed_events": 1, "audited_events": 1,
        "tcp_events": 2, "udp_events": 2, "unique_destination_ports": 3,
        "unique_destination_ips": 2, "first_seen": START, "last_seen": START + timedelta(seconds=4),
    }]


@pytest.mark.parametrize("ip", ["192.168.1.2", "10.88.0.1", "10.2.0.1", "172.16.0.1", "fe80::1", "fdeb::1", "127.0.0.1", "::1"])
def test_private_and_local_sources_are_included(events, ip):
    for event in events:
        event["src_ip"] = ip
    assert source_ips.aggregate_source_ips(events, START, END)[0]["source_ip"] == ip


def test_equivalent_ipv6_source_and_destination_spellings_merge(events):
    for event in events:
        event["src_ip"] = "2001:db8::1"
        event["dst_ip"] = "2001:db8::2"
    events[0]["src_ip"] = "2001:0DB8:0:0:0:0:0:1"
    events[1]["dst_ip"] = "2001:0db8:0:0:0:0:0:2"
    result = source_ips.aggregate_source_ips(events, START, END)
    assert len(result) == 1
    assert result[0]["total_events"] == 5
    assert result[0]["source_ip"] == "2001:db8::1"
    assert result[0]["unique_destination_ips"] == 1


@pytest.mark.parametrize("ip", [None, "", " ", "bad", [], 123, "192.0.2.0/24", "192.168.001.1", "fe80::1%eth0"])
def test_invalid_source_ips_are_skipped(events, ip):
    for event in events:
        event["src_ip"] = ip
    assert source_ips.aggregate_source_ips(events, START, END) == []


def test_invalid_destinations_do_not_discard_valid_source_events(events):
    for event in events:
        event["dst_ip"] = "not-an-ip"
        event["dst_port"] = 0
    result = source_ips.aggregate_source_ips(events, START, END)[0]
    assert result["total_events"] == 5
    assert result["unique_destination_ips"] == 0
    assert result["unique_destination_ports"] == 0


@pytest.mark.parametrize("port", [None, 0, -1, 65536, "22", True, 22.5, []])
def test_invalid_or_unknown_ports_are_not_unique_destinations(events, port):
    for event in events:
        event["dst_port"] = port
    assert source_ips.aggregate_source_ips(events, START, END)[0]["unique_destination_ports"] == 0


def test_start_inclusive_end_exclusive(events):
    events[0]["event_time"] = START - timedelta(microseconds=1)
    events[1]["event_time"] = START
    events[2]["event_time"] = END - timedelta(microseconds=1)
    events[3]["event_time"] = END
    events[4]["event_time"] = END + timedelta(seconds=1)
    result = source_ips.aggregate_source_ips(events, START, END)[0]
    assert result["total_events"] == 2
    assert result["first_seen"] == START
    assert result["last_seen"] == END - timedelta(microseconds=1)


def test_historical_interval_not_limited_to_today(events):
    for event in events:
        event["event_time"] = event["event_time"].replace(year=2025)
    assert source_ips.aggregate_source_ips(events, START.replace(year=2025), END.replace(year=2025))[0]["total_events"] == 5


def test_unsorted_input_is_not_changed(events):
    events.reverse()
    before = deepcopy(events)
    result = source_ips.aggregate_source_ips(events, START, END)[0]
    assert result["first_seen"] == START
    assert result["last_seen"] == START + timedelta(seconds=4)
    assert events == before


def test_empty_input_and_unusable_timestamps():
    assert source_ips.aggregate_source_ips([], START, END) == []
    assert source_ips.aggregate_source_ips([None, {}, {"src_ip": "192.0.2.1", "event_time": "bad"}], START, END) == []


def test_ips_are_separate(events):
    events[-1]["src_ip"] = "192.0.2.2"
    result = source_ips.aggregate_source_ips(events, START, END)
    assert [row["total_events"] for row in result] == [4, 1]


@pytest.mark.parametrize("start,end", [(START, START), (END, START), (None, END), (START, "bad"),
    (START.replace(tzinfo=timezone.utc), END), (datetime(999, 1, 1), END)])
def test_bad_time_range_never_queries(connection, start, end):
    with pytest.raises(ValueError):
        source_ips.analyze_source_ips(connection, start, end)
    connection.cursor.assert_not_called()


def test_row_limit_never_returns_partial_results(events):
    with pytest.raises(source_ips.SourceIPAnalysisError, match="Too many UFW events"):
        source_ips.aggregate_source_ips(events, START, END, max_events=4)
    assert source_ips.aggregate_source_ips(events, START, END, max_events=5)[0]["total_events"] == 5


def test_streaming_bounded_parameterized_query(connection, events):
    cursor = connection.cursor.return_value
    cursor.__iter__.return_value = iter(tuple(event[field] for field in source_ips.EVENT_FIELDS) for event in events)
    result = source_ips.analyze_source_ips(connection, START, END)
    assert result[0]["total_events"] == 5
    assert connection.cursor.call_count == 2
    assert connection.cursor.call_args.args == (pymysql.cursors.SSCursor,)
    sql, params = cursor.execute.call_args.args
    assert params == (START, END, source_ips.MAX_EVENTS + 1)
    assert "event_time >= %s AND event_time < %s" in sql
    assert "ORDER BY event_time, id LIMIT %s" in sql
    for unwanted in ("CURDATE", "DATE(event_time)", "NOT LIKE", "action =", "protocol ="):
        assert unwanted not in sql
    connection.commit.assert_not_called()


def test_exact_interval_replacement_and_commit(connection, events, monkeypatch):
    result = source_ips.aggregate_source_ips(events, START, END)
    analyze = lambda *args, **kwargs: result
    monkeypatch.setattr(source_ips, "analyze_source_ips", analyze)
    summary = source_ips.run_source_ip_analysis(connection, START, END)
    assert summary["source_count"] == 1 and summary["total_events"] == 5
    cursor = connection.cursor.return_value
    delete = next(call for call in cursor.execute.call_args_list if "DELETE" in call.args[0])
    assert delete.args == ("DELETE FROM analysis_source_ips WHERE period_start = %s AND period_end = %s AND time_basis = 'UTC_VERIFIED'", (START, END))
    expected_values = []
    for field in source_ips.RESULT_FIELDS:
        expected_values.append(result[0][field])
    expected_values.append("UTC_VERIFIED")
    assert cursor.executemany.call_args.args[1] == [tuple(expected_values)]
    connection.begin.assert_called_once()
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()
    assert "RELEASE_LOCK" in cursor.execute.call_args.args[0]


@pytest.mark.parametrize("operation", ["read", "delete", "insert", "commit"])
def test_database_errors_roll_back_without_partial_results(connection, events, monkeypatch, operation):
    result = source_ips.aggregate_source_ips(events, START, END)
    monkeypatch.setattr(source_ips, "analyze_source_ips", lambda *args, **kwargs: result)
    error = pymysql.OperationalError(2013, "private-payload")
    cursor = connection.cursor.return_value
    if operation == "read":
        monkeypatch.setattr(source_ips, "analyze_source_ips", Mock(side_effect=error))
    elif operation == "delete":
        def execute(sql, values):
            if sql.startswith("DELETE"):
                raise error
        cursor.execute.side_effect = execute
    elif operation == "insert":
        cursor.executemany.side_effect = error
    else:
        connection.commit.side_effect = error
    with pytest.raises(pymysql.OperationalError):
        source_ips.run_source_ip_analysis(connection, START, END)
    connection.rollback.assert_called_once()
    assert "RELEASE_LOCK" in cursor.execute.call_args.args[0]


def test_busy_run_never_replaces_anything(connection):
    cursor = connection.cursor.return_value
    cursor.fetchone.side_effect = [(0,)]
    assert source_ips.run_source_ip_analysis(connection, START, END)["status"] == "SKIPPED"
    connection.begin.assert_not_called()
    cursor.executemany.assert_not_called()
    assert cursor.execute.call_count == 1


def test_null_lock_is_failure(connection):
    connection.cursor.return_value.fetchone.side_effect = [(None,)]
    with pytest.raises(source_ips.SourceIPAnalysisError):
        source_ips.run_source_ip_analysis(connection, START, END)
    connection.begin.assert_not_called()
