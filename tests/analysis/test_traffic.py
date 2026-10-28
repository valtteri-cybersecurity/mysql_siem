"""Traffic CLI, time basis, locking and transaction failures with synthetic data."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pymysql
import pytest

from analysis.ufw import main, traffic

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)
ZERO = (0,) * 10 + (None, None)


def test_hour_ranges_expand_without_partial_or_overlapping_keys():
    assert list(traffic.hour_periods(START + timedelta(minutes=40), END + timedelta(minutes=5))) == [
        (START, END), (END, END + timedelta(hours=1))]
    assert list(traffic.hour_periods(START, END)) == [(START, END)]


@pytest.mark.parametrize("start,end", [(END, START), (START, START), (None, END),
    (START.replace(tzinfo=timezone.utc), END)])
def test_invalid_range_rejected_before_database_access(connection, start, end):
    with pytest.raises(ValueError):
        traffic.run_traffic_analysis(connection, start, end)
    connection.cursor.assert_not_called()


def test_aggregate_query_uses_half_open_parameterized_range_and_no_row_limit(connection):
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [None, ZERO]
    result = traffic.analyze_traffic(connection, START, END)
    assert all(result[name] == 0 for name in traffic.METRICS)
    assert result["first_seen"] is None and result["last_seen"] is None
    query, params = cursor.execute.call_args.args
    assert params == (START, END)
    assert "event_time >= %s AND event_time < %s" in query
    assert "CURDATE" not in query and "LIMIT" not in query


@pytest.mark.parametrize("daily", [False, True])
def test_mysql_failure_rolls_back_bucket(connection, monkeypatch, daily):
    monkeypatch.setattr(traffic, "analyze_traffic", Mock(side_effect=pymysql.OperationalError(1146, "synthetic")))
    with pytest.raises(pymysql.MySQLError):
        traffic.save_traffic(connection, START, END, daily=daily, now=END)
    connection.begin.assert_called_once()
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


@pytest.mark.parametrize("lock_result", [None, (None,)])
def test_lock_failure_never_writes(connection, lock_result):
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [lock_result]
    with pytest.raises(traffic.TrafficAnalysisError, match="acquire"):
        traffic.run_traffic_analysis(connection, START, END)
    connection.begin.assert_not_called()


def test_busy_lock_skips_entire_traffic_run(connection):
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(0,)]
    assert traffic.run_traffic_analysis(connection, START, END)["status"] == "SKIPPED"
    connection.begin.assert_not_called()


def test_failed_bucket_releases_lock(connection, monkeypatch):
    monkeypatch.setattr(traffic, "analyze_traffic", Mock(side_effect=pymysql.OperationalError(1213, "synthetic")))
    with pytest.raises(pymysql.MySQLError):
        traffic.run_traffic_analysis(connection, START, END)
    connection.rollback.assert_called_once()
    query, params = connection.cursor.return_value.__enter__.return_value.execute.call_args.args
    assert "RELEASE_LOCK" in query and params == (traffic.LOCK_NAME,)


def test_traffic_cli_refreshes_three_hours_and_yesterday_without_source_or_ports(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    source, ports = Mock(), Mock()
    monkeypatch.setattr(main, "run_source_ip_analysis", source)
    monkeypatch.setattr(main, "run_port_analysis", ports)
    run = Mock(return_value={"status": "SUCCESS", "hour_count": 3, "day_count": 2, "total_events": 9})
    monkeypatch.setattr(main, "run_traffic_analysis", run)
    assert main.main(["--traffic"]) == 0
    args, kwargs = run.call_args
    assert args[2] - args[1] == timedelta(hours=3)
    assert kwargs["previous_day"] is True
    source.assert_not_called()
    ports.assert_not_called()
    connection.close.assert_called_once()


def test_manual_traffic_cli_and_existing_port_option_combine(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    ports = Mock(return_value={"status": "SUCCESS", "group_count": 0, "total_events": 0})
    run = Mock(return_value={"status": "SUCCESS", "hour_count": 1, "day_count": 1, "total_events": 0})
    monkeypatch.setattr(main, "run_port_analysis", ports)
    monkeypatch.setattr(main, "run_traffic_analysis", run)
    assert main.main(["--traffic", "--ports", "--start", str(START), "--end", str(END)]) == 0
    assert run.call_args.args == (connection, START, END)
    assert run.call_args.kwargs["previous_day"] is False
    ports.assert_called_once_with(connection, START, END, max_events=100000)


def test_traffic_database_error_is_safe_and_nonzero(monkeypatch, connection, capsys):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_traffic_analysis", Mock(side_effect=pymysql.OperationalError(1146, "secret-payload")))
    assert main.main(["--traffic"]) == 1
    captured = capsys.readouterr()
    assert "FAILED" in captured.out and "secret-payload" not in captured.err
    connection.close.assert_called_once()
