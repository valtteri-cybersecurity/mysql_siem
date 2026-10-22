from datetime import datetime, timedelta
from unittest.mock import Mock

import pymysql
import pytest

from analysis.ufw import main

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)


@pytest.fixture(autouse=True)
def independent_traffic_runner(monkeypatch):
    # These pre-existing tests isolate Source IP/Port dispatch. Traffic has its
    # own CLI and real-SQL tests, and --all now dispatches all three analyses.
    monkeypatch.setattr(main, "run_traffic_analysis", Mock(return_value={
        "status": "SUCCESS", "hour_count": 3, "day_count": 2, "total_events": 0}))


def test_recent_buckets_have_stable_keys():
    expected = [(START - timedelta(hours=1), START), (START, END)]
    assert main.recent_hour_periods(START + timedelta(minutes=1)) == expected
    assert main.recent_hour_periods(START + timedelta(minutes=59)) == expected


def test_recent_buckets_cross_day_boundary():
    now = datetime(2026, 10, 22, 0, 5)
    result = main.recent_hour_periods(now)
    assert result[0] == (datetime(2026, 10, 21, 23), datetime(2026, 10, 22))
    assert result[1] == (datetime(2026, 10, 22), datetime(2026, 10, 22, 1))


def test_manual_interval_is_forwarded_and_connection_closed(monkeypatch, connection, capsys):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    run = Mock(return_value={"source_count": 3, "total_events": 7, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_source_ip_analysis", run)
    assert main.main(["--start", str(START), "--end", str(END)]) == 0
    run.assert_called_once_with(connection, START, END, max_events=100000)
    assert "valid-source events: 7" in capsys.readouterr().out
    connection.close.assert_called_once()


def test_recent_mode_runs_two_periods(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    run = Mock(return_value={"source_count": 0, "total_events": 0, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_source_ip_analysis", run)
    assert main.main(["--recent-hours", "2"]) == 0
    assert run.call_count == 2
    for call in run.call_args_list:
        assert call.args[2] - call.args[1] == timedelta(hours=1)


@pytest.mark.parametrize("args", [["--start", str(START)], ["--recent-hours", "0"], ["--recent-hours", "25"],
    ["--max-events", "0"], ["--start", str(START), "--end", str(END), "--recent-hours", "2"],
    ["--start", "2026-10-22T12:00:00+03:00", "--end", str(END)]])
def test_invalid_arguments_do_not_connect(monkeypatch, args):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit):
        main.main(args)
    connect.assert_not_called()


def test_database_failure_is_safe_and_logged(monkeypatch, connection, tmp_path):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_source_ip_analysis", Mock(side_effect=pymysql.OperationalError(1146, "private-payload")))
    logfile = tmp_path / "cron.log"
    assert main.main(["--log-file", str(logfile)]) == 1
    output = logfile.read_text()
    assert "Status: FAILED" in output and "Finished:" in output
    assert "private-payload" not in output
    connection.close.assert_called_once()


def test_failed_connection_is_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=None))
    assert main.main([]) == 1
    assert "connection failed" in capsys.readouterr().err


def test_programming_error_is_not_hidden(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_source_ip_analysis", Mock(side_effect=TypeError("bug")))
    with pytest.raises(TypeError):
        main.main([])
    connection.close.assert_called_once()


@pytest.mark.parametrize("option,source_runs,port_runs,hours", [
    ("--source-ips", 2, 0, 2), ("--ports", 0, 3, 3), ("--all", 3, 3, 3),
])
def test_selection_preserves_source_default_and_refreshes_three_hours_for_ports(
        monkeypatch, connection, option, source_runs, port_runs, hours):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    source = Mock(return_value={"source_count": 1, "total_events": 2, "status": "SUCCESS"})
    ports = Mock(return_value={"group_count": 1, "total_events": 2, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_source_ip_analysis", source)
    monkeypatch.setattr(main, "run_port_analysis", ports)
    assert main.main([option]) == 0
    assert source.call_count == source_runs and ports.call_count == port_runs
    calls = ports.call_args_list if port_runs else source.call_args_list
    assert len(calls) == hours
    assert all(call.args[2] - call.args[1] == timedelta(hours=1) for call in calls)
    assert all(calls[index].args[2] == calls[index + 1].args[1] for index in range(hours - 1))


def test_historical_interval_runs_both_analyses_independently(monkeypatch, connection, capsys):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    source = Mock(return_value={"source_count": 0, "total_events": 0, "status": "SUCCESS"})
    ports = Mock(return_value={"group_count": 0, "total_events": 0, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_source_ip_analysis", source)
    monkeypatch.setattr(main, "run_port_analysis", ports)
    assert main.main(["--all", "--start", str(START), "--end", str(END)]) == 0
    source.assert_called_once_with(connection, START, END, max_events=100000)
    ports.assert_called_once_with(connection, START, END, max_events=100000)
    output = capsys.readouterr().out
    assert "Analysis: Source IP Analysis" in output and "Analysis: Port Activity Analysis" in output


def test_ports_can_expand_the_recent_window(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    ports = Mock(return_value={"group_count": 0, "total_events": 0, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_port_analysis", ports)
    assert main.main(["--ports", "--recent-hours", "24"]) == 0
    assert ports.call_count == 24


def test_busy_source_does_not_skip_independent_ports(monkeypatch, connection):
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    source = Mock(return_value={"source_count": 0, "total_events": 0, "status": "SKIPPED", "reason": "busy"})
    ports = Mock(return_value={"group_count": 0, "total_events": 0, "status": "SUCCESS"})
    monkeypatch.setattr(main, "run_source_ip_analysis", source)
    monkeypatch.setattr(main, "run_port_analysis", ports)
    assert main.main(["--all"]) == 0
    assert source.call_count == 1 and ports.call_count == 3


def test_port_error_is_reported_and_connection_closed(monkeypatch, connection, tmp_path):
    from analysis.ufw.ports import PortAnalysisError
    monkeypatch.setattr(main, "get_connection", Mock(return_value=connection))
    monkeypatch.setattr(main, "run_port_analysis", Mock(side_effect=PortAnalysisError("Too many UFW events")))
    logfile = tmp_path / "ports.log"
    assert main.main(["--ports", "--log-file", str(logfile)]) == 1
    assert "Port Activity Analysis" in logfile.read_text() and "Status: FAILED" in logfile.read_text()
    connection.close.assert_called_once()


def test_conflicting_analysis_flags_do_not_connect(monkeypatch):
    connect = Mock()
    monkeypatch.setattr(main, "get_connection", connect)
    with pytest.raises(SystemExit):
        main.main(["--ports", "--source-ips"])
    connect.assert_not_called()
