"""Security metrics use a frozen UTC day and fake database cursors only."""

import os
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

import pymysql
import pytest

from metrics.security import database, get_data


@pytest.fixture
def host_timezone(request):
    try:
        with patch.dict(os.environ, {"TZ": request.param}):
            time.tzset()
            yield
    finally:
        time.tzset()


@pytest.fixture
def legacy_identity(monkeypatch):
    for module in (database, get_data):
        monkeypatch.setattr(module, "identity_schema_enabled", lambda connection: False)
        monkeypatch.setattr(module, "configured_identity", lambda cursor, source_type: None)


def freeze_clock(monkeypatch, instant):
    calls = []

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            calls.append(tz)
            return cls.fromtimestamp(instant.timestamp(), tz)

    monkeypatch.setattr(get_data, "datetime", FrozenDatetime)
    return calls


@pytest.mark.parametrize("host_timezone", ["UTC", "Europe/Helsinki", "America/Los_Angeles", "Pacific/Kiritimati"], indirect=True)
@pytest.mark.parametrize("instant", [
    datetime(2026, 10, 23, 21, 59, 59, 999999, tzinfo=timezone.utc),
    datetime(2026, 10, 23, 23, 59, 59, 999999, tzinfo=timezone.utc),
    datetime(2026, 10, 24, 0, 0, 0, 123456, tzinfo=timezone.utc),
    datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
    datetime(2027, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc),
])
def test_collection_and_storage_share_one_utc_instant(host_timezone, instant, legacy_identity, monkeypatch):
    calls = freeze_clock(monkeypatch, instant)
    monkeypatch.setattr(get_data, "get_uptime", lambda: 12.5)
    connection = MagicMock()
    cursors = []
    for result in (3, 7, 2, None):
        cursor = MagicMock()
        cursor.fetchone.return_value = (result,)
        cursors.append(cursor)
    connection.cursor.side_effect = cursors

    data = get_data.get_data(connection)
    assert data == {"uptime": 12.5, "blocks": 7, "failed_logins": 2, "unique_ips": 3,
                    "date": instant.replace(microsecond=0)}
    assert data["date"].tzinfo is timezone.utc
    assert calls == [timezone.utc]
    start = instant.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None)
    bounds = (start, start + timedelta(days=1))
    for cursor in cursors[:3]:
        sql, parameters = cursor.execute.call_args.args
        assert parameters == bounds
        assert "event_time >= %s AND event_time < %s" in sql
        assert "CURDATE" not in sql and "DATE(event_time)" not in sql
        cursor.close.assert_called_once()
    assert "COUNT(DISTINCT src_ip)" in cursors[0].execute.call_args.args[0]
    assert "action = 'BLOCK'" in cursors[1].execute.call_args.args[0]
    assert "FROM auth_events" in cursors[2].execute.call_args.args[0]
    assert "event_type = 'SSH_AUTH_FAILURE' AND service = 'sshd'" in cursors[2].execute.call_args.args[0]

    database.save_metrics_db(connection, data)
    sql, values = cursors[3].execute.call_args.args
    assert "INSERT INTO security_metrics" in sql and "ON DUPLICATE KEY UPDATE" in sql
    assert values == (12.5, 7, 2, 3, instant.replace(tzinfo=None, microsecond=0))
    assert values[4].tzinfo is None and values[4].microsecond == 0
    assert data["date"].tzinfo is timezone.utc
    connection.commit.assert_called_once()


def test_clock_is_sampled_before_collection_can_cross_midnight(legacy_identity, monkeypatch):
    instant = datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
    calls = freeze_clock(monkeypatch, instant)
    observed = []

    def count(connection, timestamp):
        observed.append(timestamp)
        return 1

    monkeypatch.setattr(get_data, "get_uptime", lambda: 1)
    for name in ("get_unique_ips_today", "get_blocks_today", "get_failed_logins"):
        monkeypatch.setattr(get_data, name, count)
    data = get_data.get_data(MagicMock())
    assert calls == [timezone.utc]
    assert len(observed) == 3
    for timestamp in observed:
        assert timestamp is data["date"]
        assert timestamp.date().isoformat() == "2026-12-31"


@pytest.mark.parametrize("function", [get_data.get_blocks_today, get_data.get_unique_ips_today, get_data.get_failed_logins])
@pytest.mark.parametrize("registered,host_id", [(False, None), (True, None), (True, 42)])
def test_daily_queries_preserve_host_scope(function, registered, host_id, monkeypatch):
    instant = datetime(2027, 1, 1, 1, 30, tzinfo=timezone(timedelta(hours=3)))
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = (4,)
    identity = SimpleNamespace(host_id=host_id) if host_id is not None else None
    monkeypatch.setattr(get_data, "identity_schema_enabled", lambda connection: registered)
    monkeypatch.setattr(get_data, "configured_identity", lambda cursor, source_type: identity)
    assert function(connection, instant) == 4
    sql, values = cursor.execute.call_args.args
    expected = (datetime(2026, 12, 31), datetime(2027, 1, 1))
    if registered:
        expected += (host_id,)
        assert "AND host_id <=> %s" in sql
    else:
        assert "host_id" not in sql
    assert values == expected
    cursor.close.assert_called_once()


@pytest.mark.parametrize("function", [get_data.get_blocks_today, get_data.get_unique_ips_today, get_data.get_failed_logins])
def test_standalone_daily_queries_also_use_utc(function, legacy_identity, monkeypatch):
    instant = datetime(2027, 1, 1, 0, 0, tzinfo=timezone.utc)
    calls = freeze_clock(monkeypatch, instant)
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = (0,)
    assert function(connection) == 0
    assert calls == [timezone.utc]
    assert connection.cursor.return_value.execute.call_args.args[1] == (datetime(2027, 1, 1), datetime(2027, 1, 2))


@pytest.mark.parametrize("value", [datetime(2026, 10, 23), "2026-10-23 12:00:00", None])
def test_database_boundary_rejects_ambiguous_dates(value):
    connection = MagicMock()
    with pytest.raises(ValueError):
        database.save_metrics_db(connection, {"date": value})
    connection.cursor.assert_not_called()
    connection.commit.assert_not_called()


@pytest.mark.parametrize("instant,expected", [
    (datetime(2027, 1, 1, 1, 30, 15, 123456, tzinfo=timezone(timedelta(hours=3))), datetime(2026, 12, 31, 22, 30, 15)),
    (datetime(2026, 12, 31, 23, 30, 15, 999999, tzinfo=timezone(timedelta(hours=-5))), datetime(2027, 1, 1, 4, 30, 15)),
])
def test_storage_normalizes_aware_time_only_at_database_boundary(instant, expected, legacy_identity):
    connection = MagicMock()
    data = {"uptime": 1, "blocks": 2, "failed_logins": 3, "unique_ips": 4, "date": instant}
    database.save_metrics_db(connection, data)
    assert connection.cursor.return_value.execute.call_args.args[1] == (1, 2, 3, 4, expected)
    assert data["date"] is instant


def test_registered_writer_keeps_identity_fields(legacy_identity, monkeypatch):
    from database.identity import EventIdentity

    identity = EventIdentity(11, 22, 33)
    monkeypatch.setattr(database, "configured_identity", lambda cursor, source_type: identity)
    connection = MagicMock()
    instant = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    data = {"uptime": 1, "blocks": 2, "failed_logins": 3, "unique_ips": 4, "date": instant}
    database.save_metrics_db(connection, data)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert "host_scope" in sql
    assert values == (1, 2, 3, 4, instant.replace(tzinfo=None)) + identity.values() + (identity.host_id,)


def test_failed_query_closes_cursor_and_does_not_return_a_false_zero(legacy_identity):
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.execute.side_effect = pymysql.ProgrammingError(1146, "auth table unavailable")
    with pytest.raises(pymysql.ProgrammingError):
        get_data.get_failed_logins(connection, datetime(2026, 10, 23, tzinfo=timezone.utc))
    cursor.close.assert_called_once()


def test_writer_rolls_back_on_driver_failure(legacy_identity):
    connection = MagicMock()
    connection.cursor.return_value.execute.side_effect = pymysql.OperationalError(2013, "lost")
    database.save_metrics_db(connection, {"uptime": 1, "blocks": 2, "failed_logins": 3,
                                         "unique_ips": 4, "date": datetime(2026, 10, 23, tzinfo=timezone.utc)})
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()
    connection.cursor.return_value.close.assert_called_once()


def test_missing_auth_events_is_reported_by_existing_entry_point(monkeypatch, capsys):
    from metrics.security import main

    connection = MagicMock()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    collect = MagicMock(side_effect=pymysql.ProgrammingError(1146, "auth table unavailable"))
    save = MagicMock()
    monkeypatch.setattr(main, "get_data", collect)
    monkeypatch.setattr(main, "save_metrics_db", save)
    main.main()
    save.assert_not_called()
    connection.close.assert_called_once()
    assert "Security metric collection failed." in capsys.readouterr().out


def test_uptime_field_keeps_hours_and_two_decimal_rounding():
    with patch("builtins.open", mock_open(read_data="45000.0 123.0\n")):
        assert get_data.get_uptime() == 12.5


def test_collected_metrics_can_form_wire_payload(legacy_identity, monkeypatch):
    from contracts.v1.security import SecurityMetricsPayload

    instant = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    freeze_clock(monkeypatch, instant)
    monkeypatch.setattr(get_data, "get_uptime", lambda: 12.5)
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = (3,)
    data = get_data.get_data(connection)
    payload = {"date": data["date"].isoformat(timespec="microseconds").replace("+00:00", "Z"),
               "uptime": format(Decimal(str(data["uptime"])), ".2f"),
               "blocks": str(data["blocks"]), "failed_logins": str(data["failed_logins"]),
               "unique_ips": str(data["unique_ips"]), "metric_day": "2026-10-23", "revision": "1"}
    assert SecurityMetricsPayload.model_validate(payload).model_dump() == payload


@pytest.mark.parametrize("timestamp,belongs", [
    ("2026-12-31T23:59:59.999999Z", False),
    ("2027-01-01T00:00:00.000000Z", True),
    ("2027-01-01T02:30:00+03:00", False),
    ("2026-12-31T22:30:00-02:00", True),
    ("2027-01-01T23:59:59.999999Z", True),
    ("2027-01-02T00:00:00.000000Z", False),
])
@pytest.mark.parametrize("source", ["ssh", "ufw"])
def test_daily_bounds_match_existing_ssh_and_ufw_timestamp_conversions(timestamp, belongs, source, legacy_identity):
    from ingestion.auth.parser import parse_auth_line
    from ingestion.ufw_to_mysql import convert_timestamp

    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = (0,)
    instant = datetime(2027, 1, 1, 12, tzinfo=timezone.utc)
    if source == "ssh":
        event = parse_auth_line(f"{timestamp} host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2")
        event_time = event["event_time"]
        get_data.get_failed_logins(connection, instant)
    else:
        event_time = convert_timestamp(timestamp)
        get_data.get_blocks_today(connection, instant)
    start, end = connection.cursor.return_value.execute.call_args.args[1]
    assert (start <= event_time < end) is belongs
