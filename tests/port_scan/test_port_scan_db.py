from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from detection.port_scan.db import get_db_data

START = datetime(2026, 10, 22, 12)
END = START + timedelta(minutes=5)


def legacy_connection():
    connection = Mock(_siem_identity_ready=False)
    schema_cursor = MagicMock()
    schema_cursor.__enter__.return_value.fetchone.return_value = None
    connection.cursor.side_effect = [schema_cursor, connection.cursor.return_value]
    return connection


def test_query_returns_detector_fields_and_bounded_parameters(sample_events):
    connection = legacy_connection()
    fields = ("id", "event_time", "action", "src_ip", "dst_ip", "protocol", "dst_port")
    rows = []
    for event in sample_events:
        rows.append(tuple(event[field] for field in fields))
    cursor = connection.cursor.return_value
    cursor.fetchall.return_value = rows
    assert get_db_data(connection, START, END) == sample_events
    sql, params = cursor.execute.call_args.args
    assert "SELECT id, event_time, action, src_ip, dst_ip, protocol, dst_port" in sql
    assert "event_time >= %s AND event_time < %s" in sql
    assert "ORDER BY event_time, id" in sql
    assert params == (START, END, "BLOCK", "AUDIT", "ALLOW", "TCP", "UDP")
    assert "2026" not in sql
    assert "BLOCK" not in sql
    assert "DATE(event_time)" not in sql
    connection.commit.assert_not_called()
    cursor.close.assert_called_once()


def test_empty_database_result():
    connection = legacy_connection()
    connection.cursor.return_value.fetchall.return_value = ()
    assert get_db_data(connection, START, END) == []


@pytest.mark.parametrize(
    "start,end",
    [
        (START, START),
        (END, START),
        ("2026-10-22'; SELECT 1; --", END),
        (None, END),
        (START.date(), END),
        (START, "bad"),
        (START.replace(tzinfo=timezone.utc), END),
        (START, END.replace(tzinfo=timezone.utc)),
        (datetime(999, 1, 1), END),
    ],
)
def test_invalid_time_range_never_reaches_sql(start, end):
    connection = legacy_connection()
    with pytest.raises(ValueError):
        get_db_data(connection, start, end)
    connection.cursor.assert_not_called()


@pytest.mark.parametrize("operation", ["execute", "fetchall"])
def test_database_errors_propagate_instead_of_looking_like_empty_results(operation):
    connection = legacy_connection()
    cursor = connection.cursor.return_value
    getattr(cursor, operation).side_effect = pymysql.OperationalError(
        1146, "test error"
    )
    with pytest.raises(pymysql.OperationalError):
        get_db_data(connection, START, END)
    cursor.close.assert_called_once()
