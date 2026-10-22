from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import Mock

import pymysql
import pytest

from ingestion.dns.db import DNSStorageError
from ingestion.dns.query_log import get_dns_query_log


@pytest.fixture
def connection():
    connection = Mock()
    stamp = datetime(2026, 10, 22, 12)
    connection.cursor.return_value.fetchall.return_value = [
        (
            12,
            7,
            stamp,
            "2026-10-22T12:00:00Z",
            "192.0.2.15",
            "example.net",
            "A",
            "NOERROR",
            "allowed",
            None,
            None,
            Decimal("1.25"),
            0,
            stamp,
        )
    ]
    return connection


def test_query_log_returns_dicts_and_binds_source_visibility_and_limit(connection):
    rows = get_dns_query_log(connection, 7)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert values == (7, None, None, None, None, False, 100)
    assert "e.source_id = %s" in sql and "f.source_id = e.source_id" in sql
    assert sql.index("NOT EXISTS") < sql.index("LIMIT %s")
    assert "ORDER BY e.event_time DESC, e.id DESC" in sql
    assert rows[0]["id"] == 12 and rows[0]["source_id"] == 7
    assert rows[0]["cached"] is False
    assert rows[0]["elapsed_ms"] == Decimal("1.25")
    connection.commit.assert_called_once()
    connection.cursor.return_value.close.assert_called_once()


def test_query_log_include_hidden_is_explicit_and_still_source_scoped(connection):
    get_dns_query_log(connection, 8, limit=20, include_hidden=True)
    values = connection.cursor.return_value.execute.call_args.args[1]
    assert values[0] == 8 and values[-2:] == (True, 20)


@pytest.mark.parametrize(
    "stamp",
    [
        datetime(2026, 10, 22, 12),
        datetime(2026, 10, 22, 12, tzinfo=timezone.utc),
        datetime(2026, 10, 22, 15, tzinfo=timezone(timedelta(hours=3))),
    ],
)
def test_cursor_uses_time_and_id_with_utc_normalization(connection, stamp):
    get_dns_query_log(connection, 7, before=(stamp, 12))
    values = connection.cursor.return_value.execute.call_args.args[1]
    expected = datetime(2026, 10, 22, 12)
    assert values[1:5] == (expected, expected, expected, 12)


@pytest.mark.parametrize("limit", [0, -1, 1001, True, 1.5, "1; DROP TABLE dns_events"])
def test_invalid_limit_never_reaches_sql(connection, limit):
    with pytest.raises(ValueError):
        get_dns_query_log(connection, 7, limit=limit)
    connection.begin.assert_not_called()


@pytest.mark.parametrize("include_hidden", [None, 0, 1, "true"])
def test_visibility_requires_a_real_boolean(connection, include_hidden):
    with pytest.raises(ValueError):
        get_dns_query_log(connection, 7, include_hidden=include_hidden)
    connection.begin.assert_not_called()


@pytest.mark.parametrize("source_id", [None, 0, -1, True, "7", 2**64])
def test_invalid_source_is_rejected(connection, source_id):
    with pytest.raises(ValueError):
        get_dns_query_log(connection, source_id)
    connection.begin.assert_not_called()


@pytest.mark.parametrize(
    "before",
    [
        "invalid",
        [],
        (datetime(2026, 10, 22),),
        ("2026-10-22T12:00:00Z", 12),
        (datetime(2026, 10, 22), True),
        (datetime(2026, 10, 22), 0),
        (datetime(2026, 10, 22), 2**64),
        (datetime(999, 1, 1), 12),
    ],
)
def test_invalid_cursor_is_rejected_without_sql(connection, before):
    with pytest.raises(ValueError):
        get_dns_query_log(connection, 7, before=before)
    connection.begin.assert_not_called()


def test_database_error_is_not_reported_as_empty_results(connection):
    connection.cursor.return_value.execute.side_effect = pymysql.OperationalError(
        2013, "private payload"
    )
    with pytest.raises(DNSStorageError) as error:
        get_dns_query_log(connection, 7)
    assert "private payload" not in str(error.value)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_empty_results_and_unknown_cache_value(connection):
    row = list(connection.cursor.return_value.fetchall.return_value[0])
    row[12] = None
    connection.cursor.return_value.fetchall.return_value = [tuple(row)]
    assert get_dns_query_log(connection, 7)[0]["cached"] is None
    connection.cursor.return_value.fetchall.return_value = []
    assert get_dns_query_log(connection, 7) == []
