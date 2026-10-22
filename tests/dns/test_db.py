import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import Mock

import pymysql
import pytest

from ingestion.dns.db import (
    DNSStorageError,
    load_state,
    purge_events,
    register_source,
    save_events,
)
from ingestion.dns.models import DNSEvent


@pytest.fixture
def event():
    return DNSEvent(
        "dns",
        datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc),
        "2026-10-21T12:00:00.123456789+03:00",
        "2001:db8::1",
        "example.net",
        "AAAA",
        "NOERROR",
        "allowed",
        "NotFilteredNotFound",
        "tls://dns.example.net",
        Decimal("1.23456789"),
        False,
    )


@pytest.fixture
def connection():
    connection = Mock()
    connection.cursor.return_value.fetchone.return_value = ("dns", 1)
    connection.cursor.return_value.rowcount = 2
    return connection


def test_events_and_state_commit_together(connection, event):
    state = {"version": 1, "timestamp": event.raw_timestamp}
    assert save_events(connection, 7, [event, event], state=state) == 2
    cursor = connection.cursor.return_value
    sql, rows = cursor.executemany.call_args.args
    assert "INSERT INTO dns_events" in sql
    assert "IGNORE" not in sql
    assert len(rows) == 2 and rows[0] == rows[1]
    assert rows[0][1].tzinfo is None
    assert rows[0][2] == event.raw_timestamp
    state_call = cursor.execute.call_args.args
    assert json.loads(state_call[1][1]) == state
    connection.begin.assert_called_once()
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()
    cursor.close.assert_called_once()


def test_values_are_parameterized(connection, event):
    text = "x'); DROP TABLE dns_events; --"
    save_events(connection, 7, [replace(event, domain=text)])
    sql, rows = connection.cursor.return_value.executemany.call_args.args
    assert text not in sql
    assert rows[0][4] == text
    assert "dns_collection_state" not in str(
        connection.cursor.return_value.execute.call_args
    )


def test_storage_failure_rolls_back_and_hides_payload(connection, event):
    cursor = connection.cursor.return_value
    cursor.executemany.side_effect = pymysql.DataError("secret-value")
    with pytest.raises(DNSStorageError) as error:
        save_events(connection, 7, [event], state={"version": 1})
    assert "secret-value" not in str(error.value)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()
    assert "dns_collection_state" not in str(cursor.execute.call_args)
    cursor.close.assert_called_once()


def test_checkpoint_failure_rolls_back_events(connection, event):
    cursor = connection.cursor.return_value
    cursor.execute.side_effect = [1, pymysql.OperationalError("secret-value")]
    with pytest.raises(DNSStorageError):
        save_events(connection, 7, [event], state={"version": 1})
    cursor.executemany.assert_called_once()
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


@pytest.mark.parametrize("source", [None, ("dns", 0), ("another-dns", 1)])
def test_wrong_or_disabled_source_rejected(connection, event, source):
    connection.cursor.return_value.fetchone.return_value = source
    with pytest.raises((DNSStorageError, ValueError)):
        save_events(connection, 7, [event])
    connection.cursor.return_value.executemany.assert_not_called()
    connection.rollback.assert_called_once()


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_time", datetime(2026, 10, 21)),
        ("domain", "x" * 1025),
        ("elapsed_ms", Decimal("NaN")),
        ("elapsed_ms", Decimal("1.0000000001")),
        ("elapsed_ms", Decimal(100000000000)),
        ("elapsed_ms", Decimal(-1)),
        ("cached", "false"),
        ("upstream", "bad\nvalue"),
    ],
)
def test_invalid_values_never_reach_database(connection, event, field, value):
    with pytest.raises(ValueError):
        save_events(connection, 7, [replace(event, **{field: value})])
    connection.begin.assert_not_called()


@pytest.mark.parametrize(
    "state", [[1], {"value": float("nan")}, {"value": object()}, {"x": "a" * 65536}]
)
def test_invalid_state_does_not_advance(connection, event, state):
    with pytest.raises(ValueError):
        save_events(connection, 7, [event], state=state)
    connection.begin.assert_not_called()


def test_non_utc_time_converted(connection, event):
    local_time = datetime(2026, 10, 21, 12, tzinfo=timezone(timedelta(hours=3)))
    save_events(connection, 7, [replace(event, event_time=local_time)])
    rows = connection.cursor.return_value.executemany.call_args.args[1]
    assert rows[0][1] == datetime(2026, 10, 21, 9)


def test_register_source_without_enabling_by_default(connection):
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = (7, "adguard", "https://dns.example.net")
    assert (
        register_source(connection, "dns", "adguard", "https://dns.example.net/") == 7
    )
    values = cursor.execute.call_args_list[0].args[1]
    assert values == ("dns", "adguard", "https://dns.example.net", False)
    connection.commit.assert_called_once()


def test_existing_name_cannot_switch_server(connection):
    connection.cursor.return_value.fetchone.return_value = (
        7,
        "adguard",
        "https://other.example.net",
    )
    with pytest.raises(DNSStorageError, match="another server"):
        register_source(connection, "dns", "adguard", "https://dns.example.net")
    connection.rollback.assert_called_once()


@pytest.mark.parametrize(
    "url",
    [
        "http://dns.example.net",
        "https://user:secret@dns.example.net",
        "https://dns.example.net?token=secret",
    ],
)
def test_source_url_cannot_store_credentials(connection, url):
    with pytest.raises(ValueError) as error:
        register_source(connection, "dns", "adguard", url)
    assert "secret" not in str(error.value)
    connection.begin.assert_not_called()


@pytest.mark.parametrize(
    "stored,expected", [(None, None), ('{"version": 1}', {"version": 1})]
)
def test_load_state(connection, stored, expected):
    connection.cursor.return_value.fetchone.return_value = (
        None if stored is None else (stored,)
    )
    assert load_state(connection, 7) == expected
    connection.commit.assert_called_once()


@pytest.mark.parametrize("stored", ["[1]", "invalid", "null"])
def test_corrupt_state_fails_safely(connection, stored):
    connection.cursor.return_value.fetchone.return_value = (stored,)
    with pytest.raises(DNSStorageError):
        load_state(connection, 7)
    connection.rollback.assert_called_once()


def test_empty_batch_can_save_explicit_state(connection):
    save_events(connection, 7, [], state={"version": 1})
    connection.cursor.return_value.executemany.assert_not_called()
    assert (
        "dns_collection_state"
        in connection.cursor.return_value.execute.call_args.args[0]
    )


def test_default_retention_is_bounded_30_days(connection):
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    assert purge_events(connection, now=now) == 2
    sql, params = connection.cursor.return_value.execute.call_args.args
    assert "LIMIT %s" in sql
    assert params == (datetime(2026, 9, 21), 1000)
    connection.commit.assert_called_once()


@pytest.mark.parametrize("source_id", [0, -1, True, "7", 2**64])
def test_invalid_source_id(connection, source_id):
    with pytest.raises(ValueError):
        load_state(connection, source_id)
    connection.begin.assert_not_called()


def test_replay_lookup_skips_only_known_keys(connection, event):
    cursor = connection.cursor.return_value
    first, second = b"a" * 32, b"b" * 32
    cursor.fetchall.return_value = ((first,),)
    cursor.rowcount = 1
    assert save_events(connection, 7, [event, event], dedup_keys=[first, second]) == 1
    sql, values = cursor.executemany.call_args.args
    assert "dedup_key" in sql and values[0][-1] == second and len(values) == 1
    lookup = cursor.execute.call_args_list[1].args
    assert lookup[1] == (7, (first, second))
    assert first.hex() not in lookup[0]


def test_fully_replayed_batch_still_updates_explicit_state(connection, event):
    cursor = connection.cursor.return_value
    key = bytes(range(32))
    cursor.fetchall.return_value = ((key,),)
    assert (
        save_events(connection, 7, [event], dedup_keys=[key], state={"version": 1}) == 0
    )
    cursor.executemany.assert_not_called()
    assert "dns_collection_state" in cursor.execute.call_args.args[0]
    connection.commit.assert_called_once()


@pytest.mark.parametrize("keys", [[], [b"short"], ["a" * 32]])
def test_invalid_replay_keys_never_reach_sql(connection, event, keys):
    with pytest.raises(ValueError):
        save_events(connection, 7, [event], dedup_keys=keys)
    connection.begin.assert_not_called()
