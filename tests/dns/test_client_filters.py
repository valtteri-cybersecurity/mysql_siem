from datetime import datetime
from unittest.mock import Mock

import pymysql
import pytest

from ingestion.dns import client_filters as filters
from ingestion.dns.db import DNSStorageError


@pytest.fixture
def connection():
    connection = Mock()
    connection.cursor.return_value.lastrowid = 12
    connection.cursor.return_value.rowcount = 1
    connection.cursor.return_value.fetchall.return_value = []
    return connection


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.0.2.15", "192.0.2.15"),
        ("0.0.0.0", "0.0.0.0"),
        ("2001:db8::abcd", "2001:db8::abcd"),
        ("2001:0DB8:0000:0000:0000:0000:0000:ABCD", "2001:db8::abcd"),
        ("::1", "::1"),
        ("::ffff:192.0.2.15", "::ffff:c000:20f"),
        ("::ffff:c000:020f", "::ffff:c000:20f"),
    ],
)
def test_normalize_ipv4_and_ipv6(value, expected):
    assert filters.normalize_client_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        0,
        1,
        True,
        b"192.0.2.15",
        "",
        "dns.example.net",
        "invalid",
        "999.1.1.1",
        "192.0.2.015",
        "192.0.2.15/32",
        "2001:db8::/64",
        "fe80::1%eth0",
        "::1%1",
        "192.0.2.15:53",
        "[::1]",
        " ::1",
        "::1\n",
    ],
)
def test_invalid_or_ambiguous_ip_rejected_before_sql(connection, value):
    with pytest.raises(ValueError):
        filters.normalize_client_ip(value)
    with pytest.raises(ValueError):
        filters.add_client_filter(connection, 7, value)
    connection.begin.assert_not_called()


def test_mapped_ipv6_is_not_conflated_with_ipv4():
    assert filters.normalize_client_ip(
        "::ffff:192.0.2.15"
    ) != filters.normalize_client_ip("192.0.2.15")


def test_add_normalizes_and_uses_independent_boolean_flags(connection):
    description = "TV'); DELETE FROM dns_events; --"
    result = filters.add_client_filter(
        connection,
        7,
        "2001:0DB8:0:0:0:0:0:1",
        description,
        hide_from_query_log=True,
        exclude_from_collection=True,
    )
    assert result == 12
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert "INSERT INTO dns_client_filters" in sql
    assert description not in sql
    assert values == (7, "2001:db8::1", description, True, True, True)
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()


@pytest.mark.parametrize(
    "hide,exclude", [(False, False), (True, False), (False, True), (True, True)]
)
def test_all_option_combinations_are_supported(connection, hide, exclude):
    filters.add_client_filter(
        connection,
        7,
        "192.0.2.15",
        hide_from_query_log=hide,
        exclude_from_collection=exclude,
        enabled=False,
    )
    assert connection.cursor.return_value.execute.call_args.args[1][-3:] == (
        hide,
        exclude,
        False,
    )


@pytest.mark.parametrize(
    "name", ["hide_from_query_log", "exclude_from_collection", "enabled"]
)
@pytest.mark.parametrize("value", [0, 1, "false", None])
def test_creation_requires_real_booleans(connection, name, value):
    with pytest.raises(ValueError):
        filters.add_client_filter(connection, 7, "192.0.2.15", **{name: value})
    connection.begin.assert_not_called()


@pytest.mark.parametrize(
    "description", [None, 1, "x" * 256, "bad\ntext", "bad\x7ftext"]
)
def test_invalid_description_rejected(connection, description):
    with pytest.raises(ValueError):
        filters.add_client_filter(connection, 7, "192.0.2.15", description)
    with pytest.raises(ValueError):
        filters.update_client_filter_description(connection, 7, 12, description)
    connection.begin.assert_not_called()


def test_duplicate_rolls_back_without_overwriting(connection):
    connection.cursor.return_value.execute.side_effect = pymysql.IntegrityError(
        1062, "private DB payload"
    )
    with pytest.raises(ValueError, match="already exists") as error:
        filters.add_client_filter(connection, 7, "192.0.2.15")
    assert "private DB payload" not in str(error.value)
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


def test_database_failure_is_safe_and_rolls_back(connection):
    connection.cursor.return_value.execute.side_effect = pymysql.OperationalError(
        2013, "private DB payload"
    )
    with pytest.raises(DNSStorageError) as error:
        filters.add_client_filter(connection, 7, "192.0.2.15")
    assert "private DB payload" not in str(error.value)
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()
    connection.cursor.return_value.close.assert_called_once()


def test_commit_failure_is_reported(connection):
    connection.commit.side_effect = pymysql.OperationalError(2013, "private DB payload")
    with pytest.raises(DNSStorageError):
        filters.enable_client_filter(connection, 7, 12)
    connection.rollback.assert_called_once()


def test_list_all_and_active_rules_return_normalized_dicts(connection):
    now = datetime(2026, 10, 22)
    row = (12, 7, "2001:0DB8:0:0:0:0:0:1", "TV", 1, 0, 1, now, now)
    connection.cursor.return_value.fetchall.return_value = [row]
    rules = filters.list_client_filters(connection)
    assert connection.cursor.return_value.execute.call_args.args[1] == (
        None,
        None,
        False,
    )
    assert rules[0]["client_ip"] == "2001:db8::1"
    assert rules[0]["hide_from_query_log"] is True
    assert rules[0]["exclude_from_collection"] is False
    assert rules[0]["enabled"] is True
    assert rules[0]["source_id"] == 7
    assert filters.get_active_client_filters(connection, 7) == rules
    assert connection.cursor.return_value.execute.call_args.args[1] == (7, 7, True)
    filters.list_client_filters(connection, 8)
    assert connection.cursor.return_value.execute.call_args.args[1] == (8, 8, False)


@pytest.mark.parametrize("ip", [None, "invalid", "192.0.2.0/24", "fe80::1%eth0"])
def test_invalid_stored_ip_is_not_used_as_a_filter(connection, ip):
    row = (12, 7, ip, "TV", 1, 1, 1, None, None)
    connection.cursor.return_value.fetchall.return_value = [row]
    with pytest.raises(DNSStorageError, match="Invalid stored"):
        filters.get_active_client_filters(connection, 7)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_invalid_stored_boolean_is_rejected(connection):
    connection.cursor.return_value.fetchall.return_value = [
        (12, 7, "::1", "", 2, 0, 1, None, None)
    ]
    with pytest.raises(DNSStorageError, match="option"):
        filters.list_client_filters(connection, 7)


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"hide_from_query_log": True}, (True, None, 7, 12)),
        ({"exclude_from_collection": False}, (None, False, 7, 12)),
        (
            {"hide_from_query_log": False, "exclude_from_collection": True},
            (False, True, 7, 12),
        ),
    ],
)
def test_update_options_leaves_unspecified_flag_unchanged(
    connection, options, expected
):
    assert filters.update_client_filter_options(connection, 7, 12, **options)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert "COALESCE" in sql
    assert values == expected
    connection.commit.assert_called_once()


@pytest.mark.parametrize(
    "options", [{}, {"hide_from_query_log": "yes"}, {"exclude_from_collection": 1}]
)
def test_invalid_option_update_never_reaches_database(connection, options):
    with pytest.raises(ValueError):
        filters.update_client_filter_options(connection, 7, 12, **options)
    connection.begin.assert_not_called()


@pytest.mark.parametrize(
    "operation,value",
    [
        (filters.enable_client_filter, True),
        (filters.disable_client_filter, False),
        (filters.update_client_filter_description, "TV"),
    ],
)
def test_mutations_are_scoped_to_source_and_filter(connection, operation, value):
    if operation is filters.update_client_filter_description:
        assert operation(connection, 7, 12, value)
    else:
        assert operation(connection, 7, 12)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert "WHERE source_id = %s AND id = %s" in sql
    assert values == (value, 7, 12)


def test_delete_only_touches_filter_table(connection):
    assert filters.delete_client_filter(connection, 7, 12)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert sql == "DELETE FROM dns_client_filters WHERE source_id = %s AND id = %s"
    assert values == (7, 12)
    connection.cursor.return_value.rowcount = 0
    assert not filters.delete_client_filter(connection, 8, 12)


def test_idempotent_update_returns_false_for_no_changed_rows(connection):
    connection.cursor.return_value.rowcount = 0
    assert not filters.disable_client_filter(connection, 7, 12)


@pytest.mark.parametrize("source_id", [None, True, 0, -1, 2**64, "7"])
def test_invalid_source_ids_are_rejected(connection, source_id):
    with pytest.raises(ValueError):
        filters.add_client_filter(connection, source_id, "::1")
    with pytest.raises(ValueError):
        filters.get_active_client_filters(connection, source_id)
    with pytest.raises(ValueError):
        filters.delete_client_filter(connection, source_id, 12)
    connection.begin.assert_not_called()


@pytest.mark.parametrize("filter_id", [None, True, 0, -1, 2**64, "12"])
def test_invalid_filter_ids_are_rejected(connection, filter_id):
    with pytest.raises(ValueError):
        filters.enable_client_filter(connection, 7, filter_id)
    with pytest.raises(ValueError):
        filters.delete_client_filter(connection, 7, filter_id)
    connection.begin.assert_not_called()
