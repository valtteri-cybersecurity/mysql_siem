from datetime import datetime
from unittest.mock import Mock

import pymysql
import pytest

from ingestion.dns import domain_filters as filters
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
        ("scs.samsungqbe.com", "scs.samsungqbe.com"),
        ("Scs.SamsungQBE.COM.", "scs.samsungqbe.com"),
        ("xn--mnich-kva.example", "xn--mnich-kva.example"),
        ("_sip._tcp.example.org.", "_sip._tcp.example.org"),
        ("localhost", "localhost"),
        (
            "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61,
            "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61,
        ),
    ],
)
def test_normalize_exact_domain(value, expected):
    assert filters.normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        True,
        b"example.net",
        "",
        ".",
        "*.samsungqbe.com",
        "||example.org^",
        "https://scs.samsungqbe.com",
        "example.org:443",
        "example.org/path",
        "a..org",
        ".example.org",
        "example.org..",
        " example.org",
        "example.org ",
        "example.org\n",
        "-example.org",
        "example-.org",
        "a" * 64 + ".org",
        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62,
        "münich.example",
        "K.example",
        "example.org\x00",
    ],
)
def test_invalid_or_ambiguous_domain_rejected_before_sql(connection, value):
    with pytest.raises(ValueError):
        filters.normalize_domain(value)
    with pytest.raises(ValueError):
        filters.add_domain_filter(connection, 7, value)
    connection.begin.assert_not_called()


def test_add_normalizes_and_parameterizes_description(connection):
    text = "Samsung'); DELETE FROM dns_events; --"
    assert filters.add_domain_filter(connection, 7, "SCS.SamsungQBE.COM.", text) == 12
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert text not in sql
    assert values == (7, "scs.samsungqbe.com", text, True)
    connection.commit.assert_called_once()


@pytest.mark.parametrize("enabled", [0, 1, "true", None])
def test_enabled_requires_boolean(connection, enabled):
    with pytest.raises(ValueError):
        filters.add_domain_filter(connection, 7, "example.org", enabled=enabled)
    connection.begin.assert_not_called()


@pytest.mark.parametrize("description", [None, 3, "a" * 256, "bad\ntext"])
def test_bad_description_rejected(connection, description):
    with pytest.raises(ValueError):
        filters.add_domain_filter(connection, 7, "example.org", description)
    with pytest.raises(ValueError):
        filters.update_domain_filter_description(connection, 7, 12, description)
    connection.begin.assert_not_called()


def test_duplicate_does_not_overwrite_old_rule(connection):
    connection.cursor.return_value.execute.side_effect = pymysql.IntegrityError(
        1062, "private payload"
    )
    with pytest.raises(ValueError, match="already exists") as error:
        filters.add_domain_filter(connection, 7, "example.org")
    assert "private payload" not in str(error.value)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


def test_database_failure_rolls_back_and_redacts_details(connection):
    connection.cursor.return_value.execute.side_effect = pymysql.OperationalError(
        2013, "private payload"
    )
    with pytest.raises(DNSStorageError) as error:
        filters.add_domain_filter(connection, 7, "example.org")
    assert "private payload" not in str(error.value)
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


def test_reads_are_scoped_and_return_canonical_dictionaries(connection):
    now = datetime(2026, 10, 22)
    connection.cursor.return_value.fetchall.return_value = [
        (12, 7, "SCS.SamsungQBE.COM.", "TV", 1, now, now)
    ]
    rules = filters.list_domain_filters(connection)
    assert connection.cursor.return_value.execute.call_args.args[1] == (
        None,
        None,
        False,
    )
    assert rules[0]["domain"] == "scs.samsungqbe.com"
    assert rules[0]["enabled"] is True
    assert filters.get_active_domain_filters(connection, 7) == rules
    assert connection.cursor.return_value.execute.call_args.args[1] == (7, 7, True)


@pytest.mark.parametrize("domain,enabled", [("*", 1), (None, 1), ("example.org", 2)])
def test_corrupt_stored_rules_fail_closed(connection, domain, enabled):
    connection.cursor.return_value.fetchall.return_value = [
        (12, 7, domain, "", enabled, None, None)
    ]
    with pytest.raises(DNSStorageError):
        filters.get_active_domain_filters(connection, 7)
    connection.rollback.assert_called_once()


@pytest.mark.parametrize(
    "operation,value",
    [
        (filters.enable_domain_filter, True),
        (filters.disable_domain_filter, False),
        (filters.update_domain_filter_description, "Updated"),
    ],
)
def test_mutations_require_source_and_rule_id(connection, operation, value):
    args = (connection, 7, 12)
    if isinstance(value, str):
        args += (value,)
    assert operation(*args)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert "WHERE source_id = %s AND id = %s" in sql
    assert values == (value, 7, 12)


def test_delete_affects_only_rule(connection):
    assert filters.delete_domain_filter(connection, 7, 12)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert sql == "DELETE FROM dns_domain_filters WHERE source_id = %s AND id = %s"
    assert values == (7, 12)
    connection.cursor.return_value.rowcount = 0
    assert not filters.delete_domain_filter(connection, 8, 12)


@pytest.mark.parametrize("value", [None, False, 0, -1, 2**64, "12"])
def test_invalid_ids_fail_before_sql(connection, value):
    with pytest.raises(ValueError):
        filters.add_domain_filter(connection, value, "example.org")
    with pytest.raises(ValueError):
        filters.get_active_domain_filters(connection, value)
    with pytest.raises(ValueError):
        filters.delete_domain_filter(connection, 7, value)
    connection.begin.assert_not_called()
