import json
from unittest.mock import Mock

import pymysql
import pytest

from detection.common.alerts import (
    AlertStorageError,
    make_alert_fingerprint,
    save_alert,
)


@pytest.fixture
def connection():
    connection = Mock()
    cursor = connection.cursor.return_value
    cursor.fetchone.side_effect = [(7, "HIGH", 1), None]
    cursor.lastrowid = 23
    return connection


def test_alert_and_evidence_are_committed_together(connection, alert):
    assert save_alert(connection, alert, [("UFW", 1), ("UFW", 2), ("UFW", 1)]) is True
    cursor = connection.cursor.return_value
    calls = cursor.execute.call_args_list
    assert calls[0].args[1] == ("PORT_SCAN_001",)
    sql, params = calls[2].args
    assert "INSERT INTO detection_alerts" in sql
    assert "'NEW'" in sql
    assert "IGNORE" not in sql
    assert params[:2] == (7, "HIGH")
    assert params[2:5] == (alert["title"], alert["description"], "192.0.2.1")
    assert json.loads(params[-1]) == alert["details"]
    assert cursor.executemany.call_args.args[1] == [(23, "UFW", 1), (23, "UFW", 2)]
    connection.begin.assert_called_once()
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()
    cursor.close.assert_called_once()


def test_existing_fingerprint_skips_all_writes(connection, alert):
    cursor = connection.cursor.return_value
    cursor.fetchone.side_effect = [(7, "HIGH", 1), (23,)]
    assert save_alert(connection, alert, [("UFW", 1)]) is False
    assert cursor.execute.call_count == 2
    cursor.executemany.assert_not_called()
    connection.commit.assert_called_once()


@pytest.mark.parametrize("rule", [None, (7, "HIGH", 0)])
def test_missing_or_disabled_rule_rolls_back(connection, alert, rule):
    cursor = connection.cursor.return_value
    cursor.fetchone.side_effect = [rule]
    with pytest.raises(AlertStorageError, match="missing or disabled"):
        save_alert(connection, alert, [("UFW", 1)])
    cursor.executemany.assert_not_called()
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()


@pytest.mark.parametrize("operation", ["insert", "evidence", "commit", "begin"])
def test_database_failure_rolls_back_and_does_not_expose_payload(
    connection, alert, operation
):
    cursor = connection.cursor.return_value
    error = pymysql.OperationalError(1234, "private-password-or-payload")
    if operation == "insert":
        cursor.execute.side_effect = [None, None, error]
    elif operation == "evidence":
        cursor.executemany.side_effect = error
    else:
        getattr(connection, operation).side_effect = error
    with pytest.raises(AlertStorageError) as caught:
        save_alert(connection, alert, [("UFW", 1)])
    assert "private-password" not in str(caught.value)
    connection.rollback.assert_called_once()
    if operation != "commit":
        connection.commit.assert_not_called()


def test_programming_errors_are_not_hidden_but_still_roll_back(connection, alert):
    connection.cursor.return_value.executemany.side_effect = RuntimeError(
        "programming bug"
    )
    with pytest.raises(RuntimeError, match="programming bug"):
        save_alert(connection, alert, [("UFW", 1)])
    connection.rollback.assert_called_once()


def test_concurrent_fingerprint_insert_is_skipped_precisely(connection, alert):
    cursor = connection.cursor.return_value
    cursor.execute.side_effect = [
        None,
        None,
        pymysql.IntegrityError(1062, "duplicate"),
        None,
    ]
    cursor.fetchone.side_effect = [(7, "HIGH", 1), None, (24,)]
    assert save_alert(connection, alert, [("UFW", 1)]) is False
    assert "FOR SHARE" in cursor.execute.call_args.args[0]
    cursor.executemany.assert_not_called()
    connection.commit.assert_called_once()


@pytest.mark.parametrize("code,matching_row", [(1452, None), (1062, None)])
def test_unrelated_integrity_errors_are_not_treated_as_duplicates(
    connection, alert, code, matching_row
):
    cursor = connection.cursor.return_value
    cursor.execute.side_effect = [
        None,
        None,
        pymysql.IntegrityError(code, "test"),
        None,
    ]
    cursor.fetchone.side_effect = [(7, "HIGH", 1), None, matching_row]
    with pytest.raises(AlertStorageError):
        save_alert(connection, alert, [("UFW", 1)])
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


def test_evidence_duplicate_error_is_not_silenced(connection, alert):
    connection.cursor.return_value.executemany.side_effect = pymysql.IntegrityError(
        1062, "test"
    )
    with pytest.raises(AlertStorageError):
        save_alert(connection, alert, [("UFW", 1)])
    connection.rollback.assert_called_once()


@pytest.mark.parametrize(
    "evidence",
    [
        [],
        [("UFW", True)],
        [("UFW", 0)],
        [("UFW", -1)],
        [("UFW", "1")],
        [("UFW", 2**64)],
        [("", 1)],
        [("ä", 1)],
    ],
)
def test_invalid_evidence_is_rejected_before_writing(connection, alert, evidence):
    with pytest.raises(ValueError):
        save_alert(connection, alert, evidence)
    connection.begin.assert_not_called()


def test_different_event_types_can_reference_the_same_numeric_id(connection, alert):
    save_alert(connection, alert, [("UFW", 1), ("DNS", 1)])
    assert connection.cursor.return_value.executemany.call_args.args[1] == [
        (23, "UFW", 1),
        (23, "DNS", 1),
    ]


def test_sql_values_are_bound_as_parameters(connection, alert):
    payload = "x'); SELECT 'private'; --"
    alert["title"] = payload
    alert["description"] = payload
    alert["details"] = {"text": payload}
    save_alert(connection, alert, [("UFW", 1)])
    sql, params = connection.cursor.return_value.execute.call_args.args
    assert payload not in sql
    assert payload in params
    assert json.loads(params[-1]) == {"text": payload}


def test_fingerprint_is_stable_for_dictionary_order():
    first = make_alert_fingerprint("PORT_SCAN_001", {"a": 1, "b": 2})
    second = make_alert_fingerprint("PORT_SCAN_001", {"b": 2, "a": 1})
    assert first == second
    assert len(first) == 64
    assert make_alert_fingerprint("OTHER_RULE", {"a": 1, "b": 2}) != first
