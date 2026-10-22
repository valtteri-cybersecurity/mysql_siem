from datetime import datetime, timedelta, timezone

import pymysql
import pytest

from detection.ssh_brute_force import db

START = datetime(2026, 10, 22, 12)
END = START + timedelta(minutes=5)


def test_parameterized_bounded_query_and_detector_format(connection, sample_events):
    cursor = connection.cursor.return_value
    cursor.fetchall.return_value = [tuple(event[key] for key in db.FIELDS) for event in sample_events]
    assert db.get_db_data(connection, START, END) == sample_events
    sql, params = cursor.execute.call_args.args
    assert "FROM auth_events" in sql
    assert "event_time >= %s AND event_time < %s" in sql
    assert "event_type = %s AND service = %s" in sql
    assert "ORDER BY event_time, id LIMIT %s" in sql
    assert params == (START, END, "SSH_AUTH_FAILURE", "sshd", db.MAX_EVENTS + 1)
    assert "SSH_AUTH_FAILURE" not in sql and "2026" not in sql
    connection.commit.assert_not_called()


def test_empty_result(connection):
    connection.cursor.return_value.fetchall.return_value = ()
    assert db.get_db_data(connection, START, END) == []


@pytest.mark.parametrize("start,end", [
    (START, START), (END, START), (None, END), (START, "bad"),
    ("2026-10-22'; DELETE FROM auth_events; --", END),
    (START.replace(tzinfo=timezone.utc), END), (START, END.replace(tzinfo=timezone.utc)),
    (datetime(999, 1, 1), END),
])
def test_invalid_range_rejected_before_sql(connection, start, end):
    with pytest.raises(ValueError):
        db.get_db_data(connection, start, end)
    connection.cursor.assert_not_called()


@pytest.mark.parametrize("operation", ["execute", "fetchall"])
def test_read_failure_is_not_an_empty_result(connection, operation):
    getattr(connection.cursor.return_value, operation).side_effect = pymysql.OperationalError(1146, "test")
    with pytest.raises(pymysql.OperationalError):
        db.get_db_data(connection, START, END)


def test_over_limit_fails_without_partial_detection(connection, monkeypatch):
    monkeypatch.setattr(db, "MAX_EVENTS", 1)
    connection.cursor.return_value.fetchall.return_value = [(), ()]
    with pytest.raises(db.SSHDetectionError, match="shorter time range"):
        db.get_db_data(connection, START, END)


def test_correct_rule_and_lock(connection):
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = (9, "HIGH", 1)
    assert db.get_rule(connection, lock=True) == (9, "HIGH", 1)
    sql, params = cursor.execute.call_args.args
    assert sql.endswith("FOR SHARE")
    assert params == ("SSH_BRUTE_FORCE_001",)


@pytest.mark.parametrize("row", [None, (9, "LOW", 1)])
def test_missing_or_wrong_severity_rule_fails(connection, row):
    connection.cursor.return_value.fetchone.return_value = row
    with pytest.raises(db.SSHDetectionError):
        db.get_rule(connection)


def test_disabled_rule_is_reported_even_if_severity_changed(connection):
    connection.cursor.return_value.fetchone.return_value = (9, "LOW", 0)
    assert db.get_rule(connection)[2] == 0


@pytest.mark.parametrize("ids", [[], [0], [True], [-1], [2**64], ["1"], ["1) OR 1=1 --"]])
def test_invalid_evidence_never_reaches_sql(connection, ids):
    with pytest.raises(db.SSHDetectionError):
        db.get_evidence_events(connection, ids)
    connection.cursor.assert_not_called()


def test_source_rows_are_locked_and_filtered(connection, sample_events):
    cursor = connection.cursor.return_value
    cursor.fetchall.return_value = [tuple(event[key] for key in db.FIELDS) for event in sample_events]
    ids = [event["id"] for event in sample_events]
    assert db.get_evidence_events(connection, ids + [1]) == sample_events
    sql, params = cursor.execute.call_args.args
    assert "id IN %s" in sql and "FOR SHARE" in sql
    assert params == (tuple(ids), "SSH_AUTH_FAILURE", "sshd")


def test_missing_source_evidence_fails(connection):
    connection.cursor.return_value.fetchall.return_value = []
    with pytest.raises(db.SSHDetectionError, match="missing"):
        db.get_evidence_events(connection, [1])


def test_wrong_existing_evidence_source_fails(connection):
    connection.cursor.return_value.fetchall.return_value = [("UFW", 1)]
    with pytest.raises(db.SSHDetectionError, match="unexpected evidence source"):
        db.get_alert_evidence_ids(connection, 7)


@pytest.mark.parametrize("value,expected", [(1, True), (0, False)])
def test_run_lock_is_rule_specific(connection, value, expected):
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = (value,)
    assert db.acquire_lock(connection) is expected
    assert cursor.execute.call_args.args[1] == (db.LOCK_NAME,)
    assert "SSH_BRUTE_FORCE_001" in db.LOCK_NAME


def test_lock_errors_are_reported(connection):
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = (None,)
    with pytest.raises(db.SSHDetectionError):
        db.acquire_lock(connection)
    with pytest.raises(db.SSHDetectionError):
        db.release_lock(connection)
