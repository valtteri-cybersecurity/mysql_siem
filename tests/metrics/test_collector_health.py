import json
from datetime import datetime
from unittest.mock import MagicMock

import pymysql
import pytest

from database.identity import EventIdentity, IdentityError
from metrics import collector_health as health
from metrics.snapshot import CollectionBusy, ObservationError, SnapshotError

IDENTITY = EventIdentity(10, 20, 30)


@pytest.mark.parametrize('error,code', [
    (PermissionError('sensitive path'), 'PERMISSION_DENIED'),
    (TimeoutError('sensitive command'), 'OBSERVATION_TIMEOUT'),
    (FileNotFoundError('sensitive path'), 'SOURCE_UNAVAILABLE'),
    (SnapshotError('sensitive input'), 'INVALID_OBSERVATION'),
    (ObservationError('INCOMPLETE_OBSERVATION', 'sensitive input'), 'INCOMPLETE_OBSERVATION'),
    (ObservationError('raw payload', 'sensitive input'), 'INVALID_OBSERVATION'),
    (pymysql.OperationalError(2013, 'sensitive SQL'), 'DATABASE_ERROR'),
    (IdentityError('sensitive identity'), 'IDENTITY_ERROR'),
    (CollectionBusy('sensitive lock'), 'COLLECTION_BUSY'),
    (RuntimeError('sensitive traceback'), 'UNKNOWN_ERROR'),
])
def test_error_codes_are_bounded(error, code):
    assert health.error_code(error) == code


def test_duration_and_delta_are_derived_from_monotonic_time_and_existing_results(monkeypatch):
    values = iter([2_000_000_000, 2_008_499_000])
    monkeypatch.setattr(health.time, 'monotonic_ns', lambda: next(values))
    instant = datetime(2026, 11, 16, 12, 0, 0, 123456)
    monkeypatch.setattr(health, 'utc_now', lambda: instant)
    attempt = health.Attempt('processes')
    attempt.identity = IDENTITY
    attempt.coverage.update(visible_pid_count=6, unknown_parent_count=2, raw_data='sensitive payload')
    attempt.set_delta({'added': ['a'], 'changed': ['b', 'c'], 'removed': ['d'], 'unchanged': ['e', 'f', 'g']})
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = None
    attempt.write(connection, 'SUCCESS')
    sql, args = cursor.execute.call_args.args
    assert sql.startswith('INSERT INTO collector_health')
    assert args[:15] == (10, 20, 'processes', 30, 1, instant, 'SUCCESS', None, 0, 8, 6, 1, 2, 1, 3)
    assert json.loads(args[15]) == {'visible_pid_count': 6, 'unknown_parent_count': 2}
    assert json.loads(args[16]) == [{'at': instant.isoformat() + 'Z', 'status': 'SUCCESS', 'error_code': None}]
    connection.commit.assert_not_called()


def test_only_the_last_sixteen_transitions_are_kept():
    attempt = health.Attempt('services')
    attempt.identity = IDENTITY
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    history = []
    for index in range(16):
        history.append({'at': str(index), 'status': 'SUCCESS', 'error_code': None})
    cursor.fetchone.return_value = (42, 'SUCCESS', None, 0, json.dumps(history))
    attempt.write(connection, 'FAILED', 'DATABASE_ERROR')
    _, args = cursor.execute.call_args.args
    transitions = json.loads(args[16])
    assert transitions[:-1] == history[1:]
    assert transitions[-1]['status'] == 'FAILED'
    assert len(transitions) == 16


@pytest.mark.parametrize('value', [True, -1, '12', 2**32])
def test_invalid_counters_are_rejected(value):
    with pytest.raises(SnapshotError, match='counter'):
        health.checked_count(value)


def test_reporting_failure_does_not_replace_the_original_error(monkeypatch, capsys):
    connection = MagicMock()
    cause = ObservationError('INCOMPLETE_OBSERVATION', 'private original')
    unavailable = MagicMock(side_effect=pymysql.OperationalError(2013, 'private database error'))
    monkeypatch.setattr(health.Attempt, 'write', unavailable)
    monkeypatch.setattr(health, 'release_snapshot_lock', MagicMock())

    def begin(_connection, attempt):
        attempt.identity = IDENTITY
        return IDENTITY, {}, None, 'lock'

    with pytest.raises(ObservationError) as error, health.collection(connection, 'processes', begin):
        raise cause
    assert error.value is cause
    unavailable.assert_called_once_with(connection, 'FAILED', 'INCOMPLETE_OBSERVATION')
    assert connection.rollback.call_count == 2
    output = capsys.readouterr().err
    assert 'health record unavailable (DATABASE_ERROR)' in output
    assert 'private' not in output


def test_uncertain_commit_never_writes_a_separate_failure(monkeypatch, capsys):
    connection = MagicMock()
    connection.commit.side_effect = pymysql.OperationalError(2013, 'private database error')
    write = MagicMock()
    monkeypatch.setattr(health.Attempt, 'write', write)
    monkeypatch.setattr(health, 'release_snapshot_lock', MagicMock())

    def begin(_connection, attempt):
        attempt.identity = IDENTITY
        return IDENTITY, {}, None, 'lock'

    with pytest.raises(pymysql.OperationalError), health.collection(connection, 'services', begin):
        pass
    write.assert_called_once_with(connection, 'SUCCESS')
    assert 'snapshot commit outcome is unknown' in capsys.readouterr().err
