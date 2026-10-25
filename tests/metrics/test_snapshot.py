from unittest.mock import MagicMock, patch

import pymysql
import pytest

from database.identity import EventIdentity, IdentityError
from metrics import snapshot
from metrics.processes import main as processes_main
from metrics.services import main as services_main
from metrics.services.get import get_events


def collect_snapshot(connection, kind, observe, diff):
    # Test adapter: run the same pre-refactor scenarios through main.py.
    if kind == 'services':
        with patch.object(services_main, 'get_services', observe), patch.object(services_main, 'get_events', diff):
            return services_main.collect_services(connection)
    with patch.object(processes_main, 'get_processes', observe), patch.object(processes_main, 'get_events', diff):
        return processes_main.collect_processes(connection)


IDENTITY = EventIdentity(10, 20, 30)


def protocol(monkeypatch, *, baseline=False, lock=1):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [('synthetic',), (lock,), (1,)]
    monkeypatch.setattr(snapshot, 'get_identity', lambda *args: IDENTITY)
    monkeypatch.setattr(snapshot, 'get_previous', lambda *args: ({}, baseline))
    save = MagicMock()
    monkeypatch.setattr(snapshot, 'save_snapshot', save)
    return connection, cursor, save


def test_first_baseline_commits_state_without_started_events(monkeypatch):
    connection, cursor, save = protocol(monkeypatch)
    current = {'example.service': {'active_state': 'active'}}
    assert collect_snapshot(connection, 'services', lambda old: current, get_events) == 0
    assert save.call_args.args[3:5] == (current, [])
    connection.commit.assert_called_once()
    assert any('RELEASE_LOCK' in call.args[0] for call in cursor.execute.call_args_list)


@pytest.mark.parametrize('error', [pymysql.OperationalError(2013, 'lost'), KeyboardInterrupt(),
                                 snapshot.SnapshotError('partial')])
def test_interruption_before_commit_rolls_back_and_releases(monkeypatch, error):
    connection, cursor, save = protocol(monkeypatch)

    def fail(previous):
        raise error

    with pytest.raises(type(error)):
        collect_snapshot(connection, 'services', fail, get_events)
    connection.commit.assert_not_called()
    assert connection.rollback.call_count == 3
    save.assert_not_called()
    assert 'RELEASE_LOCK' in cursor.execute.call_args.args[0]


def test_database_write_failure_rolls_back(monkeypatch):
    connection, _, save = protocol(monkeypatch)
    save.side_effect = pymysql.IntegrityError(1452, 'foreign key')
    with pytest.raises(pymysql.IntegrityError):
        collect_snapshot(connection, 'services', lambda _: {}, get_events)
    connection.commit.assert_not_called()
    assert connection.rollback.call_count == 3


def test_overlapping_run_does_not_collect_or_write(monkeypatch):
    connection, cursor, save = protocol(monkeypatch, lock=0)
    collect = MagicMock()
    with pytest.raises(snapshot.CollectionBusy):
        collect_snapshot(connection, 'services', collect, get_events)
    collect.assert_not_called()
    save.assert_not_called()
    assert all('RELEASE_LOCK' not in call.args[0] for call in cursor.execute.call_args_list)


@pytest.mark.parametrize('kind', ['processes', 'services'])
def test_missing_identity_never_falls_back_to_system(monkeypatch, kind):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = ('APPLIED',)
    monkeypatch.setattr(snapshot, 'identity_schema_enabled', lambda _: True)
    identity = MagicMock(return_value=None)
    monkeypatch.setattr(snapshot, 'configured_identity', identity)
    with pytest.raises(IdentityError):
        snapshot.get_identity(connection, kind)
    identity.assert_called_once_with(cursor, kind)


def test_current_state_query_has_host_and_source_and_no_history_scan():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (20,)
    cursor.fetchall.return_value = [('example.service', '{"active_state":"active"}')]
    assert snapshot.get_previous(connection, 'services', IDENTITY)[1]
    assert cursor.execute.call_args.args[1] == (10, 20)
    assert 'service_state' in cursor.execute.call_args.args[0]
    assert 'events' not in str(cursor.execute.call_args_list)


def test_sender_and_all_identity_fields_are_bound_in_every_write():
    connection = MagicMock()
    identity = EventIdentity(1, 2, 3, 4)
    now = snapshot.utc_now()
    state = {'active_state': 'active'}
    snapshot.save_snapshot(connection, 'services', identity, {'x.service': state},
                           [('x.service', 'APPEARED', None, state)], now)
    cursor = connection.cursor.return_value.__enter__.return_value
    for call in cursor.executemany.call_args_list:
        assert call.args[1][0][:4] == (1, 2, 3, 4)
    assert all(not call.args[0].startswith(('CREATE', 'ALTER', 'DROP')) for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


@pytest.mark.parametrize('module,kind', [(services_main, 'services'), (processes_main, 'processes')])
@pytest.mark.parametrize('failure,exit_code', [(None, 0), (snapshot.CollectionBusy(), 75),
                                              (IdentityError(), 1), (pymysql.OperationalError(), 1)])
def test_cli_closes_connection_and_returns_failure(monkeypatch, failure, exit_code, module, kind):
    connection = MagicMock()
    monkeypatch.setattr(module, 'get_connection', lambda **kwargs: connection)
    collect = MagicMock(return_value=0, side_effect=failure)
    monkeypatch.setattr(module, 'collect_' + kind, collect)
    assert module.main([]) == exit_code
    connection.close.assert_called_once()
