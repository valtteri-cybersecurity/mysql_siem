from unittest.mock import ANY, MagicMock, patch

import pymysql
import pytest

from database.identity import EventIdentity, IdentityError
from metrics import collector_health, snapshot
from metrics.processes import main as processes_main
from metrics.processes import windows
from metrics.processes.get import BootIdentityError
from metrics.services import main as services_main
from metrics.services import windows as service_windows
from metrics.services.get import get_events

BOOT_ID = '5a9a2c37-3d94-455e-97cf-c20d4d8b1040'
OTHER_BOOT_ID = '5b9a2c37-3d94-455e-97cf-c20d4d8b1040'


def collect_snapshot(connection, kind, observe, diff):
    # Test adapter: run the same pre-refactor scenarios through main.py.
    if kind == 'services':
        with (patch.object(services_main, 'get_services', lambda previous, **_: observe(previous)),
              patch.object(services_main, 'get_events', diff)):
            return services_main.collect_services(connection)
    with (patch.object(processes_main, 'read_boot_id', return_value=BOOT_ID),
          patch.object(processes_main, 'get_processes', lambda previous, **_: observe(previous)),
          patch.object(processes_main, 'get_events', diff)):
        return processes_main.collect_processes(connection)


IDENTITY = EventIdentity(10, 20, 30)


def protocol(monkeypatch, *, baseline=False, lock=1):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [('synthetic',), (lock,), (1,)]
    monkeypatch.setattr(snapshot, 'get_identity', lambda *args: IDENTITY)
    monkeypatch.setattr(snapshot, 'get_previous', lambda *args: ({}, baseline))
    monkeypatch.setattr(collector_health.Attempt, 'bind', MagicMock())
    monkeypatch.setattr(collector_health.Attempt, 'write', MagicMock())
    monkeypatch.setattr(windows, 'save_window', MagicMock(return_value=True))
    monkeypatch.setattr(service_windows, 'save_window', MagicMock(return_value=True))
    save = MagicMock()
    monkeypatch.setattr(snapshot, 'save_snapshot', save)
    return connection, cursor, save


def test_first_baseline_commits_state_without_started_events(monkeypatch):
    connection, cursor, save = protocol(monkeypatch)
    current = {'example.service': {'active_state': 'active'}}
    assert collect_snapshot(connection, 'services', lambda old: current, get_events) == 0
    assert save.call_args.args[3:6] == ({}, current, [])
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
    assert cursor.execute.call_args.args[1] == (10, 20, 4097)
    assert 'service_state' in cursor.execute.call_args.args[0]
    assert 'events' not in str(cursor.execute.call_args_list)


def test_process_boot_checkpoint_from_another_source_cannot_be_reused():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (21, BOOT_ID)
    with pytest.raises(IdentityError, match='different source'):
        snapshot.get_previous(connection, 'processes', IDENTITY)
    cursor.execute.assert_called_once()
    sql, scope = cursor.execute.call_args.args
    assert 'source_id, process_boot_id' in sql
    assert scope == (10, 'processes')
    cursor.fetchall.assert_not_called()


@pytest.mark.parametrize('checkpoint', [None, (20, None), (20, OTHER_BOOT_ID), (20, BOOT_ID)])
def test_process_baseline_uses_only_observations_from_the_same_boot(monkeypatch, capsys, checkpoint):
    connection, _, save = protocol(monkeypatch)
    previous = {}
    if checkpoint is not None:
        previous = {'old': {'pid': 12}}
    current = {'current': {'pid': 12}}
    events = [('current', 'STARTED', None, current['current'])]
    observe = MagicMock(return_value=current)
    diff = MagicMock(return_value=events)
    monkeypatch.setattr(snapshot, 'get_previous', lambda *args: (previous, checkpoint))
    monkeypatch.setattr(processes_main, 'read_boot_id', lambda: BOOT_ID)
    monkeypatch.setattr(processes_main, 'get_processes', observe)
    monkeypatch.setattr(processes_main, 'get_events', diff)

    count = processes_main.collect_processes(connection)
    connection.commit.assert_called_once()
    if checkpoint == (20, BOOT_ID):
        assert count == 1
        observe.assert_called_once_with(previous, boot_id=BOOT_ID, coverage=ANY, measurements=ANY)
        diff.assert_called_once_with(current, previous)
        assert save.call_args.args[3:6] == (previous, current, events)
        assert save.call_args.kwargs == {'process_boot_id': None}
    else:
        assert count == 0
        observe.assert_called_once_with({}, boot_id=BOOT_ID, coverage=ANY, measurements=ANY)
        diff.assert_not_called()
        assert save.call_args.args[3:6] == (previous, current, [])
        assert save.call_args.kwargs == {'process_boot_id': BOOT_ID}
    output = capsys.readouterr().out
    if checkpoint == (20, None):
        assert 'previous boot ID was unknown' in output
    if checkpoint == (20, OTHER_BOOT_ID):
        assert 'detected a new Linux boot' in output


@pytest.mark.parametrize('values', [(BootIdentityError('missing'),), (BOOT_ID, OTHER_BOOT_ID),
                                    (BOOT_ID, BootIdentityError('unreadable'))])
def test_process_boot_read_failure_or_change_blocks_checkpoint(monkeypatch, values):
    connection, cursor, save = protocol(monkeypatch, baseline=None)
    monkeypatch.setattr(processes_main, 'read_boot_id', MagicMock(side_effect=values))
    monkeypatch.setattr(processes_main, 'get_processes', MagicMock(return_value={'new': {'pid': 12}}))
    with pytest.raises(BootIdentityError):
        processes_main.collect_processes(connection)
    save.assert_not_called()
    connection.commit.assert_not_called()
    assert connection.rollback.call_count == 3
    assert 'RELEASE_LOCK' in cursor.execute.call_args.args[0]


def test_sender_and_all_identity_fields_are_bound_in_every_write():
    connection = MagicMock()
    identity = EventIdentity(1, 2, 3, 4)
    now = snapshot.utc_now()
    state = {'active_state': 'active'}
    snapshot.save_snapshot(connection, 'services', identity, {}, {'x.service': state},
                           [('x.service', 'APPEARED', None, state)], now)
    cursor = connection.cursor.return_value.__enter__.return_value
    for call in cursor.executemany.call_args_list:
        assert call.args[1][0][:4] == (1, 2, 3, 4)
    assert all(not call.args[0].startswith(('CREATE', 'ALTER', 'DROP')) for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


@pytest.mark.parametrize('kind', ['processes', 'services'])
def test_unchanged_snapshot_only_writes_completion_marker(kind):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    previous = {'a': {'measurement': 1}, 'b': {'measurement': None}, 'c': {'measurement': 3}}
    current = {'c': {'measurement': 3}, 'b': {'measurement': None}, 'a': {'measurement': 1}}
    now = snapshot.utc_now()
    snapshot.save_snapshot(connection, kind, IDENTITY, previous, current, [], now)

    cursor.executemany.assert_not_called()
    cursor.execute.assert_called_once()
    sql, values = cursor.execute.call_args.args
    assert sql.startswith('INSERT INTO collector_snapshots ')
    assert values == (10, kind, 20, 30, None, now)
    assert 'process_boot_id' not in sql


def test_changed_boot_is_bound_in_the_checkpoint_statement():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    now = snapshot.utc_now()
    snapshot.save_snapshot(connection, 'processes', IDENTITY, {}, {}, [], now, process_boot_id=BOOT_ID)
    cursor.execute.assert_called_once()
    sql, values = cursor.execute.call_args.args
    assert 'process_boot_id = VALUES(process_boot_id)' in sql
    assert BOOT_ID not in sql
    assert values == (10, 'processes', 20, 30, None, now, BOOT_ID)


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


def test_changed_and_removed_rows_use_bounded_source_scoped_batches(monkeypatch):
    monkeypatch.setattr(snapshot, 'STATE_BATCH_ROWS', 2)
    cursor = MagicMock()
    observed_at = snapshot.utc_now()
    delta = {'added': {}, 'changed': {}, 'removed': {}, 'unchanged': {}}
    for name in ('a.service', 'b.service', 'c.service'):
        delta['changed'][name] = ({}, {'active_state': 'active'})
    for name in ('d.service', 'e.service', 'f.service'):
        delta['removed'][name] = {}
    snapshot.save_state_delta(cursor, 'service_state', 'service_name', IDENTITY, delta, observed_at)
    first, second, third, fourth = cursor.execute.call_args_list
    assert 'CASE service_name WHEN %s THEN %s WHEN %s THEN %s' in first.args[0]
    assert first.args[1][-4:] == [10, 20, 'a.service', 'b.service']
    assert second.args[1][-3:] == [10, 20, 'c.service']
    assert third.args[1] == (10, 20, 'd.service', 'e.service')
    assert fourth.args[1] == (10, 20, 'f.service')
    for statement in (first, second, third, fourth):
        assert 'WHERE host_id = %s AND source_id = %s' in statement.args[0]


def test_update_batch_has_a_serialized_byte_limit(monkeypatch):
    monkeypatch.setattr(snapshot, 'STATE_BATCH_BYTES', 110)
    cursor = MagicMock()
    delta = {'added': {}, 'changed': {'a.service': ({}, {'name': 'a' * 20}),
                                    'b.service': ({}, {'name': 'b' * 20})}, 'removed': {}}
    snapshot.save_state_delta(cursor, 'service_state', 'service_name', IDENTITY, delta, snapshot.utc_now())
    assert cursor.execute.call_count == 2
