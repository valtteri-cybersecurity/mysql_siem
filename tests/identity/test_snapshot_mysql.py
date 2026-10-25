"""Real transactions on the private socket-only MySQL fixture; mocked observations."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import patch
from uuid import uuid4

import pymysql
import pytest

from database import local_identity, migrate
from database.identity import (
    IdentityError,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from metrics import snapshot
from metrics.processes import main as processes_main
from metrics.processes.get import get_events as process_diff
from metrics.services import main as services_main
from metrics.services.get import get_events


def collect_snapshot(connection, kind, observe, diff):
    # Test adapter: run the same pre-refactor scenarios through main.py.
    if kind == 'services':
        with patch.object(services_main, 'get_services', observe), patch.object(services_main, 'get_events', diff):
            return services_main.collect_services(connection)
    with patch.object(processes_main, 'get_processes', observe), patch.object(processes_main, 'get_events', diff):
        return processes_main.collect_processes(connection)


@pytest.fixture(scope='module')
def snapshot_database(identity_server):
    connection = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4',
                                 autocommit=False, read_timeout=30, write_timeout=30,
                                 init_command="SET time_zone = '+00:00'")
    name = 'snapshots_' + uuid4().hex
    try:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE DATABASE `{name}` CHARACTER SET utf8mb4')
        connection.select_db(name)
        migrate.migrate(connection)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def mysql(snapshot_database):
    # Reuse the migrated schema, with FK-safe cleanup of this module's own
    # synthetic rows. Migration interruption tests still use empty_mysql.
    snapshot_database.rollback()
    with snapshot_database.cursor() as cursor:
        for table in ('service_events', 'service_state', 'process_events', 'process_state',
                      'collector_snapshots', 'collector_sources', 'log_sources', 'collectors', 'hosts'):
            cursor.execute(f'DELETE FROM {table}')
    snapshot_database.commit()
    try:
        yield snapshot_database
    finally:
        snapshot_database.rollback()


def service(active='inactive', enablement='disabled'):
    return {'description': 'Example', 'load_state': 'loaded', 'active_state': active,
            'sub_state': 'running' if active == 'active' else 'dead', 'unit_file_state': enablement}


def enroll(connection, monkeypatch, kind='services', host=None):
    with connection.cursor() as cursor:
        if host is None:
            host = register_host(cursor, 'same-name')
            cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
        cursor.execute('SELECT collector_id FROM collectors WHERE collector_name = %s', ('local.' + str(host),))
        found = cursor.fetchone()
        collector = found[0] if found else register_collector(cursor, 'local.' + str(host), enabled=True)
        source = register_source(cursor, host, kind, kind, enabled=True)
        approve_collector_source(cursor, collector, source)
    connection.commit()
    monkeypatch.setenv('SIEM_COLLECTOR_ID', str(collector))
    monkeypatch.setenv('SIEM_' + kind.upper() + '_SOURCE_ID', str(source))
    return host, source, collector


def rows(connection, table):
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT * FROM {table}')
        return cursor.fetchall()


def connect_like(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        database = cursor.fetchone()[0]
    return pymysql.connect(unix_socket=connection._sock.getpeername(), user='root',
                           database=database, autocommit=False,
                           read_timeout=10, write_timeout=10, init_command="SET time_zone = '+00:00'")


def test_baseline_events_two_hosts_and_history(mysql, monkeypatch):
    first = enroll(mysql, monkeypatch)
    assert collect_snapshot(mysql, 'services', lambda _: {'same.service': service('active')}, get_events) == 0
    second = enroll(mysql, monkeypatch)
    assert collect_snapshot(mysql, 'services', lambda _: {'same.service': service()}, get_events) == 0
    assert collect_snapshot(mysql, 'services', lambda _: {'same.service': service('active', 'enabled')}, get_events) == 1
    assert len(rows(mysql, 'service_state')) == 2
    history = rows(mysql, 'service_events')
    assert len(history) == 1
    assert history[0][1:4] == second
    assert first[0] != second[0]
    assert history[0][6] == 'STARTED'
    assert collect_snapshot(mysql, 'services', lambda _: {'same.service': service('failed')}, get_events) == 1
    assert collect_snapshot(mysql, 'services', lambda _: {'same.service': service('active')}, get_events) == 1
    assert collect_snapshot(mysql, 'services', lambda _: {}, get_events) == 1
    assert len(rows(mysql, 'service_events')) == 4
    assert len(rows(mysql, 'service_state')) == 1  # other host remains
    assert migrate.migrate(mysql) == []
    assert len(rows(mysql, 'service_events')) == 4


@pytest.mark.parametrize('target', ['source', 'host', 'collector', 'approval', 'wrong-type', 'missing'])
def test_invalid_or_disabled_identity_prevents_collection(mysql, monkeypatch, target):
    host, source, collector = enroll(mysql, monkeypatch)
    with mysql.cursor() as cursor:
        if target == 'source':
            cursor.execute('UPDATE log_sources SET enabled = FALSE WHERE source_id = %s', (source,))
        elif target == 'host':
            cursor.execute("UPDATE hosts SET enrollment_status = 'DISABLED' WHERE host_id = %s", (host,))
        elif target == 'collector':
            cursor.execute('UPDATE collectors SET enabled = FALSE WHERE collector_id = %s', (collector,))
        elif target == 'approval':
            cursor.execute('UPDATE collector_sources SET enabled = FALSE WHERE collector_id = %s', (collector,))
        elif target == 'wrong-type':
            cursor.execute("UPDATE log_sources SET source_type = 'system' WHERE source_id = %s", (source,))
        else:
            monkeypatch.delenv('SIEM_SERVICES_SOURCE_ID')
    mysql.commit()
    with pytest.raises(IdentityError):
        collect_snapshot(mysql, 'services', lambda _: pytest.fail('must not collect'), get_events)
    assert rows(mysql, 'service_state') == ()


@pytest.mark.parametrize('fault', ['write', 'interrupt', 'commit-lost-before', 'commit-lost-after'])
def test_snapshot_atomicity_and_uncertain_commit(mysql, monkeypatch, fault):
    enroll(mysql, monkeypatch)
    collect_snapshot(mysql, 'services', lambda _: {'x.service': service()}, get_events)
    original_save, original_commit = snapshot.save_snapshot, mysql.commit

    def fail_write(*args):
        original_save(*args)
        raise KeyboardInterrupt if fault == 'interrupt' else pymysql.OperationalError(2013, 'synthetic')

    def fail_commit():
        if fault == 'commit-lost-after':
            original_commit()
        raise pymysql.OperationalError(2013, 'synthetic commit acknowledgement lost')

    with monkeypatch.context() as patch:
        if fault in ('write', 'interrupt'):
            patch.setattr(snapshot, 'save_snapshot', fail_write)
        else:
            patch.setattr(mysql, 'commit', fail_commit)
        with pytest.raises((KeyboardInterrupt, pymysql.OperationalError)):
            collect_snapshot(mysql, 'services', lambda _: {'x.service': service('active')}, get_events)
    # A successful server commit stays successful even when acknowledgement was
    # lost. Retry reads current state and never duplicates its transition.
    expected = 1 if fault == 'commit-lost-after' else 0
    assert len(rows(mysql, 'service_events')) == expected
    assert collect_snapshot(mysql, 'services', lambda _: {'x.service': service('active')}, get_events) == 1 - expected
    assert len(rows(mysql, 'service_events')) == 1


def test_concurrent_collectors_use_separate_locks_but_overlap_is_rejected(mysql, monkeypatch):
    host, _, _ = enroll(mysql, monkeypatch)
    enroll(mysql, monkeypatch, 'processes', host)
    other = connect_like(mysql)
    started, finish = Event(), Event()

    def observe(previous):
        started.set()
        assert finish.wait(10)
        return {'same.service': service()}

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(collect_snapshot, other, 'services', observe, get_events)
            assert started.wait(10)
            try:
                with pytest.raises(snapshot.CollectionBusy):
                    collect_snapshot(mysql, 'services', lambda _: pytest.fail('overlap'), get_events)
                assert collect_snapshot(mysql, 'processes', lambda _: {}, process_diff) == 0
            finally:
                finish.set()
            assert pending.result(timeout=10) == 0
        assert len(rows(mysql, 'collector_snapshots')) == 2
    finally:
        other.close()


@pytest.mark.parametrize('version', ['018', '019'])
@pytest.mark.parametrize('fault', ['ddl-committed', 'process-exit'])
def test_new_migrations_resume_without_changing_history(empty_mysql, monkeypatch, version, fault):
    original = migrate.apply_one
    original(empty_mysql, '013')
    original(empty_mysql, '014')
    with empty_mysql.cursor() as cursor:
        cursor.execute("INSERT INTO hosts (administrative_name) VALUES ('keep-history')")
    empty_mysql.commit()
    history = rows(empty_mysql, 'hosts')

    def fail(connection, step):
        original(connection, step)
        if step == version:
            if fault == 'process-exit':
                raise SystemExit('synthetic exit after DDL')
            raise RuntimeError('synthetic interruption after DDL')

    with monkeypatch.context() as patch:
        patch.setattr(migrate, 'apply_one', fail)
        with pytest.raises((SystemExit, RuntimeError)):
            migrate.migrate(empty_mysql)
    assert rows(empty_mysql, 'hosts') == history
    assert migrate.migrate(empty_mysql) == (['018', '019'] if version == '018' else ['019'])
    assert migrate.migrate(empty_mysql) == []
    assert rows(empty_mysql, 'hosts') == history


@pytest.mark.parametrize('phase', ['ready', 'database_ready', 'prepared'])
@pytest.mark.parametrize('receipt_failure', [False, True])
def test_old_receipt_is_read_and_safely_extended(mysql, tmp_path, monkeypatch, phase, receipt_failure):
    # Build a real version-1 installation receipt using the old source set.
    receipt = tmp_path / 'receipt.json'
    kwargs = {'confirmed': True, 'auth_reader': 'reader', 'ufw_paths': [], 'auth_paths': []}
    old_keys = {kind: local_identity.LOCAL_KEYS[kind] for kind in local_identity.ORIGINAL_LOCAL_TYPES}
    with monkeypatch.context() as patch:
        patch.setattr(local_identity, 'LOCAL_KEYS', old_keys)
        old = local_identity.provision(mysql, receipt, {}, **kwargs)
    record = local_identity.read_receipt(receipt)
    record['phase'] = phase
    if phase == 'prepared':
        record['identity'] = {}
        record['host_id'] = None
    local_identity.save_receipt(receipt, record)
    original_save = local_identity.save_receipt

    def fail_publish(path, value):
        if len(value['identity']) > len(old):
            raise OSError('synthetic receipt disk failure')
        original_save(path, value)

    if receipt_failure:
        with monkeypatch.context() as patch:
            patch.setattr(local_identity, 'save_receipt', fail_publish)
            with pytest.raises(OSError):
                local_identity.provision(mysql, receipt, old if phase != 'prepared' else {}, **kwargs)
    result = local_identity.provision(mysql, receipt, old if phase != 'prepared' else {}, **kwargs)
    assert all(result[key] == value for key, value in old.items())
    assert set(result) == set(local_identity.LOCAL_KEYS.values()) | {local_identity.COLLECTOR_KEY}
    with mysql.cursor() as cursor:
        cursor.execute('SELECT COUNT(DISTINCT host_id), COUNT(*) FROM log_sources')
        assert cursor.fetchone() == (1, 7)
    assert local_identity.provision(mysql, receipt, result, **kwargs) == result
    assert json.loads(receipt.read_text())['identity'] == result


def test_both_cli_collectors_restore_real_mysql_state(mysql, monkeypatch):
    """Mock only Linux reads; exercise main, identity, diff, SQL and the next run."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from metrics.processes import get as process_get
    from metrics.services import get as service_get

    host, _, _ = enroll(mysql, monkeypatch)
    enroll(mysql, monkeypatch, 'processes', host)
    observed = {'active': 'inactive', 'name': 'worker', 'created': 1000.25, 'failure': False}

    def systemctl(arguments, **kwargs):
        if observed['failure']:
            return SimpleNamespace(returncode=1, stdout='', stderr='synthetic failure')
        if 'list-units' in arguments:
            output = 'example.service loaded inactive dead Example\n'
        elif 'list-unit-files' in arguments:
            output = 'example.service disabled -\n'
        else:
            output = ('Id=example.service\nNames=example.service\nDescription=Example\n'
                      'LoadState=loaded\nActiveState=' + observed['active'] + '\nSubState=dead\n')
        return SimpleNamespace(returncode=0, stdout=output, stderr='')

    def processes(*args, **kwargs):
        info = {'pid': 12, 'name': observed['name'], 'create_time': observed['created'],
                'username': 'synthetic', 'cpu_percent': 0, 'memory_percent': 1,
                'memory_info': SimpleNamespace(rss=1048576), 'status': 'running', 'exe': '/synthetic'}
        return [SimpleNamespace(pid=12, info=info)]

    monkeypatch.setattr(service_get.subprocess, 'run', systemctl)
    monkeypatch.setattr(process_get.psutil, 'pids', lambda: [12])
    monkeypatch.setattr(process_get.psutil, 'process_iter', MagicMock(side_effect=processes))
    monkeypatch.setattr(services_main, 'get_connection', lambda **kwargs: connect_like(mysql))
    monkeypatch.setattr(processes_main, 'get_connection', lambda **kwargs: connect_like(mysql))
    assert services_main.main([]) == processes_main.main([]) == 0
    mysql.rollback()
    assert not rows(mysql, 'service_events') and not rows(mysql, 'process_events')
    observed.update(active='active', name='renamed')
    assert services_main.main([]) == processes_main.main([]) == 0
    mysql.rollback()
    assert rows(mysql, 'service_events')[0][6] == 'STARTED'
    assert rows(mysql, 'process_events')[0][6] == 'CHANGED'
    observed['created'] = 2000.5
    assert processes_main.main([]) == 0
    mysql.rollback()
    assert {row[6] for row in rows(mysql, 'process_events')} == {'CHANGED', 'STARTED', 'STOPPED'}
    assert len(rows(mysql, 'process_state')) == 1
    before = rows(mysql, 'service_state')
    observed['failure'] = True
    assert services_main.main([]) == 1
    mysql.rollback()
    assert rows(mysql, 'service_state') == before
