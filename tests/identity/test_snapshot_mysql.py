"""Real transactions on the private socket-only MySQL fixture; mocked observations."""

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier, Event
from unittest.mock import patch
from uuid import uuid4

import pymysql
import pytest

from config.reset_installation import RUNTIME_TABLE_PRIVILEGES
from config.snapshot_policy import retention_policy
from database import local_identity, migrate
from database.identity import (
    EventIdentity,
    IdentityError,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from metrics import collector_health, snapshot, snapshot_retention
from metrics.processes import executable, windows
from metrics.processes import main as processes_main
from metrics.processes.get import get_events as process_diff
from metrics.processes.get import process_key
from metrics.services import main as services_main
from metrics.services import windows as service_windows
from metrics.services.get import get_events

BOOT_ID = '5a9a2c37-3d94-455e-97cf-c20d4d8b1040'
OTHER_BOOT_ID = '5b9a2c37-3d94-455e-97cf-c20d4d8b1040'


@pytest.fixture(autouse=True)
def mock_process_environment(monkeypatch):
    monkeypatch.setattr(processes_main, 'read_boot_id', lambda: BOOT_ID)

    def missing_executable(_):
        raise FileNotFoundError()

    monkeypatch.setattr(executable, 'read_executable', missing_executable)


def collect_snapshot(connection, kind, observe, diff):
    # Test adapter: run the same pre-refactor scenarios through main.py.
    if kind == 'services':
        with (patch.object(services_main, 'get_services', lambda previous, **_: observe(previous)),
              patch.object(services_main, 'get_events', diff)):
            return services_main.collect_services(connection)
    with (patch.object(processes_main, 'get_processes', lambda previous, **_: observe(previous)),
          patch.object(processes_main, 'get_events', diff)):
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
                      'collector_snapshots', 'collector_health', 'process_measurement_windows', 'service_measurement_windows',
                      'collector_sources', 'log_sources', 'collectors', 'hosts'):
            cursor.execute(f'DELETE FROM {table}')
    snapshot_database.commit()
    try:
        yield snapshot_database
    finally:
        snapshot_database.rollback()


def service(active='inactive', enablement='disabled'):
    return {'description': 'Example', 'load_state': 'loaded', 'active_state': active,
            'sub_state': 'running' if active == 'active' else 'dead', 'unit_file_state': enablement}


def process(pid):
    return {'pid': pid, 'process_name': 'worker', 'username': 'synthetic', 'status': 'running',
            'executable_path': '/synthetic', 'start_time': '1970-01-01T00:16:40+00:00',
            'cpu_percent': 1.0, 'memory_percent': 2.0, 'memory_mb': 3.0}


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


def checkpoint_times(connection):
    checkpoints = {}
    for row in rows(connection, 'collector_snapshots'):
        checkpoints[row[0]] = row[5]
    return checkpoints


def health_record(connection, host, kind):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute('SELECT * FROM collector_health WHERE host_id = %s AND collector_type = %s', (host, kind))
        return cursor.fetchone()


@pytest.mark.parametrize('kind', ['processes', 'services'])
def test_health_recovers_without_extra_history_or_late_skip(mysql, monkeypatch, kind):
    host, source, collector = enroll(mysql, monkeypatch, kind)
    if kind == 'processes':
        key, item, diff = process_key(BOOT_ID, 12, 1000.0), process(12), process_diff
    else:
        key, item, diff = 'x.service', service(), get_events
    current = {key: item}
    assert collect_snapshot(mysql, kind, lambda _: current, diff) == 0
    initial = health_record(mysql, host, kind)
    assert initial['status'] == 'SUCCESS'
    assert initial['observed_count'] == initial['added_count'] == 1
    assert collect_snapshot(mysql, kind, lambda _: current, diff) == 0
    unchanged = health_record(mysql, host, kind)
    assert unchanged['added_count'] == unchanged['changed_count'] == unchanged['removed_count'] == 0
    assert unchanged['unchanged_count'] == 1
    assert unchanged['transitions'] == initial['transitions']
    completed = checkpoint_times(mysql)
    late_skip = collector_health.Attempt(kind)
    late_skip.bind(mysql, EventIdentity(host, source, collector))

    def failed(_):
        raise PermissionError('synthetic secret path and arguments')

    for count in (1, 2):
        with pytest.raises(PermissionError, match='synthetic secret'):
            collect_snapshot(mysql, kind, failed, diff)
        health = health_record(mysql, host, kind)
        assert health['status'] == 'FAILED' and health['error_code'] == 'PERMISSION_DENIED'
        assert health['consecutive_failures'] == count
        assert 'synthetic secret' not in str(health)
        assert health['observed_count'] is None and health['removed_count'] is None
        assert checkpoint_times(mysql) == completed

    assert collect_snapshot(mysql, kind, lambda _: current, diff) == 0
    recovered = health_record(mysql, host, kind)
    assert recovered['status'] == 'SUCCESS' and recovered['consecutive_failures'] == 0
    history = json.loads(recovered['transitions'])
    assert [history[0]['status'], history[1]['status'], history[2]['status']] == ['SUCCESS', 'FAILED', 'SUCCESS']
    mysql.begin()
    late_skip.write(mysql, 'SKIPPED', 'COLLECTION_BUSY')
    mysql.commit()
    assert health_record(mysql, host, kind) == recovered


def test_partial_process_attempt_never_replaces_the_complete_snapshot(mysql, monkeypatch):
    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    key = process_key(BOOT_ID, 12, 1000.0)
    baseline = {key: process(12)}
    assert collect_snapshot(mysql, 'processes', lambda _: baseline, process_diff) == 0
    original_state = rows(mysql, 'process_state')
    original_checkpoint = checkpoint_times(mysql)

    def partial(previous, *, boot_id, coverage, measurements):
        assert previous == baseline and boot_id == BOOT_ID
        coverage.update(visible_pid_count=2, observed_count=1, incomplete_process_count=1,
                        unverified_identity_count=1)
        return {process_key(BOOT_ID, 13, 1000.0): process(13)}

    monkeypatch.setattr(processes_main, 'get_processes', partial)
    with pytest.raises(snapshot.ObservationError, match='Process inventory incomplete'):
        processes_main.collect_processes(mysql)
    health = health_record(mysql, host, 'processes')
    assert health['status'] == 'PARTIAL' and health['error_code'] == 'INCOMPLETE_OBSERVATION'
    assert health['observed_count'] == 1 and health['removed_count'] is None
    assert json.loads(health['coverage'])['unverified_identity_count'] == 1
    assert rows(mysql, 'process_state') == original_state
    assert rows(mysql, 'process_events') == ()
    assert checkpoint_times(mysql) == original_checkpoint


def connect_like(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        database = cursor.fetchone()[0]
    return pymysql.connect(unix_socket=connection._sock.getpeername(), user='root',
                           database=database, autocommit=False,
                           read_timeout=10, write_timeout=10, init_command="SET time_zone = '+00:00'")


@pytest.fixture
def snapshot_runtime(mysql):
    user = 'snapshot_' + uuid4().hex[:16]
    password = uuid4().hex
    tables = ('process_state', 'service_state', 'process_events', 'service_events', 'collector_snapshots',
              'collector_health', 'process_measurement_windows', 'service_measurement_windows',
              'schema_migrations', 'hosts', 'log_sources', 'collectors', 'collector_sources')
    with mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        cursor.execute("CREATE USER %s@'localhost' IDENTIFIED BY %s", (user, password))
    try:
        with mysql.cursor() as cursor:
            for table in tables:
                privileges = RUNTIME_TABLE_PRIVILEGES[table]
                cursor.execute(f"GRANT {privileges} ON `{database}`.`{table}` TO %s@'localhost'", (user,))
        runtime = pymysql.connect(unix_socket=mysql._sock.getpeername(), user=user, password=password,
                                  database=database, autocommit=False, read_timeout=10, write_timeout=10)
        try:
            yield runtime
        finally:
            if runtime.open:
                runtime.close()
    finally:
        with mysql.cursor() as cursor:
            cursor.execute("DROP USER %s@'localhost'", (user,))


@pytest.mark.parametrize('kind,table,history,expected_events', [
    ('processes', 'process_state', 'process_events', ('STOPPED', 'CHANGED', 'STARTED')),
    ('services', 'service_state', 'service_events', ('REMOVED', 'STARTED', 'APPEARED')),
])
def test_mixed_delta_and_row_timestamps_with_runtime_grants(
        mysql, snapshot_runtime, monkeypatch, kind, table, history, expected_events):
    if kind == 'processes':
        removed = process_key(BOOT_ID, 1, 1000.0)
        changed = process_key(BOOT_ID, 2, 1000.0)
        added = process_key(BOOT_ID, 3, 1000.0)
        unchanged = process_key(BOOT_ID, 4, 1000.0)
        previous = {removed: process(1), changed: process(2), unchanged: process(4)}
        current = {added: process(3), changed: {**process(2), 'status': 'sleeping'}, unchanged: process(4)}
        diff = process_diff
    else:
        removed, changed, added, unchanged = 'a.service', 'b.service', 'c.service', 'd.service'
        previous = {removed: service(), changed: service(), unchanged: service()}
        current = {added: service(), changed: service('active'), unchanged: service()}
        diff = get_events

    first = enroll(mysql, monkeypatch, kind)
    runtime = snapshot_runtime
    baseline = datetime(2026, 11, 16, 12, 0, 0, 123456)
    rechecked = baseline + timedelta(seconds=1)
    updated = baseline + timedelta(seconds=2)
    times = iter((baseline, baseline, rechecked, updated))
    monkeypatch.setattr(snapshot, 'utc_now', lambda: next(times))
    assert collect_snapshot(runtime, kind, lambda _: previous, diff) == 0
    with monkeypatch.context() as second_host:
        second = enroll(mysql, second_host, kind)
        assert collect_snapshot(runtime, kind, lambda _: previous, diff) == 0
    before = sorted(rows(runtime, table))
    assert rows(runtime, history) == ()
    assert collect_snapshot(runtime, kind, lambda _: previous, diff) == 0
    assert sorted(rows(runtime, table)) == before
    assert rows(runtime, history) == ()
    assert checkpoint_times(runtime) == {first[0]: rechecked, second[0]: baseline}

    assert collect_snapshot(runtime, kind, lambda _: current, diff) == 3
    own = {}
    other = []
    for row in rows(runtime, table):
        if row[0] == first[0]:
            assert row[:3] == first
            own[row[4]] = (json.loads(row[5]), row[6])
        else:
            other.append(row)
    assert own == {added: (current[added], updated), changed: (current[changed], updated),
                   unchanged: (previous[unchanged], baseline)}
    other_before = []
    for row in before:
        if row[0] == second[0]:
            other_before.append(row)
    assert sorted(other) == other_before
    expected = [(removed, expected_events[0], previous[removed], None),
                (changed, expected_events[1], previous[changed], current[changed]),
                (added, expected_events[2], None, current[added])]
    events = []
    for row in sorted(rows(runtime, history)):
        assert row[1:4] == first
        assert row[7] == updated
        events.append((row[5], row[6], json.loads(row[8] or 'null'), json.loads(row[9] or 'null')))
    assert events == sorted(expected)
    assert checkpoint_times(runtime) == {first[0]: updated, second[0]: baseline}


@pytest.mark.parametrize('field,value', [('cpu_percent', 5.0), ('memory_percent', 8.0),
                                        ('memory_mb', 7.0), ('cpu_percent', None), ('memory_mb', None)])
def test_process_measurement_only_refreshes_state_without_an_event(mysql, monkeypatch, field, value):
    enroll(mysql, monkeypatch, 'processes')
    key = process_key(BOOT_ID, 1, 1000.0)
    before = process(1)
    after = {**before, field: value}
    assert collect_snapshot(mysql, 'processes', lambda _: {key: before}, process_diff) == 0
    assert collect_snapshot(mysql, 'processes', lambda _: {key: after}, process_diff) == 0
    assert json.loads(rows(mysql, 'process_state')[0][5]) == after
    assert rows(mysql, 'process_events') == ()


def test_service_security_metadata_delta_and_rollback_on_mysql(mysql, monkeypatch):
    from types import SimpleNamespace

    from metrics.services import get as service_get

    host, _, _ = enroll(mysql, monkeypatch)
    name = 'example.service'
    tick = datetime(2026, 11, 16, 12, 0) - timedelta(seconds=1)
    monkeypatch.setattr(snapshot, 'utc_now', lambda: tick)
    assert collect_snapshot(mysql, 'services', lambda _: {name: service('active', 'enabled')}, get_events) == 0
    settings = {'pid': 241, 'user': 'worker', 'drop_in': '/etc/systemd/system/example.service.d/10.conf'}

    def systemctl(args, **_kwargs):
        if 'list-units' in args:
            output = 'example.service loaded active running Example\n'
        elif 'list-unit-files' in args:
            output = 'example.service enabled enabled\n'
        else:
            for argument in args:
                assert 'ExecStart' not in argument
            output = ('Id=example.service\nNames=example.service\nDescription=Example\nLoadState=loaded\n'
                      'ActiveState=active\nSubState=running\nGroup=\nFragmentPath=/run/systemd/generator/example.service\n'
                      f'MainPID={settings["pid"]}\nDropInPaths={settings["drop_in"]}\n')
            if settings['user'] is not None:
                output += f'User={settings["user"]}\n'
            output += '\n'
        return SimpleNamespace(returncode=0, stdout=output, stderr='')

    monkeypatch.setattr(service_get, 'bounded_output', systemctl)
    tick += timedelta(seconds=1)
    assert services_main.collect_services(mysql) == 0
    initial, = rows(mysql, 'service_state')
    assert json.loads(initial[5])['configured_user'] == 'worker'
    assert json.loads(initial[5])['configured_group'] == ''
    assert json.loads(initial[5])['main_pid'] == 241
    tick += timedelta(seconds=1)
    assert services_main.collect_services(mysql) == 0
    assert rows(mysql, 'service_state') == (initial,)
    assert checkpoint_times(mysql)[host] == tick

    settings['pid'] = 342
    tick += timedelta(seconds=1)
    assert services_main.collect_services(mysql) == 0
    runtime, = rows(mysql, 'service_state')
    assert runtime[4] == name and runtime[6] == tick
    assert json.loads(runtime[5])['main_pid'] == 342

    settings['user'] = None
    tick += timedelta(seconds=1)
    assert services_main.collect_services(mysql) == 0
    gap_row, = rows(mysql, 'service_state')
    gap = json.loads(gap_row[5])
    assert gap['configured_user'] is None
    assert gap['last_known_config'] == {'configured_user': 'worker'}
    checkpoint = rows(mysql, 'collector_snapshots')

    settings['user'] = 'other'
    settings['drop_in'] = '/etc/systemd/system/example.service.d/20.conf'
    tick += timedelta(seconds=1)
    finish = snapshot.save_checkpoint

    def fail_checkpoint(*args):
        finish(*args)
        raise pymysql.IntegrityError(1451, 'synthetic write failure')

    with monkeypatch.context() as fault:
        fault.setattr(snapshot, 'save_checkpoint', fail_checkpoint)
        with pytest.raises(pymysql.IntegrityError):
            services_main.collect_services(mysql)
    assert rows(mysql, 'service_state') == (gap_row,)
    assert rows(mysql, 'collector_snapshots') == checkpoint
    assert rows(mysql, 'service_events') == ()

    assert services_main.collect_services(mysql) == 1
    changed_row, = rows(mysql, 'service_state')
    changed = json.loads(changed_row[5])
    assert changed['configured_user'] == 'other'
    assert changed['drop_in_paths'] == [settings['drop_in']]
    assert 'last_known_config' not in changed
    event, = rows(mysql, 'service_events')
    assert event[5:7] == (name, 'CHANGED')
    assert json.loads(event[8]) == gap and json.loads(event[9]) == changed
    assert services_main.collect_services(mysql) == 0
    assert rows(mysql, 'service_events') == (event,)


def test_process_executable_delta_and_rollback_on_mysql(mysql, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from metrics.processes import get as process_get

    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    key = process_key(BOOT_ID, 12, 1000.0)
    path = '/synthetic/worker'
    info = {'pid': 12, 'name': 'worker', 'create_time': 1000.0, 'username': 'synthetic', 'ppid': 0,
            'status': 'running', 'memory_percent': 1, 'memory_info': SimpleNamespace(rss=1048576), 'exe': path,
            'uids': SimpleNamespace(real=1000, effective=0), 'gids': SimpleNamespace(real=100, effective=0)}
    observed = SimpleNamespace(pid=12, info=info, cpu_percent=Mock(return_value=0.0),
                               is_running=Mock(return_value=True), ppid=Mock(return_value=0))
    metadata = {'executable_path': path, 'executable_device': 2049, 'executable_inode': 100, 'executable_uid': 0,
                'executable_gid': 5, 'executable_mode': stat.S_IFREG | 0o755, 'executable_size': 8192,
                'executable_mtime_ns': 1777777777123456789, 'executable_deleted': False,
                'executable_identity_status': 'VERIFIED'}
    observation = Mock(return_value=metadata)
    monkeypatch.setattr(executable, 'read_executable', observation)
    monkeypatch.setattr(process_get.psutil, 'pids', lambda: [12])
    monkeypatch.setattr(process_get.psutil, 'process_iter', Mock(return_value=[observed]))
    tick = datetime(2026, 11, 16, 12, 0)
    monkeypatch.setattr(snapshot, 'utc_now', lambda: tick)

    assert processes_main.collect_processes(mysql) == 0
    initial, = rows(mysql, 'process_state')
    state = json.loads(initial[5])
    assert state['executable_inode'] == 100
    assert state['executable_uid'] == 0 and state['uid'] == 1000 and state['euid'] == 0
    assert state['parent_identity_status'] == 'NO_PARENT'
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    assert rows(mysql, 'process_state') == (initial,)
    assert checkpoint_times(mysql)[host] == tick

    observation.side_effect = PermissionError()
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    gap_row, = rows(mysql, 'process_state')
    gap = json.loads(gap_row[5])
    assert gap['executable_identity_status'] == 'PATH_ONLY'
    assert gap['executable_inode'] is None
    assert gap['last_known_executable'] == metadata
    checkpoint = rows(mysql, 'collector_snapshots')

    observation.side_effect = None
    observation.return_value = {**metadata, 'executable_inode': 200}
    tick += timedelta(seconds=1)
    finish = snapshot.save_checkpoint

    def fail_checkpoint(*args):
        finish(*args)
        raise pymysql.IntegrityError(1451, 'synthetic write failure')

    with monkeypatch.context() as fault:
        fault.setattr(snapshot, 'save_checkpoint', fail_checkpoint)
        with pytest.raises(pymysql.IntegrityError):
            processes_main.collect_processes(mysql)
    assert rows(mysql, 'process_state') == (gap_row,)
    assert rows(mysql, 'collector_snapshots') == checkpoint
    assert rows(mysql, 'process_events') == ()

    assert processes_main.collect_processes(mysql) == 1
    changed_row, = rows(mysql, 'process_state')
    changed = json.loads(changed_row[5])
    event, = rows(mysql, 'process_events')
    assert changed_row[4] == key
    assert event[5:7] == (key, 'CHANGED')
    assert json.loads(event[8]) == gap
    assert json.loads(event[9]) == changed
    assert changed['executable_path'] == path and changed['executable_inode'] == 200

    observation.return_value = {**observation.return_value, 'executable_size': 12288, 'executable_mtime_ns': 8}
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    latest, = rows(mysql, 'process_state')
    assert json.loads(latest[5])['executable_size'] == 12288 and latest[6] == tick
    assert rows(mysql, 'process_events') == (event,)
    assert rows(mysql, 'collector_snapshots')[0][6] == BOOT_ID


def test_process_credentials_preserve_history_and_unchanged_rows_on_mysql(mysql, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from metrics.processes import get as process_get

    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    key = process_key(BOOT_ID, 12, 1000.0)
    uids = SimpleNamespace(real=1000, effective=0, saved=1000)
    info = {'pid': 12, 'name': 'worker', 'create_time': 1000.0, 'username': 'synthetic', 'ppid': 0,
            'status': 'running', 'memory_percent': 1, 'memory_info': SimpleNamespace(rss=1048576),
            'exe': '/synthetic', 'uids': uids, 'gids': SimpleNamespace(real=100, effective=0, saved=100)}
    observed = SimpleNamespace(pid=12, info=info, cpu_percent=Mock(return_value=0.0),
                               is_running=Mock(return_value=True), ppid=Mock(return_value=0))
    monkeypatch.setattr(process_get.psutil, 'pids', lambda: [12])
    monkeypatch.setattr(process_get.psutil, 'process_iter', Mock(return_value=[observed]))
    tick = datetime(2026, 11, 16, 12, 0)
    monkeypatch.setattr(snapshot, 'utc_now', lambda: tick)

    assert processes_main.collect_processes(mysql) == 0
    first, = rows(mysql, 'process_state')
    original = json.loads(first[5])
    assert (original['uid'], original['euid'], original['gid'], original['egid']) == (1000, 0, 100, 0)
    assert original['parent_identity_status'] == 'NO_PARENT'
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    assert rows(mysql, 'process_state') == (first,)
    assert checkpoint_times(mysql)[host] == tick

    info['uids'] = None
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    unavailable_row, = rows(mysql, 'process_state')
    unavailable = json.loads(unavailable_row[5])
    assert unavailable['uid'] is None and unavailable['euid'] is None
    assert unavailable['egid'] == 0
    assert unavailable['last_known_credentials'] == {'uid': 1000, 'euid': 0}
    assert unavailable['username'] == 'synthetic'
    assert rows(mysql, 'process_events') == ()
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    assert rows(mysql, 'process_state') == (unavailable_row,)
    assert checkpoint_times(mysql)[host] == tick

    info['uids'] = SimpleNamespace(real=1000, effective=1000)
    info['gids'] = SimpleNamespace(real=100, effective=100)
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 1
    changed_row, = rows(mysql, 'process_state')
    changed = json.loads(changed_row[5])
    assert changed_row[4] == key and changed_row[6] == tick
    assert changed['euid'] == 1000 and changed['egid'] == 100
    assert 'last_known_credentials' not in changed
    assert changed['parent_identity_status'] == original['parent_identity_status']
    event, = rows(mysql, 'process_events')
    assert event[5:7] == (key, 'CHANGED')
    assert json.loads(event[8]) == unavailable
    assert json.loads(event[9]) == changed
    assert processes_main.collect_processes(mysql) == 0
    assert rows(mysql, 'process_events') == (event,)
    assert rows(mysql, 'collector_snapshots')[0][6] == BOOT_ID

    tick += timedelta(seconds=1)
    info['name'] = None
    info['gids'] = SimpleNamespace(real=100, effective=101)
    assert processes_main.collect_processes(mysql) == 1
    partial_row, = rows(mysql, 'process_state')
    partial = json.loads(partial_row[5])
    assert partial_row[4] == key
    assert partial['process_name'] == changed['process_name']
    assert partial['egid'] == 101
    assert len(rows(mysql, 'process_events')) == 2
    health = health_record(mysql, host, 'processes')
    assert health['status'] == 'SUCCESS' and health['observed_count'] == 1
    coverage = json.loads(health['coverage'])
    assert coverage['partial_metadata_count'] == 1 and coverage['incomplete_process_count'] == 0


def test_process_parent_availability_and_reparenting_on_mysql(mysql, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    import psutil

    from metrics.processes import get as process_get

    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    settings = {'ppid': 7, 'denied': False}
    now = datetime(2026, 11, 16, 12, 0)
    tick = now

    def processes(*_args, **_kwargs):
        result = []
        for pid, created in ((7, 900.0), (8, 950.0), (12, 1000.0)):
            ppid = 0
            if pid == 12:
                ppid = settings['ppid']
            info = {'pid': pid, 'ppid': ppid, 'name': 'worker', 'create_time': created,
                    'username': 'synthetic', 'memory_percent': 1, 'status': 'running',
                    'memory_info': SimpleNamespace(rss=1048576), 'exe': '/synthetic'}
            parent_status = Mock(return_value='running')
            if pid == 7 and settings['denied']:
                parent_status.side_effect = psutil.AccessDenied(7)
            result.append(SimpleNamespace(pid=pid, info=info, cpu_percent=Mock(return_value=0.0),
                                          is_running=Mock(return_value=True), ppid=Mock(return_value=ppid),
                                          status=parent_status))
        return result

    def child_state():
        with mysql.cursor() as cursor:
            cursor.execute('SELECT state, observed_at FROM process_state WHERE host_id = %s AND process_key = %s',
                           (host, key))
            data, timestamp = cursor.fetchone()
        return json.loads(data), timestamp

    monkeypatch.setattr(process_get.psutil, 'pids', lambda: [7, 8, 12])
    monkeypatch.setattr(process_get.psutil, 'process_iter', Mock(side_effect=processes))
    monkeypatch.setattr(snapshot, 'utc_now', lambda: tick)
    key = process_key(BOOT_ID, 12, 1000.0)
    first_parent = process_key(BOOT_ID, 7, 900.0)
    second_parent = process_key(BOOT_ID, 8, 950.0)
    assert processes_main.collect_processes(mysql) == 0
    first, _ = child_state()
    assert first['parent_process_key'] == first_parent
    assert first['parent_identity_status'] == 'VERIFIED'

    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    assert child_state() == (first, now)
    assert checkpoint_times(mysql)[host] == tick

    settings['denied'] = True
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    unavailable, unavailable_at = child_state()
    assert unavailable['ppid'] == 7
    assert unavailable['parent_process_key'] is None
    assert unavailable['parent_identity_status'] == 'UNKNOWN'
    assert unavailable['last_known_parent'] == {'ppid': 7, 'parent_process_key': first_parent}
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 0
    assert child_state() == (unavailable, unavailable_at)
    assert checkpoint_times(mysql)[host] == tick
    assert rows(mysql, 'process_events') == ()

    settings['ppid'] = 8
    tick += timedelta(seconds=1)
    assert processes_main.collect_processes(mysql) == 1
    changed, observed_at = child_state()
    assert observed_at == tick
    assert changed['parent_process_key'] == second_parent
    assert changed['parent_identity_status'] == 'VERIFIED'
    assert 'last_known_parent' not in changed
    event, = rows(mysql, 'process_events')
    assert event[5:7] == (key, 'CHANGED')
    assert json.loads(event[8]) == unavailable
    assert json.loads(event[9]) == changed
    assert processes_main.collect_processes(mysql) == 0
    assert rows(mysql, 'process_events') == (event,)


@pytest.mark.parametrize('failure', [None, 'write', 'commit-lost-before', 'commit-lost-after'])
def test_process_reboot_preserves_history_and_is_atomic(mysql, monkeypatch, capsys, failure):
    first = enroll(mysql, monkeypatch, 'processes')
    pid = 1
    old_key = process_key(BOOT_ID, pid, 1000.0)
    new_key = process_key(OTHER_BOOT_ID, pid, 1000.0)
    state = process(pid)
    assert collect_snapshot(mysql, 'processes', lambda _: {old_key: state}, process_diff) == 0
    state['process_name'] = 'renamed'
    assert collect_snapshot(mysql, 'processes', lambda _: {old_key: state}, process_diff) == 1
    history = rows(mysql, 'process_events')
    assert history[0][5:7] == (old_key, 'CHANGED')
    with monkeypatch.context() as second_host:
        second = enroll(mysql, second_host, 'processes')
        assert collect_snapshot(mysql, 'processes', lambda _: {old_key: state}, process_diff) == 0
    with monkeypatch.context() as services:
        enroll(mysql, services, host=first[0])
        assert collect_snapshot(mysql, 'services', lambda _: {'x.service': service()}, get_events) == 0
    services_before = rows(mysql, 'service_state')
    baseline = sorted(rows(mysql, 'process_state'))
    checkpoint = sorted(rows(mysql, 'collector_snapshots'))

    monkeypatch.setattr(processes_main, 'read_boot_id', lambda: OTHER_BOOT_ID)
    seen = []

    def observe(previous):
        seen.append(previous)
        return {new_key: process(pid)}

    original_commit = mysql.commit
    original_save = snapshot.save_checkpoint

    def fail_checkpoint(*args):
        original_save(*args)
        raise pymysql.IntegrityError(1451, 'synthetic write failure')

    def fail_commit():
        if failure == 'commit-lost-after':
            original_commit()
        raise pymysql.OperationalError(2013, 'synthetic lost acknowledgement')

    if failure is not None:
        with monkeypatch.context() as fault:
            if failure == 'write':
                fault.setattr(snapshot, 'save_checkpoint', fail_checkpoint)
            else:
                fault.setattr(mysql, 'commit', fail_commit)
            with pytest.raises((pymysql.IntegrityError, pymysql.OperationalError)):
                collect_snapshot(mysql, 'processes', observe, process_diff)
        assert seen == [{}]
        assert 'detected a new Linux boot' not in capsys.readouterr().out
        if failure != 'commit-lost-after':
            assert sorted(rows(mysql, 'process_state')) == baseline
            assert sorted(rows(mysql, 'collector_snapshots')) == checkpoint
        assert rows(mysql, 'process_events') == history

    assert collect_snapshot(mysql, 'processes', observe, process_diff) == 0
    if failure == 'commit-lost-after':
        assert seen[-1] == {new_key: process(pid)}
        assert 'detected a new Linux boot' not in capsys.readouterr().out
    else:
        assert seen[-1] == {}
        assert 'detected a new Linux boot' in capsys.readouterr().out
    assert rows(mysql, 'process_events') == history
    states = sorted(rows(mysql, 'process_state'))
    state_keys = []
    for row in states:
        state_keys.append((row[0], row[4]))
    assert state_keys == [(first[0], new_key), (second[0], old_key)]
    assert states[1] == baseline[1]
    assert rows(mysql, 'service_state') == services_before
    for row in rows(mysql, 'collector_snapshots'):
        if row[4] == 'services':
            assert row in checkpoint and row[6] is None
        elif row[0] == second[0]:
            assert row in checkpoint and row[6] == BOOT_ID
        else:
            assert row[6] == OTHER_BOOT_ID


def test_040_resumes_after_ddl_and_rebaselines_legacy_processes(empty_mysql, monkeypatch, capsys):
    connection = empty_mysql
    with monkeypatch.context() as previous_version:
        previous_version.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:-4])
        assert migrate.migrate(connection)[-1] == '039'
    identity = EventIdentity(*enroll(connection, monkeypatch, 'processes'))
    legacy_key = '1:1000.000000'
    legacy_state = process(1)
    snapshot.save_snapshot(connection, 'processes', identity, {}, {legacy_key: legacy_state},
                           [(legacy_key, 'STARTED', None, legacy_state)], snapshot.utc_now())
    connection.commit()
    history = rows(connection, 'process_events')
    baseline = rows(connection, 'process_state')
    checkpoint = rows(connection, 'collector_snapshots')[0]
    original = migrate.apply_one

    def interrupt_after_ddl(conn, version):
        original(conn, version)
        if version == '040':
            raise RuntimeError('synthetic interruption after DDL')

    with monkeypatch.context() as fault:
        fault.setattr(migrate, 'apply_one', interrupt_after_ddl)
        with pytest.raises(RuntimeError, match='interruption after DDL'):
            migrate.migrate(connection)
    with pytest.raises(IdentityError, match='migration is incomplete'):
        collect_snapshot(connection, 'processes', lambda _: pytest.fail('must not collect'), process_diff)
    assert migrate.migrate(connection) == ['040', '041', '042', '043']
    assert migrate.migrate(connection) == []
    assert rows(connection, 'process_state') == baseline
    assert rows(connection, 'process_events') == history
    assert rows(connection, 'collector_snapshots') == (checkpoint + (None,),)

    key = process_key(BOOT_ID, 1, 1000.0)

    def observe(previous):
        assert previous == {}
        return {key: legacy_state}

    assert collect_snapshot(connection, 'processes', observe, process_diff) == 0
    assert rows(connection, 'process_state')[0][4] == key
    assert rows(connection, 'process_events') == history
    assert rows(connection, 'collector_snapshots')[0][6] == BOOT_ID
    assert 'previous boot ID was unknown' in capsys.readouterr().out


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


def test_rebound_source_cannot_modify_another_sources_baseline(mysql, monkeypatch):
    host, _, collector = enroll(mysql, monkeypatch)
    collect_snapshot(mysql, 'services', lambda _: {'x.service': service()}, get_events)
    before = rows(mysql, 'service_state')
    with mysql.cursor() as cursor:
        alternate = register_source(cursor, host, 'alternate', 'services', enabled=True)
        approve_collector_source(cursor, collector, alternate)
    mysql.commit()
    monkeypatch.setenv('SIEM_SERVICES_SOURCE_ID', str(alternate))
    with pytest.raises(IdentityError, match='different source'):
        collect_snapshot(mysql, 'services', lambda _: pytest.fail('must not collect'), get_events)
    assert rows(mysql, 'service_state') == before
    assert rows(mysql, 'service_events') == ()


@pytest.mark.parametrize('fault', ['write', 'interrupt', 'commit-lost-before', 'commit-lost-after'])
def test_snapshot_atomicity_and_uncertain_commit(mysql, monkeypatch, fault):
    enroll(mysql, monkeypatch)
    collect_snapshot(mysql, 'services', lambda _: {'x.service': service(), 'old.service': service()}, get_events)
    before = sorted(rows(mysql, 'service_state'))
    checkpoints = rows(mysql, 'collector_snapshots')
    current = {'x.service': service('active'), 'new.service': service()}
    original_save, original_commit = snapshot.save_snapshot, mysql.commit
    original_execute = pymysql.cursors.Cursor.execute

    def interrupt(*args):
        original_save(*args)
        raise KeyboardInterrupt

    def fail_delete(cursor, sql, parameters=None):
        if isinstance(sql, str) and sql.startswith('DELETE FROM service_state '):
            raise pymysql.IntegrityError(1451, 'synthetic delete failed after inserts and update')
        return original_execute(cursor, sql, parameters)

    def fail_commit():
        if fault == 'commit-lost-after':
            original_commit()
        raise pymysql.OperationalError(2013, 'synthetic commit acknowledgement lost')

    with monkeypatch.context() as patch:
        if fault == 'write':
            patch.setattr(pymysql.cursors.Cursor, 'execute', fail_delete)
        elif fault == 'interrupt':
            patch.setattr(snapshot, 'save_snapshot', interrupt)
        else:
            patch.setattr(mysql, 'commit', fail_commit)
        with pytest.raises((KeyboardInterrupt, pymysql.OperationalError, pymysql.IntegrityError)):
            collect_snapshot(mysql, 'services', lambda _: current, get_events)
    # A successful server commit stays successful even when acknowledgement was
    # lost. Retry reads current state and never duplicates its transition.
    expected = 0
    if fault == 'commit-lost-after':
        expected = 3
    else:
        assert sorted(rows(mysql, 'service_state')) == before
        assert rows(mysql, 'collector_snapshots') == checkpoints
    assert len(rows(mysql, 'service_events')) == expected
    assert collect_snapshot(mysql, 'services', lambda _: current, get_events) == 3 - expected
    assert len(rows(mysql, 'service_events')) == 3


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
                assert health_record(mysql, host, 'services')['status'] == 'SKIPPED'
                monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
                identity = snapshot.get_identity(mysql, 'services')
                mysql.rollback()
                with pytest.raises(snapshot.CollectionBusy):
                    snapshot_retention.cleanup(mysql, 'services', host, identity.source_id, retention_policy(), apply=True)
                assert collect_snapshot(mysql, 'processes', lambda _: {}, process_diff) == 0
            finally:
                finish.set()
            assert pending.result(timeout=10) == 0
        assert len(rows(mysql, 'collector_snapshots')) == 2
        assert service_window_records(mysql)[0]['sample_count'] == 1
    finally:
        other.close()


@pytest.mark.parametrize('version', ['018', '019', '020', '021'])
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
    audit_targets = None
    if version == '020':
        with empty_mysql.cursor() as cursor:
            cursor.execute("UPDATE audit_targets SET enabled = 0 WHERE target_name = 'passwd'")
        empty_mysql.commit()
        audit_targets = rows(empty_mysql, 'audit_targets')
    remaining = []
    for step, _, _ in migrate.MIGRATIONS:
        if step >= version:
            remaining.append(step)
    assert migrate.migrate(empty_mysql) == remaining
    assert migrate.migrate(empty_mysql) == []
    assert rows(empty_mysql, 'hosts') == history
    if audit_targets is not None:
        assert rows(empty_mysql, 'audit_targets') == audit_targets


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
        assert cursor.fetchone() == (1, 8)
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
        return [SimpleNamespace(pid=12, info=info, cpu_percent=MagicMock(return_value=0.0),
                                is_running=MagicMock(return_value=True))]

    monkeypatch.setattr(service_get, 'bounded_output', systemctl)
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


WINDOW_AT = datetime(2026, 11, 17, 10)


def observe_process_measurement(monkeypatch, state=None):
    key = process_key(BOOT_ID, 12, 1000.0)
    if state is None:
        state = {**process(12), 'executable_identity_status': 'PATH_ONLY', 'euid': 0, 'uid': 0}

    def observe(previous, *, boot_id, coverage, measurements):
        measurements[key] = state
        return {key: state}

    monkeypatch.setattr(processes_main, 'get_processes', observe)
    return observe


def window_records(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute('SELECT * FROM process_measurement_windows ORDER BY window_start')
        return cursor.fetchall()


def test_measurement_windows_survive_restart_and_roll_over_after_gaps(mysql, monkeypatch):
    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    observe = observe_process_measurement(monkeypatch)
    for minute in (0, 1):
        connection = connect_like(mysql)
        try:
            assert processes_main.collect_processes(connection, observed_at=WINDOW_AT + timedelta(minutes=minute)) == 0
        finally:
            connection.close()

    def partial(previous, *, boot_id, coverage, measurements):
        result = observe(previous, boot_id=boot_id, coverage=coverage, measurements=measurements)
        coverage.update(observed_count=1, incomplete_process_count=1)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(processes_main, 'get_processes', partial)
        with pytest.raises(snapshot.ObservationError, match='inventory incomplete'):
            processes_main.collect_processes(mysql, observed_at=WINDOW_AT + timedelta(minutes=2))
    assert health_record(mysql, host, 'processes')['status'] == 'PARTIAL'
    assert checkpoint_times(mysql)[host] == WINDOW_AT + timedelta(minutes=1)

    for minute in (3, 4, 10):
        assert processes_main.collect_processes(mysql, observed_at=WINDOW_AT + timedelta(minutes=minute)) == 0
    first, next_window = window_records(mysql)
    assert first['sample_count'] == 4 and next_window['sample_count'] == 1
    assert first['first_observed_at'] == first['window_start'] == WINDOW_AT
    assert first['last_observed_at'] == WINDOW_AT + timedelta(minutes=4)
    assert first['window_end'] == WINDOW_AT + timedelta(minutes=5)
    assert next_window['window_start'] == WINDOW_AT + timedelta(minutes=10)
    metrics = json.loads(first['metrics'])
    assert metrics['cpu_percent_sum'] == {'sum': 4, 'min': 1, 'max': 1, 'count': 4}
    program, = json.loads(first['executables']).values()
    assert program['snapshot_count'] == 4 and program['max_concurrent_instances'] == 1
    assert program['new_since_previous_snapshot_count'] == 0
    assert rows(mysql, 'process_events') == ()


@pytest.mark.parametrize('lost_after_commit', [False, True])
def test_window_and_snapshot_replay_after_ambiguous_commit(mysql, monkeypatch, lost_after_commit):
    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    observe_process_measurement(monkeypatch)
    assert processes_main.collect_processes(mysql, observed_at=WINDOW_AT) == 0
    changed = {**process(12), 'process_name': 'new', 'cpu_percent': 151}
    observe_process_measurement(monkeypatch, changed)
    second = WINDOW_AT + timedelta(minutes=1)
    commit = mysql.commit

    def lost():
        if lost_after_commit:
            commit()
        raise pymysql.OperationalError(2013, 'synthetic')

    with monkeypatch.context() as patch:
        patch.setattr(mysql, 'commit', lost)
        with pytest.raises(pymysql.OperationalError):
            processes_main.collect_processes(mysql, observed_at=second)

    window, = window_records(mysql)
    assert window['sample_count'] == 1 + int(lost_after_commit)
    assert len(rows(mysql, 'process_events')) == int(lost_after_commit)
    health_before = health_record(mysql, host, 'processes')
    assert processes_main.collect_processes(mysql, observed_at=second) == 1 - int(lost_after_commit)
    window, = window_records(mysql)
    assert window['sample_count'] == 2
    assert len(rows(mysql, 'process_events')) == 1
    assert checkpoint_times(mysql)[host] == second
    assert json.loads(window['metrics'])['cpu_percent_sum']['sum'] == 152
    if lost_after_commit:
        assert health_record(mysql, host, 'processes') == health_before


def test_window_update_rolls_back_if_snapshot_write_fails(mysql, monkeypatch):
    host, _, _ = enroll(mysql, monkeypatch, 'processes')
    observe_process_measurement(monkeypatch)
    assert processes_main.collect_processes(mysql, observed_at=WINDOW_AT) == 0
    before = window_records(mysql)

    def failed(*args, **kwargs):
        raise pymysql.IntegrityError(1452, 'synthetic')

    monkeypatch.setattr(snapshot, 'save_snapshot', failed)
    with pytest.raises(pymysql.IntegrityError):
        processes_main.collect_processes(mysql, observed_at=WINDOW_AT + timedelta(minutes=1))
    assert window_records(mysql) == before
    assert checkpoint_times(mysql)[host] == WINDOW_AT
    assert health_record(mysql, host, 'processes')['error_code'] == 'DATABASE_ERROR'


def test_window_scope_and_storage_volume(mysql, monkeypatch):
    from time import perf_counter

    first = EventIdentity(*enroll(mysql, monkeypatch, 'processes'))
    with mysql.cursor() as cursor:
        alternate = register_source(cursor, first.host_id, 'alternate', 'processes', enabled=True)
        approve_collector_source(cursor, first.collector_id, alternate)
    mysql.commit()
    second = EventIdentity(first.host_id, alternate, first.collector_id)
    third = EventIdentity(*enroll(mysql, monkeypatch, 'processes'))
    states = {}
    for number in range(65):
        states[str(number)] = {
            'executable_path': f'/synthetic/example-program-{number}', 'executable_identity_status': 'PATH_ONLY',
            'parent_identity_status': 'VERIFIED', 'parent_process_key': str(max(0, number - 1)),
            'cpu_percent': number, 'memory_mb': number,
        }
    started = perf_counter()
    assert windows.save_window(mysql, first, WINDOW_AT, states, None, len(states))
    mysql.commit()
    elapsed_ms = (perf_counter() - started) * 1000
    assert windows.save_window(mysql, second, WINDOW_AT, {}, None, 0)
    assert windows.save_window(mysql, third, WINDOW_AT, {}, None, 0)
    mysql.commit()
    records = {}
    for row in window_records(mysql):
        records[(row['host_id'], row['source_id'])] = row
    assert len(records) == 3
    scoped = records[(first.host_id, first.source_id)]
    assert len(json.loads(scoped['executables'])) == 64
    assert len(json.loads(scoped['parent_child'])) == 63
    assert json.loads(scoped['metrics'])['executable_detail_omitted_count']['sum'] == 1
    assert json.loads(records[(second.host_id, second.source_id)]['metrics'])['process_count']['sum'] == 0
    with mysql.cursor() as cursor:
        cursor.execute('SELECT JSON_STORAGE_SIZE(metrics) + JSON_STORAGE_SIZE(executables) '
                       '+ JSON_STORAGE_SIZE(parent_child) FROM process_measurement_windows '
                       'WHERE host_id = %s AND source_id = %s', (first.host_id, first.source_id))
        (payload_size,) = cursor.fetchone()
    assert payload_size > 0
    print(f'Process window volume: {payload_size} JSON bytes; first write and commit: {elapsed_ms:.1f} ms.')


def test_overlapping_process_attempt_cannot_update_window(mysql, monkeypatch):
    enroll(mysql, monkeypatch, 'processes')
    observe = observe_process_measurement(monkeypatch)
    observing, resume = Event(), Event()

    def block_observation(previous, *, boot_id, coverage, measurements):
        observing.set()
        assert resume.wait(30)
        return observe(previous, boot_id=boot_id, coverage=coverage, measurements=measurements)

    monkeypatch.setattr(processes_main, 'get_processes', block_observation)
    with connect_like(mysql) as connection, ThreadPoolExecutor() as executor:
        pending = executor.submit(processes_main.collect_processes, connection, observed_at=WINDOW_AT)
        try:
            assert observing.wait(20)
            with pytest.raises(snapshot.CollectionBusy):
                processes_main.collect_processes(mysql, observed_at=WINDOW_AT + timedelta(seconds=30))
            assert window_records(mysql) == ()
        finally:
            resume.set()
        assert pending.result(timeout=30) == 0
    mysql.rollback()
    window, = window_records(mysql)
    assert window['sample_count'] == 1 and window['last_observed_at'] == WINDOW_AT


def service_window_records(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute('SELECT * FROM service_measurement_windows ORDER BY window_start')
        return cursor.fetchall()


def test_service_window_counts_only_accepted_inventories_across_connections(mysql, monkeypatch):
    from types import SimpleNamespace

    from metrics.services import get as service_get

    host, _, _ = enroll(mysql, monkeypatch)
    stage = 'ok'

    def systemctl(args, **_kwargs):
        if 'list-units' in args:
            if stage == 'unavailable':
                return SimpleNamespace(returncode=1, stdout='')
            output = 'example.service loaded inactive dead Example\n'
        elif 'list-unit-files' in args:
            output = 'example.service disabled -\n'
        elif stage == 'partial':
            output = ''
        else:
            output = ('Id=example.service\nNames=example.service\nDescription=Example\nLoadState=loaded\n'
                      'ActiveState=inactive\nSubState=dead\nMainPID=0\n')
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(service_get, 'bounded_output', systemctl)
    with connect_like(mysql) as collector:
        assert services_main.collect_services(collector, observed_at=WINDOW_AT) == 0
        assert services_main.collect_services(collector, observed_at=WINDOW_AT + timedelta(minutes=1)) == 0
    for stage in ('unavailable', 'partial'):
        with pytest.raises(snapshot.ObservationError):
            services_main.collect_services(mysql, observed_at=WINDOW_AT + timedelta(minutes=2))
        assert health_record(mysql, host, 'services')['status'] == 'FAILED'
        assert checkpoint_times(mysql)[host] == WINDOW_AT + timedelta(minutes=1)
    stage = 'ok'
    for minute in (3, 4, 25):
        assert services_main.collect_services(mysql, observed_at=WINDOW_AT + timedelta(minutes=minute)) == 0
    first, later = service_window_records(mysql)
    assert first['sample_count'] == 4 and later['sample_count'] == 1
    assert first['first_observed_at'] == first['window_start'] == WINDOW_AT
    assert first['last_observed_at'] == WINDOW_AT + timedelta(minutes=4)
    assert first['window_end'] == WINDOW_AT + timedelta(minutes=5)
    assert later['window_start'] == WINDOW_AT + timedelta(minutes=25)
    metrics = json.loads(first['metrics'])
    assert metrics['observed_utc_minute_mask'] == 0b11011
    assert metrics['inactive_count'] == {'sum': 4, 'min': 1, 'max': 1, 'count': 4}
    assert metrics['zero_main_pid_count']['sum'] == 4
    assert json.loads(first['activity']) == {}
    assert rows(mysql, 'service_events') == ()
    assert health_record(mysql, host, 'services')['status'] == 'SUCCESS'


@pytest.mark.parametrize('lost_after_commit', [False, True])
def test_service_window_is_atomic_with_snapshot_and_commit_replay(mysql, monkeypatch, lost_after_commit):
    host, _, _ = enroll(mysql, monkeypatch)
    name = 'example.service'
    collected = {name: service()}
    monkeypatch.setattr(services_main, 'get_services', lambda *_args, **_kwargs: collected)
    assert services_main.collect_services(mysql, observed_at=WINDOW_AT) == 0
    collected[name] = service('active')
    second = WINDOW_AT + timedelta(minutes=1)

    def failed(*args, **kwargs):
        raise pymysql.IntegrityError(1452, 'synthetic')

    with monkeypatch.context() as patch:
        patch.setattr(snapshot, 'save_snapshot', failed)
        with pytest.raises(pymysql.IntegrityError):
            services_main.collect_services(mysql, observed_at=second)
    assert service_window_records(mysql)[0]['sample_count'] == 1
    assert checkpoint_times(mysql)[host] == WINDOW_AT
    assert rows(mysql, 'service_events') == ()
    assert health_record(mysql, host, 'services')['error_code'] == 'DATABASE_ERROR'
    commit = mysql.commit

    def lost():
        if lost_after_commit:
            commit()
        raise pymysql.OperationalError(2013, 'synthetic')

    with monkeypatch.context() as patch:
        patch.setattr(mysql, 'commit', lost)
        with pytest.raises(pymysql.OperationalError):
            services_main.collect_services(mysql, observed_at=second)
    assert service_window_records(mysql)[0]['sample_count'] == 1 + int(lost_after_commit)
    assert len(rows(mysql, 'service_events')) == int(lost_after_commit)
    health_before = health_record(mysql, host, 'services')
    assert services_main.collect_services(mysql, observed_at=second) == 1 - int(lost_after_commit)
    window, = service_window_records(mysql)
    assert window['sample_count'] == 2 and window['last_observed_at'] == second
    assert json.loads(window['metrics'])['observed_started_count']['sum'] == 1
    assert json.loads(window['activity'])[name]['active_count'] == 1
    event, = rows(mysql, 'service_events')
    assert event[5:8] == (name, 'STARTED', second)
    assert checkpoint_times(mysql)[host] == second
    if lost_after_commit:
        assert health_record(mysql, host, 'services') == health_before


def test_service_window_identity_scope_and_storage_volume(mysql, monkeypatch):
    from time import perf_counter

    first = EventIdentity(*enroll(mysql, monkeypatch))
    with mysql.cursor() as cursor:
        alternate = register_source(cursor, first.host_id, 'alternate', 'services', enabled=True)
        approve_collector_source(cursor, first.collector_id, alternate)
    mysql.commit()
    second = EventIdentity(first.host_id, alternate, first.collector_id)
    third = EventIdentity(*enroll(mysql, monkeypatch))
    inventory = {'failed.service': service('failed')}
    for number in range(300):
        inventory[f'quiet-{number}.service'] = service('active', 'enabled')
    later = {**inventory, 'quiet-12.service': service('inactive', 'enabled')}
    started = perf_counter()
    assert service_windows.save_window(mysql, first, WINDOW_AT, inventory, [])
    mysql.commit()
    first_ms = (perf_counter() - started) * 1000
    started = perf_counter()
    assert service_windows.save_window(mysql, first, WINDOW_AT + timedelta(minutes=1), later,
                                       get_events(later, inventory))
    mysql.commit()
    update_ms = (perf_counter() - started) * 1000
    assert service_windows.save_window(mysql, second, WINDOW_AT, {}, [])
    assert service_windows.save_window(mysql, third, WINDOW_AT, {'elsewhere.service': service()}, [])
    mysql.commit()
    by_scope = {}
    for record in service_window_records(mysql):
        by_scope[(record['host_id'], record['source_id'])] = record
    assert len(by_scope) == 3
    selected = by_scope[(first.host_id, first.source_id)]
    assert selected['sample_count'] == 2 and len(json.loads(selected['activity'])) == 2
    assert json.loads(selected['metrics'])['service_count']['sum'] == 602
    assert json.loads(by_scope[(second.host_id, second.source_id)]['metrics'])['service_count']['sum'] == 0
    assert json.loads(by_scope[(third.host_id, third.source_id)]['metrics'])['service_count']['sum'] == 1
    with mysql.cursor() as cursor:
        cursor.execute('SELECT JSON_STORAGE_SIZE(metrics) + JSON_STORAGE_SIZE(activity) '
                       'FROM service_measurement_windows WHERE host_id = %s AND source_id = %s',
                       (first.host_id, first.source_id))
        (payload_size,) = cursor.fetchone()
    assert payload_size > 0
    print(f'Service window volume: {payload_size} JSON bytes; insert and commit: {first_ms:.1f} ms; '
          f'update and commit: {update_ms:.1f} ms.')


def test_retention_preview_and_apply_preserve_current_state_history_and_replay_anchor(mysql, monkeypatch):
    host, source, collector = enroll(mysql, monkeypatch)
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
    monkeypatch.setenv('SIEM_SNAPSHOT_EVENT_DAYS', '45')
    monkeypatch.setenv('SIEM_SNAPSHOT_DETAIL_DAYS', '10')
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_BATCH_ROWS', '1')
    policy = retention_policy()
    observed = {}

    def observe(*args, **kwargs):
        return observed

    monkeypatch.setattr(services_main, 'get_services', observe)
    for days, status in ((65, 'inactive'), (60, 'active'), (40, 'inactive'), (15, 'active'), (0, 'inactive')):
        observed['test.service'] = service(status)
        services_main.collect_services(mysql, observed_at=WINDOW_AT - timedelta(days=days))

    transitions = [
        {'at': '2026-08-01T10:00:00.000000Z', 'status': 'FAILED', 'error_code': 'SOURCE_UNAVAILABLE'},
        {'at': '2026-11-16T10:00:00.000000Z', 'status': 'SUCCESS', 'error_code': None},
    ]
    with mysql.cursor() as cursor:
        alternate = register_source(cursor, host, 'retention-alternate', 'services', enabled=True)
        approve_collector_source(cursor, collector, alternate)
        cursor.execute('UPDATE collector_health SET transitions = %s WHERE host_id = %s AND source_id = %s',
                       (json.dumps(transitions), host, source))
    other = EventIdentity(host, alternate, collector)
    assert service_windows.save_window(mysql, other, WINDOW_AT - timedelta(days=75), {}, [])
    mysql.commit()

    events = rows(mysql, 'service_events')
    state = rows(mysql, 'service_state')
    checkpoint = rows(mysql, 'collector_snapshots')
    before = service_window_records(mysql)
    health = health_record(mysql, host, 'services')
    mysql.rollback()

    assert snapshot_retention.cleanup(mysql, 'services', host, source, policy, now=WINDOW_AT) == (1, 3, 1, 1)
    assert service_window_records(mysql) == before
    assert health_record(mysql, host, 'services') == health
    mysql.rollback()
    assert snapshot_retention.cleanup(mysql, 'services', host, source, policy,
                                      apply=True, now=WINDOW_AT) == (None, 1, 1, 1)
    updated = service_window_records(mysql)
    assert len(updated) == len(before) - 1
    assert updated[-1] == before[-1]
    assert updated[0] == before[0]
    pruned = updated[-2]
    assert pruned['window_start'] == WINDOW_AT - timedelta(days=15)
    assert json.loads(pruned['activity']) == {}
    metrics = json.loads(pruned['metrics'])
    assert metrics['details_expired'] is True and metrics['active_count']['sum'] == 1
    assert rows(mysql, 'service_events') == events and rows(mysql, 'service_state') == state
    assert rows(mysql, 'collector_snapshots') == checkpoint
    after_health = health_record(mysql, host, 'services')
    assert json.loads(after_health['transitions']) == transitions[1:]
    after_health['transitions'] = health['transitions']
    assert after_health == health
    mysql.rollback()
    assert snapshot_retention.cleanup(mysql, 'services', host, alternate, policy,
                                      apply=True, now=WINDOW_AT) == (None, 0, 0, 0)
    assert services_main.collect_services(mysql, observed_at=WINDOW_AT) == 0
    assert service_window_records(mysql) == updated


def test_retention_rolls_back_a_batch_if_health_update_fails(mysql, monkeypatch):
    host, source, _ = enroll(mysql, monkeypatch, 'processes')
    observe_process_measurement(monkeypatch)
    assert processes_main.collect_processes(mysql, observed_at=WINDOW_AT - timedelta(days=60)) == 0
    assert processes_main.collect_processes(mysql, observed_at=WINDOW_AT) == 0
    before = window_records(mysql)
    mysql.rollback()
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
    policy = retention_policy()

    def fail(*args, **kwargs):
        raise pymysql.IntegrityError(1451, 'synthetic retention write failure')

    monkeypatch.setattr(snapshot_retention, 'expired_health', fail)
    with pytest.raises(pymysql.IntegrityError):
        snapshot_retention.cleanup(mysql, 'processes', host, source, policy, apply=True, now=WINDOW_AT)
    assert window_records(mysql) == before
    assert checkpoint_times(mysql)[host] == WINDOW_AT


@pytest.mark.parametrize('kind', ['processes', 'services'])
def test_inventory_resource_limit_preserves_current_state_and_events(mysql, monkeypatch, kind):
    from types import SimpleNamespace

    from metrics.processes import get as process_get
    from metrics.services import get as service_get

    host, _, _ = enroll(mysql, monkeypatch, kind)
    if kind == 'processes':
        current = {process_key(BOOT_ID, 12, 1000.0): process(12)}
        assert collect_snapshot(mysql, kind, lambda _: current, process_diff) == 0
        collect = processes_main.collect_processes
        monkeypatch.setenv('SIEM_SNAPSHOT_MAX_PROCESSES', '1')
        monkeypatch.setattr(process_get.psutil, 'pids', lambda: [12, 13])
    else:
        assert collect_snapshot(mysql, kind, lambda _: {'old.service': service()}, get_events) == 0
        collect = services_main.collect_services
        monkeypatch.setenv('SIEM_SNAPSHOT_MAX_SERVICES', '1')

        def systemctl(arguments, **kwargs):
            if 'list-units' in arguments:
                return SimpleNamespace(returncode=0, stdout='new.service loaded active running New\n'
                                                           'other.service loaded inactive dead Other\n')
            return SimpleNamespace(returncode=0, stdout='')

        monkeypatch.setattr(service_get, 'bounded_output', systemctl)
    _, history, table, _ = snapshot.TABLES[kind]
    before = rows(mysql, table)
    checkpoint = checkpoint_times(mysql)
    with pytest.raises(snapshot.ResourceLimitError):
        collect(mysql)
    assert rows(mysql, table) == before and rows(mysql, history) == ()
    assert checkpoint_times(mysql) == checkpoint
    health = health_record(mysql, host, kind)
    assert health['status'] == 'FAILED' and health['error_code'] == 'INCOMPLETE_OBSERVATION'
    assert json.loads(health['coverage'])['resource_limit_exceeded'] == 1


def test_write_limit_rolls_back_window_and_preserves_event_history(mysql, monkeypatch):
    host, _, _ = enroll(mysql, monkeypatch)
    current = {'one.service': service('inactive')}
    monkeypatch.setattr(services_main, 'get_services', lambda *args, **kwargs: current)
    assert services_main.collect_services(mysql, observed_at=WINDOW_AT) == 0
    before = service_window_records(mysql)
    state = rows(mysql, 'service_state')
    current['one.service'] = service('active')
    monkeypatch.setenv('SIEM_SNAPSHOT_MAX_WRITE_ROWS', '1')
    with pytest.raises(snapshot.ResourceLimitError):
        services_main.collect_services(mysql, observed_at=WINDOW_AT + timedelta(minutes=1))
    assert health_record(mysql, host, 'services')['status'] == 'FAILED'
    assert service_window_records(mysql) == before and rows(mysql, 'service_state') == state
    assert rows(mysql, 'service_events') == ()


@pytest.mark.parametrize('apply', [False, True])
def test_retention_never_commits_or_rolls_back_an_existing_transaction(mysql, monkeypatch, apply):
    host, source, _ = enroll(mysql, monkeypatch, 'services')
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
    policy = retention_policy()
    with connect_like(mysql) as observer:
        with mysql.cursor() as cursor:
            cursor.execute("UPDATE hosts SET administrative_name = 'uncommitted' WHERE host_id = %s", (host,))
        with pytest.raises(pymysql.MySQLError) as error:
            snapshot_retention.cleanup(mysql, 'services', host, source, policy, apply=apply, now=WINDOW_AT)
        assert error.value.args[0] == 1568
        with observer.cursor() as cursor:
            cursor.execute('SELECT administrative_name FROM hosts WHERE host_id = %s', (host,))
            assert cursor.fetchone() == ('same-name',)
        with mysql.cursor() as cursor:
            cursor.execute('SELECT administrative_name FROM hosts WHERE host_id = %s', (host,))
            assert cursor.fetchone() == ('uncommitted',)
    mysql.rollback()


@pytest.mark.parametrize(('prefix', 'errno'), [
    ('INSERT INTO service_state ', 1452),
    ('UPDATE service_state ', 1205),
    ('INSERT INTO service_events ', 1213),
    ('INSERT INTO service_measurement_windows ', 1452),
    ('INSERT INTO collector_health ', 1452),
    ('UPDATE service_state ', 2013),
])
def test_release_atomicity_at_individual_writes(mysql, snapshot_runtime, monkeypatch, prefix, errno):
    host, _, _ = enroll(mysql, monkeypatch)
    previous = {'kept.service': service()}
    current = {'kept.service': service('active'), 'added.service': service()}
    collect_snapshot(snapshot_runtime, 'services', lambda _: previous, get_events)
    tables = ('service_state', 'service_events', 'collector_snapshots', 'service_measurement_windows')
    before = {}
    for table in tables:
        before[table] = rows(mysql, table)
    mysql.rollback()
    original = pymysql.cursors.Cursor.execute
    failures = []

    def fail_once(cursor, sql, parameters=None):
        statement = sql
        if isinstance(sql, (bytes, bytearray)):
            statement = sql.decode('utf-8')
        if cursor.connection is snapshot_runtime and not failures and statement.startswith(prefix):
            failures.append(errno)
            if errno == 2013:
                # Close the real session while its writes are still uncommitted.
                snapshot_runtime.close()
            raise pymysql.OperationalError(errno, 'synthetic write or transport failure')
        return original(cursor, sql, parameters)

    with monkeypatch.context() as patch:
        patch.setattr(pymysql.cursors.Cursor, 'execute', fail_once)
        with pytest.raises(pymysql.OperationalError) as error:
            collect_snapshot(snapshot_runtime, 'services', lambda _: current, get_events)
    assert error.value.args[0] == errno and failures == [errno]
    for table in tables:
        assert rows(mysql, table) == before[table]
    health = health_record(mysql, host, 'services')
    if errno != 2013:
        assert health['status'] == 'FAILED' and health['error_code'] == 'DATABASE_ERROR'
    mysql.rollback()
    assert collect_snapshot(mysql, 'services', lambda _: current, get_events) == 2
    assert len(rows(mysql, 'service_events')) == 2


@pytest.mark.parametrize('scenario', ['unchanged', 'typical', 'large', 'stress'])
@pytest.mark.parametrize('kind', ['processes', 'services'])
def test_release_snapshot_workload(mysql, monkeypatch, tmp_path, kind, scenario):
    import os

    from tests.benchmarks.snapshot_workload import compare, load_baseline

    if os.getenv('SIEM_TEST_SNAPSHOT_BENCHMARK') != '1':
        pytest.skip('Set SIEM_TEST_SNAPSHOT_BENCHMARK=1 with the private MySQL fixture enabled.')
    enroll(mysql, monkeypatch, kind)
    legacy = load_baseline(tmp_path, 'metrics/snapshot.py')
    legacy_get = load_baseline(tmp_path, f'metrics/{kind}/get.py')
    compare(mysql, kind, scenario, legacy, legacy_get.get_events, BOOT_ID, WINDOW_AT, monkeypatch)


def test_release_parallel_distinct_hosts(mysql, monkeypatch):
    first = EventIdentity(*enroll(mysql, monkeypatch))
    second = EventIdentity(*enroll(mysql, monkeypatch))
    ready = Barrier(2, timeout=30)

    def observe(previous, **kwargs):
        ready.wait()
        return {'same-name.service': service('active')}

    monkeypatch.setattr(services_main, 'get_services', observe)
    with connect_like(mysql) as left, connect_like(mysql) as right, ThreadPoolExecutor(max_workers=2) as executor:
        identities = {left: first, right: second}
        monkeypatch.setattr(snapshot, 'get_identity', lambda connection, kind: identities[connection])
        left_run = executor.submit(services_main.collect_services, left, observed_at=WINDOW_AT)
        right_run = executor.submit(services_main.collect_services, right, observed_at=WINDOW_AT)
        assert left_run.result(timeout=30) == right_run.result(timeout=30) == 0
    mysql.rollback()
    checkpoint = checkpoint_times(mysql)
    assert checkpoint == {first.host_id: WINDOW_AT, second.host_id: WINDOW_AT}
    assert len(service_window_records(mysql)) == 2
    assert len(rows(mysql, 'service_state')) == 2
