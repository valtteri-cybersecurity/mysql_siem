"""Enrollment/legacy transitions against the private resource-limited MySQL fixture."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pymysql
import pytest

from analysis.ufw.source_ips import analyze_source_ips
from database import local_identity as local
from database.identity import IdentityError, configured_identity, register_host
from database.migrate import migrate
from ingestion import ufw_to_mysql as ufw
from ingestion.auth.collector import collect_auth_events
from metrics.security.database import save_metrics_db as save_security
from metrics.system.db import save_metrics_db as save_system

START = datetime(2026, 10, 24, 12)


@pytest.fixture(scope='module')
def local_database(identity_server):
    """Migrate once: these tests change registry data, never schema definitions."""
    connection = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4',
                                 autocommit=False, connect_timeout=5, read_timeout=30,
                                 write_timeout=30, init_command="SET time_zone = '+00:00'")
    name = 'local_identity_test_' + uuid4().hex
    try:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE DATABASE `{name}` CHARACTER SET utf8mb4')
        connection.select_db(name)
        migrate(connection)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def mysql(local_database):
    # Reset only this module's synthetic rows in the fixture's private server.
    # Keep foreign-key checks enabled and leave the migrated schema untouched.
    tables = ('ufw_log', 'auth_events', 'system_metrics', 'filesystem_metrics', 'security_metrics',
              'ufw_state', 'auth_ingestion_state', 'collector_sources', 'log_sources', 'collectors', 'hosts')
    with local_database.cursor() as cursor:
        for table in tables:
            cursor.execute(f'DELETE FROM {table}')
    local_database.commit()
    try:
        yield local_database
    finally:
        local_database.rollback()


def enroll(connection, path, *, configured=None, **options):
    arguments = {'confirmed': True, 'auth_reader': 'reader', 'ufw_paths': [], 'auth_paths': []}
    arguments.update(options)
    return local.provision(connection, path, configured or {}, **arguments)


def apply_environment(monkeypatch, settings):
    for key in local.ALLOWED_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv('SIEM_LOCAL_IDENTITY_REQUIRED', raising=False)
    for key, value in settings.items():
        monkeypatch.setenv(key, str(value))


def counts(connection):
    values = []
    with connection.cursor() as cursor:
        for table in ('hosts', 'collectors', 'log_sources', 'collector_sources'):
            cursor.execute(f'SELECT COUNT(*) FROM {table}')
            values.append(cursor.fetchone()[0])
    return values


def ufw_line(second):
    return f'2026-10-24T12:00:{second:02d}.123456+00:00 local kernel: [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=443\n'


def ssh_line(second):
    return f'2026-10-24T12:00:{second:02d}+00:00 local sshd[1]: Failed password for alice from 192.0.2.1 port 123 ssh2\n'


def test_fresh_setup_and_all_metric_writers_keep_registered_identity(mysql, tmp_path, monkeypatch):
    from metrics.filesystem import db as filesystem

    receipt = tmp_path / 'receipt.json'
    settings = enroll(mysql, receipt)
    assert counts(mysql) == [1, 1, 7, 7]
    apply_environment(monkeypatch, settings)
    monkeypatch.setenv('SIEM_LOCAL_IDENTITY_REQUIRED', '1')
    save_system(mysql, [Decimal(1)] * 10)
    save_security(mysql, {'uptime': 1, 'blocks': 2, 'failed_logins': 3, 'unique_ips': 4,
                         'date': START.replace(tzinfo=timezone.utc)})
    monkeypatch.setattr(filesystem, 'get_connection', lambda: mysql)
    close = mysql.close
    monkeypatch.setattr(mysql, 'close', lambda: None)
    try:
        filesystem.save_metrics(3, 7)
    finally:
        monkeypatch.setattr(mysql, 'close', close)
    host = local.read_receipt(receipt)['host_id']
    with mysql.cursor() as cursor:
        for table, source_type in (('system_metrics', 'system'), ('filesystem_metrics', 'filesystem'),
                                   ('security_metrics', 'security')):
            cursor.execute(f'SELECT host_id, source_id, collector_id, sender_id FROM {table}')
            assert cursor.fetchall() == ((host, settings[local.LOCAL_KEYS[source_type]], settings[local.COLLECTOR_KEY], None),)
    assert enroll(mysql, receipt, configured=settings) == settings
    assert counts(mysql) == [1, 1, 7, 7]
    assert enroll(mysql, receipt) == settings  # A missing file is recoverable from the trusted receipt.
    assert counts(mysql) == [1, 1, 7, 7]


def test_legacy_collection_continues_exactly_once_without_rewriting_history(mysql, tmp_path, monkeypatch):
    apply_environment(monkeypatch, {})
    firewall = tmp_path / 'ufw.log'
    auth = tmp_path / 'auth.log'
    firewall.write_text(ufw_line(0))
    auth.write_text(ssh_line(0))
    monkeypatch.setattr(ufw, 'get_logfiles', lambda: [str(firewall)])
    ufw.process_log(mysql)
    collect_auth_events(mysql, str(auth), collector_id='reader')
    with mysql.cursor() as cursor:
        cursor.execute('SELECT id, event_hash, host_id FROM ufw_log')
        old_ufw = cursor.fetchall()
        cursor.execute('SELECT id, event_hash, host_id FROM auth_events')
        old_auth = cursor.fetchall()
        cursor.execute('SELECT logfile, last_position, file_device, file_inode FROM ufw_state WHERE source_scope = 0')
        old_position = cursor.fetchall()
    receipt = tmp_path / 'receipt.json'
    settings = enroll(mysql, receipt, ufw_paths=[firewall], auth_paths=[auth])
    # Simulate completed publication before deliberately running registered jobs.
    ready = local.read_receipt(receipt)
    ready['phase'] = 'ready'
    local.save_receipt(receipt, ready)
    apply_environment(monkeypatch, settings)
    with firewall.open('a') as output:
        output.write(ufw_line(1))
    with auth.open('a') as output:
        output.write(ssh_line(1))
    ufw.process_log(mysql)
    result = collect_auth_events(mysql, str(auth), collector_id='reader')
    assert result['inserted'] == 1
    ufw.process_log(mysql)
    assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 0
    with mysql.cursor() as cursor:
        cursor.execute('SELECT id, event_hash, host_id FROM ufw_log WHERE host_id IS NULL')
        assert cursor.fetchall() == old_ufw
        cursor.execute('SELECT id, event_hash, host_id FROM auth_events WHERE host_id IS NULL')
        assert cursor.fetchall() == old_auth
        cursor.execute('SELECT logfile, last_position, file_device, file_inode FROM ufw_state WHERE source_scope = 0')
        assert cursor.fetchall() == old_position
        for table in ('ufw_log', 'auth_events'):
            cursor.execute(f'SELECT COUNT(*), COUNT(host_id) FROM {table}')
            assert cursor.fetchone() == (2, 1)
    rows = analyze_source_ips(mysql, START, START + timedelta(hours=1))
    assert len(rows) == 2
    assert {row['host_id'] for row in rows} == {None, local.read_receipt(receipt)['host_id']}
    assert {row['total_events'] for row in rows} == {1}
    assert enroll(mysql, receipt, configured=settings) == settings
    assert counts(mysql) == [1, 1, 7, 7]


def test_commit_before_receipt_publication_recovers_without_duplicate_registration(mysql, tmp_path, monkeypatch):
    receipt = tmp_path / 'receipt.json'
    original = local.save_receipt

    def fail_after_commit(path, value):
        if value['phase'] == 'database_ready':
            raise OSError('simulated interrupted receipt publication')
        return original(path, value)

    with monkeypatch.context() as patch:
        patch.setattr(local, 'save_receipt', fail_after_commit)
        with pytest.raises(OSError):
            enroll(mysql, receipt)
    assert local.read_receipt(receipt)['phase'] == 'prepared'
    assert counts(mysql) == [1, 1, 7, 7]
    settings = enroll(mysql, receipt)
    assert len(settings) == 8
    assert counts(mysql) == [1, 1, 7, 7]
    assert local.read_receipt(receipt)['phase'] == 'database_ready'


def test_checkpoint_failure_rolls_back_registry_and_can_retry(mysql, tmp_path, monkeypatch):
    receipt = tmp_path / 'receipt.json'

    def fail_checkpoint(*args, **kwargs):
        raise IdentityError('simulated checkpoint failure')

    with monkeypatch.context() as patch:
        patch.setattr(local, 'copy_checkpoints', fail_checkpoint)
        with pytest.raises(IdentityError):
            enroll(mysql, receipt)
    assert counts(mysql) == [0, 0, 0, 0]
    assert len(enroll(mysql, receipt)) == 8
    assert counts(mysql) == [1, 1, 7, 7]


def test_registry_without_persistent_binding_is_not_adopted(mysql, tmp_path):
    with mysql.cursor() as cursor:
        register_host(cursor, 'same-name')
    mysql.commit()
    with pytest.raises(IdentityError, match='without a persistent'):
        enroll(mysql, tmp_path / 'receipt.json')
    assert counts(mysql) == [1, 0, 0, 0]


@pytest.mark.parametrize('fault', ['disabled', 'wrong-host', 'config-conflict', 'wrong-server'])
def test_existing_identity_conflicts_never_create_replacements(mysql, tmp_path, fault):
    receipt = tmp_path / 'receipt.json'
    settings = enroll(mysql, receipt)
    before = counts(mysql)
    if fault == 'disabled':
        with mysql.cursor() as cursor:
            cursor.execute('UPDATE collectors SET enabled = FALSE WHERE collector_id = %s', (settings[local.COLLECTOR_KEY],))
    elif fault == 'wrong-host':
        with mysql.cursor() as cursor:
            other = register_host(cursor, 'other')
            # No events exist, so all local sources can be reassigned by an administrator.
            cursor.execute('UPDATE log_sources SET host_id = %s', (other,))
        before[0] += 1
    elif fault == 'config-conflict':
        settings = dict(settings)
        settings[local.LOCAL_KEYS['system']] += 100
    else:
        value = local.read_receipt(receipt)
        value['server'] = 'another-server'
        local.save_receipt(receipt, value)
    mysql.commit()
    with pytest.raises(IdentityError):
        enroll(mysql, receipt, configured=settings)
    assert counts(mysql) == before


def test_legacy_events_without_checkpoint_fail_closed(mysql, tmp_path):
    with mysql.cursor() as cursor:
        ufw.save_event(cursor, ufw_line(0))
    mysql.commit()
    with pytest.raises(IdentityError, match='no trustworthy checkpoint'):
        enroll(mysql, tmp_path / 'receipt.json')
    assert counts(mysql) == [0, 0, 0, 0]
    with mysql.cursor() as cursor:
        cursor.execute('SELECT COUNT(*), COUNT(host_id) FROM ufw_log')
        assert cursor.fetchone() == (1, 0)


def test_legacy_confirmation_is_required_before_commit(mysql, tmp_path):
    with mysql.cursor() as cursor:
        cursor.execute('INSERT INTO system_metrics (timestamp) VALUES (%s)', (START,))
    mysql.commit()
    with pytest.raises(IdentityError, match='not confirmed'):
        enroll(mysql, tmp_path / 'receipt.json', confirmed=False, confirm=lambda prompt: 'no')
    assert counts(mysql) == [0, 0, 0, 0]


def test_partial_approved_config_preserves_existing_bindings(mysql, tmp_path):
    first = enroll(mysql, tmp_path / 'first.json')
    partial = {local.COLLECTOR_KEY: first[local.COLLECTOR_KEY], local.LOCAL_KEYS['ufw']: first[local.LOCAL_KEYS['ufw']]}
    with mysql.cursor() as cursor:
        cursor.execute('INSERT INTO ufw_state (logfile, last_position, file_device, file_inode, source_scope) '
                       'VALUES (%s, %s, %s, %s, %s)', ('ufw.log', 120, 1, 2, first[local.LOCAL_KEYS['ufw']]))
        cursor.execute('INSERT INTO auth_ingestion_state '
                       '(collector_id, file_device, file_inode, logfile, last_position, position_hash, source_scope) '
                       'VALUES (%s, %s, %s, %s, %s, %s, %s)',
                       ('reader', 1, 3, 'auth.log', 240, 'a' * 64, first[local.LOCAL_KEYS['auth']]))
    mysql.commit()
    before_positions = []
    with mysql.cursor() as cursor:
        for table in ('ufw_state', 'auth_ingestion_state'):
            cursor.execute(f'SELECT * FROM {table}')
            before_positions.append(cursor.fetchall())
    restored = enroll(mysql, tmp_path / 'recovery.json', configured=partial)
    with mysql.cursor() as cursor:
        for index, table in enumerate(('ufw_state', 'auth_ingestion_state')):
            cursor.execute(f'SELECT * FROM {table}')
            assert cursor.fetchall() == before_positions[index]
    assert restored[local.COLLECTOR_KEY] == partial[local.COLLECTOR_KEY]
    assert restored[local.LOCAL_KEYS['ufw']] == partial[local.LOCAL_KEYS['ufw']]
    assert restored == first
    assert counts(mysql) == [1, 1, 7, 7]
    assert enroll(mysql, tmp_path / 'recovery.json', configured=partial) == first
    assert enroll(mysql, tmp_path / 'recovery.json', configured=restored) == first
    assert counts(mysql) == [1, 1, 7, 7]


def test_required_missing_source_is_not_legacy(mysql, monkeypatch):
    apply_environment(monkeypatch, {})
    monkeypatch.setenv('SIEM_LOCAL_IDENTITY_REQUIRED', '1')
    with mysql.cursor() as cursor, pytest.raises(IdentityError, match='required local source'):
        configured_identity(cursor, 'system')


@pytest.mark.parametrize('source_type', local.LOCAL_TYPES)
def test_missing_source_setting_reuses_its_existing_id(mysql, tmp_path, source_type):
    first = enroll(mysql, tmp_path / 'first.json')
    partial = dict(first)
    del partial[local.LOCAL_KEYS[source_type]]
    recovery = tmp_path / 'recovery.json'
    assert enroll(mysql, recovery, configured=partial) == first
    assert enroll(mysql, recovery, configured=partial) == first
    assert counts(mysql) == [1, 1, 7, 7]


@pytest.mark.parametrize('fault', ['ambiguous', 'disabled-source', 'disabled-binding', 'unbound', 'disabled-collector'])
def test_partial_config_never_approves_or_duplicates_unsafe_sources(mysql, tmp_path, fault):
    from database.identity import approve_collector_source, register_source

    first = enroll(mysql, tmp_path / 'first.json')
    auth_id = first[local.LOCAL_KEYS['auth']]
    collector = first[local.COLLECTOR_KEY]
    host = local.read_receipt(tmp_path / 'first.json')['host_id']
    with mysql.cursor() as cursor:
        if fault == 'ambiguous':
            other = register_source(cursor, host, 'another-auth-source', 'auth', enabled=True)
            approve_collector_source(cursor, collector, other)
        elif fault == 'disabled-source':
            cursor.execute('UPDATE log_sources SET enabled = FALSE WHERE source_id = %s', (auth_id,))
        elif fault == 'disabled-binding':
            cursor.execute('UPDATE collector_sources SET enabled = FALSE WHERE collector_id = %s AND source_id = %s', (collector, auth_id))
        elif fault == 'unbound':
            cursor.execute('DELETE FROM collector_sources WHERE collector_id = %s AND source_id = %s', (collector, auth_id))
        else:
            cursor.execute('UPDATE collectors SET enabled = FALSE WHERE collector_id = %s', (collector,))
    mysql.commit()
    before = counts(mysql)
    with mysql.cursor() as cursor:
        cursor.execute('SELECT source_id, enabled FROM log_sources ORDER BY source_id')
        sources_before = cursor.fetchall()
        cursor.execute('SELECT collector_id, source_id, enabled FROM collector_sources ORDER BY collector_id, source_id')
        bindings_before = cursor.fetchall()
    partial = {local.COLLECTOR_KEY: collector, local.LOCAL_KEYS['ufw']: first[local.LOCAL_KEYS['ufw']]}
    with pytest.raises(IdentityError):
        enroll(mysql, tmp_path / 'recovery.json', configured=partial)
    assert counts(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute('SELECT source_id, enabled FROM log_sources ORDER BY source_id')
        assert cursor.fetchall() == sources_before
        cursor.execute('SELECT collector_id, source_id, enabled FROM collector_sources ORDER BY collector_id, source_id')
        assert cursor.fetchall() == bindings_before


@pytest.mark.parametrize('interrupted', [False, True])
def test_absent_sources_are_created_once_and_partial_setup_can_resume(mysql, tmp_path, monkeypatch, interrupted):
    from database.identity import (
        approve_collector_source,
        register_collector,
        register_source,
    )

    with mysql.cursor() as cursor:
        host = register_host(cursor, 'explicit-local-host')
        cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
        collector = register_collector(cursor, 'explicit-local-collector', enabled=True)
        source = register_source(cursor, host, 'explicit-local-ufw', 'ufw', enabled=True)
        approve_collector_source(cursor, collector, source)
    mysql.commit()
    partial = {local.COLLECTOR_KEY: collector, local.LOCAL_KEYS['ufw']: source}
    receipt = tmp_path / 'receipt.json'
    if interrupted:
        original = local.save_receipt

        def fail_after_commit(path, value):
            if value['phase'] == 'database_ready':
                raise OSError('simulated interruption after partial enrollment commit')
            original(path, value)

        with monkeypatch.context() as patch:
            patch.setattr(local, 'save_receipt', fail_after_commit)
            with pytest.raises(OSError):
                enroll(mysql, receipt, configured=partial)
        assert local.read_receipt(receipt)['phase'] == 'prepared'
        assert counts(mysql) == [1, 1, 7, 7]
    restored = enroll(mysql, receipt, configured=partial)
    assert restored[local.COLLECTOR_KEY] == collector
    assert restored[local.LOCAL_KEYS['ufw']] == source
    assert enroll(mysql, receipt, configured=partial) == restored
    assert counts(mysql) == [1, 1, 7, 7]


def test_partial_config_without_trusted_host_is_not_inferred(mysql, tmp_path):
    first = enroll(mysql, tmp_path / 'first.json')
    with pytest.raises(IdentityError, match='No persistent local host binding'):
        enroll(mysql, tmp_path / 'recovery.json', configured={local.COLLECTOR_KEY: first[local.COLLECTOR_KEY]})
    assert counts(mysql) == [1, 1, 7, 7]


def test_partial_config_with_unknown_source_is_not_replaced(mysql, tmp_path):
    first = enroll(mysql, tmp_path / 'first.json')
    partial = {local.COLLECTOR_KEY: first[local.COLLECTOR_KEY], local.LOCAL_KEYS['ufw']: 2**63}
    with pytest.raises(IdentityError):
        enroll(mysql, tmp_path / 'recovery.json', configured=partial)
    assert counts(mysql) == [1, 1, 7, 7]


def legacy_log_set(mysql, tmp_path, monkeypatch, rotations=0):
    """Use real collectors and only synthetic files in this test's directory."""
    from ingestion.auth.collector import get_logfiles

    apply_environment(monkeypatch, {})
    firewall = tmp_path / 'ufw.log'
    auth = tmp_path / 'auth.log'
    for base, make_line in ((firewall, ufw_line), (auth, ssh_line)):
        base.write_text(make_line(0))
        for number in range(1, rotations + 1):
            base.with_name(base.name + '.' + str(number)).write_text(make_line(number))
    monkeypatch.setattr(ufw, 'LOGFILE', str(firewall))
    ufw.process_log(mysql)
    collect_auth_events(mysql, str(auth), collector_id='reader')
    return firewall, auth, get_logfiles(str(firewall)), get_logfiles(str(auth))


def checkpoint_snapshot(mysql):
    result = []
    with mysql.cursor() as cursor:
        for table in ('ufw_state', 'auth_ingestion_state'):
            cursor.execute(f'SELECT * FROM {table} ORDER BY source_scope, file_device, file_inode')
            result.append(cursor.fetchall())
    return result


def test_all_rotated_logs_continue_without_cross_source_replay(mysql, tmp_path, monkeypatch):
    firewall, auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch, rotations=2)
    before = checkpoint_snapshot(mysql)
    # A rename is safe when every inode is still in the current rotation set.
    firewall.rename(tmp_path / 'ufw.log.3')
    (tmp_path / 'ufw.log.2').rename(firewall)
    auth.rename(tmp_path / 'auth.log.3')
    (tmp_path / 'auth.log.2').rename(auth)
    from ingestion.auth.collector import get_logfiles

    ufw_paths = get_logfiles(str(firewall))
    auth_paths = get_logfiles(str(auth))
    settings = enroll(mysql, tmp_path / 'receipt.json', ufw_paths=ufw_paths, auth_paths=auth_paths)
    apply_environment(monkeypatch, settings)
    assert ufw.process_log(mysql)['inserted'] == 0
    assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 0
    for base, line in ((firewall, ufw_line(10)), (auth, ssh_line(10))):
        with base.open('a') as output:
            output.write(line)
    assert ufw.process_log(mysql)['inserted'] == 1
    assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 1
    with mysql.cursor() as cursor:
        for table in ('ufw_log', 'auth_events'):
            cursor.execute(f'SELECT COUNT(*), COUNT(host_id), COUNT(DISTINCT event_hash) FROM {table}')
            assert cursor.fetchone() == (4, 1, 4)
        for index, table in enumerate(('ufw_state', 'auth_ingestion_state')):
            cursor.execute(f'SELECT * FROM {table} WHERE source_scope = 0 ORDER BY source_scope, file_device, file_inode')
            assert cursor.fetchall() == before[index]


@pytest.mark.parametrize('source_type', ['ufw', 'auth'])
@pytest.mark.parametrize('fault', ['missing-position', 'missing-file', 'inode', 'truncated',
                                  'regrown', 'wrong-path', 'untracked-rotation', 'stale-offset'])
def test_unsafe_log_transition_rolls_back_every_checkpoint(mysql, tmp_path, monkeypatch, source_type, fault):
    firewall, auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch, rotations=1)
    table = 'ufw_state' if source_type == 'ufw' else 'auth_ingestion_state'
    base = firewall if source_type == 'ufw' else auth
    line = ufw_line if source_type == 'ufw' else ssh_line
    info = base.stat()
    with mysql.cursor() as cursor:
        if fault == 'missing-position':
            cursor.execute(f'DELETE FROM {table} WHERE file_inode = %s', (info.st_ino,))
        elif fault == 'wrong-path':
            cursor.execute(f'UPDATE {table} SET logfile = %s WHERE file_inode = %s',
                           (str(tmp_path / 'another.log'), info.st_ino))
        elif fault == 'stale-offset':
            cursor.execute(f'UPDATE {table} SET last_position = 0 WHERE file_inode = %s', (info.st_ino,))
            if source_type == 'auth':
                import hashlib
                cursor.execute(f'UPDATE {table} SET position_hash = %s WHERE file_inode = %s',
                               (hashlib.sha256(b'').hexdigest(), info.st_ino))
    mysql.commit()
    if fault == 'missing-file':
        base.unlink()
    elif fault == 'inode':
        replacement = tmp_path / 'replacement'
        replacement.write_text(line(0))
        replacement.replace(base)
    elif fault == 'truncated':
        base.write_text('')
    elif fault == 'regrown':
        base.write_text(line(10) + line(11) + line(12))
    elif fault == 'untracked-rotation':
        base.with_name(base.name + '.2').write_text(line(20))
    before = checkpoint_snapshot(mysql)
    receipt = tmp_path / 'receipt.json'
    with pytest.raises(IdentityError):
        enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert counts(mysql) == [0, 0, 0, 0]
    assert checkpoint_snapshot(mysql) == before
    with mysql.cursor() as cursor:
        for events in ('ufw_log', 'auth_events'):
            cursor.execute(f'SELECT COUNT(*), COUNT(host_id) FROM {events}')
            assert cursor.fetchone() == (2, 0)
    assert local.read_receipt(receipt)['phase'] == 'prepared'


@pytest.mark.parametrize('source_type', ['ufw', 'auth'])
def test_regrown_prefix_is_rejected_even_when_checkpoint_tail_is_unchanged(mysql, tmp_path, monkeypatch, source_type):
    apply_environment(monkeypatch, {})
    path = tmp_path / ('ufw.log' if source_type == 'ufw' else 'auth.log')
    make_line = ufw_line if source_type == 'ufw' else ssh_line
    # The last 256 bytes are unchanged; an SSH tail hash alone would accept it.
    original = make_line(0) + make_line(1) * 6
    path.write_text(original)
    options = {'ufw_paths': [], 'auth_paths': []}
    if source_type == 'ufw':
        monkeypatch.setattr(ufw, 'LOGFILE', str(path))
        ufw.process_log(mysql)
        options['ufw_paths'] = [path]
    else:
        collect_auth_events(mysql, str(path), collector_id='reader')
        options['auth_paths'] = [path]
    info = path.stat()
    path.write_text(make_line(2) + make_line(1) * 6)
    assert path.stat().st_ino == info.st_ino
    assert path.stat().st_size == info.st_size
    before = checkpoint_snapshot(mysql)
    with pytest.raises(IdentityError, match='Consumed log content'):
        enroll(mysql, tmp_path / 'receipt.json', **options)
    assert checkpoint_snapshot(mysql) == before
    assert counts(mysql) == [0, 0, 0, 0]


def test_missing_position_can_be_repaired_by_legacy_collection_then_retried(mysql, tmp_path, monkeypatch):
    _firewall, auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch, rotations=1)
    with mysql.cursor() as cursor:
        cursor.execute('DELETE FROM auth_ingestion_state WHERE file_inode = %s', (auth.stat().st_ino,))
    mysql.commit()
    receipt = tmp_path / 'receipt.json'
    with pytest.raises(IdentityError, match='no legacy checkpoint'):
        enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert counts(mysql) == [0, 0, 0, 0]
    # Explicit synthetic legacy rerun restores the missing state without new events.
    assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 0
    settings = enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    apply_environment(monkeypatch, settings)
    assert ufw.process_log(mysql)['inserted'] == 0
    assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 0
    assert counts(mysql) == [1, 1, 7, 7]


@pytest.mark.parametrize('source_type', ['ufw', 'auth'])
@pytest.mark.parametrize('fault', ['same', 'advanced', 'other-source'])
def test_existing_registered_positions_are_never_overwritten(mysql, tmp_path, monkeypatch, source_type, fault):
    _firewall, _auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch)
    settings = enroll(mysql, tmp_path / 'receipt.json', ufw_paths=ufw_paths, auth_paths=auth_paths)
    table = 'ufw_state' if source_type == 'ufw' else 'auth_ingestion_state'
    source = settings[local.LOCAL_KEYS[source_type]]
    with mysql.cursor() as cursor:
        if fault == 'advanced':
            cursor.execute(f'UPDATE {table} SET last_position = last_position + 1 WHERE source_scope = %s', (source,))
        elif fault == 'other-source':
            other = settings[local.LOCAL_KEYS['system']]
            cursor.execute(f'UPDATE {table} SET source_scope = %s WHERE source_scope = %s', (other, source))
    mysql.commit()
    before = checkpoint_snapshot(mysql)
    with mysql.cursor() as cursor:
        if fault == 'same':
            local.copy_checkpoints(cursor, settings, auth_reader='reader', ufw_paths=ufw_paths, auth_paths=auth_paths)
        else:
            with pytest.raises(IdentityError):
                local.copy_checkpoints(cursor, settings, auth_reader='reader', ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert checkpoint_snapshot(mysql) == before
    mysql.rollback()


def test_checkpoint_copy_failure_after_first_insert_rolls_back_and_retries(mysql, tmp_path, monkeypatch):
    _firewall, auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch)
    before = checkpoint_snapshot(mysql)
    receipt = tmp_path / 'receipt.json'
    original = local.unchanged_checkpoint_files
    calls = []

    def fail_after_copies(*args):
        calls.append(args)
        if len(calls) == 3:
            raise IdentityError('simulated interruption after checkpoint inserts')
        return original(*args)

    with monkeypatch.context() as patch:
        patch.setattr(local, 'unchanged_checkpoint_files', fail_after_copies)
        with pytest.raises(IdentityError, match='simulated interruption'):
            enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert checkpoint_snapshot(mysql) == before
    assert counts(mysql) == [0, 0, 0, 0]
    settings = enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    apply_environment(monkeypatch, settings)
    assert ufw.process_log(mysql)['inserted'] == 0
    assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 0


def test_wrong_auth_reader_and_source_binding_fail_closed(mysql, tmp_path, monkeypatch):
    _firewall, _auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch)
    before = checkpoint_snapshot(mysql)
    with pytest.raises(IdentityError, match='SSH reader differs'):
        enroll(mysql, tmp_path / 'receipt.json', auth_reader='other', ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert checkpoint_snapshot(mysql) == before
    assert counts(mysql) == [0, 0, 0, 0]
    settings = enroll(mysql, tmp_path / 'receipt.json', ufw_paths=ufw_paths, auth_paths=auth_paths)
    wrong = dict(settings)
    wrong[local.LOCAL_KEYS['auth']] = settings[local.LOCAL_KEYS['ufw']]
    before = checkpoint_snapshot(mysql)
    with mysql.cursor() as cursor, pytest.raises(IdentityError):
        local.copy_checkpoints(cursor, wrong, auth_reader='reader', ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert checkpoint_snapshot(mysql) == before


@pytest.mark.parametrize('exists', [False, True])
def test_fresh_logs_do_not_need_legacy_positions(mysql, tmp_path, monkeypatch, exists):
    from ingestion.auth.collector import get_logfiles

    apply_environment(monkeypatch, {})
    firewall = tmp_path / 'ufw.log'
    auth = tmp_path / 'auth.log'
    if exists:
        firewall.write_text(ufw_line(0))
        auth.write_text(ssh_line(0))
    monkeypatch.setattr(ufw, 'LOGFILE', str(firewall))
    settings = enroll(mysql, tmp_path / 'receipt.json', ufw_paths=get_logfiles(str(firewall)),
                      auth_paths=get_logfiles(str(auth)))
    assert checkpoint_snapshot(mysql) == [(), ()]
    if exists:
        apply_environment(monkeypatch, settings)
        assert ufw.process_log(mysql)['inserted'] == 1
        assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 1
        assert ufw.process_log(mysql)['inserted'] == 0
        assert collect_auth_events(mysql, str(auth), collector_id='reader')['inserted'] == 0
        with mysql.cursor() as cursor:
            for table in ('ufw_log', 'auth_events'):
                cursor.execute(f'SELECT COUNT(*), COUNT(host_id) FROM {table}')
                assert cursor.fetchone() == (1, 1)


@pytest.mark.parametrize('change', ['append', 'rotate', 'truncate-regrow'])
def test_concurrent_log_change_aborts_transaction(mysql, tmp_path, monkeypatch, change):
    firewall, _auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch)
    original = local.validate_checkpoint_history
    changed = []

    def change_after_validation(*args):
        original(*args)
        if not changed:
            changed.append(True)
            if change == 'append':
                with firewall.open('a') as output:
                    output.write(ufw_line(1))
            elif change == 'rotate':
                firewall.rename(tmp_path / 'ufw.log.1')
                firewall.write_text(ufw_line(1))
            else:
                firewall.write_text(ufw_line(1))

    before = checkpoint_snapshot(mysql)
    with monkeypatch.context() as patch:
        patch.setattr(local, 'validate_checkpoint_history', change_after_validation)
        with pytest.raises(IdentityError, match='changed|rotation'):
            enroll(mysql, tmp_path / 'receipt.json', ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert counts(mysql) == [0, 0, 0, 0]
    assert checkpoint_snapshot(mysql) == before


@pytest.mark.parametrize('receipt_written', [False, True])
def test_committed_transition_cannot_skip_checkpoint_proof_on_retry(mysql, tmp_path, monkeypatch, receipt_written):
    firewall, _auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch)
    receipt = tmp_path / 'receipt.json'
    original = local.save_receipt

    def fail_after_commit(path, value):
        if value['phase'] == 'database_ready':
            raise OSError('simulated receipt write failure')
        return original(path, value)

    if receipt_written:
        expected = enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    else:
        with monkeypatch.context() as patch:
            patch.setattr(local, 'save_receipt', fail_after_commit)
            with pytest.raises(OSError):
                enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
        expected = None
    before = checkpoint_snapshot(mysql)
    old_bytes = firewall.read_bytes()
    firewall.write_text(ufw_line(10) + ufw_line(11))
    with pytest.raises(IdentityError, match='Consumed log content'):
        enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    assert counts(mysql) == [1, 1, 7, 7]
    assert checkpoint_snapshot(mysql) == before
    with mysql.cursor() as cursor:
        for table in ('ufw_log', 'auth_events'):
            cursor.execute(f'SELECT COUNT(*), COUNT(host_id) FROM {table}')
            assert cursor.fetchone() == (1, 0)
    firewall.write_bytes(old_bytes)
    recovered = enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    if expected is not None:
        assert recovered == expected
    assert checkpoint_snapshot(mysql) == before
    assert counts(mysql) == [1, 1, 7, 7]


def test_committed_transition_cannot_continue_while_legacy_writer_is_running(mysql, tmp_path, monkeypatch, identity_server):
    _firewall, _auth, ufw_paths, auth_paths = legacy_log_set(mysql, tmp_path, monkeypatch)
    receipt = tmp_path / 'receipt.json'
    expected = enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    before = checkpoint_snapshot(mysql)
    other = pymysql.connect(unix_socket=identity_server, user='root', connect_timeout=5)
    try:
        with other.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s, 0)', (local.LOCKS[0],))
            assert cursor.fetchone() == (1,)
        with pytest.raises(IdentityError, match='still running'):
            enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths)
    finally:
        other.close()
    assert enroll(mysql, receipt, ufw_paths=ufw_paths, auth_paths=auth_paths) == expected
    assert checkpoint_snapshot(mysql) == before
