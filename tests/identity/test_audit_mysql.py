"""Audit transactions on the existing private, socket-only MySQL fixture.

Never use application DB_* settings, real audit logs or system services.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

import pymysql
import pytest

from database import migrate
from database.identity import (
    EventIdentity,
    IdentityError,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from ingestion.audit import database, get, main

NOW = datetime.fromtimestamp(1792886500, timezone.utc)
HEALTH = {'boot_id': '00000000-0000-0000-0000-000000000001'}


@pytest.fixture(scope='module')
def audit_database(identity_server):
    connection = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4',
                                 autocommit=False, read_timeout=30, write_timeout=30,
                                 init_command="SET time_zone = '+00:00'")
    name = 'audit_test_' + uuid4().hex
    try:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE DATABASE `{name}` CHARACTER SET utf8mb4')
        connection.select_db(name)
        migrate.migrate(connection)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def audit_mysql(audit_database, monkeypatch):
    audit_database.rollback()
    with audit_database.cursor() as cursor:
        for table in ('audit_events', 'audit_checkpoints', 'collector_sources',
                      'log_sources', 'collectors', 'hosts'):
            cursor.execute(f'DELETE FROM {table}')
    audit_database.commit()
    monkeypatch.setattr(get, 'LOG_OWNER', os.getuid())
    monkeypatch.setattr(main, 'runtime_health', Mock(return_value=dict(HEALTH)))
    try:
        yield audit_database
    finally:
        audit_database.rollback()


def enroll(connection, monkeypatch):
    with connection.cursor() as cursor:
        host = register_host(cursor, 'synthetic-audit-host')
        cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
        collector = register_collector(cursor, 'synthetic-audit-' + str(host), enabled=True)
        source = register_source(cursor, host, 'synthetic-audit', 'audit', enabled=True)
        approve_collector_source(cursor, collector, source)
    connection.commit()
    monkeypatch.setenv('SIEM_AUDIT_SOURCE_ID', str(source))
    monkeypatch.setenv('SIEM_COLLECTOR_ID', str(collector))
    return EventIdentity(host, source, collector)


def event_text(path='/etc/passwd', serial=12, extra_path=None):
    identity = '1792886390.123:' + str(serial)
    paths = [path]
    if extra_path is not None:
        paths.append(extra_path)
    lines = [(f'type=SYSCALL msg=audit({identity}): arch=c000003e syscall=257 '
             f'success=yes exit=3 a0=ffffff9c a2=241 items={len(paths)} '
             'ppid=10 pid=20 auid=1000 uid=0 euid=0 comm="test-editor" '
             'exe="/usr/bin/test-editor" key="siem_passwd"')]
    for index, name in enumerate(paths):
        lines.append(f'type=PATH msg=audit({identity}): item={index} name="{name}" '
                     'inode=200 dev=08:01 nametype=NORMAL')
    return '\n'.join(lines) + '\n'


def write_log(path, text):
    path.write_text(text)
    path.chmod(0o600)
    return path


def rows(connection, table):
    if table not in ('audit_events', 'audit_checkpoints'):
        raise ValueError('Unexpected test table.')
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT * FROM {table} ORDER BY host_id, source_id')
        return cursor.fetchall()


def other_connection(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        name = cursor.fetchone()[0]
    return pymysql.connect(unix_socket=connection._sock.getpeername(), user='root', database=name,
                           autocommit=False, read_timeout=10, write_timeout=10,
                           init_command="SET time_zone = '+00:00'")


@pytest.mark.parametrize('path,target', [
    ('/etc/passwd', 'passwd'), ('/etc/shadow', 'shadow'),
    ('/etc/sudoers', 'sudoers'), ('/etc/sudoers.d/admin', 'sudoers'),
])
def test_registered_collection_and_durable_resume(audit_mysql, monkeypatch, tmp_path, path, target):
    identity = enroll(audit_mysql, monkeypatch)
    logfile = write_log(tmp_path / 'audit.log', event_text(path))
    assert main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)['inserted'] == 1
    events = rows(audit_mysql, 'audit_events')
    checkpoints = rows(audit_mysql, 'audit_checkpoints')
    assert len(events) == 1 and len(checkpoints) == 1
    assert events[0][1:5] == identity.values()
    assert events[0][5:7] == (target, path)
    assert checkpoints[0][:4] == identity.values()
    assert json.loads(checkpoints[0][4])['offset'] == logfile.stat().st_size
    assert main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)['inserted'] == 0
    assert len(rows(audit_mysql, 'audit_events')) == 1


def test_replay_deduplicates_without_losing_multi_path_event(audit_mysql, monkeypatch, tmp_path):
    identity = enroll(audit_mysql, monkeypatch)
    logfile = write_log(tmp_path / 'audit.log', event_text(extra_path='/etc/shadow'))
    main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    with audit_mysql.cursor() as cursor:
        checkpoint = database.load_checkpoint(cursor, identity)
        checkpoint['offset'] = 0
        checkpoint['fingerprint'] = hashlib.sha256(b'').hexdigest()
        cursor.execute('UPDATE audit_checkpoints SET position = %s WHERE source_id = %s',
                       (json.dumps(checkpoint), identity.source_id))
    audit_mysql.commit()
    result = main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    assert result['inserted'] == 0 and result['duplicates'] == 1
    events = rows(audit_mysql, 'audit_events')
    assert len(events) == 1
    metadata = json.loads(events[0][-1])
    assert len(metadata['paths']) == 2
    assert set(metadata['targets']) == {'passwd', 'shadow'}


@pytest.mark.parametrize('table', ['audit_events', 'audit_checkpoints'])
def test_real_insert_error_rolls_back_history_and_position(audit_mysql, monkeypatch, tmp_path, table):
    enroll(audit_mysql, monkeypatch)
    logfile = write_log(tmp_path / 'audit.log', event_text(serial=12) + event_text(serial=13))
    with audit_mysql.cursor() as cursor:
        if table == 'audit_events':
            cursor.execute("CREATE TRIGGER audit_test_failure BEFORE INSERT ON audit_events FOR EACH ROW "
                           "BEGIN IF NEW.audit_event_id LIKE '%:13' THEN "
                           "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic insert failure'; END IF; END")
        else:
            cursor.execute("CREATE TRIGGER audit_test_failure BEFORE INSERT ON audit_checkpoints FOR EACH ROW "
                           "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic checkpoint failure'")
    audit_mysql.commit()
    try:
        with pytest.raises(pymysql.MySQLError):
            main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
        assert rows(audit_mysql, 'audit_events') == ()
        assert rows(audit_mysql, 'audit_checkpoints') == ()
    finally:
        with audit_mysql.cursor() as cursor:
            cursor.execute('DROP TRIGGER audit_test_failure')
        audit_mysql.commit()
    assert main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)['inserted'] == 2


@pytest.mark.parametrize('fault', ['interrupt', 'commit-before', 'commit-after'])
def test_interruption_and_uncertain_commit_are_safe_to_retry(audit_mysql, monkeypatch, tmp_path, fault):
    enroll(audit_mysql, monkeypatch)
    logfile = write_log(tmp_path / 'audit.log', event_text())
    original_save = database.save_batch
    original_commit = audit_mysql.commit

    def interrupted_save(cursor, identity, events, checkpoint):
        original_save(cursor, identity, events, checkpoint)
        raise KeyboardInterrupt

    def failed_commit():
        if fault == 'commit-after':
            original_commit()
        raise pymysql.OperationalError(2013, 'synthetic acknowledgement loss')

    with monkeypatch.context() as patch:
        if fault == 'interrupt':
            patch.setattr(database, 'save_batch', interrupted_save)
        else:
            patch.setattr(audit_mysql, 'commit', failed_commit)
        with pytest.raises((KeyboardInterrupt, pymysql.OperationalError)):
            main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    expected = 1 if fault == 'commit-after' else 0
    assert len(rows(audit_mysql, 'audit_events')) == expected
    assert len(rows(audit_mysql, 'audit_checkpoints')) == expected
    assert main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)['inserted'] == 1 - expected
    assert len(rows(audit_mysql, 'audit_events')) == 1


@pytest.mark.parametrize('invalid', ['missing', 'host', 'source', 'collector', 'approval', 'wrong-type'])
def test_invalid_identity_prevents_source_read_and_writes(audit_mysql, monkeypatch, invalid):
    identity = enroll(audit_mysql, monkeypatch)
    with audit_mysql.cursor() as cursor:
        if invalid == 'missing':
            monkeypatch.delenv('SIEM_AUDIT_SOURCE_ID')
        elif invalid == 'host':
            cursor.execute("UPDATE hosts SET enrollment_status = 'DISABLED' WHERE host_id = %s", (identity.host_id,))
        elif invalid == 'source':
            cursor.execute('UPDATE log_sources SET enabled = FALSE WHERE source_id = %s', (identity.source_id,))
        elif invalid == 'collector':
            cursor.execute('UPDATE collectors SET enabled = FALSE WHERE collector_id = %s', (identity.collector_id,))
        elif invalid == 'approval':
            cursor.execute('UPDATE collector_sources SET enabled = FALSE WHERE source_id = %s', (identity.source_id,))
        else:
            cursor.execute("UPDATE log_sources SET source_type = 'auth' WHERE source_id = %s", (identity.source_id,))
    audit_mysql.commit()
    reader = Mock(side_effect=AssertionError('must not read'))
    monkeypatch.setattr(main, 'read_log_batch', reader)
    with pytest.raises(IdentityError):
        main.collect_to_mysql(audit_mysql)
    reader.assert_not_called()
    assert rows(audit_mysql, 'audit_events') == ()
    assert rows(audit_mysql, 'audit_checkpoints') == ()


def test_two_hosts_keep_events_and_checkpoints_separate(audit_mysql, monkeypatch, tmp_path):
    first = enroll(audit_mysql, monkeypatch)
    logfile = write_log(tmp_path / 'audit.log', event_text())
    main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    second = enroll(audit_mysql, monkeypatch)
    main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    events = rows(audit_mysql, 'audit_events')
    assert len(events) == 2
    assert events[0][1:5] == first.values()
    assert events[1][1:5] == second.values()
    assert events[0][10] != events[1][10]
    assert len(rows(audit_mysql, 'audit_checkpoints')) == 2


def test_second_database_session_cannot_overlap_writer(audit_mysql, monkeypatch, tmp_path):
    enroll(audit_mysql, monkeypatch)
    logfile = write_log(tmp_path / 'audit.log', event_text())
    second = other_connection(audit_mysql)
    lock = None
    try:
        identity, lock = database.begin_collection(audit_mysql)
        assert identity is not None
        result = main.collect_to_mysql(second, logfile=logfile, now=NOW)
        assert result['status'] == 'busy'
        assert rows(second, 'audit_events') == ()
        assert rows(second, 'audit_checkpoints') == ()
        audit_mysql.rollback()
        database.release_lock(audit_mysql, lock)
        lock = None
        assert main.collect_to_mysql(second, logfile=logfile, now=NOW)['inserted'] == 1
    finally:
        audit_mysql.rollback()
        database.release_lock(audit_mysql, lock)
        second.close()


@pytest.mark.parametrize('resumed', [False, True])
def test_log_rewrite_never_commits_events_or_checkpoint(audit_mysql, monkeypatch, tmp_path, resumed):
    enroll(audit_mysql, monkeypatch)
    original = event_text(serial=12)
    logfile = write_log(tmp_path / 'audit.log', original)
    replacement = event_text(serial=14)
    if resumed:
        main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
        logfile.write_text(original + event_text(serial=13))
        replacement = original + replacement
    old_events = rows(audit_mysql, 'audit_events')
    old_checkpoints = rows(audit_mysql, 'audit_checkpoints')
    inode = logfile.stat().st_ino
    parse = get.parse_events
    rewritten = False

    def rewrite_then_parse(*args, **kwargs):
        nonlocal rewritten
        if not rewritten:
            logfile.write_text(replacement)
            rewritten = True
        return parse(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(get, 'parse_events', rewrite_then_parse)
        with pytest.raises(RuntimeError, match='Audit log bytes changed'):
            main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    assert logfile.stat().st_ino == inode
    assert rows(audit_mysql, 'audit_events') == old_events
    assert rows(audit_mysql, 'audit_checkpoints') == old_checkpoints

    result = main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)
    assert result['inserted'] == 1
    serials = []
    for row in rows(audit_mysql, 'audit_events'):
        serials.append(json.loads(row[-1])['serial'])
    expected = [14]
    if resumed:
        expected = [12, 14]
    assert sorted(serials) == expected
    assert main.collect_to_mysql(audit_mysql, logfile=logfile, now=NOW)['inserted'] == 0
