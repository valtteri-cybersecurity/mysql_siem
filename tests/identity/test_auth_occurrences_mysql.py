"""Private MySQL: occurrence IDs, evidence, rollback, scoped sources and additive DDL."""
import hashlib
from datetime import datetime, timedelta

import pymysql
import pytest

from database import auth_occurrence_schema, migrate
from database.identity import (
    EventIdentity,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from detection.ssh_brute_force.runner import run_automatic
from ingestion.auth.collector import (
    AuthCollectionError,
    collect_auth_events,
    position_hash,
)
from ingestion.auth.db import save_event
from ingestion.auth.parser import parse_auth_line

LINE = (b'2026-11-06T12:00:00Z same-name sshd[123]: Failed password for alice '
        b'from 192.0.2.1 port 2222 ssh2\n')
NOW = datetime(2026, 11, 6, 12, 0, 1)
CONFIG = {'batch_size': 1000, 'late_seconds': 600, 'max_buffer_events': 10000}


def rows(connection, sql, values=()):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute(sql, values)
        return cursor.fetchall()


def event_rows(connection):
    return rows(connection, 'SELECT id,event_time,event_hash,raw_message,host_id,source_id,collector_id,'
                           'source_scope,file_generation,file_position FROM auth_events ORDER BY id')


def register(connection, name):
    with connection.cursor() as cursor:
        host = register_host(cursor, name)
        cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
        collector = register_collector(cursor, name + '-reader', enabled=True)
        source = register_source(cursor, host, name + '-auth', 'auth', enabled=True)
        approve_collector_source(cursor, collector, source)
    connection.commit()
    return EventIdentity(host, source, collector)


def configure(monkeypatch, identity):
    monkeypatch.setenv('SIEM_COLLECTOR_ID', str(identity.collector_id))
    monkeypatch.setenv('SIEM_AUTH_SOURCE_ID', str(identity.source_id))


def test_identical_occurrences_replay_rotation_atomicity_and_ssh_evidence(mysql, tmp_path, monkeypatch):
    first = register(mysql, 'first-auth-host')
    configure(monkeypatch, first)
    path = tmp_path / 'auth.log'
    path.write_bytes(LINE * 5)
    stats = {}
    assert collect_auth_events(mysql, path, collector_id='reader', stats=stats)['inserted'] == 5
    original = event_rows(mysql)
    assert len(original) == 5
    event_hash = parse_auth_line(LINE.decode())['event_hash']
    generation = original[0][8]
    positions = []
    for event in original:
        assert event[2] == event_hash
        assert event[4:8] == (first.host_id, first.source_id, first.collector_id, first.source_id)
        assert event[8] == generation
        positions.append(event[9])
    assert positions == [0, len(LINE), 2 * len(LINE), 3 * len(LINE), 4 * len(LINE)]
    with mysql.cursor() as cursor:
        cursor.execute('UPDATE auth_ingestion_state SET last_position=0,position_hash=%s,prefix_sha=%s '
                       'WHERE source_scope=%s', (hashlib.sha256(b'').hexdigest(), hashlib.sha256(b'').hexdigest(), first.source_id))
    mysql.commit()
    assert collect_auth_events(mysql, path, collector_id='reader', stats=stats)['inserted'] == 0
    assert stats['duplicates'] == 5
    assert event_rows(mysql) == original
    small_batch = dict(CONFIG, batch_size=2)
    for _attempt in range(3):
        run_automatic(mysql, small_batch, now=NOW)
    assert rows(mysql, 'SELECT COUNT(*) FROM detection_alerts') == ((1,),)
    evidence = rows(mysql, 'SELECT event_type,event_id FROM alert_evidence ORDER BY event_id')
    expected = []
    for event in original:
        expected.append(('AUTH', event[0]))
    assert evidence == tuple(expected)
    run_automatic(mysql, CONFIG, now=NOW + timedelta(seconds=1))
    assert rows(mysql, 'SELECT COUNT(*) FROM alert_evidence') == ((5,),)

    rotation = tmp_path / 'auth.log.1'
    path.rename(rotation)
    fresh = LINE.replace(b'port 2222', b'port 3333')
    path.write_bytes(fresh)
    assert collect_auth_events(mysql, path, collector_id='reader')['inserted'] == 1
    assert event_rows(mysql)[:5] == original
    assert rows(mysql, 'SELECT generation_key FROM auth_ingestion_state WHERE file_inode=%s AND source_scope=%s',
                (rotation.stat().st_ino, first.source_id)) == ((generation,),)
    before = event_rows(mysql)
    checkpoints = rows(mysql, 'SELECT * FROM auth_ingestion_state ORDER BY source_scope,file_inode')
    appended = LINE.replace(b'port 2222', b'port 4444')
    with path.open('ab') as output:
        output.write(appended * 2)
    reject_position = len(fresh) + len(appended)
    with mysql.cursor() as cursor:
        cursor.execute('CREATE TRIGGER reject_auth_occurrence BEFORE INSERT ON auth_events FOR EACH ROW '
                       'BEGIN IF NEW.file_position=' + str(reject_position) + " THEN SIGNAL SQLSTATE '45000' "
                       "SET MESSAGE_TEXT='synthetic second occurrence failure'; END IF; END")
    with pytest.raises(pymysql.MySQLError):
        collect_auth_events(mysql, path, collector_id='reader')
    assert event_rows(mysql) == before
    assert rows(mysql, 'SELECT * FROM auth_ingestion_state ORDER BY source_scope,file_inode') == checkpoints
    with mysql.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_auth_occurrence')
    assert collect_auth_events(mysql, path, collector_id='reader')['inserted'] == 2
    assert event_rows(mysql)[:len(before)] == before

    before = event_rows(mysql)
    checkpoints = rows(mysql, 'SELECT * FROM auth_ingestion_state ORDER BY source_scope,file_inode')
    with path.open('ab') as output:
        output.write(LINE.replace(b'port 2222', b'port 5555'))
    def fail_commit():
        raise pymysql.OperationalError(2013, 'synthetic commit acknowledgement failure')
    with monkeypatch.context() as failure:
        failure.setattr(mysql, 'commit', fail_commit)
        with pytest.raises(pymysql.OperationalError):
            collect_auth_events(mysql, path, collector_id='reader')
    assert event_rows(mysql) == before
    assert rows(mysql, 'SELECT * FROM auth_ingestion_state ORDER BY source_scope,file_inode') == checkpoints
    assert collect_auth_events(mysql, path, collector_id='reader')['inserted'] == 1

    second = register(mysql, 'second-auth-host')
    configure(monkeypatch, second)
    other = tmp_path / 'other-auth.log'
    other.write_bytes(LINE * 5)
    assert collect_auth_events(mysql, other, collector_id='reader')['inserted'] == 5
    with mysql.cursor() as cursor:
        third_source = register_source(cursor, first.host_id, 'first-host-second-auth', 'auth', enabled=True)
        approve_collector_source(cursor, first.collector_id, third_source)
    mysql.commit()
    third = EventIdentity(first.host_id, third_source, first.collector_id)
    configure(monkeypatch, third)
    extra = tmp_path / 'extra-auth.log'
    extra.write_bytes(LINE)
    assert collect_auth_events(mysql, extra, collector_id='reader')['inserted'] == 1
    assert rows(mysql, 'SELECT source_scope,COUNT(*) FROM auth_events GROUP BY source_scope ORDER BY source_scope') == (
        (first.source_id, 9), (second.source_id, 5), (third.source_id, 1))
    run_automatic(mysql, CONFIG, now=NOW + timedelta(seconds=2))
    assert rows(mysql, 'SELECT COUNT(*) FROM detection_alerts') == ((2,),)
    assert rows(mysql, 'SELECT COUNT(*) FROM alert_evidence') == ((15,),)

    configure(monkeypatch, first)
    before = event_rows(mysql)
    checkpoints = rows(mysql, 'SELECT * FROM auth_ingestion_state ORDER BY source_scope,file_inode')
    copied = tmp_path / 'copied-auth.log'
    copied.write_bytes(rotation.read_bytes())
    with pytest.raises(AuthCollectionError, match='Ambiguous Auth occurrence'):
        collect_auth_events(mysql, copied, collector_id='reader')
    assert event_rows(mysql) == before
    assert rows(mysql, 'SELECT * FROM auth_ingestion_state ORDER BY source_scope,file_inode') == checkpoints


def test_migration_preserves_old_rows_checkpoints_and_evidence_and_resumes(empty_mysql, tmp_path, monkeypatch):
    previous = []
    for item in migrate.MIGRATIONS:
        if item[0] < '032':
            previous.append(item)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(previous))
        migrate.migrate(empty_mysql)
    identity = register(empty_mysql, 'legacy-auth-host')
    configure(monkeypatch, identity)
    path = tmp_path / 'legacy-auth.log'
    content = bytearray()
    with empty_mysql.cursor() as cursor:
        for pid in range(100, 105):
            line = LINE.replace(b'sshd[123]', ('sshd[' + str(pid) + ']').encode())
            content.extend(line)
            assert save_event(cursor, parse_auth_line(line.decode()), identity=identity) == 1
    empty_mysql.commit()
    path.write_bytes(content)
    with path.open('rb') as source:
        fingerprint = position_hash(source, len(content))
    with empty_mysql.cursor() as cursor:
        cursor.execute('INSERT INTO auth_ingestion_state '
                       '(collector_id,file_device,file_inode,logfile,last_position,position_hash,source_scope) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                       ('legacy-reader', path.stat().st_dev, path.stat().st_ino, str(path), len(content), fingerprint, identity.source_id))
    empty_mysql.commit()
    run_automatic(empty_mysql, CONFIG, now=NOW)
    before = rows(empty_mysql, 'SELECT id,event_time,event_hash,raw_message,host_id,source_id,collector_id,source_scope '
                              'FROM auth_events ORDER BY id')
    checkpoint = rows(empty_mysql, 'SELECT collector_id,file_device,file_inode,logfile,last_position,position_hash,source_scope '
                                   'FROM auth_ingestion_state')
    alerts = rows(empty_mysql, 'SELECT * FROM detection_alerts')
    evidence = rows(empty_mysql, 'SELECT * FROM alert_evidence ORDER BY event_id')
    detection_state = rows(empty_mysql, 'SELECT * FROM detection_state')
    add = auth_occurrence_schema.add_column
    def interrupt(cursor, table, name, definition):
        add(cursor, table, name, definition)
        raise RuntimeError('synthetic interrupted Auth occurrence DDL')
    with monkeypatch.context() as failure:
        failure.setattr(auth_occurrence_schema, 'add_column', interrupt)
        with pytest.raises(RuntimeError, match='synthetic interrupted'):
            migrate.migrate(empty_mysql)
    assert migrate.migrate(empty_mysql) == ['032']
    assert migrate.migrate(empty_mysql) == []
    assert rows(empty_mysql, 'SELECT id,event_time,event_hash,raw_message,host_id,source_id,collector_id,source_scope '
                            'FROM auth_events ORDER BY id') == before
    assert rows(empty_mysql, 'SELECT collector_id,file_device,file_inode,logfile,last_position,position_hash,source_scope '
                            'FROM auth_ingestion_state') == checkpoint
    assert rows(empty_mysql, 'SELECT * FROM detection_alerts') == alerts
    assert rows(empty_mysql, 'SELECT * FROM alert_evidence ORDER BY event_id') == evidence
    assert rows(empty_mysql, 'SELECT * FROM detection_state') == detection_state
    assert rows(empty_mysql, 'SELECT DISTINCT file_generation,file_position FROM auth_events') == ((None, None),)
    with pytest.raises(AuthCollectionError, match='Legacy Auth checkpoint'):
        collect_auth_events(empty_mysql, path, collector_id='legacy-reader')
    assert rows(empty_mysql, 'SELECT collector_id,file_device,file_inode,logfile,last_position,position_hash,source_scope '
                            'FROM auth_ingestion_state') == checkpoint
