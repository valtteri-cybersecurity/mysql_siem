"""Occurrence identity, fail-closed ambiguity and additive migration on private MySQL."""
import gzip
import hashlib
import shutil
from datetime import datetime

import pymysql
import pytest

from database import migrate, ufw_occurrence_schema
from database.identity import (
    EventIdentity,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from ingestion import ufw_filters as filters
from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_batch import OccurrenceConflict
from tests.identity.test_ufw_filtering_mysql import collection as collection  # noqa: PLC0414 -- pytest fixture re-export

LINE = (b'2026-10-29T12:00:00Z host [UFW AUDIT] IN=lo OUT= SRC=127.0.0.1 '
        b'DST=127.0.0.1 PROTO=TCP SPT=12345 DPT=3306\n')


def rows(connection, query, values=()):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute(query, values)
        return cursor.fetchall()


def raw_rows(connection):
    return rows(connection, 'SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id')


def rewind_checkpoint(connection):
    # Force a real replay only in this private test database, not an EOF no-op.
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute('UPDATE ufw_file_checkpoints SET byte_position=0,prefix_sha=%s',
                       (hashlib.sha256(b'').hexdigest(),))
    connection.commit()


def test_raw_filtered_replay_failures_and_ambiguous_sources(collection, monkeypatch, tmp_path, capsys):
    admin, runtime, path, host, source = collection
    path.write_bytes(LINE * 2)
    result = ufw.process_log(runtime)
    assert result['inserted'] == 2
    assert result['duplicates'] == 0
    original = raw_rows(admin)
    assert len(original) == 2
    assert original[0][0] != original[1][0]
    assert original[0][1:] == original[1][1:]
    assert original[0][2] == hashlib.sha256(LINE.strip()).hexdigest()
    assert ufw.process_log(runtime)['inserted'] == 0
    rewind_checkpoint(admin)
    runtime.rollback()
    replay = ufw.process_log(runtime)
    assert replay['inserted'] == 0
    assert replay['duplicates'] == 2
    assert raw_rows(admin) == original

    # Identical bytes remain distinct across SQL batch and invocation boundaries.
    monkeypatch.setattr('ingestion.ufw_batch.MAX_ROWS', 1)
    with path.open('ab') as output:
        output.write(LINE * 3)
    assert ufw.process_log(runtime, max_lines=1)['inserted'] == 1
    assert ufw.process_log(runtime)['inserted'] == 2
    assert len(raw_rows(admin)) == 5

    filters.change(admin, source, host, True, actor='private-test',
                   reason='occurrence regression', acknowledge_risk=True)
    with path.open('ab') as output:
        output.write(LINE * 2)
    result = ufw.process_log(runtime)
    assert result['filtered'] == 2
    assert result['duplicates'] == 0
    original = raw_rows(admin)
    assert len(original) == 5
    assert rows(admin, 'SELECT SUM(filtered_count) FROM ufw_filter_stats WHERE source_id=%s', (source,)) == ((2,),)
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_filter_seen WHERE source_id=%s', (source,)) == ((2,),)
    rewind_checkpoint(admin)
    runtime.rollback()
    replay = ufw.process_log(runtime)
    assert replay['filtered'] == replay['inserted'] == 0
    assert replay['duplicates'] == 7
    assert raw_rows(admin) == original
    assert rows(admin, 'SELECT SUM(filtered_count) FROM ufw_filter_stats WHERE source_id=%s', (source,)) == ((2,),)

    # Replay must preserve the original decision after a filter configuration change.
    filters.change(admin, source, host, False, actor='private-test', reason='retain details')
    rewind_checkpoint(admin)
    runtime.rollback()
    assert ufw.process_log(runtime)['inserted'] == 0
    assert raw_rows(admin) == original
    with path.open('ab') as output:
        output.write(LINE)
    assert ufw.process_log(runtime)['inserted'] == 1
    assert len(raw_rows(admin)) == 6

    # A failed filtered INSERT rolls back events, counters and the shared checkpoint.
    filters.change(admin, source, host, True, actor='private-test',
                   reason='transaction regression', acknowledge_risk=True)
    before_events = raw_rows(admin)
    before_checkpoints = rows(admin, 'SELECT * FROM ufw_file_checkpoints ORDER BY id')
    before_seen = rows(admin, 'SELECT * FROM ufw_filter_seen ORDER BY file_position')
    before_stats = rows(admin, 'SELECT * FROM ufw_filter_stats')
    with admin.cursor() as cursor:
        cursor.execute("CREATE TRIGGER reject_seen BEFORE INSERT ON ufw_filter_seen FOR EACH ROW "
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic occurrence failure'")
    with path.open('ab') as output:
        output.write(LINE.replace(b'AUDIT', b'BLOCK') + LINE)
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(runtime)
    assert raw_rows(admin) == before_events
    assert rows(admin, 'SELECT * FROM ufw_file_checkpoints ORDER BY id') == before_checkpoints
    assert rows(admin, 'SELECT * FROM ufw_filter_seen ORDER BY file_position') == before_seen
    assert rows(admin, 'SELECT * FROM ufw_filter_stats') == before_stats
    with admin.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_seen')
    retry = ufw.process_log(runtime)
    assert retry['inserted'] == retry['filtered'] == 1

    # Losing the reply after COMMIT must not create new occurrences on retry.
    with path.open('ab') as output:
        output.write(LINE.replace(b'AUDIT', b'BLOCK'))
    real_commit = runtime.commit
    attempts = [0]
    def lost_reply():
        attempts[0] += 1
        real_commit()
        if attempts[0] == 2:
            raise pymysql.OperationalError(2013, 'synthetic lost commit reply')
    with monkeypatch.context() as lost:
        lost.setattr(runtime, 'commit', lost_reply)
        with pytest.raises(pymysql.MySQLError):
            ufw.process_log(runtime)
    committed = raw_rows(admin)
    assert ufw.process_log(runtime)['inserted'] == 0
    assert raw_rows(admin) == committed

    # A second source has its own occurrence namespace and exact filter counter.
    with admin.cursor() as cursor:
        cursor.execute('SELECT collector_id FROM ufw_log WHERE source_scope=%s LIMIT 1', (source,))
        collector = cursor.fetchone()[0]
        other = register_source(cursor, host, 'private-other-ufw', 'ufw', enabled=True)
        approve_collector_source(cursor, collector, other)
    admin.commit()
    other_path = tmp_path / 'other-source.log'
    other_path.write_bytes(LINE * 2)
    stats = {'lines_read': 0}
    with runtime.cursor() as cursor:
        ufw.process_file(cursor, str(other_path), identity=EventIdentity(host, other, collector),
                         batch=True, policy=True, stats=stats)
    runtime.commit()
    assert stats['filtered'] == 2
    assert rows(admin, 'SELECT SUM(filtered_count) FROM ufw_filter_stats WHERE source_id=%s', (other,)) == ((2,),)

    # A copy has no trusted lineage: do not silently discard it or count it again.
    copied = path.with_name('ufw.log.9')
    copied.write_bytes(path.read_bytes())
    original = raw_rows(admin)
    with pytest.raises(OccurrenceConflict, match='UFW_AMBIGUOUS_OCCURRENCE_SOURCE'):
        ufw.process_log(runtime)
    assert raw_rows(admin) == original
    copied.unlink()
    assert 'UFW_AMBIGUOUS_OCCURRENCE_SOURCE' in capsys.readouterr().out

    # Ordinary rename rotation keeps the exact generation and occurrence IDs.
    path.rename(path.with_name('ufw.log.1'))
    path.write_bytes(b'')
    assert ufw.process_log(runtime)['inserted'] == 0
    assert raw_rows(admin) == original

    # A fresh archive contains two occurrences, and its own replay inserts none.
    archive_line = LINE.replace(b'AUDIT', b'BLOCK').rstrip(b'\n') + b' UID=archive\n'
    archived = path.with_name('ufw.log.8.gz')
    archived.write_bytes(gzip.compress(archive_line * 2, mtime=0))
    assert ufw.process_log(runtime)['inserted'] == 2
    original = raw_rows(admin)
    assert ufw.process_log(runtime)['inserted'] == 0
    assert raw_rows(admin) == original
    copied_archive = path.with_name('ufw.log.7.gz')
    shutil.copyfile(archived, copied_archive)
    with pytest.raises(OccurrenceConflict, match='UFW_AMBIGUOUS_ARCHIVE_COPY'):
        ufw.process_log(runtime)
    assert raw_rows(admin) == original
    copied_archive.unlink()

    overlap = path.with_name('ufw.log.6.gz')
    overlap.write_bytes(gzip.compress(LINE * 2, mtime=0))
    assert ufw.process_log(runtime)['status'] == 'FAILED'
    assert raw_rows(admin) == original
    assert 'UFW_AMBIGUOUS_OCCURRENCE_SOURCE' in capsys.readouterr().out


def test_migration_preserves_history_and_resumes_after_ddl(empty_mysql, monkeypatch):
    connection = empty_mysql
    previous = []
    for entry in migrate.MIGRATIONS:
        if entry[0] < '029':
            previous.append(entry)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(previous))
        migrate.migrate(connection)
    with connection.cursor() as cursor:
        assert ufw.save_event(cursor, LINE.decode()) == 1
        host = register_host(cursor, 'legacy-ufw-host')
        collector = register_collector(cursor, 'legacy-ufw-collector', enabled=True)
        source = register_source(cursor, host, 'legacy-ufw-source', 'ufw', enabled=True)
        approve_collector_source(cursor, collector, source)
        filters.record_counts(cursor, EventIdentity(host, source, collector),
                              [('e' * 64, {'event_time': datetime(2026, 10, 29, 12)})])
        cursor.execute('INSERT INTO ufw_file_checkpoints '
                       '(source_scope,file_device,file_inode,filename,byte_position,prefix_sha,observed_size,observed_sha,status,checked_at) '
                       "VALUES (0,1,2,'/synthetic/ufw.log',123,%s,123,%s,'CAUGHT_UP',UTC_TIMESTAMP(6))", ('a' * 64, 'a' * 64))
    connection.commit()
    projections = {
        'ufw_log': 'id,event_time,event_hash,raw_line',
        'ufw_file_checkpoints': 'id,source_scope,file_device,file_inode,filename,byte_position,prefix_sha,observed_size,observed_sha,status,checked_at',
        'ufw_filter_seen': 'source_id,event_hash,host_id,rule_key,rule_version,event_time,recorded_at',
        'ufw_filter_stats': '*',
    }
    original = {}
    for table, fields in projections.items():
        original[table] = rows(connection, 'SELECT ' + fields + ' FROM ' + table)
    real_upgrade = ufw_occurrence_schema.upgrade
    def interrupted(database):
        real_upgrade(database)
        raise RuntimeError('synthetic interruption after occurrence DDL')
    with monkeypatch.context() as failure:
        failure.setattr(ufw_occurrence_schema, 'upgrade', interrupted)
        with pytest.raises(RuntimeError, match='after occurrence DDL'):
            migrate.migrate(connection)
    assert rows(connection, "SELECT status FROM schema_migrations WHERE version='029'") == (('FAILED',),)
    assert migrate.migrate(connection) == ['029', '030', '031', '032', '033', '034', '035']
    assert migrate.migrate(connection) == []
    for table, fields in projections.items():
        assert rows(connection, 'SELECT ' + fields + ' FROM ' + table) == original[table]
    with connection.cursor() as cursor:
        assert ufw.save_event(cursor, LINE.decode()) == 0
    connection.rollback()
    assert raw_rows(connection) == original['ufw_log']
