"""Private MySQL: retry bounds, immutable events, failure history and legacy safety."""
import errno
import gzip
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from database import migrate, ufw_archive_retry_schema
from ingestion import ufw_archives as archives
from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_batch import OccurrenceConflict
from tests.analysis.test_ufw_archive_retry import inline_worker
from tests.identity.test_ufw_filtering_mysql import collection as collection  # noqa: PLC0414 -- fixture re-export

PREPARE = archives.prepare

GOOD = (b'2026-11-05T12:00:00Z host [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.1 '
        b'DST=198.51.100.1 PROTO=TCP SPT=12345 DPT=443\n')


def rows(connection, query, values=()):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute(query, values)
        return cursor.fetchall()


def due(admin, runtime, scope, digest):
    runtime.rollback()
    with admin.cursor() as cursor:
        cursor.execute('UPDATE ufw_archives SET retry_after=DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND) '
                       'WHERE source_scope=%s AND archive_sha=%s', (scope, digest))
    admin.commit()
    manifest = archives.CACHE / (digest + '.json')
    record = archives.read_manifest(manifest)
    if record is not None and record.get('status') == 'ERROR':
        record['retry_after'] = 0
        archives.write_manifest(manifest, record)


def test_transient_failure_resumes_exact_offset_and_keeps_failure_history(collection, monkeypatch):
    admin, runtime, active, _host, scope = collection
    # Exercise the real prepare/worker state machine with a synchronous child only.
    launch = Mock(side_effect=inline_worker)
    monkeypatch.setattr(archives.subprocess, 'Popen', launch)
    monkeypatch.setattr(archives, 'prepare', PREPARE)
    active.write_bytes(GOOD.replace(b'DPT=443', b'DPT=9999'))
    archive = active.with_name('ufw.log.1.gz')
    content = bytearray()
    for port in range(1000, 1005):
        content.extend(GOOD.replace(b'DPT=443', ('DPT=' + str(port)).encode()))
    archive.write_bytes(gzip.compress(content, mtime=0))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    ufw.process_log(runtime, max_lines=2)
    ufw.process_log(runtime, max_lines=2)
    before = rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id')
    assert 2 <= len(before) < 6
    position = rows(admin, 'SELECT logical_position FROM ufw_archives WHERE archive_sha=%s', (digest,))[0][0]
    assert position > 0
    checkpoints = rows(admin, 'SELECT id,byte_position,prefix_sha,generation_key FROM ufw_file_checkpoints')
    identify = archives.identify_archive
    def fail_discovery(filename, deadline):
        raise OSError(errno.EIO, 'synthetic temporary read failure')
    open_regular = archives.regular
    def denied(filename, *args, **kwargs):
        if str(filename) == str(archive):
            raise PermissionError(errno.EACCES, 'synthetic temporary access failure')
        return open_regular(filename, *args, **kwargs)
    with monkeypatch.context() as failure:
        failure.setattr(archives, 'regular', denied)
        assert ufw.process_log(runtime)['status'] == 'FAILED'
    assert rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id') == before
    assert rows(admin, 'SELECT * FROM ufw_file_checkpoints') != ()
    failed = rows(admin, 'SELECT source_key,filename,reason,detected_at,archive_sha,retryable,resolved_at '
                        'FROM ufw_archive_failures')
    assert len(failed) == 1
    assert failed[0][4:] == (digest, 1, None)
    assert rows(admin, 'SELECT logical_position,status,retry_count FROM ufw_archives WHERE archive_sha=%s',
                (digest,)) == ((position, 'FAILED', 0),)
    launch_count = launch.call_count
    assert ufw.process_log(runtime)['status'] == 'FAILED'
    assert launch.call_count == launch_count
    due(admin, runtime, scope, digest)
    renamed = active.with_name('ufw.log.9.gz')
    archive.rename(renamed)
    archive = renamed
    assert ufw.process_log(runtime)['status'] == 'SUCCESS'
    assert rows(admin, 'SELECT filename FROM ufw_archives WHERE archive_sha=%s', (digest,)) == ((str(renamed),),)
    after = rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id')
    assert len(after) == 6
    assert after[:len(before)] == before
    assert rows(admin, 'SELECT logical_position,status,retry_count,failure_reason FROM ufw_archives WHERE archive_sha=%s',
                (digest,)) == ((len(content), 'COMPLETE', 1, 'ARCHIVE_IO_TRANSIENT'),)
    resolved = rows(admin, 'SELECT source_key,filename,reason,detected_at,archive_sha,retryable,resolved_at '
                          'FROM ufw_archive_failures')
    assert resolved[0][:-1] == failed[0][:-1]
    assert resolved[0][-1] is not None
    # Raw checkpoint identity and position remain unchanged by archive recovery.
    current = rows(admin, 'SELECT id,byte_position,prefix_sha,generation_key FROM ufw_file_checkpoints')
    assert current == checkpoints

    # A later transient source-check failure gets a new history row, not a rewrite.
    with monkeypatch.context() as failure:
        failure.setattr(archives, 'identify_archive', fail_discovery)
        assert ufw.process_log(runtime)['status'] == 'FAILED'
    history = rows(admin, 'SELECT reason,detected_at,resolved_at FROM ufw_archive_failures ORDER BY detected_at')
    assert len(history) == 2
    assert history[0][-1] is not None
    assert history[1][-1] is None
    assert ufw.process_log(runtime)['status'] == 'FAILED'
    due(admin, runtime, scope, digest)
    assert ufw.process_log(runtime)['status'] == 'SUCCESS'
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_archive_failures WHERE resolved_at IS NULL') == ((0,),)
    assert rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id') == after

    # Persistent resource exhaustion stops after the original attempt and two retries.
    second = active.with_name('ufw.log.2.gz')
    second.write_bytes(gzip.compress(GOOD.replace(b'DPT=443', b'DPT=8000'), mtime=0))
    second_digest = hashlib.sha256(second.read_bytes()).hexdigest()
    initial_launches = launch.call_count
    with monkeypatch.context() as pressure:
        pressure.setattr(archives, 'MAX_CACHE', 1)
        ufw.process_log(runtime)
        ufw.process_log(runtime)
        for _attempt in range(4):
            due(admin, runtime, scope, second_digest)
            ufw.process_log(runtime)
            ufw.process_log(runtime)
    assert launch.call_count - initial_launches == archives.MAX_ATTEMPTS
    assert rows(admin, 'SELECT logical_position,status,retry_count FROM ufw_archives WHERE archive_sha=%s',
                (second_digest,)) == ((0, 'FAILED', archives.MAX_ATTEMPTS - 1),)
    assert rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id') == after

    # A CRC failure and an old unclassified failure cannot be promoted by a due time.
    broken = active.with_name('ufw.log.3.gz')
    corrupt = bytearray(gzip.compress(GOOD.replace(b'DPT=443', b'DPT=7000'), mtime=0))
    corrupt[-8] ^= 1
    broken.write_bytes(corrupt)
    broken_digest = hashlib.sha256(corrupt).hexdigest()
    ufw.process_log(runtime)
    ufw.process_log(runtime)
    assert rows(admin, 'SELECT failure_reason FROM ufw_archives WHERE archive_sha=%s',
                (broken_digest,)) == (('GZIP_CRC_OR_HEADER',),)
    initial_launches = launch.call_count
    due(admin, runtime, scope, broken_digest)
    ufw.process_log(runtime)
    assert launch.call_count == initial_launches
    assert rows(admin, 'SELECT retry_count,status FROM ufw_archives WHERE archive_sha=%s',
                (broken_digest,)) == ((0, 'FAILED'),)
    assert identify is archives.identify_archive

    # Identical replacement bytes do not prove the original file generation.
    origin = active.with_name('ufw.log.4.gz')
    origin.write_bytes(gzip.compress(GOOD.replace(b'DPT=443', b'DPT=6000') * 4, mtime=0))
    origin_digest = hashlib.sha256(origin.read_bytes()).hexdigest()
    ufw.process_log(runtime, max_lines=2)
    ufw.process_log(runtime, max_lines=2)
    saved_events = rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id')
    saved_position = rows(admin, 'SELECT logical_position FROM ufw_archives WHERE archive_sha=%s', (origin_digest,))
    def origin_failure(filename, deadline):
        if filename == str(origin):
            raise OSError(errno.EIO, 'synthetic origin read failure')
        return identify(filename, deadline)
    with monkeypatch.context() as failure:
        failure.setattr(archives, 'identify_archive', origin_failure)
        ufw.process_log(runtime)
    due(admin, runtime, scope, origin_digest)
    retained = origin.with_name('retained-original-source')
    origin.rename(retained)
    origin.write_bytes(retained.read_bytes())
    with pytest.raises(OccurrenceConflict, match='UFW_AMBIGUOUS_ARCHIVE_COPY'):
        ufw.process_log(runtime)
    assert rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id') == saved_events
    assert rows(admin, 'SELECT logical_position FROM ufw_archives WHERE archive_sha=%s', (origin_digest,)) == saved_position
    assert rows(admin, 'SELECT resolved_at FROM ufw_archive_failures WHERE archive_sha=%s', (origin_digest,)) == ((None,),)


def test_retry_migration_resumes_and_preserves_legacy_failure(empty_mysql, monkeypatch):
    previous = []
    for item in migrate.MIGRATIONS:
        if item[0] < '031':
            previous.append(item)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(previous))
        migrate.migrate(empty_mysql)
    with empty_mysql.cursor() as cursor:
        cursor.execute('INSERT INTO ufw_archive_failures (source_scope,source_key,filename,reason) '
                       "VALUES (0,%s,'/private/old.gz','OSError')", ('a' * 64,))
    empty_mysql.commit()
    before = rows(empty_mysql, 'SELECT source_scope,source_key,filename,reason,detected_at FROM ufw_archive_failures')
    add = ufw_archive_retry_schema.add_column
    def interrupt(cursor, table, name, definition):
        add(cursor, table, name, definition)
        raise RuntimeError('synthetic interruption after first additive DDL')
    with monkeypatch.context() as failure:
        failure.setattr(ufw_archive_retry_schema, 'add_column', interrupt)
        with pytest.raises(RuntimeError, match='synthetic interruption'):
            migrate.migrate(empty_mysql)
    assert migrate.migrate(empty_mysql) == ['031', '032']
    assert rows(empty_mysql, 'SELECT source_scope,source_key,filename,reason,detected_at FROM ufw_archive_failures') == before
    assert rows(empty_mysql, 'SELECT archive_sha,retryable,resolved_at FROM ufw_archive_failures') == ((None, 0, None),)
    assert migrate.migrate(empty_mysql) == []


def test_post_commit_cleanup_failures_keep_complete_state_and_do_not_replay(collection, monkeypatch, capsys):
    admin, runtime, active, _host, scope = collection
    unlink = Path.unlink
    previous_events = ()
    def cleanup_failure(spool, digest, position, calls, error_type, error_number):
        def fail_cleanup(path, *args, **kwargs):
            if path != spool:
                return unlink(path, *args, **kwargs)
            # A separate connection must already see the completed transaction.
            assert rows(admin, 'SELECT logical_position,status FROM ufw_archives '
                               'WHERE source_scope=%s AND archive_sha=%s', (scope, digest)) == ((position, 'COMPLETE'),)
            calls.append(str(path))
            if error_type is FileNotFoundError:
                unlink(path)
            raise error_type(error_number, 'synthetic post-commit cleanup failure')
        return fail_cleanup
    for number, error_type, error_number in [(1, PermissionError, errno.EACCES),
                                             (2, OSError, errno.EIO),
                                             (3, FileNotFoundError, errno.ENOENT)]:
        archive = active.with_name('ufw.log.' + str(number) + '.gz')
        line = GOOD.replace(b'DPT=443', ('DPT=' + str(9000 + number)).encode())
        content = gzip.compress(line * 2, mtime=0)
        archive.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        spool = archives.CACHE / (digest + '.data')
        cleanup_calls = []
        with monkeypatch.context() as failure:
            failure.setattr(Path, 'unlink', cleanup_failure(spool, digest, len(line) * 2, cleanup_calls,
                                                          error_type, error_number))
            result = ufw.process_log(runtime)
        assert result['status'] == 'SUCCESS'
        assert result['archive_errors'] == result['archives_pending'] == 0
        assert len(cleanup_calls) == 1
        output = capsys.readouterr().out
        assert 'UFW archive spool cleanup deferred: ' + error_type.__name__ in output
        assert digest in output
        assert rows(admin, 'SELECT logical_position,status,retry_count,failure_reason FROM ufw_archives '
                           'WHERE source_scope=%s AND archive_sha=%s', (scope, digest)) == ((len(line) * 2, 'COMPLETE', 0, None),)
        committed = rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id')
        assert len(committed) == number * 2
        assert committed[:len(previous_events)] == previous_events
        assert archive.read_bytes() == content
        replay = ufw.process_log(runtime)
        assert replay['status'] == 'SUCCESS'
        assert replay['inserted'] == replay['archive_lines'] == replay['archive_errors'] == 0
        assert rows(admin, 'SELECT id,event_time,event_hash,file_generation,file_position FROM ufw_log ORDER BY id') == committed
        assert rows(admin, 'SELECT logical_position,status FROM ufw_archives '
                           'WHERE source_scope=%s AND archive_sha=%s', (scope, digest)) == ((len(line) * 2, 'COMPLETE'),)
        assert rows(admin, 'SELECT COUNT(*) FROM ufw_archive_failures WHERE source_scope=%s', (scope,)) == ((0,),)
        previous_events = committed
