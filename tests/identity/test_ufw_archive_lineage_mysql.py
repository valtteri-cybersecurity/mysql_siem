"""Trusted compression handoff, replay, filters and failure preservation on private MySQL."""
import gzip
import hashlib
import os
import shutil

import pymysql
import pytest

from ingestion import ufw_compress as compressor
from ingestion import ufw_continuity as continuity
from ingestion import ufw_filters as filters
from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_batch import OccurrenceConflict
from tests.identity.test_ufw_filtering_mysql import collection as collection  # noqa: PLC0414 -- fixture re-export

AUDIT = (b'2026-10-29T12:00:00Z host [UFW AUDIT] IN=lo OUT= SRC=127.0.0.1 '
         b'DST=127.0.0.1 PROTO=TCP SPT=12345 DPT=3306\n')
BLOCK = AUDIT.replace(b'AUDIT', b'BLOCK')


def rows(connection, query, values=()):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute(query, values)
        return cursor.fetchall()


def pack(runtime, original, output):
    original.chmod(0o600)
    with original.open('rb') as source, output.open('wb') as destination:
        output.chmod(0o600)
        return compressor.compress_stream(runtime, source, destination, str(original))


def test_producer_lineage_preserves_occurrences_filters_and_raw_history(collection, monkeypatch, tmp_path):
    admin, runtime, active, host, scope = collection
    monkeypatch.setattr(compressor, 'TRUSTED_OWNER', os.geteuid())
    filters.change(admin, scope, host, True, actor='private-test', reason='lineage regression', acknowledge_risk=True)
    content = BLOCK * 2 + AUDIT * 2
    active.write_bytes(content)
    assert ufw.process_log(runtime, max_lines=2)['inserted'] == 2
    original_events = rows(admin, 'SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id')
    original_checkpoints = rows(admin, 'SELECT * FROM ufw_file_checkpoints ORDER BY id')
    checkpoint = original_checkpoints[0][0]
    generation = rows(admin, 'SELECT generation_key FROM ufw_file_checkpoints')[0][0]
    plain = active.with_name('ufw.log.1')
    archive = active.with_name('ufw.log.1.gz')
    active.rename(plain)
    active.write_bytes(BLOCK.replace(b'DPT=3306', b'DPT=4444'))
    digest = pack(runtime, plain, archive)
    assert digest == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert gzip.decompress(archive.read_bytes()) == content
    assert rows(admin, 'SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id') == original_events
    assert rows(admin, 'SELECT * FROM ufw_file_checkpoints ORDER BY id') == original_checkpoints
    assert rows(admin, 'SELECT checkpoint_id,generation_key,expanded_size FROM ufw_archive_lineage') == (
        (checkpoint, generation, len(content)),)
    plain.unlink()  # Only simulate logrotate's successful deletion in this private fixture.
    assert ufw.process_log(runtime, max_lines=2)['inserted'] == 1
    result = None
    for _attempt in range(5):
        result = ufw.process_log(runtime, max_lines=4)
        if result['archives_pending'] == 0:
            break
    assert result['status'] == 'SUCCESS'
    assert result['collection_state'] == 'HEALTHY'
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_log') == ((3,),)
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_filter_seen WHERE source_id=%s', (scope,)) == ((2,),)
    assert rows(admin, 'SELECT SUM(filtered_count) FROM ufw_filter_stats WHERE source_id=%s', (scope,)) == ((2,),)
    assert rows(admin, 'SELECT status FROM ufw_file_checkpoints WHERE id=%s', (checkpoint,)) == (('ARCHIVED',),)
    assert rows(admin, 'SELECT byte_position FROM ufw_file_checkpoints WHERE id=%s', (checkpoint,)) == ((len(BLOCK) * 2,),)
    assert rows(admin, 'SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id')[:2] == original_events
    copied = active.with_name('ufw.log.9.gz')
    shutil.copyfile(archive, copied)
    assert ufw.process_log(runtime)['inserted'] == 0
    archive.unlink()
    assert ufw.process_log(runtime)['inserted'] == 0
    assert rows(admin, 'SELECT SUM(filtered_count) FROM ufw_filter_stats WHERE source_id=%s', (scope,)) == ((2,),)

    # An output created by logrotate before the child starts is not an archive yet.
    empty = active.with_name('ufw.log.5.gz')
    empty.touch()
    deferred = ufw.process_log(runtime)
    assert deferred['archives_unscanned'] == 1
    assert deferred['collection_state'] == 'UNKNOWN'
    empty.unlink()
    # A crashed producer leaves a durable WRITING record: never decompress its tail.
    partial = active.with_name('ufw.log.4.gz')
    partial.write_bytes(b'partial gzip output')
    info = partial.stat()
    with runtime.cursor() as cursor:
        cursor.execute('INSERT INTO ufw_compression_jobs '
                       '(source_scope,checkpoint_id,generation_key,source_device,source_inode,archive_device,'
                       'archive_inode,expanded_size,expanded_sha,status) SELECT source_scope,checkpoint_id,generation_key,'
                       "source_device,source_inode,%s,%s,expanded_size,expanded_sha,'WRITING' "
                       "FROM ufw_compression_jobs WHERE status='READY' LIMIT 1", (info.st_dev, info.st_ino))
        interrupted_job = cursor.lastrowid
    runtime.commit()
    deferred = ufw.process_log(runtime)
    assert deferred['archives_unscanned'] == 1
    assert deferred['collection_state'] == 'UNKNOWN'
    assert rows(admin, 'SELECT 1 FROM ufw_archives WHERE archive_sha=%s',
                (hashlib.sha256(partial.read_bytes()).hexdigest(),)) == ()
    with runtime.cursor() as cursor:
        cursor.execute("UPDATE ufw_compression_jobs SET status='FAILED' WHERE id=%s", (interrupted_job,))
    runtime.commit()
    deferred = ufw.process_log(runtime)
    assert deferred['archives_unscanned'] == 1
    assert deferred['collection_state'] == 'UNKNOWN'
    # Retain this inode so the separate unbound-artifact case cannot inherit it.
    partial.rename(active.with_name('retained-failed-output'))
    # ARCHIVED cannot hide an invalidated binding: diagnostics recheck its proof.
    with admin.cursor() as cursor:
        cursor.execute("UPDATE ufw_compression_jobs SET status='FAILED' WHERE status='READY'")
    admin.commit()
    diagnosis = continuity.read_health(admin, scope)
    assert diagnosis['state'] == 'GAP_DETECTED'
    assert diagnosis['unverified_recoveries'] == 1
    with admin.cursor() as cursor:
        cursor.execute("UPDATE ufw_compression_jobs SET status='READY' WHERE id IN (SELECT job_id FROM ufw_archive_lineage)")
    admin.commit()
    runtime.rollback()

    # An unrelated gzip with identical expanded bytes still has no generation proof.
    unbound = active.with_name('ufw.log.8.gz')
    unbound.write_bytes(gzip.compress(content, mtime=0))
    try:
        rejected = ufw.process_log(runtime)
    except OccurrenceConflict as error:
        # The OS may reuse the original managed output inode for this unbound file.
        assert str(error) == 'UFW_MANAGED_ARCHIVE_CHANGED'
    else:
        assert rejected['status'] == 'FAILED'
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_log') == ((3,),)
    assert rows(admin, 'SELECT SUM(filtered_count) FROM ufw_filter_stats WHERE source_id=%s', (scope,)) == ((2,),)

    # Foreign keys prohibit moving a valid artifact into a different generation.
    job = rows(admin, 'SELECT id,expanded_sha FROM ufw_compression_jobs WHERE status=\'READY\'')[0]
    with runtime.cursor() as cursor:
        cursor.execute('INSERT INTO ufw_compression_jobs '
                       '(source_scope,checkpoint_id,generation_key,source_device,source_inode,archive_device,'
                       'archive_inode,expanded_size,expanded_sha,status) SELECT source_scope,checkpoint_id,'
                       "generation_key,source_device,source_inode,archive_device,archive_inode,expanded_size,expanded_sha,'WRITING' "
                       'FROM ufw_compression_jobs WHERE id=%s', (job[0],))
        fake_job = cursor.lastrowid
        with pytest.raises(pymysql.IntegrityError) as failure:
            cursor.execute('INSERT INTO ufw_archive_lineage '
                           '(source_scope,archive_sha,job_id,checkpoint_id,generation_key,expanded_size,expanded_sha,compressed_size) '
                           'VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                           (scope, 'e' * 64, fake_job, checkpoint, b'z' * 32, len(content), job[1], 100))
        assert failure.value.args[0] == 1452
    runtime.rollback()

    # A failed metadata commit cannot leave a usable archive or advance a source.
    pending = active.with_name('ufw.log.2')
    failed_archive = active.with_name('ufw.log.2.gz')
    pending_content = BLOCK + b'ordinary pending line\n'
    pending.write_bytes(pending_content)
    runtime.rollback()
    with admin.cursor() as cursor:
        cursor.execute("CREATE TRIGGER reject_lineage BEFORE INSERT ON ufw_archive_lineage FOR EACH ROW "
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic lineage failure'")
    with pytest.raises(pymysql.MySQLError):
        pack(runtime, pending, failed_archive)
    assert failed_archive.read_bytes() == b''
    assert pending.read_bytes() == pending_content
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_archive_lineage') == ((1,),)
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_log') == ((3,),)
    assert rows(admin, 'SELECT byte_position FROM ufw_file_checkpoints WHERE filename=%s', (str(pending),)) == ((0,),)
    with admin.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_lineage')
    pack(runtime, pending, failed_archive)
    assert gzip.decompress(failed_archive.read_bytes()) == pending_content
    assert rows(admin, 'SELECT COUNT(*) FROM ufw_archive_lineage') == ((2,),)
