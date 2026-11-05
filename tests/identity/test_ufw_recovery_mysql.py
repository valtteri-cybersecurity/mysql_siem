"""Private MySQL: content-only recovery is forbidden; exact verified sources recover."""
import hashlib
import time

import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_batch import OccurrenceConflict

CONTENT = b'ordinary one\nordinary two\n'
DIGEST = hashlib.sha256(CONTENT).hexdigest()


def checkpoint(cursor, path, generation):
    info = path.stat()
    cursor.execute('INSERT INTO ufw_file_checkpoints '
                   '(source_scope,file_device,file_inode,filename,byte_position,prefix_sha,observed_size,'
                   'observed_sha,status,checked_at,generation_key,file_mtime_ns) '
                   "VALUES (0,%s,%s,%s,%s,%s,%s,%s,'READING',UTC_TIMESTAMP(6),%s,%s)",
                   (info.st_dev, info.st_ino, str(path), len(CONTENT), DIGEST, len(CONTENT), DIGEST,
                    generation, info.st_mtime_ns))
    return cursor.lastrowid


def test_missing_generations_require_their_exact_verified_source(mysql, tmp_path):
    first = tmp_path / 'ufw.log.1'
    second = tmp_path / 'ufw.log.2'
    copy = tmp_path / 'ufw.log.3'
    for path in (first, second, copy):
        path.write_bytes(CONTENT)
    with mysql.cursor() as cursor:
        one = checkpoint(cursor, first, b'a' * 32)
        two = checkpoint(cursor, second, b'b' * 32)
        checkpoint(cursor, copy, b'c' * 32)
        line = ('2026-11-05T12:00:00Z host [UFW BLOCK] SRC=192.0.2.1 '
                'DST=198.51.100.1 PROTO=TCP DPT=22')
        ufw.save_event(cursor, line)
        cursor.execute('SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id')
        original_events = cursor.fetchall()
        assert continuity.reconcile(cursor, 0, [], time.monotonic() + 10)
        cursor.execute("SELECT COUNT(*) FROM ufw_file_checkpoints WHERE status='RECOVERED'")
        assert cursor.fetchone() == (0,)
        cursor.execute('SELECT COUNT(*) FROM ufw_collection_gaps WHERE resolved=FALSE')
        assert cursor.fetchone() == (3,)
        # Even COMPLETE plus a matching archive prefix is only a content proof.
        cursor.execute('INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode,status) '
                       "VALUES (0,%s,'/missing/ufw.log.gz',1,2,'COMPLETE')", ('d' * 64,))
        continuity.record_proof(cursor, 0, 'd' * 64, len(CONTENT), DIGEST)
        assert continuity.reconcile(cursor, 0, [str(copy)], time.monotonic() + 10)
        cursor.execute("SELECT COUNT(*) FROM ufw_file_checkpoints WHERE status='RECOVERED'")
        assert cursor.fetchone() == (0,)
        cursor.execute('SELECT COUNT(*) FROM ufw_collection_gaps WHERE resolved=FALSE')
        assert cursor.fetchone() == (3,)
        continuity.gap(cursor, 0, one, 'CONTENT_CHANGED', str(first))
        continuity.gap(cursor, 99, one, 'MISSING_SOURCE', str(first))
        # Partial progress cannot resolve a missing-source gap.
        partial = len(b'ordinary one\n')
        cursor.execute('UPDATE ufw_file_checkpoints SET byte_position=%s,prefix_sha=%s WHERE id=%s',
                       (partial, hashlib.sha256(CONTENT[:partial]).hexdigest(), one))
        with first.open('rb') as source:
            info = first.stat()
            key, prefix, observed, generation = continuity.start(cursor, source, str(first), info, 0, None)
            continuity.finish(cursor, source, str(first), info, 0, key, prefix, observed, None, generation=generation)
        cursor.execute('SELECT resolved FROM ufw_collection_gaps WHERE source_scope=0 AND checkpoint_id=%s '
                       "AND reason='MISSING_SOURCE'", (one,))
        assert cursor.fetchone() == (0,)
        # The returning exact generation, fully read and reverified, can resolve itself.
        with first.open('rb') as source:
            info = first.stat()
            key, prefix, observed, generation = continuity.start(cursor, source, str(first), info, 0, None)
            assert key == one and generation == b'a' * 32
            prefix.update(source.read())
            continuity.finish(cursor, source, str(first), info, 0, key, prefix, observed, None, generation=generation)
        cursor.execute('SELECT source_scope,checkpoint_id,reason,resolved FROM ufw_collection_gaps '
                       'WHERE resolved=TRUE')
        assert cursor.fetchall() == ((0, one, 'MISSING_SOURCE', 1),)
        # A rewritten generation does not recover the old checkpoint with the same inode.
        second.write_bytes(b'a different generation\n')
        with second.open('rb') as source:
            info = second.stat()
            key, prefix, observed, generation = continuity.start(cursor, source, str(second), info, 0, None)
            assert key is None
            prefix.update(source.read())
            continuity.finish(cursor, source, str(second), info, 0, key, prefix, observed, None, generation=generation)
        cursor.execute('SELECT byte_position,prefix_sha,status FROM ufw_file_checkpoints WHERE id=%s', (two,))
        assert cursor.fetchone() == (len(CONTENT), DIGEST, 'SUPERSEDED')
        cursor.execute('SELECT resolved FROM ufw_collection_gaps WHERE source_scope=0 AND checkpoint_id=%s '
                       "AND reason='MISSING_SOURCE'", (two,))
        assert cursor.fetchone() == (0,)
        # A legacy checkpoint cannot acquire a new generation to erase an old gap.
        cursor.execute('UPDATE ufw_file_checkpoints SET generation_key=NULL WHERE filename=%s', (str(copy),))
        with copy.open('rb') as source, pytest.raises(OccurrenceConflict, match='UFW_UNVERIFIED_RECOVERY_GENERATION'):
            continuity.start(cursor, source, str(copy), copy.stat(), 0, None)
        cursor.execute('SELECT generation_key FROM ufw_file_checkpoints WHERE filename=%s', (str(copy),))
        assert cursor.fetchone() == (None,)
        cursor.execute('SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id')
        assert cursor.fetchall() == original_events
        # Simulate the old bug: recovered flags and resolved gaps remain on disk.
        cursor.execute("UPDATE ufw_file_checkpoints SET status='RECOVERED' WHERE id=%s OR filename=%s",
                       (two, str(copy)))
        cursor.execute('UPDATE ufw_collection_gaps SET resolved=TRUE WHERE source_scope=0')
    continuity.save_health(mysql, 0, {'active_state': 'HEALTHY', 'stop_reason': 'snapshot_end'})
    saved = {}
    tables = ('ufw_file_checkpoints', 'ufw_collection_gaps', 'ufw_log', 'ufw_archive_proofs', 'ufw_collection_health')
    with mysql.cursor() as cursor:
        for table in tables:
            cursor.execute('SELECT * FROM ' + table + ' ORDER BY 1,2')
            saved[table] = cursor.fetchall()
    diagnosis = continuity.read_health(mysql, 0)
    assert diagnosis['state'] == 'GAP_DETECTED'
    assert diagnosis['gaps'] == 0
    assert diagnosis['unverified_recoveries'] == 2
    with mysql.cursor() as cursor:
        for table in tables:
            cursor.execute('SELECT * FROM ' + table + ' ORDER BY 1,2')
            assert cursor.fetchall() == saved[table]
    # Other scopes are unaffected; no runtime state is needed for the audit.
    assert continuity.read_health(mysql, 77)['unverified_recoveries'] == 0
    assert continuity.read_health(mysql, 77)['state'] == 'UNKNOWN'
    continuity.save_health(mysql, 55, {'active_state': 'HEALTHY', 'stop_reason': 'snapshot_end'})
    assert continuity.read_health(mysql, 55)['state'] == 'HEALTHY'
    assert continuity.read_health(mysql, 55)['unverified_recoveries'] == 0
    mysql.commit()
