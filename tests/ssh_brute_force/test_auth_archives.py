"""Auth gzip lineage, bounded extraction and transaction behavior."""

import gzip
import hashlib
import json
import os
from functools import partial
from unittest.mock import MagicMock

import pymysql
import pytest

from ingestion.auth import archives, collector

LINE = b"2026-10-22T12:00:00Z server-a sshd[12]: Failed password for alice from 192.0.2.1 port 22 ssh2\n"
ACTIVE = LINE.replace(b'alice', b'active-user')
READER = 'archive-reader'


@pytest.fixture
def approvals(tmp_path, monkeypatch):
    folder = tmp_path / 'approved'
    folder.mkdir()
    monkeypatch.setattr(archives, 'PROOFS', folder)
    monkeypatch.setattr(archives, 'PROOF_OWNER', os.geteuid())
    monkeypatch.setattr(archives, 'trusted_directory', lambda _: None)

    def approve(path, generation, *, original=(1, 2), previously_seen=False, database=('test', 'test-server')):
        info = path.stat()
        receipt = folder / f'{info.st_dev}-{info.st_ino}.json'
        receipt.write_text(json.dumps({
            'source_scope': 0, 'reader': READER, 'generation_key': generation.hex(),
            'archive_ctime_ns': info.st_ctime_ns, 'archive_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'device': original[0], 'inode': original[1], 'previously_seen': previously_seen,
            'database': database[0], 'server': database[1],
        }))
        receipt.chmod(0o600)
        return receipt

    return approve


def run(connection, active, **options):
    stats = {}
    result = collector.collect_auth_events(connection, active, collector_id=READER, stats=stats, **options)
    return result['inserted'], stats


def mock_connection():
    connection = MagicMock()
    cursor = connection.cursor.return_value
    def fetchone():
        sql = cursor.execute.call_args.args[0]
        if 'GET_LOCK' in sql:
            return (1,)
        if 'SELECT DATABASE()' in sql:
            return ('test', 'test-server')
        return None

    cursor.fetchone.side_effect = fetchone
    return connection


@pytest.mark.parametrize('damage', ['crc', 'truncated', 'header', 'partial-line', 'symlink'])
def test_bad_archive_is_reported_without_preventing_available_plain_log(tmp_path, approvals, damage):
    active = tmp_path / 'auth.log'
    active.write_bytes(ACTIVE)
    path = tmp_path / 'auth.log.1.gz'
    compressed = gzip.compress(LINE)
    if damage == 'crc':
        compressed = compressed[:-8] + bytes(8)
    elif damage == 'truncated':
        compressed = compressed[:-4]
    elif damage == 'header':
        compressed = b'bad format'
    elif damage == 'partial-line':
        compressed = gzip.compress(LINE[:-1])
    if damage == 'symlink':
        target = tmp_path / 'target.gz'
        target.write_bytes(compressed)
        path.symlink_to(target)
    else:
        path.write_bytes(compressed)
        approvals(path, b'a' * 32)
    connection = mock_connection()
    inserted, stats = run(connection, active)
    assert inserted == 1
    assert stats['archives_failed'] == 1
    assert stats['archives_complete'] == stats['coverage_gaps'] == 0
    connection.commit.assert_called_once()


def test_unsupported_formats_do_not_claim_lost_events(tmp_path):
    active = tmp_path / 'auth.log'
    active.write_bytes(ACTIVE)
    for suffix in ('xz', 'bz2', 'zst'):
        active.with_name(f'auth.log.1.{suffix}').touch()
    inserted, stats = run(mock_connection(), active)
    assert inserted == 1
    assert stats['compressed_rotations'] == stats['unsupported_rotations'] == 3
    assert stats['coverage_gaps'] == stats['archives_failed'] == 0


def test_expansion_limit_keeps_plain_collection_running(tmp_path, approvals, monkeypatch):
    active = tmp_path / 'auth.log'
    active.write_bytes(ACTIVE)
    path = tmp_path / 'auth.log.1.gz'
    path.write_bytes(gzip.compress(LINE))
    approvals(path, b'a' * 32)
    monkeypatch.setattr(archives, 'MAX_EXPANDED', len(LINE) - 1)
    inserted, stats = run(mock_connection(), active)
    assert inserted == 1
    assert stats['archives_failed'] == 1
    assert 'size limit' in stats['archive_diagnostics'][0][1]


@pytest.mark.parametrize('fault', ['wrong-server', 'wrong-sha', 'writable-receipt'])
def test_untrusted_receipt_keeps_archive_pending_for_review(tmp_path, approvals, fault):
    active = tmp_path / 'auth.log'
    active.write_bytes(ACTIVE)
    path = tmp_path / 'auth.log.1.gz'
    path.write_bytes(gzip.compress(LINE))
    receipt = approvals(path, b'a' * 32)
    if fault == 'writable-receipt':
        receipt.chmod(0o620)
    else:
        proof = json.loads(receipt.read_text())
        if fault == 'wrong-server':
            proof['server'] = 'another-server'
        else:
            proof['archive_sha256'] = '12' * 32
        receipt.write_text(json.dumps(proof))
    inserted, stats = run(mock_connection(), active)
    assert inserted == 1
    assert stats['archives_unverified'] == 1
    assert stats['archives_complete'] == stats['coverage_gaps'] == 0


def stored(connection, query):
    with connection.cursor() as cursor:
        cursor.execute(query)
        return cursor.fetchall()


@pytest.fixture
def mysql_approvals(mysql, approvals):
    database = stored(mysql, 'SELECT DATABASE(), @@server_uuid')[0]
    return partial(approvals, database=database)


def test_new_gzip_resumes_logical_offset_and_recognizes_complete_and_empty(mysql, tmp_path, mysql_approvals):
    active = tmp_path / 'auth.log'
    active.write_bytes(b'')
    path = tmp_path / 'auth.log.1.gz'
    path.write_bytes(gzip.compress(LINE * 2))
    mysql_approvals(path, b'a' * 32)
    empty = tmp_path / 'auth.log.2.gz'
    empty.write_bytes(gzip.compress(b''))
    mysql_approvals(empty, b'e' * 32, original=(1, 3))
    offsets = 'SELECT logical_position,expanded_size FROM auth_archive_checkpoints ORDER BY generation_key'

    inserted, stats = run(mysql, active, max_lines=1)
    assert inserted == 1
    assert stats['archives_pending'] == stats['archives_complete'] == 1
    assert stored(mysql, offsets) == ((len(LINE), len(LINE) * 2), (0, 0))

    inserted, stats = run(mysql, active)
    assert inserted == 1
    assert stats['archives_complete'] == 2
    assert stored(mysql, offsets) == ((len(LINE) * 2, len(LINE) * 2), (0, 0))
    events = stored(mysql, 'SELECT id,event_hash,file_position FROM auth_events ORDER BY id')
    assert len(events) == 2
    assert events[0][1] == events[1][1]
    assert (events[0][2], events[1][2]) == (0, len(LINE))
    assert run(mysql, active)[0] == 0

    renamed = path.rename(tmp_path / 'auth.log.3.gz')
    mysql_approvals(renamed, b'a' * 32)
    assert run(mysql, active)[0] == 0
    assert stored(mysql, 'SELECT id,event_hash,file_position FROM auth_events ORDER BY id') == events

    copy = tmp_path / 'auth.log.4.gz'
    copy.write_bytes(renamed.read_bytes())
    inserted, stats = run(mysql, active)
    assert inserted == 0
    assert stats['archives_complete'] == 2
    assert stats['archives_unverified'] == 1
    assert stats['coverage_gaps'] == 0


def test_gzip_continues_original_plain_generation_after_compression(mysql, tmp_path, mysql_approvals):
    active = tmp_path / 'auth.log'
    active.write_bytes(LINE * 2)
    assert run(mysql, active, max_lines=1)[0] == 1
    plain = stored(mysql, 'SELECT file_device,file_inode,generation_key,last_position FROM auth_ingestion_state')
    device, inode, generation, position = plain[0]
    rotated = active.rename(tmp_path / 'auth.log.1')
    path = tmp_path / 'auth.log.2.gz'
    path.write_bytes(gzip.compress(rotated.read_bytes()))
    assert path.stat().st_ino != inode
    mysql_approvals(path, generation, original=(device, inode), previously_seen=True)
    active.write_bytes(ACTIVE)

    # While the original exists its plain reader remains authoritative.
    inserted, stats = run(mysql, active, max_lines=1)
    assert inserted == 1
    assert stats['archives_unverified'] == 1
    rotated.unlink()
    inserted, stats = run(mysql, active)
    assert inserted == 1
    assert stats['archives_complete'] == 1
    assert stored(mysql, 'SELECT logical_position FROM auth_archive_checkpoints') == ((position * 2,),)
    events = stored(mysql, 'SELECT file_generation,file_position FROM auth_events ORDER BY id')
    assert events[:2] == ((generation, 0), (generation, position))
    assert run(mysql, active)[0] == 0


def test_gzip_uses_plain_offset_when_original_rotates_before_catchup(mysql, tmp_path, mysql_approvals):
    active = tmp_path / 'auth.log'
    active.write_bytes(LINE * 2)
    assert run(mysql, active, max_lines=1)[0] == 1
    device, inode, generation, position = stored(
        mysql, 'SELECT file_device,file_inode,generation_key,last_position FROM auth_ingestion_state')[0]
    original = active.rename(tmp_path / 'retired')
    active.write_bytes(b'')
    path = tmp_path / 'auth.log.1.gz'
    content = original.read_bytes()
    original.unlink()

    path.write_bytes(gzip.compress(content.replace(b'alice', b'other')))
    mysql_approvals(path, generation, original=(device, inode), previously_seen=True)
    inserted, stats = run(mysql, active)
    assert inserted == 0
    assert stats['archives_unverified'] == 1
    assert 'verified plain checkpoint snapshot' in stats['archive_diagnostics'][0][1]
    assert stored(mysql, 'SELECT logical_position FROM auth_archive_checkpoints') == ()

    path.write_bytes(gzip.compress(content))
    mysql_approvals(path, generation, original=(device, inode), previously_seen=True)
    inserted, stats = run(mysql, active)
    assert inserted == 1
    assert stats['archives_complete'] == 1
    assert stored(mysql, 'SELECT file_generation,file_position FROM auth_events ORDER BY id') == (
        (generation, 0), (generation, position),
    )
    assert stored(mysql, 'SELECT last_position FROM auth_ingestion_state WHERE generation_key=0x'
                  + generation.hex()) == ((position,),)


def test_interrupt_and_sql_failure_roll_back_archive_events_and_checkpoint(mysql, tmp_path, mysql_approvals, monkeypatch):
    active = tmp_path / 'auth.log'
    active.write_bytes(b'')
    path = tmp_path / 'auth.log.1.gz'
    path.write_bytes(gzip.compress(LINE * 2))
    mysql_approvals(path, b'a' * 32)
    assert run(mysql, active, max_lines=1)[0] == 1
    save = collector.save_event

    def interrupt(*args, **kwargs):
        save(*args, **kwargs)
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(collector, 'save_event', interrupt)
        with pytest.raises(KeyboardInterrupt):
            run(mysql, active)
    assert stored(mysql, 'SELECT file_position FROM auth_events') == ((0,),)
    assert stored(mysql, 'SELECT logical_position FROM auth_archive_checkpoints') == ((len(LINE),),)

    with mysql.cursor() as cursor:
        cursor.execute("CREATE TRIGGER fail_gzip BEFORE UPDATE ON auth_archive_checkpoints "
                       "FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic failure'")
    with pytest.raises(pymysql.MySQLError, match='synthetic failure'):
        run(mysql, active)
    assert stored(mysql, 'SELECT file_position FROM auth_events') == ((0,),)
    assert stored(mysql, 'SELECT logical_position FROM auth_archive_checkpoints') == ((len(LINE),),)
    with mysql.cursor() as cursor:
        cursor.execute('DROP TRIGGER fail_gzip')
    assert run(mysql, active)[0] == 1


def test_ambiguous_archive_content_rolls_back_only_its_own_batch(mysql, tmp_path, mysql_approvals):
    active = tmp_path / 'auth.log'
    active.write_bytes(LINE)
    assert run(mysql, active)[0] == 1
    path = tmp_path / 'auth.log.2.gz'
    path.write_bytes(gzip.compress(LINE.replace(b'alice', b'archive-user') + LINE))
    mysql_approvals(path, b'a' * 32)
    with active.open('ab') as source:
        source.write(ACTIVE)
    inserted, stats = run(mysql, active)
    assert inserted == 1
    assert stats['archives_unverified'] == 1
    assert stats['coverage_gaps'] == 0
    assert stored(mysql, 'SELECT logical_position FROM auth_archive_checkpoints') == ()
    assert stored(mysql, 'SELECT username FROM auth_events ORDER BY id') == (('alice',), ('active-user',))
