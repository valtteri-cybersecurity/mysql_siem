"""Archive logical checkpoints, CRC gating and live-log priority on private MySQL."""
import gzip
import hashlib

import pytest

from ingestion import ufw_archives as archives
from ingestion import ufw_to_mysql as ufw

GOOD = b'2026-10-25T13:35:58Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=443\n'


@pytest.fixture
def collection(mysql, tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'')
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    monkeypatch.setattr(archives, 'CACHE', tmp_path / 'cache')
    archives.cache_directory()
    def prepare(filename, digest):
        manifest = archives.read_manifest(archives.CACHE / (digest + '.json'))
        if manifest is None:
            archives.worker(filename, archives.CACHE, digest)
        return archives.read_manifest(archives.CACHE / (digest + '.json'))
    monkeypatch.setattr(archives, 'prepare', prepare)
    return mysql, path


def test_gzip_resume_dedupe_quarantine_and_live_priority(collection):
    connection, path = collection
    bad = GOOD.replace(b'DPT=443', b'DPT=bad')
    raw = GOOD + b'\x00' * 3000 + GOOD + bad + b'\xff malformed [UFW BLOCK]\n'
    gz = path.with_name('ufw.log.9.gz')
    gz.write_bytes(gzip.compress(raw))
    path.write_bytes(GOOD * 3)
    first = ufw.process_log(connection, max_lines=4)
    assert first['inserted'] == 1
    assert first['duplicates'] == 3
    with connection.cursor() as cursor:
        cursor.execute('SELECT logical_position,status FROM ufw_archives')
        position, status = cursor.fetchone()
        assert position == len(GOOD)
        assert status == 'READING'
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints')
        assert cursor.fetchone() == (len(GOOD) * 3,)
    # The original disappears after verified extraction. The protected spool still has every byte.
    gz.unlink()
    for _ in range(6):
        result = ufw.process_log(connection, max_lines=8)
        if result['archives_pending'] == 0:
            break
    assert result['archive_errors'] == 0
    with connection.cursor() as cursor:
        cursor.execute('SELECT logical_position,status FROM ufw_archives')
        assert cursor.fetchone() == (len(raw), 'COMPLETE')
        cursor.execute('SELECT COUNT(*) FROM ufw_log')
        assert cursor.fetchone() == (1,)
        cursor.execute('SELECT COUNT(*) FROM ufw_quarantine')
        assert cursor.fetchone() == (2,)
    gz.write_bytes(gzip.compress(raw))
    assert ufw.process_log(connection)['inserted'] == 0
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM ufw_quarantine')
        assert cursor.fetchone() == (2,)


def test_archive_quarantine_failure_rolls_back_its_offset_but_keeps_live_commit(collection):
    connection, path = collection
    path.write_bytes(GOOD)
    raw = GOOD.replace(b'DPT=443', b'DPT=444') + GOOD.replace(b'DPT=443', b'DPT=bad')
    path.with_name('ufw.log.1.gz').write_bytes(gzip.compress(raw))
    with connection.cursor() as cursor:
        cursor.execute('CREATE TRIGGER reject_quarantine BEFORE INSERT ON ufw_quarantine FOR EACH ROW '
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic quarantine failure'")
    result = ufw.process_log(connection, max_lines=100)
    assert result['status'] == 'FAILED'
    assert result['inserted'] == 1
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM ufw_log')
        assert cursor.fetchone() == (1,)
        cursor.execute('SELECT logical_position,status FROM ufw_archives')
        assert cursor.fetchone() == (0, 'PENDING')
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints')
        assert cursor.fetchone() == (len(GOOD),)
        cursor.execute('DROP TRIGGER reject_quarantine')
    assert ufw.process_log(connection)['inserted'] == 1


@pytest.mark.parametrize('bad', ['crc', 'truncated', 'gone'])
def test_failed_archive_never_hides_live_progress_or_incomplete_state(collection, bad):
    connection, path = collection
    path.write_bytes(GOOD)
    gz = path.with_name('ufw.log.2.gz')
    content = gzip.compress(GOOD)
    if bad == 'crc':
        content = content[:-8] + b'\0\0\0\0' + content[-4:]
    elif bad == 'truncated':
        content = content[:-3]
    gz.write_bytes(content)
    if bad == 'gone':
        digest = hashlib.sha256(content).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode) '
                           'VALUES (0,%s,%s,1,2)', (digest, str(gz)))
        connection.commit()
        gz.unlink()
    result = ufw.process_log(connection)
    assert result['status'] == 'FAILED'
    assert result['inserted'] == 1
    if bad == 'gone':
        assert result['collection_state'] == 'GAP_DETECTED'
    with connection.cursor() as cursor:
        cursor.execute('SELECT logical_position,status FROM ufw_archives')
        assert cursor.fetchone() == (0, 'FAILED')
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints')
        assert cursor.fetchone() == (len(GOOD),)


def test_failed_backlog_does_not_starve_good_archives(collection):
    connection, path = collection
    path.write_bytes(GOOD)
    path.with_name('ufw.log.3.gz').write_bytes(gzip.compress(GOOD.replace(b'DPT=443', b'DPT=444')))
    with connection.cursor() as cursor:
        for index in range(65):
            digest = hashlib.sha256(('synthetic broken archive ' + str(index)).encode()).hexdigest()
            cursor.execute("INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode,status) "
                           "VALUES (0,%s,'/synthetic/missing.gz',1,2,'FAILED')", (digest,))
    connection.commit()
    result = ufw.process_log(connection)
    assert result['status'] == 'FAILED'
    assert result['inserted'] == 2
    assert result['archives_pending'] == 65
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_archives WHERE status='COMPLETE'")
        assert cursor.fetchone() == (1,)


def test_modified_archive_gets_a_new_content_identity(collection):
    connection, path = collection
    gz = path.with_name('ufw.log.1.gz')
    gz.write_bytes(gzip.compress(GOOD))
    assert ufw.process_log(connection)['inserted'] == 1
    gz.write_bytes(gzip.compress(GOOD + GOOD.replace(b'DPT=443', b'DPT=444')))
    result = ufw.process_log(connection)
    assert result['inserted'] == 1
    assert result['duplicates'] == 1
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_archives WHERE status='COMPLETE'")
        assert cursor.fetchone() == (2,)
        cursor.execute('SELECT COUNT(*) FROM ufw_log')
        assert cursor.fetchone() == (2,)


def test_discovery_failure_remains_visible_after_source_disappears(collection):
    connection, path = collection
    path.write_bytes(GOOD)
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO ufw_archive_failures (source_scope,source_key,filename,reason) '
                       'VALUES (0,%s,%s,%s)', ('a' * 64, str(path) + '.1.gz', 'FileNotFoundError'))
    connection.commit()
    result = ufw.process_log(connection)
    assert result['inserted'] == 1
    assert result['archive_errors'] == 1
    assert result['status'] == 'FAILED'
    with path.open('ab') as output:
        output.write(GOOD.replace(b'DPT=443', b'DPT=444'))
    again = ufw.process_log(connection)
    assert again['inserted'] == 1
    assert again['archive_errors'] == 1
    assert again['status'] == 'FAILED'
