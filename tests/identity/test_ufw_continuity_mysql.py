"""Private socket-only MySQL: rotation, failures, recovery and 10,000 retained events."""
import gzip
import hashlib
from datetime import datetime, timedelta

import pymysql
import pytest

from database import migrate
from ingestion import ufw_archives as archives
from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw


def event(index):
    stamp = datetime(2026, 10, 29) + timedelta(seconds=index)
    return (stamp.isoformat() + 'Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 '
            'PROTO=TCP DPT=' + str(1000 + index) + '\n').encode()


@pytest.fixture
def collection(mysql, tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'')
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    monkeypatch.setattr(archives, 'CACHE', tmp_path / 'cache')
    archives.cache_directory()
    def prepare(filename, digest):
        record = archives.read_manifest(archives.CACHE / (digest + '.json'))
        if record is None:
            assert archives.worker(filename, archives.CACHE, digest) == 0
        return archives.read_manifest(archives.CACHE / (digest + '.json'))
    monkeypatch.setattr(archives, 'prepare', prepare)
    return mysql, path


def checkpoints(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,source_scope,file_device,file_inode,filename,byte_position,prefix_sha '
                       'FROM ufw_file_checkpoints ORDER BY id')
        return cursor.fetchall()


def test_ten_thousand_events_rotate_compress_interrupt_and_resume(collection, monkeypatch):
    connection, path = collection
    original = bytearray()
    expected = set()
    for index in range(6000):
        raw = event(index)
        original.extend(raw)
        expected.add(hashlib.sha256(raw.strip()).hexdigest())
    path.write_bytes(original)
    assert ufw.process_log(connection, max_lines=1000)['inserted'] == 1000
    before = checkpoints(connection)
    first_position = 0
    for index in range(1000):
        first_position += len(event(index))
    assert before[0][5] == first_position
    # A crash before COMMIT must leave both event count and checkpoint unchanged.
    real_commit = connection.commit
    attempts = [0]
    def fail_once():
        attempts[0] += 1
        if attempts[0] == 2:
            raise pymysql.OperationalError(2013, 'synthetic lost connection before commit')
        real_commit()
    with monkeypatch.context() as interrupted:
        interrupted.setattr(connection, 'commit', fail_once)
        with pytest.raises(pymysql.OperationalError):
            ufw.process_log(connection, max_lines=1000)
    assert checkpoints(connection) == before
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM ufw_log')
        assert cursor.fetchone() == (1000,)
    rotated = path.with_name('ufw.log.7')
    path.rename(rotated)
    compressed = path.with_name('ufw.log.7.gz')
    compressed.write_bytes(gzip.compress(original))
    rotated.unlink()
    live = bytearray()
    for index in range(6000, 10000):
        raw = event(index)
        live.extend(raw)
        expected.add(hashlib.sha256(raw.strip()).hexdigest())
    path.write_bytes(live)
    first = ufw.process_log(connection, max_lines=1000)
    assert first['active_lines'] == 750
    assert first['archive_lines'] == 250
    # A client may lose the reply after COMMIT. Retrying must not duplicate events.
    attempts[0] = 0
    def commit_then_fail():
        attempts[0] += 1
        real_commit()
        if attempts[0] == 2:
            raise pymysql.OperationalError(2013, 'synthetic lost commit reply')
    with monkeypatch.context() as interrupted:
        interrupted.setattr(connection, 'commit', commit_then_fail)
        with pytest.raises(pymysql.OperationalError):
            ufw.process_log(connection, max_lines=1000)
    for _ in range(40):
        result = ufw.process_log(connection, max_lines=1000)
        if result['collection_state'] == 'HEALTHY':
            break
    assert result['collection_state'] == 'HEALTHY'
    assert result['archives_pending'] == 0
    with connection.cursor() as cursor:
        cursor.execute('SELECT event_hash FROM ufw_log')
        actual = []
        for row in cursor.fetchall():
            actual.append(row[0])
        assert len(actual) == len(set(actual)) == 10000
        assert set(actual) == expected
        cursor.execute('SELECT logical_position,status FROM ufw_archives')
        assert cursor.fetchone() == (len(original), 'COMPLETE')
        cursor.execute('SELECT byte_position,prefix_sha FROM ufw_file_checkpoints WHERE filename=%s ORDER BY id DESC LIMIT 1', (str(path),))
        assert cursor.fetchone() == (len(live), hashlib.sha256(live).hexdigest())
        cursor.execute('SELECT COUNT(*) FROM ufw_collection_gaps WHERE resolved=FALSE')
        assert cursor.fetchone() == (0,)
    snapshot = checkpoints(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ufw_collection_health')
        health = cursor.fetchall()
    assert continuity.read_health(connection, 0)['state'] == 'HEALTHY'
    assert checkpoints(connection) == snapshot
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ufw_collection_health')
        assert cursor.fetchall() == health


def test_rotation_rewrite_partial_quarantine_and_missing_source(collection, monkeypatch, identity_server):
    connection, path = collection
    path.write_bytes(event(0) + event(1))
    ufw.process_log(connection, max_lines=1)
    first = checkpoints(connection)[0]
    rotated = path.with_name('ufw.log.9')
    path.rename(rotated)
    path.write_bytes(event(2))
    assert ufw.process_log(connection)['inserted'] == 2
    assert checkpoints(connection)[0][0] == first[0]
    # The rotated file grows before compression. Its verified prefix still proves continuity.
    with rotated.open('ab') as output:
        output.write(event(13))
    path.with_name('ufw.log.9.gz').write_bytes(gzip.compress(rotated.read_bytes()))
    rotated.unlink()
    assert ufw.process_log(connection)['inserted'] == 1
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM ufw_collection_gaps WHERE checkpoint_id=%s AND resolved=FALSE', (first[0],))
        assert cursor.fetchone() == (0,)
    # Same inode, larger than the old position: no old offset may skip new bytes.
    prior = checkpoints(connection)[-1]
    path.write_bytes(event(3) + event(4) + event(5))
    assert ufw.process_log(connection)['inserted'] == 3
    after = checkpoints(connection)
    assert after[-2][5] == prior[5]
    assert after[-1][0] != prior[0]
    assert continuity.read_health(connection, 0)['state'] == 'GAP_DETECTED'
    # Equal-size rewrite, then a partial final line.
    path.write_bytes(event(6) + event(7) + event(8))
    assert ufw.process_log(connection)['inserted'] == 3
    with path.open('ab') as output:
        output.write(event(9)[:-1])
    assert ufw.process_log(connection)['inserted'] == 0
    assert checkpoints(connection)[-1][5] == len(event(6) + event(7) + event(8))
    with path.open('ab') as output:
        output.write(b'\n')
    assert ufw.process_log(connection)['inserted'] == 1
    # Quarantine failure rolls back its event checkpoint and survives restart.
    before = checkpoints(connection)
    with path.open('ab') as output:
        output.write(b'bad [UFW BLOCK]\n')
    with connection.cursor() as cursor:
        cursor.execute("CREATE TRIGGER fail_q BEFORE INSERT ON ufw_quarantine FOR EACH ROW "
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic quarantine failure'")
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(connection)
    assert checkpoints(connection) == before
    with connection.cursor() as cursor:
        cursor.execute('DROP TRIGGER fail_q')
    assert ufw.process_log(connection)['quarantined'] == 1
    # Competing processes use the same MySQL advisory lock.
    other = pymysql.connect(unix_socket=identity_server, user='root')
    try:
        with other.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s,0)', (ufw.LOCK_NAME,))
            assert cursor.fetchone() == (1,)
        before = checkpoints(connection)
        with pytest.raises(RuntimeError, match='Another UFW collector'):
            ufw.process_log(connection)
        assert checkpoints(connection) == before
    finally:
        other.close()
    # A real dropped MySQL session rolls back both rows and checkpoint.
    before = checkpoints(connection)
    with path.open('ab') as output:
        output.write(event(12))
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        name = cursor.fetchone()[0]
    victim = pymysql.connect(unix_socket=identity_server, user='root', database=name, autocommit=False)
    killer = pymysql.connect(unix_socket=identity_server, user='root')
    from ingestion import ufw_records
    save = ufw_records.process_line
    def save_and_disconnect(cursor, value, *arguments, **options):
        inserted = save(cursor, value, *arguments, **options)
        with killer.cursor() as admin:
            admin.execute('KILL CONNECTION %s', (victim.thread_id(),))
        return inserted
    try:
        with monkeypatch.context() as disconnected:
            disconnected.setattr(ufw_records, 'process_line', save_and_disconnect)
            with pytest.raises(pymysql.MySQLError):
                ufw.process_log(victim)
    finally:
        victim.close()
        killer.close()
    connection.rollback()
    assert checkpoints(connection) == before
    with connection.cursor() as cursor:
        cursor.execute('SELECT active_state,stop_reason FROM ufw_collection_health')
        assert cursor.fetchone() == ('UNKNOWN', 'running')
    assert ufw.process_log(connection)['inserted'] == 1
    # A genuinely unfinished rotation disappears; never claim it was recovered.
    pending = path.with_name('ufw.log.23')
    pending.write_bytes(event(10) + event(11))
    with connection.cursor() as cursor:
        ufw.process_file(cursor, str(pending), max_lines=1)
    connection.commit()
    pending.unlink()
    ufw.process_log(connection)
    assert continuity.read_health(connection, 0)['state'] == 'GAP_DETECTED'
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_collection_gaps WHERE reason='MISSING_SOURCE' AND resolved=FALSE")
        assert cursor.fetchone()[0] >= 1
    # Even a one-line budget must give all three queues regular turns.
    small_archive = path.with_name('ufw.log.31.gz')
    small_archive.write_bytes(gzip.compress(event(40) + event(41)))
    small_rotation = path.with_name('ufw.log.19')
    small_rotation.write_bytes(event(42) + event(43))
    live_progress = 0
    archive_progress = 0
    for index in range(12):
        with path.open('ab') as output:
            output.write(event(14 + index))
        result = ufw.process_log(connection, max_lines=1)
        assert result['lines_read'] <= 1
        live_progress += result.get('active_lines', 0)
        archive_progress += result.get('archive_lines', 0)
    assert live_progress > 0
    assert archive_progress >= 2
    with connection.cursor() as cursor:
        cursor.execute('SELECT status FROM ufw_archives WHERE filename=%s', (str(small_archive),))
        assert cursor.fetchone() == ('COMPLETE',)
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints WHERE filename=%s', (str(small_rotation),))
        assert cursor.fetchone() == (len(event(42) + event(43)),)


def test_migration_preserves_legacy_and_archive_checkpoints(empty_mysql, monkeypatch):
    connection = empty_mysql
    with monkeypatch.context() as older:
        versions = []
        for item in migrate.MIGRATIONS:
            if item[0] < '025':
                versions.append(item)
        older.setattr(migrate, 'MIGRATIONS', tuple(versions))
        migrate.migrate(connection)
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO ufw_state (logfile,last_position,file_device,file_inode,source_scope) "
                       "VALUES ('/synthetic/ufw.log',987654,1,2,0)")
        cursor.execute("INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode,logical_position,status) "
                       "VALUES (0,%s,'/synthetic/ufw.log.4.gz',3,4,567,'READING')", ('a' * 64,))
        cursor.execute('SELECT * FROM ufw_state')
        legacy = cursor.fetchall()
        cursor.execute('SELECT * FROM ufw_archives')
        archive = cursor.fetchall()
    connection.commit()
    assert migrate.migrate(connection) == ['025', '026']
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ufw_state')
        assert cursor.fetchall() == legacy
        cursor.execute('SELECT * FROM ufw_archives')
        assert cursor.fetchall() == archive
