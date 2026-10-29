"""Private, CRC-verified gzip spools; persistent logical offsets, one bounded worker."""
import argparse
import fcntl
import gzip
import hashlib
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

CACHE = Path('/var/lib/mysql_siem/ufw-archives')
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_CACHE = 1024 * 1024 * 1024
MAX_RATIO = 200
WORKER_SECONDS = 120
RESERVE_FREE = 256 * 1024 * 1024
CHUNK = 65536


def regular(path, flags=os.O_RDONLY):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise OSError('UNSAFE_ARCHIVE_FILE')
    return fd


def private_file(path):
    fd = regular(path)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise OSError('UNSAFE_ARCHIVE_CACHE_FILE')
    return fd


def cache_directory():
    parent = CACHE.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise OSError('UNSAFE_ARCHIVE_CACHE_PARENT')
    CACHE.mkdir(mode=0o700, exist_ok=True)
    info = CACHE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise OSError('UNSAFE_ARCHIVE_CACHE')
    return CACHE


def signature(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def read_manifest(path):
    try:
        fd = private_file(path)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as source:
        data = source.read(16385)
    if len(data) > 16384:
        raise OSError('ARCHIVE_MANIFEST_TOO_LARGE')
    return json.loads(data)


def write_manifest(path, record):
    fd, temporary = tempfile.mkstemp(prefix='.manifest-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(record, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def archive_digest(filename, deadline):
    with os.fdopen(regular(filename), 'rb') as source:
        initial = signature(os.fstat(source.fileno()))
        if initial[2] > MAX_COMPRESSED:
            raise OSError('ARCHIVE_COMPRESSED_LIMIT')
        digest = hashlib.sha256()
        while True:
            if time.monotonic() >= deadline:
                raise OSError('ARCHIVE_HASH_TIME_LIMIT')
            block = source.read(CHUNK)
            if not block:
                break
            digest.update(block)
        if signature(os.fstat(source.fileno())) != initial:
            raise OSError('ARCHIVE_CHANGED')
    return digest.hexdigest(), initial


def identify_archive(filename, deadline):
    """Reuse a verified SHA only with an unchanged inode, size, mtime AND ctime."""
    with os.fdopen(regular(filename), 'rb') as source:
        info = signature(os.fstat(source.fileno()))
    if info[2] > MAX_COMPRESSED:
        raise OSError('ARCHIVE_COMPRESSED_LIMIT')
    key = hashlib.sha256(json.dumps(info).encode('ascii')).hexdigest()
    lookup = CACHE / ('source-' + key + '.json')
    known = read_manifest(lookup)
    if known is not None:
        digest = known.get('sha256', '')
        valid = isinstance(digest, str) and len(digest) == 64
        if valid:
            for character in digest:
                if character not in '0123456789abcdef':
                    valid = False
        if known.get('signature') != info or not valid:
            raise OSError('INVALID_ARCHIVE_SOURCE_CACHE')
        return digest, info
    digest, current = archive_digest(filename, deadline)
    if current != info:
        raise OSError('ARCHIVE_CHANGED')
    write_manifest(lookup, {'sha256': digest, 'signature': info})
    return digest, info


def discover(logfile):
    logfile = Path(logfile)
    result = []
    with os.scandir(logfile.parent) as entries:
        for entry in entries:
            if not entry.name.startswith(logfile.name + '.') or not entry.name.endswith('.gz'):
                continue
            number = entry.name[len(logfile.name) + 1:-3]
            if not number.isascii() or not number.isdigit() or int(number) < 1:
                continue
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise OSError('UNSAFE_ARCHIVE_SOURCE')
            result.append((int(number), entry.path))
            if len(result) > 256:
                raise OSError('ARCHIVE_DISCOVERY_LIMIT')
    result.sort(reverse=True)
    return result


def worker(filename, folder, digest):
    """No database credentials or external commands; nothing is ingestible before EOF CRC."""
    folder = Path(folder)
    manifest = folder / (digest + '.json')
    data = folder / (digest + '.data')
    temporary = folder / (digest + '.part')
    try:
        deadline = time.monotonic() + WORKER_SECONDS
        actual, initial = archive_digest(filename, deadline)
        if actual != digest:
            raise OSError('ARCHIVE_CHANGED')
        used = 0
        for path in folder.iterdir():
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                used += info.st_size
        if used + MAX_EXPANDED > MAX_CACHE or shutil.disk_usage(folder).free < MAX_EXPANDED + RESERVE_FREE:
            raise OSError('ARCHIVE_DISK_LIMIT')
        # A crashed extraction has never published READY or ingestion offsets.
        if temporary.exists():
            fd = private_file(temporary)
            os.close(fd)
            temporary.unlink()
        count = 0
        expanded_hash = hashlib.sha256()
        with os.fdopen(regular(filename), 'rb') as source:
            if signature(os.fstat(source.fileno())) != initial:
                raise OSError('ARCHIVE_CHANGED')
            fd = regular(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(fd, 'wb') as output, gzip.GzipFile(fileobj=source) as decompressed:
                while True:
                    if time.monotonic() >= deadline:
                        raise OSError('ARCHIVE_DECOMPRESSION_TIME_LIMIT')
                    block = decompressed.read(CHUNK)
                    if not block:
                        break  # gzip verifies every member's CRC, size and trailer here.
                    count += len(block)
                    if count > MAX_EXPANDED or count > max(initial[2], 1) * MAX_RATIO:
                        raise OSError('ARCHIVE_EXPANSION_LIMIT')
                    output.write(block)
                    expanded_hash.update(block)
                output.flush()
                os.fsync(output.fileno())
            if signature(os.fstat(source.fileno())) != initial:
                raise OSError('ARCHIVE_CHANGED')
        # Recheck the compressed bytes as well as inode/mtime after extraction.
        if archive_digest(filename, deadline)[0] != digest:
            raise OSError('ARCHIVE_CHANGED')
        os.replace(temporary, data)
        write_manifest(manifest, {'status': 'READY', 'sha256': digest,
                                 'expanded_sha256': expanded_hash.hexdigest(),
                                 'signature': signature(data.stat())})
    except (OSError, EOFError, ValueError, zlib.error) as error:
        reason = 'ARCHIVE_IO_ERROR'
        if isinstance(error, gzip.BadGzipFile):
            reason = 'GZIP_CRC_OR_HEADER'
        elif isinstance(error, EOFError):
            reason = 'GZIP_TRUNCATED'
        elif isinstance(error, zlib.error):
            reason = 'GZIP_DEFLATE'
        elif error.args and error.args[0] in ('ARCHIVE_CHANGED', 'ARCHIVE_DISK_LIMIT', 'ARCHIVE_EXPANSION_LIMIT',
                                             'ARCHIVE_DECOMPRESSION_TIME_LIMIT', 'ARCHIVE_HASH_TIME_LIMIT',
                                             'ARCHIVE_COMPRESSED_LIMIT', 'ARCHIVE_WALL_TIME_LIMIT'):
            reason = error.args[0]
        write_manifest(manifest, {'status': 'ERROR', 'class': type(error).__name__, 'reason': reason})
        return 1
    return 0


def prepare(filename, digest):
    if len(digest) != 64:
        raise ValueError('INVALID_ARCHIVE_ID')
    for character in digest:
        if character not in '0123456789abcdef':
            raise ValueError('INVALID_ARCHIVE_ID')
    folder = cache_directory()
    manifest = folder / (digest + '.json')
    record = read_manifest(manifest)
    if record is not None and record.get('status') in ('READY', 'ERROR'):
        return record
    lock = regular(folder / '.worker.lock', os.O_RDWR | os.O_CREAT)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status': 'BUSY'}
        restarts = 0
        if record is not None:
            restarts = record.get('restarts', 0) + 1
            if restarts > 1:
                write_manifest(manifest, {'status': 'ERROR', 'class': 'WORKER_INTERRUPTED'})
                return {'status': 'ERROR'}
        write_manifest(manifest, {'status': 'WORKING', 'restarts': restarts})
        subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                          '--worker', filename, str(folder), digest, str(lock)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, pass_fds=(lock,),
                         env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        return {'status': 'WORKING'}
    finally:
        os.close(lock)  # The child retains the open file description and its lock.


def process_archives(connection, logfile, *, max_lines, deadline, totals=None):
    """One transaction per bounded archive chunk, after active collection commits."""
    import pymysql

    from database.identity import configured_identity
    from ingestion.ufw_batch import EventBatch
    from ingestion.ufw_continuity import gap, prove_archive
    from ingestion.ufw_records import process_line
    from ingestion.ufw_to_mysql import MAX_LINE_BYTES

    if totals is None:
        totals = {}
    totals.update({'inserted': 0, 'lines_read': 0, 'duplicates': 0, 'quarantined': 0, 'non_ufw': 0,
              'archives_pending': 0, 'archives_unscanned': 0, 'archive_errors': 0, 'filtered': 0})
    with connection.cursor() as cursor:
        identity = configured_identity(cursor, 'ufw')
    scope = 0
    if identity is not None:
        scope = identity.source_id
    cache_directory()
    candidates = discover(logfile)
    for index, (_number, filename) in enumerate(candidates):
        if time.monotonic() >= deadline:
            totals['archives_unscanned'] = len(candidates) - index
            break
        try:
            digest, info = identify_archive(filename, deadline)
        except OSError as error:
            if error.args and error.args[0] == 'ARCHIVE_HASH_TIME_LIMIT':
                totals['archives_unscanned'] = len(candidates) - index
                break
            failure_key = hashlib.sha256(os.fsencode(filename)).hexdigest()
            with connection.cursor() as cursor:
                if isinstance(error, FileNotFoundError):
                    gap(cursor, scope, 0, 'ARCHIVE_MISSING', filename)
                cursor.execute('SELECT 1 FROM ufw_archive_failures WHERE source_scope=%s AND source_key=%s',
                               (scope, failure_key))
                if cursor.fetchone() is None:
                    cursor.execute('INSERT INTO ufw_archive_failures (source_scope,source_key,filename,reason) '
                                   'VALUES (%s,%s,%s,%s)', (scope, failure_key, filename, type(error).__name__))
            connection.commit()
            print(f'UFW archive: FAILED class={type(error).__name__} stage=discovery file={filename!r}')
            continue
        with connection.cursor() as cursor:
            cursor.execute('SELECT status FROM ufw_archives WHERE source_scope=%s AND archive_sha=%s', (scope, digest))
            if cursor.fetchone() is None:
                cursor.execute('INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode) '
                               'VALUES (%s,%s,%s,%s,%s)', (scope, digest, filename, info[0], info[1]))
        connection.commit()
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_archives WHERE source_scope=%s AND status <> 'COMPLETE'", (scope,))
        totals['archives_pending'] = cursor.fetchone()[0]
        cursor.execute("SELECT archive_sha,filename,file_device,file_inode,logical_position,status FROM ufw_archives "
                       "WHERE source_scope=%s AND status IN ('PENDING','READING') ORDER BY checked_at,archive_sha LIMIT 64", (scope,))
        pending = cursor.fetchall()
    for digest, filename, device, inode, position, status in pending:
        if time.monotonic() >= deadline or totals['lines_read'] >= max_lines:
            break
        part = {'lines_read': 0, 'inserted': 0, 'duplicates': 0, 'quarantined': 0, 'non_ufw': 0, 'filtered': 0}
        try:
            if status == 'FAILED':
                raise OSError('ARCHIVE_PREVIOUSLY_FAILED')
            record = prepare(filename, digest)
            if record['status'] in ('BUSY', 'WORKING'):
                continue
            if record['status'] != 'READY' or record.get('sha256') != digest:
                if record.get('class') == 'FileNotFoundError':
                    raise FileNotFoundError('ARCHIVE_SOURCE_MISSING')
                reason = record.get('reason', 'ARCHIVE_UNVERIFIED')
                if reason not in ('GZIP_CRC_OR_HEADER', 'GZIP_TRUNCATED', 'GZIP_DEFLATE', 'ARCHIVE_CHANGED',
                                  'ARCHIVE_DISK_LIMIT', 'ARCHIVE_EXPANSION_LIMIT', 'ARCHIVE_DECOMPRESSION_TIME_LIMIT',
                                  'ARCHIVE_HASH_TIME_LIMIT', 'ARCHIVE_COMPRESSED_LIMIT', 'ARCHIVE_WALL_TIME_LIMIT'):
                    reason = 'ARCHIVE_UNVERIFIED'
                print(f'UFW archive: FAILED reason={reason} file={filename!r}')
                raise OSError('ARCHIVE_NOT_VERIFIED')
            path = CACHE / (digest + '.data')
            with os.fdopen(private_file(path), 'rb') as source:
                if signature(os.fstat(source.fileno())) != record['signature']:
                    raise OSError('ARCHIVE_SPOOL_CHANGED')
                connection.begin()
                with connection.cursor() as cursor:
                    writer = EventBatch(cursor, identity, connection.__dict__.get('_siem_ufw_policy'), part)
                    prove_archive(cursor, source, scope, digest, record['signature'][2], deadline)
                    source.seek(position)
                    while part['lines_read'] < min(1000, max_lines - totals['lines_read']):
                        if time.monotonic() >= deadline:
                            break
                        start = source.tell()
                        raw = source.readline(MAX_LINE_BYTES + 1)
                        if not raw:
                            break
                        if len(raw) > MAX_LINE_BYTES:
                            raise OSError('ARCHIVE_LINE_LIMIT')
                        part['inserted'] += process_line(cursor, raw, filename, start, device, inode, identity, part,
                                                         archive_sha=digest, partial=not raw.endswith(b'\n'), writer=writer)
                        part['lines_read'] += 1
                    writer.flush()
                    part['inserted'] = writer.inserted
                    position = source.tell()
                    complete = position == record['signature'][2]
                    new_status = 'READING'
                    if complete:
                        new_status = 'COMPLETE'
                    if signature(os.fstat(source.fileno())) != record['signature']:
                        raise OSError('ARCHIVE_SPOOL_CHANGED')
                    cursor.execute('INSERT INTO ufw_archive_proofs (source_scope,archive_sha,expanded_size,expanded_sha) '
                                   'VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE archive_sha=VALUES(archive_sha)',
                                   (scope, digest, record['signature'][2], record['expanded_sha256']))
                    cursor.execute('UPDATE ufw_archives SET logical_position=%s,status=%s,checked_at=CURRENT_TIMESTAMP(6) '
                                   'WHERE source_scope=%s AND archive_sha=%s', (position, new_status, scope, digest))
                connection.commit()
            for key, value in part.items():
                totals[key] += value
            if complete:
                totals['archives_pending'] -= 1
                path.unlink()  # Only our disposable, committed spool; never the source archive.
        except (OSError, EOFError, ValueError, RuntimeError, pymysql.MySQLError) as error:
            connection.rollback()
            if isinstance(error, pymysql.MySQLError):
                totals['archive_errors'] += 1
            print(f'UFW archive: FAILED class={type(error).__name__} stage=archive file={filename!r} position={position}')
            # Checkpoints and previously committed events are preserved on every failure.
            if not isinstance(error, pymysql.MySQLError):
                with connection.cursor() as cursor:
                    if isinstance(error, FileNotFoundError):
                        gap(cursor, scope, 0, 'ARCHIVE_MISSING', filename)
                    cursor.execute("UPDATE ufw_archives SET status='FAILED',checked_at=CURRENT_TIMESTAMP(6) WHERE source_scope=%s AND archive_sha=%s",
                                   (scope, digest))
                connection.commit()
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_archives WHERE source_scope=%s AND status='FAILED'", (scope,))
        failed = cursor.fetchone()[0]
        totals['archive_errors'] += failed
        cursor.execute('SELECT COUNT(*) FROM ufw_archive_failures WHERE source_scope=%s', (scope,))
        totals['archive_errors'] += cursor.fetchone()[0]
    return totals


def worker_timeout(_signum, _frame):
    raise TimeoutError('ARCHIVE_WALL_TIME_LIMIT')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', nargs=4, required=True)
    args = parser.parse_args()
    filename, folder, digest, lock = args.worker
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CPU, (WORKER_SECONDS, WORKER_SECONDS + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_EXPANDED, MAX_EXPANDED))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    # Inherited descriptor keeps exactly one decompressor alive across cron passes.
    fd = int(lock)
    signal.signal(signal.SIGALRM, worker_timeout)
    signal.alarm(WORKER_SECONDS)
    try:
        return worker(filename, folder, digest)
    finally:
        signal.alarm(0)
        os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
