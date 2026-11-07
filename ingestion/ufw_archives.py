"""Private, CRC-verified gzip spools; persistent logical offsets, one bounded worker."""
import argparse
import errno
import fcntl
import gzip
import hashlib
import json
import os
import resource
import secrets
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


MAX_ATTEMPTS = 3
RETRY_SECONDS = 60
TRANSIENT = ('ARCHIVE_DISK_LIMIT', 'ARCHIVE_HASH_TIME_LIMIT', 'ARCHIVE_DECOMPRESSION_TIME_LIMIT',
             'ARCHIVE_WALL_TIME_LIMIT', 'ARCHIVE_IO_TRANSIENT', 'WORKER_INTERRUPTED', 'ARCHIVE_SPOOL_MISSING')
IO_ERRORS = (errno.EAGAIN, errno.EBUSY, errno.EIO, errno.ETIMEDOUT, errno.ENOSPC, errno.EDQUOT,
             errno.EMFILE, errno.ENFILE, errno.EACCES)


def error_reason(error):
    if isinstance(error, OSError) and error.errno in IO_ERRORS:
        return 'ARCHIVE_IO_TRANSIENT'
    if error.args and error.args[0] in TRANSIENT:
        return error.args[0]
    return None


def manifest_reason(record):
    reason = record.get('reason', 'ARCHIVE_UNVERIFIED')
    if record.get('cleanup_error'):
        return 'ARCHIVE_CLEANUP_UNVERIFIED'
    if not isinstance(reason, str) or len(reason) > 64:
        return 'ARCHIVE_UNVERIFIED'
    return reason


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


def valid_digest(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    for character in value:
        if character not in '0123456789abcdef':
            return False
    return True


def discard_partial(folder, digest):
    """Remove only a private, singly linked collector temporary; never follow links."""
    if not valid_digest(digest):
        raise ValueError('INVALID_ARCHIVE_ID')
    path = folder / (digest + '.part')
    try:
        fd = private_file(path)
    except FileNotFoundError:
        return
    try:
        opened = os.fstat(fd)
        try:
            named = path.lstat()
        except FileNotFoundError:
            return
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise OSError('UNSAFE_ARCHIVE_CACHE_FILE')
        path.unlink()
    finally:
        os.close(fd)


def worker(filename, folder, digest):
    """No database credentials or external commands; nothing is ingestible before EOF CRC."""
    if not valid_digest(digest):
        raise ValueError('INVALID_ARCHIVE_ID')
    folder = Path(folder)
    manifest = folder / (digest + '.json')
    data = folder / (digest + '.data')
    temporary = folder / (digest + '.part')
    attempt = read_manifest(manifest)
    attempts = 1
    restarts = 0
    if attempt is not None:
        attempts = attempt.get('attempts', 1)
        restarts = attempt.get('restarts', 0)
    try:
        deadline = time.monotonic() + WORKER_SECONDS
        actual, initial = archive_digest(filename, deadline)
        if actual != digest:
            raise OSError('ARCHIVE_CHANGED')
        # A failed publication may leave a disposable spool, never accepted as READY.
        if data.exists() or data.is_symlink():
            descriptor = private_file(data)
            os.close(descriptor)
            data.unlink()
        used = 0
        # The inherited single-worker lock excludes another active extraction.
        # Reclaim crashed/failed extractions before reserving space for new data.
        for path in folder.iterdir():
            if path.suffix == '.part' and valid_digest(path.stem):
                discard_partial(folder, path.stem)
                continue
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                used += info.st_size
        if used + MAX_EXPANDED > MAX_CACHE or shutil.disk_usage(folder).free < MAX_EXPANDED + RESERVE_FREE:
            raise OSError('ARCHIVE_DISK_LIMIT')
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
                                 'signature': signature(data.stat()), 'attempts': attempts, 'restarts': restarts})
    except (OSError, EOFError, ValueError, zlib.error) as error:
        reason = error_reason(error)
        if reason is None:
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
        record = {'status': 'ERROR', 'class': type(error).__name__, 'reason': reason,
                  'attempts': attempts, 'restarts': restarts, 'retry_after': int(time.time()) + RETRY_SECONDS}
        try:
            discard_partial(folder, digest)
        except OSError as cleanup_error:
            record['cleanup_error'] = type(cleanup_error).__name__
        write_manifest(manifest, record)
        return 1
    return 0


def prepare(filename, digest):
    if not valid_digest(digest):
        raise ValueError('INVALID_ARCHIVE_ID')
    folder = cache_directory()
    manifest = folder / (digest + '.json')
    record = read_manifest(manifest)
    if record is not None and record.get('status') == 'READY':
        return record
    lock = regular(folder / '.worker.lock', os.O_RDWR | os.O_CREAT)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status': 'BUSY'}
        record = read_manifest(manifest)
        attempts = 0
        restarts = 0
        if record is not None:
            if record.get('status') == 'READY':
                return record
            attempts = record.get('attempts', 1)
            restarts = record.get('restarts', 0)
            if type(attempts) is not int or not 1 <= attempts <= MAX_ATTEMPTS:
                raise ValueError('INVALID_ARCHIVE_ATTEMPTS')
            if type(restarts) is not int or not 0 <= restarts <= 1:
                raise ValueError('INVALID_ARCHIVE_RESTARTS')
            if record.get('status') == 'ERROR':
                if manifest_reason(record) not in TRANSIENT or attempts >= MAX_ATTEMPTS:
                    return record
                after = record.get('retry_after', 0)
                if type(after) is not int or after < 0:
                    raise ValueError('INVALID_ARCHIVE_RETRY_TIME')
                if time.time() < after:
                    return record
            elif record.get('status') == 'WORKING':
                restarts += 1
                if restarts > 1 or attempts >= MAX_ATTEMPTS:
                    record = {'status': 'ERROR', 'class': 'WORKER_INTERRUPTED', 'reason': 'WORKER_INTERRUPTED',
                              'attempts': MAX_ATTEMPTS, 'restarts': 1}
                    write_manifest(manifest, record)
                    return record
            else:
                raise ValueError('INVALID_ARCHIVE_WORKER_STATE')
        attempts += 1
        write_manifest(manifest, {'status': 'WORKING', 'attempts': attempts, 'restarts': restarts})
        try:
            subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                              '--worker', filename, str(folder), digest, str(lock)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, pass_fds=(lock,),
                             env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        except OSError as error:
            reason = error_reason(error)
            if reason is None:
                reason = 'WORKER_START_FAILED'
            record = {'status': 'ERROR', 'class': type(error).__name__,
                      'reason': reason, 'attempts': attempts,
                      'restarts': restarts, 'retry_after': int(time.time()) + RETRY_SECONDS}
            write_manifest(manifest, record)
            return record
        return {'status': 'WORKING'}
    finally:
        os.close(lock)  # The child retains the open file description and its lock.


def process_archives(connection, logfile, *, max_lines, deadline, totals=None):
    """One transaction per bounded archive chunk, after active collection commits."""
    import pymysql

    from database.identity import configured_identity
    from ingestion import ufw_archive_retry as retry
    from ingestion.ufw_batch import EventBatch, OccurrenceConflict
    from ingestion.ufw_continuity import gap, prove_archive, record_proof
    from ingestion.ufw_lineage import archive_binding, output_job, verify_binding
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
    with connection.cursor() as cursor:
        retry.resume_due(cursor, scope)
    connection.commit()  # Persist the retry count before any extraction can start.
    candidates = discover(logfile)
    for index, (_number, filename) in enumerate(candidates):
        if time.monotonic() >= deadline:
            totals['archives_unscanned'] += len(candidates) - index
            break
        job = None
        candidate_info = None
        try:
            candidate_info = os.stat(filename, follow_symlinks=False)
            if not stat.S_ISREG(candidate_info.st_mode) or candidate_info.st_nlink != 1:
                raise OSError('UNSAFE_ARCHIVE_FILE')
            with connection.cursor() as cursor:
                if not retry.discovery_allowed(cursor, scope, candidate_info):
                    continue
                connection.commit()  # A recheck attempt survives process interruption.
                job = output_job(cursor, scope, candidate_info)
            if candidate_info.st_size == 0 or (job is not None and job[0] != 'READY'):
                totals['archives_unscanned'] += 1
                continue
            digest, info = identify_archive(filename, deadline)
            with connection.cursor() as cursor:
                binding = archive_binding(cursor, scope, digest)
            if job is not None and job[1:] != (digest, info[2]):
                raise OccurrenceConflict('UFW_MANAGED_ARCHIVE_CHANGED')
            if binding is not None and binding[4] != info[2]:
                raise OccurrenceConflict('UFW_ARCHIVE_LINEAGE_CONTENT_CHANGED')
        except OSError as error:
            if job is not None and job[0] == 'READY' and error.args == ('ARCHIVE_CHANGED',):
                # Logrotate may still be applying owner/mode/times after compression.
                totals['archives_unscanned'] += 1
                continue
            if error.args and error.args[0] == 'ARCHIVE_HASH_TIME_LIMIT':
                totals['archives_unscanned'] += len(candidates) - index
                break
            failure_key = secrets.token_hex(32)
            with connection.cursor() as cursor:
                if isinstance(error, FileNotFoundError):
                    gap(cursor, scope, 0, 'ARCHIVE_MISSING', filename)
                known = None
                if candidate_info is not None:
                    cursor.execute('SELECT archive_sha FROM ufw_archives WHERE source_scope=%s '
                                   'AND file_device=%s AND file_inode=%s AND file_mtime_ns=%s',
                                   (scope, candidate_info.st_dev, candidate_info.st_ino, candidate_info.st_mtime_ns))
                    matches = cursor.fetchall()
                    if len(matches) == 1:
                        known = matches[0][0]
                retryable = error_reason(error) is not None and known is not None
                cursor.execute('SELECT 1 FROM ufw_archive_failures WHERE source_scope=%s AND filename=%s '
                               'AND reason=%s AND archive_sha <=> %s AND resolved_at IS NULL LIMIT 1',
                               (scope, filename, type(error).__name__, known))
                if cursor.fetchone() is None:
                    cursor.execute('INSERT INTO ufw_archive_failures '
                                   '(source_scope,source_key,filename,reason,archive_sha,retryable) '
                                   'VALUES (%s,%s,%s,%s,%s,%s)',
                                   (scope, failure_key, filename, type(error).__name__, known, retryable))
                if retryable:
                    cursor.execute("SELECT status FROM ufw_archives WHERE source_scope=%s AND archive_sha=%s", (scope, known))
                    complete = cursor.fetchone() == ('COMPLETE',)
                    retry.failed(cursor, scope, known, error_reason(error), complete=complete)
            connection.commit()
            print(f'UFW archive: FAILED class={type(error).__name__} stage=discovery file={filename!r}')
            continue
        with connection.cursor() as cursor:
            cursor.execute('SELECT status,file_device,file_inode,file_mtime_ns FROM ufw_archives WHERE source_scope=%s AND archive_sha=%s', (scope, digest))
            existing = cursor.fetchone()
            if existing is not None and binding is not None:
                # An exact copy of a producer-recorded artifact is a proven replay.
                cursor.execute('UPDATE ufw_archives SET filename=%s,file_device=%s,file_inode=%s,file_mtime_ns=%s '
                               'WHERE source_scope=%s AND archive_sha=%s',
                               (filename, info[0], info[1], info[3], scope, digest))
            elif existing is not None:
                if existing[1:3] != (info[0], info[1]):
                    gap(cursor, scope, 0, 'AMBIGUOUS_SOURCE', filename)
                    connection.commit()
                    raise OccurrenceConflict('UFW_AMBIGUOUS_ARCHIVE_COPY')
                if existing[3] is not None and existing[3] != info[3]:
                    gap(cursor, scope, 0, 'AMBIGUOUS_SOURCE', filename)
                    connection.commit()
                    raise OccurrenceConflict('UFW_AMBIGUOUS_ARCHIVE_GENERATION')
                cursor.execute('UPDATE ufw_archives SET filename=%s WHERE source_scope=%s AND archive_sha=%s',
                               (filename, scope, digest))
            if existing is None:
                cursor.execute('INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode,file_mtime_ns) '
                               'VALUES (%s,%s,%s,%s,%s,%s)', (scope, digest, filename, info[0], info[1], info[3]))
            if existing is not None and existing[0] == 'FAILED':
                retry.adopt_legacy(cursor, scope, digest, read_manifest(CACHE / (digest + '.json')))
            retry.resolve(cursor, scope, digest)
        connection.commit()
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_archives WHERE source_scope=%s AND status <> 'COMPLETE'", (scope,))
        totals['archives_pending'] = cursor.fetchone()[0]
        cursor.execute("SELECT archive_sha,filename,file_device,file_inode,logical_position,status,file_mtime_ns FROM ufw_archives "
                       "WHERE source_scope=%s AND status IN ('PENDING','READING') ORDER BY checked_at,archive_sha LIMIT 64", (scope,))
        pending = cursor.fetchall()
    for digest, filename, device, inode, position, status, mtime in pending:
        if time.monotonic() >= deadline or totals['lines_read'] >= max_lines:
            break
        part = {'lines_read': 0, 'inserted': 0, 'duplicates': 0, 'quarantined': 0, 'non_ufw': 0, 'filtered': 0}
        failure_reason = None
        try:
            saved = read_manifest(CACHE / (digest + '.json'))
            if saved is None or saved.get('status') != 'READY':
                with os.fdopen(regular(filename), 'rb') as original:
                    info = os.fstat(original.fileno())
                if (info.st_dev, info.st_ino) != (device, inode):
                    raise OccurrenceConflict('UFW_AMBIGUOUS_ARCHIVE_COPY')
                if mtime is not None and info.st_mtime_ns != mtime:
                    raise OccurrenceConflict('UFW_AMBIGUOUS_ARCHIVE_GENERATION')
            record = prepare(filename, digest)
            if record['status'] in ('BUSY', 'WORKING'):
                continue
            if record['status'] != 'READY' or record.get('sha256') != digest:
                if record.get('class') == 'FileNotFoundError':
                    raise FileNotFoundError('ARCHIVE_SOURCE_MISSING')
                reason = manifest_reason(record)
                failure_reason = reason
                if reason not in ('GZIP_CRC_OR_HEADER', 'GZIP_TRUNCATED', 'GZIP_DEFLATE', 'ARCHIVE_CHANGED',
                                  'ARCHIVE_DISK_LIMIT', 'ARCHIVE_EXPANSION_LIMIT', 'ARCHIVE_DECOMPRESSION_TIME_LIMIT',
                                  'ARCHIVE_HASH_TIME_LIMIT', 'ARCHIVE_COMPRESSED_LIMIT', 'ARCHIVE_WALL_TIME_LIMIT'):
                    reason = 'ARCHIVE_UNVERIFIED'
                print(f'UFW archive: FAILED reason={reason} file={filename!r}')
                raise OSError('ARCHIVE_NOT_VERIFIED')
            path = CACHE / (digest + '.data')
            try:
                spool = private_file(path)
            except FileNotFoundError:
                failure_reason = 'ARCHIVE_SPOOL_MISSING'
                interrupted = dict(record)
                interrupted.update({'status': 'ERROR', 'reason': failure_reason,
                                    'retry_after': int(time.time()) + RETRY_SECONDS})
                write_manifest(CACHE / (digest + '.json'), interrupted)
                raise OSError(failure_reason) from None
            with os.fdopen(spool, 'rb') as source:
                if signature(os.fstat(source.fileno())) != record['signature']:
                    raise OSError('ARCHIVE_SPOOL_CHANGED')
                connection.begin()
                with connection.cursor() as cursor:
                    binding = archive_binding(cursor, scope, digest)
                    verify_binding(binding, record)
                    generation = bytes.fromhex(digest)
                    if binding is not None:
                        generation = binding[1]
                    writer = EventBatch(cursor, identity, connection.__dict__.get('_siem_ufw_policy'), part,
                                        generation=generation)
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
                    record_proof(cursor, scope, digest, record['signature'][2], record['expanded_sha256'])
                    cursor.execute('UPDATE ufw_archives SET logical_position=%s,status=%s,checked_at=CURRENT_TIMESTAMP(6) '
                                   'WHERE source_scope=%s AND archive_sha=%s', (position, new_status, scope, digest))
                    retry.resolve(cursor, scope, digest)
            connection.commit()
        except (OSError, EOFError, ValueError, RuntimeError, pymysql.MySQLError) as error:
            connection.rollback()
            if isinstance(error, pymysql.MySQLError):
                totals['archive_errors'] += 1
            if isinstance(error, OccurrenceConflict):
                print('UFW archive stopped: ' + str(error))
            print(f'UFW archive: FAILED class={type(error).__name__} stage=archive file={filename!r} position={position}')
            # Checkpoints and previously committed events are preserved on every failure.
            if not isinstance(error, pymysql.MySQLError):
                with connection.cursor() as cursor:
                    if isinstance(error, FileNotFoundError):
                        gap(cursor, scope, 0, 'ARCHIVE_MISSING', filename)
                    if failure_reason is None:
                        failure_reason = error_reason(error)
                        if failure_reason is None:
                            failure_reason = type(error).__name__
                    retry.failed(cursor, scope, digest, failure_reason)
                connection.commit()
            continue
        # Everything below follows a successful COMMIT and cannot undo its state.
        for key, value in part.items():
            totals[key] += value
        if complete:
            totals['archives_pending'] -= 1
            try:
                path.unlink()  # Only the disposable spool, never the source archive.
            except OSError as error:
                print(f'UFW archive spool cleanup deferred: {type(error).__name__} archive_sha={digest}')
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM ufw_archives WHERE source_scope=%s AND status='FAILED'", (scope,))
        failed = cursor.fetchone()[0]
        totals['archive_errors'] += failed
        cursor.execute('SELECT COUNT(*) FROM ufw_archive_failures WHERE source_scope=%s AND resolved_at IS NULL', (scope,))
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
