"""Recover gzip Auth rotations using independently approved file lineage."""

import gzip
import hashlib
import json
import os
import stat
import tempfile
import time
import zlib

from config.installation_state import STATE_DIR
from config.service_installation import InstallationError, trusted_directory
from ingestion.auth.db import load_position
from ingestion.auth.identity import (
    CHUNK,
    AuthCollectionError,
    AuthOccurrenceConflict,
    AuthRecordError,
    AuthSourceError,
    AuthVerificationTimeout,
    hashes,
)
from ingestion.auth.parser import AuthParseError

PROOFS = STATE_DIR / 'auth-archives'
PROOF_OWNER = 0
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
RESERVE_FREE = 128 * 1024 * 1024


class ArchiveUnverified(AuthCollectionError):
    """Origin is ambiguous. Keep the archive available for review."""


class ArchiveReadError(AuthCollectionError):
    """The gzip container or its contents could not be read safely."""


def check_time(deadline):
    if time.monotonic() >= deadline:
        raise AuthVerificationTimeout('gzip verification budget reached')


def approval(info, scope, reader):
    """A protected receipt binds exact compressed bytes to an original generation.

    The receipt is named by the gzip output's device and inode and binds its
    ctime and SHA-256. A renamed/copied gzip needs a renewed receipt if its
    filesystem identity changed. The original device and inode refer to the
    plain file, not the gzip. A continuation must name its stored generation.
    For a new source the administrator attests that the source was never
    collected and supplies a stable, unique 32-byte generation token.
    """
    path = PROOFS / f'{info.st_dev}-{info.st_ino}.json'
    try:
        trusted_directory(PROOFS)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            proof_info = os.fstat(source.fileno())
            if (not stat.S_ISREG(proof_info.st_mode) or proof_info.st_nlink != 1
                    or proof_info.st_uid != PROOF_OWNER or proof_info.st_mode & 0o022):
                raise ValueError
            content = source.read(4097)
            if len(content) > 4096:
                raise ValueError
        proof = json.loads(content)
        if (type(proof['source_scope']) is not int or proof['source_scope'] != scope
                or proof['reader'] != reader or type(proof['archive_ctime_ns']) is not int
                or not isinstance(proof['database'], str) or not isinstance(proof['server'], str)
                or proof['archive_ctime_ns'] != info.st_ctime_ns
                or type(proof['previously_seen']) is not bool):
            raise ValueError
        for field in ('device', 'inode'):
            if type(proof[field]) is not int or not 0 < proof[field] < 2**64:
                raise ValueError
        for field in ('generation_key', 'archive_sha256'):
            value = proof[field]
            decoded = bytes.fromhex(value)
            if len(decoded) != 32 or decoded.hex() != value or not any(decoded):
                raise ValueError
            proof[field] = decoded
    except (InstallationError, OSError, ValueError, KeyError, TypeError):
        raise ArchiveUnverified(
            f'valid root-owned lineage receipt required at {path}; preserve the gzip for review '
            '(database, server UUID, source_scope, reader, archive_ctime_ns, archive_sha256, '
            'original device and inode, generation_key, previously_seen)'
        ) from None
    return proof


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def unchanged(source, filename, info):
    expected = signature(info)
    if signature(os.fstat(source.fileno())) != expected or signature(os.lstat(filename)) != expected:
        raise ArchiveReadError('gzip file changed during verification')


def verify_compressed(source, filename, info, expected, deadline, *, snapshot=None):
    if not 2 <= info.st_size <= MAX_COMPRESSED:
        raise ArchiveReadError('invalid gzip size or compressed size limit exceeded')
    if snapshot is not None:
        disk = os.fstatvfs(snapshot.fileno())
        if info.st_size > disk.f_bavail * disk.f_frsize - RESERVE_FREE:
            raise ArchiveReadError('not enough free space to verify gzip safely')
    if source.read(2) != b'\x1f\x8b':
        raise ArchiveReadError('invalid gzip header')
    source.seek(0)
    digest = hashlib.sha256()
    while True:
        check_time(deadline)
        block = source.read(CHUNK)
        if not block:
            break
        if source.tell() > info.st_size:
            raise ArchiveReadError('gzip grew during verification')
        digest.update(block)
        if snapshot is not None:
            snapshot.write(block)
    unchanged(source, filename, info)
    if digest.digest() != expected:
        raise ArchiveUnverified('compressed SHA-256 differs from the lineage receipt')
    if snapshot is not None:
        snapshot.seek(0)


def expand(source, spool, deadline):
    """Bound disk, memory and time. Read to gzip EOF before parsing any events."""
    size = 0
    disk = os.fstatvfs(spool.fileno())
    writable = disk.f_bavail * disk.f_frsize - RESERVE_FREE
    try:
        with gzip.GzipFile(fileobj=source, mode='rb') as compressed:
            while True:
                check_time(deadline)
                block = compressed.read(CHUNK)
                if not block:
                    break
                size += len(block)
                if size > MAX_EXPANDED:
                    raise ArchiveReadError('expanded gzip size limit exceeded')
                if size > writable:
                    raise ArchiveReadError('not enough free space to verify gzip safely')
                spool.write(block)
    except (gzip.BadGzipFile, EOFError, zlib.error):
        raise ArchiveReadError('gzip header, CRC, or compressed stream is invalid or truncated') from None
    if size:
        spool.seek(size - 1)
        if spool.read(1) != b'\n':
            raise ArchiveReadError('gzip ends with an incomplete log record')
    spool.seek(0)
    return size


def initial_position(cursor, spool, size, logfile, scope, reader, proof, deadline):
    from ingestion.auth.collector import get_logfiles, position_hash

    device, inode = proof['device'], proof['inode']
    generation = proof['generation_key']
    for path in get_logfiles(logfile, include_gzip=False):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if (info.st_dev, info.st_ino) == (device, inode):
            raise ArchiveUnverified('the original plain file is still available; collect it before adopting its gzip')
    if not proof['previously_seen']:
        # A scope-zero checkpoint left by enrollment is still evidence of history.
        cursor.execute('SELECT 1 FROM auth_ingestion_state WHERE collector_id=%s '
                       'AND file_device=%s AND file_inode=%s LIMIT 1', (reader, device, inode))
        if cursor.fetchone() is not None:
            raise ArchiveUnverified('the alleged new source already has a plain checkpoint')
        cursor.execute('SELECT 1 FROM auth_ingestion_state WHERE source_scope=%s AND generation_key=%s LIMIT 1',
                       (scope, generation))
        if cursor.fetchone() is not None:
            raise ArchiveUnverified('the alleged new generation is already assigned to a plain checkpoint')
        cursor.execute('SELECT 1 FROM auth_events WHERE source_scope=%s AND file_generation=%s LIMIT 1',
                       (scope, generation))
        if cursor.fetchone() is not None:
            raise ArchiveUnverified('the alleged new generation already has stored events')
        return 0

    state = load_position(cursor, reader, device, inode, source_scope=scope, with_origin=True)
    if state is None or state[2] != generation:
        raise ArchiveUnverified('the receipt does not match a verified plain checkpoint generation')
    position, digest, _generation, prefix, observed_size, observed, _mtime = state
    if (type(position) is not int or type(observed_size) is not int
            or not 0 <= position <= observed_size <= size):
        raise ArchiveUnverified('gzip does not cover the verified plain checkpoint snapshot')
    verified = hashes(spool, (position, observed_size), deadline)
    if verified[position].hexdigest() != prefix or verified[observed_size].hexdigest() != observed:
        raise ArchiveUnverified('expanded gzip content differs from the verified plain checkpoint snapshot')
    if position:
        spool.seek(position - 1)
        if spool.read(1) != b'\n' or position_hash(spool, position) != digest:
            raise ArchiveUnverified('plain checkpoint is not a verified record boundary in the gzip')
    return position


def checkpoint(cursor, scope, reader, proof):
    generation = proof['generation_key']
    cursor.execute('SELECT collector_id,file_device,file_inode,archive_sha,logical_position,expanded_size '
                   'FROM auth_archive_checkpoints WHERE source_scope=%s AND generation_key=%s', (scope, generation))
    saved = cursor.fetchone()
    if saved is not None:
        if saved[:4] != (reader, proof['device'], proof['inode'], proof['archive_sha256']):
            raise ArchiveUnverified('archive conflicts with the previously accepted generation or compressed content')
        if not 0 <= saved[4] <= saved[5]:
            raise ArchiveUnverified('the stored gzip checkpoint is invalid')
    return saved


def record_result(stats, counter, filename, reason):
    stats[counter] += 1
    if len(stats['archive_diagnostics']) < 16:
        stats['archive_diagnostics'].append((os.path.basename(filename), reason))


def process(cursor, logfile, filename, reader, stats, *, identity, line_limit, deadline,
            syslog_start, syslog_end, syslog_timezone):
    from ingestion.auth.collector import open_logfile, read_records

    scope = 0
    if identity is not None:
        scope = identity.source_id
    savepoint = False
    try:
        check_time(deadline)
        try:
            source = open_logfile(filename)
        except AuthSourceError as error:
            raise ArchiveReadError(str(error)) from None
        with source:
            info = os.fstat(source.fileno())
            proof = approval(info, scope, reader)
            cursor.execute('SELECT DATABASE(), @@server_uuid')
            if cursor.fetchone() != (proof['database'], proof['server']):
                raise ArchiveUnverified('lineage receipt belongs to a different database or server')
            saved = checkpoint(cursor, scope, reader, proof)
            if saved is not None and saved[4] == saved[5]:
                verify_compressed(source, filename, info, proof['archive_sha256'], deadline)
                stats['archives_complete'] += 1
                return 0, 0
            with tempfile.TemporaryFile() as spool:
                # Expand the exact bytes verified against the trusted receipt.
                with tempfile.TemporaryFile() as snapshot:
                    verify_compressed(source, filename, info, proof['archive_sha256'], deadline, snapshot=snapshot)
                    size = expand(snapshot, spool, deadline)
                unchanged(source, filename, info)
                if saved is None:
                    position = initial_position(cursor, spool, size, logfile, scope, reader, proof, deadline)
                else:
                    position = saved[4]
                    if size != saved[5]:
                        raise ArchiveUnverified('expanded gzip size differs from its checkpoint')
                spool.seek(position)
                part = stats.copy()
                cursor.execute('SAVEPOINT auth_archive')
                savepoint = True
                inserted, skipped = read_records(
                    cursor, spool, size, proof['generation_key'], part, identity=identity, line_limit=line_limit,
                    deadline=deadline, syslog_start=syslog_start, syslog_end=syslog_end,
                    syslog_timezone=syslog_timezone,
                )
                end = spool.tell()
                unchanged(source, filename, info)
                cursor.execute(
                    'INSERT INTO auth_archive_checkpoints '
                    '(source_scope,generation_key,collector_id,file_device,file_inode,archive_sha,'
                    'logical_position,expanded_size) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) '
                    'ON DUPLICATE KEY UPDATE logical_position=%s',
                    (scope, proof['generation_key'], reader, proof['device'], proof['inode'],
                     proof['archive_sha256'], end, size, end),
                )
        cursor.execute('RELEASE SAVEPOINT auth_archive')
        stats.update(part)
        stats['remaining_bytes'] += size - end
        if end == size:
            stats['archives_complete'] += 1
        else:
            stats['archives_pending'] += 1
        return inserted, skipped
    except AuthVerificationTimeout:
        stats['archives_pending'] += 1
    except (ArchiveUnverified, AuthOccurrenceConflict) as error:
        record_result(stats, 'archives_unverified', filename, str(error))
    except (ArchiveReadError, AuthRecordError, AuthParseError) as error:
        record_result(stats, 'archives_failed', filename, str(error))
    except OSError:
        record_result(stats, 'archives_failed', filename, 'gzip or its temporary file could not be read safely')
    if savepoint:
        cursor.execute('ROLLBACK TO SAVEPOINT auth_archive')
        cursor.execute('RELEASE SAVEPOINT auth_archive')
    return 0, 0
