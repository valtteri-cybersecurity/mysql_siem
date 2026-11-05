"""Logrotate compressor: record lineage while the original file descriptor exists."""
import argparse
import contextlib
import gzip
import hashlib
import os
import pwd
import secrets
import stat
import sys
import time
from pathlib import Path

import pymysql

from database.connection import get_connection
from database.identity import configured_identity
from ingestion import ufw_archives as archives
from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw

TRUSTED_OWNER = 0


def checked_file(source):
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OSError('UNSAFE_COMPRESSION_DESCRIPTOR')
    trusted = info.st_uid == TRUSTED_OWNER
    try:
        logger_uid = pwd.getpwnam('syslog').pw_uid
    except KeyError:
        logger_uid = None
    if logger_uid is not None and logger_uid != os.geteuid() and info.st_uid == logger_uid:
        trusted = True
    if not trusted or info.st_mode & 0o022:
        raise OSError('UNTRUSTED_COMPRESSION_DESCRIPTOR')
    return info


class CompressedOutput:
    def __init__(self, output):
        self.output = output
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, block):
        if self.size + len(block) > archives.MAX_COMPRESSED:
            raise OSError('ARCHIVE_COMPRESSED_LIMIT')
        written = self.output.write(block)
        if written != len(block):
            raise OSError('ARCHIVE_SHORT_WRITE')
        self.digest.update(block)
        self.size += written
        return written

    def flush(self):
        self.output.flush()


def compress_stream(connection, source, output, filename, *, level=6):
    """No event inserts or checkpoint advancement. Failure leaves the source intact."""
    named = Path(filename)
    expected = Path(ufw.LOGFILE)
    suffix = named.name[len(expected.name) + 1:]
    if (named.parent != expected.parent or not named.name.startswith(expected.name + '.')
            or not suffix.isascii() or not suffix.isdigit() or int(suffix) < 1):
        raise ValueError('Compression requires an uncompressed numbered UFW rotation.')
    checked_file(source)
    destination = checked_file(output)
    if destination.st_size != 0 or output.tell() != 0:
        raise OSError('COMPRESSION_OUTPUT_NOT_EMPTY')
    locked = False
    job = None
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s,20)', (ufw.LOCK_NAME,))
            if cursor.fetchone() != (1,):
                raise RuntimeError('UFW_COMPRESSION_LOCK_UNAVAILABLE')
            locked = True
            identity = configured_identity(cursor, 'ufw')
            scope = 0
            if identity is not None:
                scope = identity.source_id
            info = checked_file(source)
            if (info.st_dev, info.st_ino) == (destination.st_dev, destination.st_ino):
                raise OSError('COMPRESSION_SOURCE_IS_OUTPUT')
            if info.st_size > archives.MAX_EXPANDED:
                raise OSError('ARCHIVE_EXPANSION_LIMIT')
            deadline = time.monotonic() + archives.WORKER_SECONDS
            connection.begin()
            checkpoint, prefix, observed, generation = continuity.start(
                cursor, source, filename, info, scope, deadline)
            if checkpoint is None:
                cursor.execute('INSERT INTO ufw_file_checkpoints '
                               '(filename,byte_position,prefix_sha,observed_size,observed_sha,status,source_scope,'
                               'file_device,file_inode,checked_at,generation_key,file_mtime_ns) '
                               "VALUES (%s,0,%s,%s,%s,'READING',%s,%s,%s,UTC_TIMESTAMP(6),%s,%s)",
                               (filename, prefix.hexdigest(), info.st_size, observed, scope, info.st_dev,
                                info.st_ino, generation, info.st_mtime_ns))
                checkpoint = cursor.lastrowid
            cursor.execute('SELECT generation_key FROM ufw_file_checkpoints WHERE id=%s AND source_scope=%s',
                           (checkpoint, scope))
            if cursor.fetchone() != (generation,):
                raise RuntimeError('UFW_COMPRESSION_GENERATION_UNVERIFIED')
            cursor.execute('INSERT INTO ufw_compression_jobs '
                           '(source_scope,checkpoint_id,generation_key,source_device,source_inode,archive_device,'
                           'archive_inode,expanded_size,expanded_sha,status) '
                           "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'WRITING')",
                           (scope, checkpoint, generation, info.st_dev, info.st_ino, destination.st_dev,
                            destination.st_ino, info.st_size, observed))
            job = cursor.lastrowid
        # Discovery sees WRITING after a crash and never ingests a partial output.
        connection.commit()
        source.seek(0)
        writer = CompressedOutput(output)
        expanded = hashlib.sha256()
        remaining = info.st_size
        # A fresh artifact nonce makes a managed output distinct from any unrelated gzip.
        with gzip.GzipFile(fileobj=writer, mode='wb', filename='mysql-siem-' + secrets.token_hex(16),
                           mtime=0, compresslevel=level) as compressed:
            while remaining:
                if time.monotonic() >= deadline:
                    raise TimeoutError('ARCHIVE_COMPRESSION_TIME_LIMIT')
                block = source.read(min(archives.CHUNK, remaining))
                if not block:
                    raise OSError('SOURCE_CHANGED')
                compressed.write(block)
                expanded.update(block)
                remaining -= len(block)
        output.flush()
        os.fsync(output.fileno())
        if expanded.hexdigest() != observed or archives.signature(os.fstat(source.fileno())) != archives.signature(info):
            raise OSError('SOURCE_CHANGED')
        named_info = os.stat(filename, follow_symlinks=False)
        if not stat.S_ISREG(named_info.st_mode) or (named_info.st_dev, named_info.st_ino) != (info.st_dev, info.st_ino):
            raise OSError('SOURCE_REPLACED')
        if os.fstat(output.fileno()).st_size != writer.size:
            raise OSError('COMPRESSION_OUTPUT_CHANGED')
        if time.monotonic() >= deadline:
            raise TimeoutError('ARCHIVE_COMPRESSION_TIME_LIMIT')
        if info.st_size > max(writer.size, 1) * archives.MAX_RATIO:
            raise OSError('ARCHIVE_EXPANSION_LIMIT')
        digest = writer.digest.hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO ufw_archive_lineage '
                           '(source_scope,archive_sha,job_id,checkpoint_id,generation_key,expanded_size,'
                           'expanded_sha,compressed_size) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                           (scope, digest, job, checkpoint, generation, info.st_size, observed, writer.size))
            cursor.execute("UPDATE ufw_compression_jobs SET status='READY',finished_at=UTC_TIMESTAMP(6) WHERE id=%s",
                           (job,))
        connection.commit()
        return digest
    except BaseException:
        connection.rollback()
        # Only the explicitly empty output handed to us by logrotate is disposable.
        output.seek(0)
        output.truncate(0)
        output.flush()
        if job is not None:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE ufw_compression_jobs SET status='FAILED',finished_at=UTC_TIMESTAMP(6) "
                                   "WHERE id=%s AND status='WRITING'", (job,))
                connection.commit()
            except pymysql.MySQLError:
                connection.rollback()
        raise
    finally:
        if locked:
            with connection.cursor() as cursor:
                cursor.execute('SELECT RELEASE_LOCK(%s)', (ufw.LOCK_NAME,))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Managed UFW logrotate compressor (stdin to stdout).', add_help=False)
    for level in range(1, 10):
        parser.add_argument('-' + str(level), dest='level', action='store_const', const=level)
    parser.set_defaults(level=6)
    args = parser.parse_args(argv)
    connection = None
    try:
        with os.fdopen(os.dup(0), 'rb') as source, os.fdopen(os.dup(1), 'wb') as output:
            filename = os.readlink('/proc/self/fd/' + str(source.fileno()))
            with contextlib.redirect_stdout(sys.stderr):
                connection = get_connection(quiet=True)
                if connection is None:
                    raise RuntimeError('UFW_COMPRESSION_DATABASE_UNAVAILABLE')
                compress_stream(connection, source, output, filename, level=args.level)
        return 0
    except (OSError, ValueError, RuntimeError, pymysql.MySQLError) as error:
        print('UFW compression failed: ' + type(error).__name__ + '; original rotation must be retained.',
              file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
