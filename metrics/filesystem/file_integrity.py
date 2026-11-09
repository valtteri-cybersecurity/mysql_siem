"""Safe Linux path access and bounded hashing for filesystem inventory."""

import errno
import hashlib
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_HASH_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 64 * 1024


class FileChangedError(OSError):
    """The observed path no longer describes the same file version."""


@dataclass(frozen=True)
class FileDigest:
    status: str
    sha256: bytes | None = None
    bytes_read: int = 0


def approved_path(path):
    try:
        path = os.fsencode(path)
    except (TypeError, UnicodeError):
        raise ValueError('Invalid inventory target path.') from None
    if (not path.startswith(b'/') or path.startswith(b'//') or path == b'/' or b'\0' in path
            or len(path) > 4096 or os.path.normpath(path) != path):
        raise ValueError('Inventory targets require canonical absolute paths.')
    if path.split(b'/', 2)[1] in (b'dev', b'proc', b'sys'):
        raise ValueError('Inventory targets cannot be in virtual system trees.')
    return path


@contextmanager
def open_parent(path):
    """Open a validated absolute path's parent without following any symlink."""
    parts = path[1:].split(b'/')
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open(b'/', flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        yield directory, parts[-1]
    finally:
        os.close(directory)


def verify_version(expected, actual):
    for field in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
        if getattr(expected, field) != getattr(actual, field):
            raise FileChangedError()


def observation_error(error, *, seen):
    if isinstance(error, FileChangedError) or error.errno == errno.ESTALE:
        return 'CHANGED'
    if isinstance(error, PermissionError):
        return 'DENIED'
    if isinstance(error, FileNotFoundError):
        if seen:
            return 'CHANGED'
        return 'MISSING'
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        if seen:
            return 'CHANGED'
        return 'UNSUPPORTED'
    return 'IO_ERROR'


def hash_regular_file(directory, name, expected, *, max_file_bytes, max_bytes):
    """Hash a regular file previously observed under an approved directory descriptor."""
    if not isinstance(name, bytes) or not name or name in (b'.', b'..') or b'/' in name or b'\0' in name:
        raise ValueError('Hashing requires one file name relative to the approved directory.')
    if type(max_file_bytes) is not int or not 0 <= max_file_bytes <= MAX_FILE_BYTES:
        raise ValueError('Invalid per-file hash limit.')
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_HASH_BYTES:
        raise ValueError('Invalid remaining hash budget.')
    if not stat.S_ISREG(expected.st_mode):
        return FileDigest('UNSUPPORTED')
    if expected.st_size > max_file_bytes:
        return FileDigest('TOO_LARGE')
    if expected.st_size > max_bytes:
        return FileDigest('BYTE_LIMIT')

    read = 0
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
        try:
            verify_version(expected, os.fstat(descriptor))
            while read < expected.st_size:
                chunk = os.read(descriptor, min(CHUNK_BYTES, expected.st_size - read))
                if not chunk:
                    raise FileChangedError()
                read += len(chunk)
                digest.update(chunk)
            verify_version(expected, os.fstat(descriptor))
            verify_version(expected, os.stat(name, dir_fd=directory, follow_symlinks=False))
        finally:
            os.close(descriptor)
    except OSError as error:
        return FileDigest(observation_error(error, seen=True), bytes_read=read)
    return FileDigest('HASHED', digest.digest(), read)
