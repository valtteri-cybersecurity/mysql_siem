"""Bounded inventory of explicitly approved Linux files and directory trees."""

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone

from metrics.filesystem.file_integrity import (
    MAX_FILE_BYTES,
    MAX_HASH_BYTES,
    FileDigest,
    approved_path,
    hash_regular_file,
    observation_error,
    open_parent,
    verify_version,
)

DEFAULT_FILES = (
    '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/passwd',
    '/etc/group', '/etc/crontab', '/etc/fstab',
)
MAX_TARGETS = 128
MAX_DIRECTORY_ENTRIES = 4096
RELIABLE = {'FOUND', 'MISSING', 'SCANNED'}
EXCLUDED = {'SKIPPED_TYPE', 'DEPTH_LIMIT'}


@dataclass(frozen=True)
class InventoryConfig:
    files: tuple[str, ...] = DEFAULT_FILES
    directories: tuple[str, ...] = ()
    max_depth: int = 1
    max_files: int = 256
    hash_content: bool = True
    max_file_bytes: int = 1024 * 1024
    max_hash_bytes: int = 16 * 1024 * 1024
    metadata_only: tuple[str, ...] = ()


DEFAULT_CONFIG = InventoryConfig()


@dataclass(frozen=True)
class FileMetadata:
    size_bytes: int
    owner_uid: int
    group_gid: int
    mode: int
    modified_at_ns: int


def _metadata(info):
    return FileMetadata(info.st_size, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_mtime_ns)


@dataclass(frozen=True)
class InventoryEntry:
    path: bytes
    status: str
    observed_at: datetime
    file_type: str | None = None
    metadata: FileMetadata | None = None
    digest: FileDigest | None = None


@dataclass(frozen=True)
class InventoryResult:
    entries: tuple[InventoryEntry, ...]
    config_sha256: bytes
    observed_at: datetime

    @property
    def status(self):
        reliable = False
        incomplete = False
        for entry in self.entries:
            if entry.status in RELIABLE:
                reliable = True
            elif entry.status not in EXCLUDED:
                incomplete = True
        if not incomplete:
            return 'SUCCESS'
        if reliable:
            return 'PARTIAL'
        return 'FAILED'


def validate_config(config):
    if not isinstance(config, InventoryConfig) or type(config.hash_content) is not bool:
        raise ValueError('Invalid inventory configuration.')
    for value, minimum, maximum in ((config.max_depth, 0, 8), (config.max_files, 1, 1024),
                                    (config.max_file_bytes, 1, MAX_FILE_BYTES),
                                    (config.max_hash_bytes, 1, MAX_HASH_BYTES)):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError('Invalid inventory limit.')
    if not isinstance(config.files, (tuple, list)) or not isinstance(config.directories, (tuple, list)):
        raise TypeError('Inventory targets require lists of file and directory paths.')
    if not 1 <= len(config.files) + len(config.directories) <= MAX_TARGETS:
        raise ValueError('Invalid number of inventory targets.')

    files = tuple(sorted(map(approved_path, config.files)))
    directories = tuple(sorted(map(approved_path, config.directories)))
    if not isinstance(config.metadata_only, (tuple, list)):
        raise TypeError('Metadata-only targets require a path list.')
    metadata_only = tuple(map(approved_path, config.metadata_only))
    if len(set(metadata_only)) != len(metadata_only) or set(metadata_only) - set(files):
        raise ValueError('Metadata-only paths must be unique, explicitly monitored files.')
    paths = files + directories
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate inventory target.')
    for directory in directories:
        if directory.count(b'/') < 2:
            raise ValueError('Inventory directory targets must be narrower than a top-level tree.')
        for path in paths:
            if path.startswith(directory + b'/'):
                raise ValueError('Overlapping inventory targets.')
    return files, directories


def config_digest(config, files, directories):
    policy = (1, tuple(map(bytes.hex, files)), tuple(map(bytes.hex, directories)),
              config.max_depth, config.max_files, config.hash_content, config.max_file_bytes, config.max_hash_bytes)
    if config.metadata_only:
        paths = sorted(map(approved_path, config.metadata_only))
        policy += (tuple(map(bytes.hex, paths)),)
    return hashlib.sha256(json.dumps(policy).encode('ascii')).digest()


def file_type(info):
    if stat.S_ISREG(info.st_mode):
        return 'regular'
    if stat.S_ISDIR(info.st_mode):
        return 'directory'
    if stat.S_ISLNK(info.st_mode):
        return 'symlink'
    return 'special'


class ScanLimit(ValueError):
    """Stop the inventory once a global traversal limit is reached."""


class _Inventory:
    def __init__(self, config):
        self.config = config
        self.entries = {}
        self.files = 0
        self.directory_entries = 0
        self.hash_bytes = config.max_hash_bytes
        self.metadata_only = set(map(approved_path, config.metadata_only))

    def record(self, path, status, kind=None, metadata=None, digest=None):
        self.entries[path] = InventoryEntry(path, status, datetime.now(timezone.utc), kind, metadata, digest)

    def observe_file(self, parent, name, path, info):
        if self.files == self.config.max_files:
            raise ScanLimit('FILE_LIMIT')
        self.files += 1
        digest = FileDigest('DISABLED')
        if self.config.hash_content and path not in self.metadata_only:
            digest = hash_regular_file(parent, name, info, max_file_bytes=self.config.max_file_bytes,
                                       max_bytes=self.hash_bytes)
            self.hash_bytes -= digest.bytes_read
        if digest.status == 'CHANGED':
            self.record(path, 'CHANGED', 'regular', digest=digest)
            return

        verify_version(info, os.stat(name, dir_fd=parent, follow_symlinks=False))
        status = digest.status
        if status in ('HASHED', 'DISABLED', 'TOO_LARGE'):
            status = 'FOUND'
        self.record(path, status, 'regular', _metadata(info), digest)

    def scan_directory(self, parent, name, path, info, depth):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open(name, flags, dir_fd=parent)
        try:
            verify_version(info, os.fstat(directory))
            with os.scandir(directory) as entries:
                for entry in entries:
                    if self.directory_entries == MAX_DIRECTORY_ENTRIES:
                        raise ScanLimit('ENTRY_LIMIT')
                    self.directory_entries += 1
                    child_name = os.fsencode(entry.name)
                    child_path = path + b'/' + child_name
                    self.visit_child(directory, child_name, child_path, depth)
            verify_version(info, os.fstat(directory))
            verify_version(info, os.stat(name, dir_fd=parent, follow_symlinks=False))
        finally:
            os.close(directory)
        self.record(path, 'SCANNED', 'directory', _metadata(info))

    def visit_child(self, parent, name, path, depth):
        if len(path) > 4096:
            self.record(path, 'PATH_LIMIT')
            return
        kind = None
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            kind = file_type(info)
            if kind == 'regular':
                self.observe_file(parent, name, path, info)
            elif kind != 'directory':
                self.record(path, 'SKIPPED_TYPE', kind)
            elif depth == self.config.max_depth:
                self.record(path, 'DEPTH_LIMIT', kind)
            else:
                self.scan_directory(parent, name, path, info, depth + 1)
        except OSError as error:
            self.record(path, observation_error(error, seen=True), kind)

    def visit_target(self, path, required_type):
        seen = False
        kind = None
        try:
            with open_parent(path) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                seen = True
                kind = file_type(info)
                if kind != required_type:
                    self.record(path, 'UNSUPPORTED', kind)
                    return
                if kind == 'regular':
                    self.observe_file(parent, name, path, info)
                else:
                    self.scan_directory(parent, name, path, info, 0)
            entry = self.entries[path]
            if entry.status != 'SCANNED' and entry.metadata is None:
                return
            # Reopen from the root to detect an ancestor renamed during the scan.
            with open_parent(path) as (parent, name):
                verify_version(info, os.stat(name, dir_fd=parent, follow_symlinks=False))
        except OSError as error:
            self.record(path, observation_error(error, seen=seen), kind)


def collect_inventory(config=DEFAULT_CONFIG):
    """Collect approved targets. Only SUCCESS proves coverage of the configured scope."""
    files, directories = validate_config(config)
    inventory = _Inventory(config)
    try:
        for kind, targets in (('regular', files), ('directory', directories)):
            for path in targets:
                inventory.visit_target(path, kind)
    except ScanLimit as error:
        inventory.record(path, str(error), kind)
    return InventoryResult(tuple(inventory.entries.values()), config_digest(config, files, directories),
                           datetime.now(timezone.utc))
