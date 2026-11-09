"""Compare verified filesystem observations without database access."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from metrics.filesystem.file_integrity import FileDigest, approved_path
from metrics.filesystem.inventory import FileMetadata, InventoryResult


class FimError(ValueError):
    """The filesystem baseline cannot be advanced safely."""


class RebaselineRequired(FimError):
    """The monitoring configuration changed and needs administrative review."""


@dataclass(frozen=True)
class FileState:
    content_sha256: bytes | None
    size_bytes: int
    owner_uid: int
    group_gid: int
    mode: int
    observed_at: datetime


def _utc_stamp(value):
    if not isinstance(value, datetime) or value.year < 1000 or value.utcoffset() != timedelta(0):
        raise FimError('File inventory requires UTC timestamps.')
    return value.replace(tzinfo=None)


def _file_state(entry, observed_at):
    metadata = entry.metadata
    digest = entry.digest
    if entry.file_type != 'regular' or not isinstance(metadata, FileMetadata) or not isinstance(digest, FileDigest):
        raise FimError('Invalid regular file observation.')
    if digest.status == 'HASHED':
        if not isinstance(digest.sha256, bytes) or len(digest.sha256) != 32:
            raise FimError('Invalid file digest.')
    elif digest.status not in ('DISABLED', 'TOO_LARGE') or digest.sha256 is not None:
        raise FimError('Incomplete file digest observation.')
    for value, maximum in ((metadata.size_bytes, 2**64 - 1), (metadata.owner_uid, 2**32 - 1),
                           (metadata.group_gid, 2**32 - 1), (metadata.mode, 0o7777)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise FimError('Invalid file metadata.')
    return FileState(digest.sha256, metadata.size_bytes, metadata.owner_uid, metadata.group_gid,
                     metadata.mode, observed_at)


def prepare_inventory(inventory):
    if not isinstance(inventory, InventoryResult) or not inventory.entries or inventory.status != 'SUCCESS':
        raise FimError('A complete file inventory is required.')
    digest = inventory.config_sha256
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise FimError('Invalid inventory configuration digest.')
    scan_at = _utc_stamp(inventory.observed_at)
    first_observed = scan_at
    coverage = {}
    current = {}
    for entry in inventory.entries:
        path = approved_path(entry.path)
        if path in coverage:
            raise FimError('Duplicate path in file inventory.')
        observed_at = _utc_stamp(entry.observed_at)
        if observed_at > scan_at:
            raise FimError('A file observation is newer than its inventory checkpoint.')
        first_observed = min(first_observed, observed_at)
        coverage[path] = entry.status
        if entry.status == 'FOUND':
            current[path] = _file_state(entry, observed_at)
    return current, coverage, scan_at, first_observed


def _confirmed_missing(path, coverage):
    status = coverage.get(path)
    if status is not None:
        return status == 'MISSING'
    parent = path.rpartition(b'/')[0]
    while parent:
        status = coverage.get(parent)
        if status is not None:
            return status in ('MISSING', 'SCANNED', 'FOUND')
        parent = parent.rpartition(b'/')[0]
    return False


def detect_changes(previous, current, coverage):
    """Return changes only when each disappearance is covered by the inventory."""
    changes = []
    for path in sorted(previous.keys() | current.keys()):
        before = previous.get(path)
        after = current.get(path)
        if before is None:
            changes.append((path, 'CREATED', None, after))
            continue
        if after is None:
            if not _confirmed_missing(path, coverage):
                raise FimError('A previously monitored path has no verified absence.')
            changes.append((path, 'DELETED', before, None))
            continue
        if (before.content_sha256 is not None and after.content_sha256 is not None
                and before.content_sha256 != after.content_sha256):
            changes.append((path, 'CONTENT_CHANGED', before, after))
        if before.mode != after.mode:
            changes.append((path, 'PERMISSION_CHANGED', before, after))
        if before.owner_uid != after.owner_uid or before.group_gid != after.group_gid:
            changes.append((path, 'OWNER_CHANGED', before, after))
    return changes
