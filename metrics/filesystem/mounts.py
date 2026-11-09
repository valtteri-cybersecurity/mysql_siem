"""Read-only capacity and security observations for local Linux mounts."""

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone

LOCAL_FILESYSTEMS = frozenset({
    'bcachefs', 'btrfs', 'exfat', 'ext2', 'ext3', 'ext4', 'f2fs', 'iso9660',
    'jfs', 'nilfs2', 'ntfs3', 'reiserfs', 'squashfs', 'udf', 'vfat', 'xfs', 'zfs',
})
TRAVERSABLE_FILESYSTEMS = LOCAL_FILESYSTEMS | {'devtmpfs', 'overlay', 'ramfs', 'rootfs', 'tmpfs'}
MOUNTINFO_LIMIT = 2 * 1024 * 1024
DEFAULT_MAX_MOUNTS = 128
ESCAPES = {b'040': b' ', b'011': b'\t', b'012': b'\n', b'134': b'\\'}


class MountError(ValueError):
    """A mount observation cannot be trusted."""


@dataclass(frozen=True)
class Mount:
    mount_id: int
    parent_id: int
    device: bytes
    root: bytes
    mount_point: bytes
    filesystem_type: str
    mount_source: bytes
    mount_options: str
    super_options: str


@dataclass(frozen=True)
class MountMeasurement:
    mount_point: bytes
    filesystem_type: str
    mount_source: bytes
    mount_options: str
    super_options: str
    measured_at: datetime
    total_bytes: int
    used_bytes: int
    free_bytes: int
    available_bytes: int
    usage_percent: float | None
    total_inodes: int
    used_inodes: int
    free_inodes: int
    inode_usage_percent: float | None
    read_only: bool
    nosuid: bool
    nodev: bool
    noexec: bool


@dataclass(frozen=True)
class MountFailure:
    mount_point: bytes | None
    reason: str


@dataclass(frozen=True)
class MountCollection:
    measurements: tuple[MountMeasurement, ...]
    failures: tuple[MountFailure, ...]

    @property
    def status(self):
        if not self.failures:
            return 'complete'
        if self.measurements:
            return 'partial'
        return 'failed'


def read_mountinfo(path='/proc/self/mountinfo'):
    with open(path, 'rb') as stream:
        data = stream.read(MOUNTINFO_LIMIT + 1)
    if len(data) > MOUNTINFO_LIMIT:
        raise MountError('Mountinfo exceeds the size limit.')
    return data


def _decode_mount_field(value):
    parts = value.split(b'\\')
    decoded = bytearray(parts[0])
    for part in parts[1:]:
        character = ESCAPES.get(part[:3])
        if character is None:
            raise MountError('Invalid mountinfo escape.')
        decoded.extend(character)
        decoded.extend(part[3:])
    return bytes(decoded)


def _mount_path(value):
    path = _decode_mount_field(value)
    if not path.startswith(b'/') or path.startswith(b'//') or os.path.normpath(path) != path:
        raise MountError('Invalid mountinfo path.')
    return path


def _parse_mount_line(line):
    before, separator, after = line.partition(b' - ')
    fields = before.split(b' ')
    tail = after.split(b' ')
    if (not separator or len(fields) < 6 or len(tail) != 3 or b'' in fields or b'' in tail
            or b'\0' in line or b'\t' in line):
        raise MountError('Invalid mountinfo fields.')
    mount_id, parent_id, device, root, mount_point, options = fields[:6]
    major, _, minor = device.partition(b':')
    if not (mount_id.isdigit() and parent_id.isdigit() and major.isdigit() and minor.isdigit()):
        raise MountError('Invalid mountinfo identifiers.')
    mount_id = int(mount_id)
    parent_id = int(parent_id)
    if not mount_id or not parent_id:
        raise MountError('Invalid mountinfo identifiers.')
    filesystem_type, source, super_options = tail
    for flags in (options, super_options):
        if flags.split(b',', 1)[0] not in (b'ro', b'rw'):
            raise MountError('Invalid mountinfo options.')
    return Mount(mount_id, parent_id, device, _mount_path(root), _mount_path(mount_point),
                 filesystem_type.decode('utf-8', 'backslashreplace'), _decode_mount_field(source),
                 options.decode('utf-8', 'backslashreplace'), super_options.decode('utf-8', 'backslashreplace'))


def parse_mountinfo(data):
    if not data.endswith(b'\n'):
        raise MountError('Mountinfo is empty or incomplete.')
    mounts = {}
    for number, line in enumerate(data[:-1].split(b'\n'), 1):
        try:
            mount = _parse_mount_line(line)
        except ValueError:
            raise MountError(f'Invalid mountinfo line {number}.') from None
        if mount.mount_id in mounts:
            raise MountError(f'Duplicate mount ID on mountinfo line {number}.')
        mounts[mount.mount_id] = mount
    return mounts


def select_mounts(mounts):
    """Select visible local mounts, including aliases with distinct mount options."""
    children = {}
    covered = set()
    pending = []
    for mount in mounts.values():
        parent = mounts.get(mount.parent_id)
        if parent is None or parent.mount_id == mount.mount_id:
            pending.append((mount, True))
            continue
        children.setdefault(parent.mount_id, []).append(mount)
        if parent.mount_point == mount.mount_point:
            covered.add(parent.mount_id)

    selected = []
    visited = 0
    while pending:
        mount, reachable = pending.pop()
        visited += 1
        is_covered = mount.mount_id in covered
        if reachable and not is_covered and mount.filesystem_type in LOCAL_FILESYSTEMS:
            selected.append(mount)
        traversable = not is_covered and mount.filesystem_type in TRAVERSABLE_FILESYSTEMS
        for child in children.get(mount.mount_id, ()):
            # A stacked mount can be reached without looking up paths inside the covered filesystem.
            child_reachable = reachable and (traversable or child.mount_point == mount.mount_point)
            pending.append((child, child_reachable))
    if visited != len(mounts):
        raise MountError('Invalid mountinfo parent relationships.')
    return sorted(selected, key=lambda mount: mount.mount_point)


def _descriptor_mount_id(descriptor):
    with open(f'/proc/self/fdinfo/{descriptor}', 'rb') as stream:
        for line in stream:
            if line.startswith(b'mnt_id:'):
                value = line.removeprefix(b'mnt_id:').strip()
                if value.isdigit():
                    return int(value)
                break
    raise MountError('Could not verify the mount ID.')


def _usage_percent(used, total):
    if total == 0:
        return None
    return round(100 * used / total, 2)


def _build_measurement(mount, info, measured_at):
    if info.f_frsize <= 0 or not 0 <= info.f_bavail <= info.f_bfree <= info.f_blocks:
        raise MountError('Invalid filesystem capacity counters.')
    if not 0 <= info.f_ffree <= info.f_files < 2**64:
        raise MountError('Invalid filesystem inode counters.')

    total_bytes = info.f_blocks * info.f_frsize
    if total_bytes >= 2**64:
        raise MountError('Filesystem capacity exceeds the storage range.')
    free_bytes = info.f_bfree * info.f_frsize
    available_bytes = info.f_bavail * info.f_frsize
    used_bytes = total_bytes - free_bytes
    used_inodes = info.f_files - info.f_ffree
    options = mount.mount_options.split(',')
    return MountMeasurement(
        mount_point=mount.mount_point,
        filesystem_type=mount.filesystem_type,
        mount_source=mount.mount_source,
        mount_options=mount.mount_options,
        super_options=mount.super_options,
        measured_at=measured_at,
        total_bytes=total_bytes,
        used_bytes=used_bytes,
        free_bytes=free_bytes,
        available_bytes=available_bytes,
        usage_percent=_usage_percent(used_bytes, total_bytes),
        total_inodes=info.f_files,
        used_inodes=used_inodes,
        free_inodes=info.f_ffree,
        inode_usage_percent=_usage_percent(used_inodes, info.f_files),
        read_only='ro' in options or 'ro' in mount.super_options.split(','),
        nosuid='nosuid' in options,
        nodev='nodev' in options,
        noexec='noexec' in options,
    )


def _measure_mount(mount, samples):
    if len(mount.mount_point) > 4096:
        raise MountError('Mount point exceeds the storage range.')
    descriptor = os.open(mount.mount_point, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if stat.S_ISLNK(os.fstat(descriptor).st_mode) or _descriptor_mount_id(descriptor) != mount.mount_id:
            raise MountError('Mount point changed before measurement.')
        # Bind aliases can share a sample. Distinct roots may have different quotas.
        key = (mount.device, mount.filesystem_type, mount.root)
        sample = samples.get(key)
        if sample is None:
            sample = os.statvfs(descriptor), datetime.now(timezone.utc)
        measurement = _build_measurement(mount, *sample)
        samples[key] = sample
        return measurement
    finally:
        os.close(descriptor)


def collect_mount_metrics(*, mountinfo_path='/proc/self/mountinfo', max_mounts=DEFAULT_MAX_MOUNTS):
    """Collect local mounts. Usage percentages describe physical usage of total capacity."""
    if type(max_mounts) is not int or max_mounts < 1:
        raise ValueError('max_mounts must be a positive integer.')
    try:
        mounts = select_mounts(parse_mountinfo(read_mountinfo(mountinfo_path)))
    except OSError:
        return MountCollection((), (MountFailure(None, 'Could not read mountinfo.'),))
    except MountError as error:
        return MountCollection((), (MountFailure(None, str(error)),))

    measurements = []
    failures = []
    samples = {}
    if len(mounts) > max_mounts:
        failures.append(MountFailure(None, f'Mount limit exceeded by {len(mounts) - max_mounts}.'))
    for mount in mounts[:max_mounts]:
        try:
            measurements.append(_measure_mount(mount, samples))
        except OSError as error:
            failures.append(MountFailure(mount.mount_point, f'Mount could not be measured (errno {error.errno}).'))
        except MountError as error:
            failures.append(MountFailure(mount.mount_point, str(error)))
    return MountCollection(tuple(measurements), tuple(failures))
