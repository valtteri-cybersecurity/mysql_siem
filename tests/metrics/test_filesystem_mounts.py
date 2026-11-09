import errno
import os
import stat
from datetime import timezone
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from metrics.filesystem import mounts


def mount_line(mount_id=1, parent_id=1, *, device=b'8:1', root=b'/', point=b'/', kind=b'ext4',
               source=b'UUID=local', options=b'rw', super_options=b'rw', optional=b''):
    fields = (str(mount_id).encode(), str(parent_id).encode(), device, root, point, options)
    return b' '.join(fields) + optional + b' - ' + b' '.join((kind, source, super_options)) + b'\n'


def capacity(**changes):
    values = {'f_bsize': 16384, 'f_frsize': 4096, 'f_blocks': 1000, 'f_bfree': 200,
              'f_bavail': 150, 'f_files': 100, 'f_ffree': 25}
    values.update(changes)
    return SimpleNamespace(**values)


def mock_kernel(monkeypatch, mountinfo, descriptors):
    def open_proc(path, mode):
        assert mode == 'rb'
        if path == '/proc/self/mountinfo':
            return BytesIO(mountinfo)
        assert path.startswith('/proc/self/fdinfo/')
        descriptor = path.rsplit('/', 1)[-1]
        return BytesIO(f'pos:\t0\nmnt_id:\t{descriptor}\n'.encode())

    kernel = SimpleNamespace(
        open=Mock(side_effect=lambda path, _flags: descriptors[path]),
        fstat=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFDIR)),
        statvfs=Mock(return_value=capacity()),
        close=Mock(),
        path=os.path,
        O_PATH=os.O_PATH,
        O_NOFOLLOW=os.O_NOFOLLOW,
        O_CLOEXEC=os.O_CLOEXEC,
    )
    monkeypatch.setattr(mounts, 'open', open_proc, raising=False)
    monkeypatch.setattr(mounts, 'os', kernel)
    return kernel


@pytest.mark.parametrize('kind,source', [(b'ext4', b'UUID=local'), (b'xfs', b'/dev/dm-0'), (b'btrfs', b'LABEL=pool')])
def test_local_mount_and_capacity(monkeypatch, kind, source):
    kernel = mock_kernel(monkeypatch, mount_line(kind=kind, source=source), {b'/': 1})

    result = mounts.collect_mount_metrics()

    assert result.status == 'complete'
    assert result.failures == ()
    measurement, = result.measurements
    assert measurement.mount_point == b'/'
    assert measurement.filesystem_type == kind.decode()
    assert measurement.mount_source == source
    assert measurement.mount_options == 'rw'
    assert measurement.measured_at.tzinfo == timezone.utc
    assert measurement.total_bytes == 1000 * 4096
    assert measurement.used_bytes == 800 * 4096
    assert measurement.free_bytes == 200 * 4096
    assert measurement.available_bytes == 150 * 4096
    assert measurement.usage_percent == 80.0
    assert (measurement.total_inodes, measurement.used_inodes, measurement.free_inodes) == (100, 75, 25)
    assert measurement.inode_usage_percent == 75.0
    assert not measurement.read_only
    kernel.open.assert_called_once_with(b'/', os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    kernel.statvfs.assert_called_once_with(1)
    kernel.close.assert_called_once_with(1)


@pytest.mark.parametrize('kind', [b'proc', b'sysfs', b'tmpfs', b'devtmpfs', b'cgroup', b'cgroup2', b'overlay',
                                  b'nfs', b'nfs4', b'cifs', b'fuse.sshfs', b'fuse.unknown', b'9p'])
def test_virtual_network_and_unknown_mounts_are_not_opened(monkeypatch, kind):
    data = mount_line(kind=kind, source=b'/dev/unreliable-source-name')
    kernel = mock_kernel(monkeypatch, data, {})

    result = mounts.collect_mount_metrics()

    assert result.status == 'complete'
    assert result.measurements == ()
    kernel.open.assert_not_called()
    kernel.statvfs.assert_not_called()


@pytest.mark.parametrize('options,super_options', [(b'ro,nosuid,nodev,noexec', b'rw'), (b'rw,nosuid,nodev,noexec', b'ro')])
def test_read_only_and_security_flags(monkeypatch, options, super_options):
    mock_kernel(monkeypatch, mount_line(options=options, super_options=super_options), {b'/': 1})

    measurement, = mounts.collect_mount_metrics().measurements

    assert measurement.read_only
    assert measurement.nosuid and measurement.nodev and measurement.noexec
    assert measurement.mount_options == options.decode()
    assert measurement.super_options == super_options.decode()


def test_proc_escapes_and_non_utf8_paths_are_preserved(monkeypatch):
    point = br'/with\040space\011tab\012line\134040' + b'\xff'
    decoded = b'/with space\ttab\nline\\040\xff'
    data = mount_line(point=point, root=br'/sub\040root', source=br'LABEL=my\040drive', optional=b' shared:5 future:tag')
    kernel = mock_kernel(monkeypatch, data, {decoded: 1})

    assert mounts.parse_mountinfo(data)[1].root == b'/sub root'
    measurement, = mounts.collect_mount_metrics().measurements
    assert measurement.mount_point == decoded
    assert measurement.mount_source == b'LABEL=my drive'
    assert kernel.open.call_args.args[0] == decoded


def test_bind_aliases_share_capacity_and_keep_mount_flags(monkeypatch):
    data = mount_line() + mount_line(2, point=b'/bind', options=b'ro,noexec')
    kernel = mock_kernel(monkeypatch, data, {b'/': 1, b'/bind': 2})

    root, alias = mounts.collect_mount_metrics().measurements

    kernel.statvfs.assert_called_once_with(1)
    assert kernel.close.call_args_list == [call(1), call(2)]
    assert root.total_bytes == alias.total_bytes
    assert root.measured_at == alias.measured_at
    assert not root.read_only and not root.noexec
    assert alias.read_only and alias.noexec


def test_distinct_btrfs_roots_are_measured_separately(monkeypatch):
    data = mount_line(kind=b'btrfs', root=b'/@') + mount_line(2, kind=b'btrfs', root=b'/@home', point=b'/home')
    kernel = mock_kernel(monkeypatch, data, {b'/': 1, b'/home': 2})
    kernel.statvfs.side_effect = [capacity(f_files=0, f_ffree=0), capacity(f_bfree=180, f_bavail=130)]

    root, home = mounts.collect_mount_metrics().measurements

    assert kernel.statvfs.call_args_list == [call(1), call(2)]
    assert root.total_inodes == root.used_inodes == root.free_inodes == 0
    assert root.inode_usage_percent is None
    assert home.free_bytes == 180 * 4096


def test_file_bind_mount_can_be_sampled(monkeypatch):
    data = mount_line(root=b'/some-file', point=b'/etc/some-file')
    kernel = mock_kernel(monkeypatch, data, {b'/etc/some-file': 1})
    kernel.fstat.return_value.st_mode = stat.S_IFREG

    result = mounts.collect_mount_metrics()

    assert result.status == 'complete'
    kernel.statvfs.assert_called_once_with(1)


def test_hidden_mounts_and_paths_through_network_mounts_are_skipped(monkeypatch):
    data = mount_line() + mount_line(2, point=b'/disk') + mount_line(3, 2, point=b'/disk/hidden')
    data += mount_line(4, 2, point=b'/disk', kind=b'nfs') + mount_line(5, 4, point=b'/disk/local', device=b'8:2')
    kernel = mock_kernel(monkeypatch, data, {b'/': 1})

    result = mounts.collect_mount_metrics()

    assert result.status == 'complete'
    kernel.statvfs.assert_called_once_with(1)


def test_local_mount_under_overlay_root_is_measured(monkeypatch):
    data = mount_line(kind=b'overlay') + mount_line(2, point=b'/disk', device=b'8:2')
    kernel = mock_kernel(monkeypatch, data, {b'/disk': 2})

    result = mounts.collect_mount_metrics()

    assert result.status == 'complete'
    assert result.measurements[0].mount_point == b'/disk'
    kernel.statvfs.assert_called_once_with(2)


def test_disappearing_mount_produces_partial_result(monkeypatch):
    data = mount_line() + mount_line(2, point=b'/gone', device=b'8:2')
    kernel = mock_kernel(monkeypatch, data, {b'/': 1, b'/gone': 2})
    kernel.statvfs.side_effect = [capacity(), FileNotFoundError(errno.ENOENT, 'Gone')]

    result = mounts.collect_mount_metrics()

    assert result.status == 'partial'
    assert len(result.measurements) == 1
    assert result.measurements[0].mount_point == b'/'
    assert len(result.failures) == 1 and result.failures[0].mount_point == b'/gone'
    assert kernel.close.call_args_list == [call(1), call(2)]


@pytest.mark.parametrize('failure', ['absent', 'different_mount_id', 'symlink'])
def test_missing_or_replaced_mount_is_never_sampled(monkeypatch, failure):
    kernel = mock_kernel(monkeypatch, mount_line(), {b'/': 1})
    if failure == 'absent':
        kernel.open.side_effect = FileNotFoundError(errno.ENOENT, 'Gone')
    elif failure == 'different_mount_id':
        kernel.open.side_effect = None
        kernel.open.return_value = 2
    else:
        kernel.fstat.return_value.st_mode = stat.S_IFLNK

    result = mounts.collect_mount_metrics()

    assert result.status == 'failed'
    assert result.measurements == ()
    assert len(result.failures) == 1 and result.failures[0].mount_point == b'/'
    kernel.statvfs.assert_not_called()


@pytest.mark.parametrize('invalid', [b'bad\n', mount_line(2, point=b'relative'), mount_line(2, point=br'/bad\999'),
                                     mount_line(2, options=b'noexec'), mount_line(1, point=b'/duplicate'),
                                     mount_line(2, 3, point=b'/two') + mount_line(3, 2, point=b'/three'),
                                     mount_line(2, point=b'/truncated')[:-1]])
def test_malformed_mountinfo_produces_no_measurements(monkeypatch, invalid):
    kernel = mock_kernel(monkeypatch, mount_line() + invalid, {})

    result = mounts.collect_mount_metrics()

    assert result.status == 'failed'
    assert result.measurements == ()
    assert len(result.failures) == 1 and result.failures[0].mount_point is None
    kernel.open.assert_not_called()


def test_unreadable_or_oversized_mountinfo_is_a_failed_collection(monkeypatch):
    kernel = mock_kernel(monkeypatch, mount_line(), {})
    monkeypatch.setattr(mounts, 'MOUNTINFO_LIMIT', 1)
    assert mounts.collect_mount_metrics().status == 'failed'
    monkeypatch.setattr(mounts, 'open', Mock(side_effect=PermissionError(errno.EACCES, 'Denied')))
    result = mounts.collect_mount_metrics()
    assert result.status == 'failed'
    assert result.measurements == ()
    kernel.open.assert_not_called()


def test_invalid_capacity_is_reported_instead_of_replaced_by_zeros(monkeypatch):
    kernel = mock_kernel(monkeypatch, mount_line(), {b'/': 1})
    kernel.statvfs.return_value = capacity(f_bavail=201)

    result = mounts.collect_mount_metrics()

    assert result.status == 'failed'
    assert result.measurements == ()
    assert result.failures[0].reason == 'Invalid filesystem capacity counters.'


def test_mount_limit_is_reported_as_partial_collection(monkeypatch):
    data = mount_line() + mount_line(2, point=b'/other', device=b'8:2')
    kernel = mock_kernel(monkeypatch, data, {b'/': 1})

    result = mounts.collect_mount_metrics(max_mounts=1)

    assert result.status == 'partial'
    assert len(result.measurements) == 1
    assert result.failures == (mounts.MountFailure(None, 'Mount limit exceeded by 1.'),)
    kernel.statvfs.assert_called_once_with(1)
