import errno
import hashlib
import os
from contextlib import contextmanager
from datetime import timezone
from unittest.mock import Mock

import pytest

from metrics.filesystem import file_integrity, inventory


def scan_files(*paths, **settings):
    return inventory.collect_inventory(inventory.InventoryConfig(files=paths, **settings))


def scan_directory(path, **settings):
    return inventory.collect_inventory(inventory.InventoryConfig(files=(), directories=(path,), **settings))


def test_regular_file_metadata_and_chunked_sha256(tmp_path, monkeypatch):
    path = tmp_path / 'tracked'
    content = b'content' * (file_integrity.CHUNK_BYTES // 7 + 3)
    path.write_bytes(content)
    path.chmod(0o640)
    info = path.stat()
    read = Mock(wraps=os.read)
    monkeypatch.setattr(file_integrity.os, 'read', read)

    result = scan_files(path)

    assert result.status == 'SUCCESS'
    entry, = result.entries
    assert entry.path == os.fsencode(path)
    assert entry.status == 'FOUND' and entry.file_type == 'regular'
    assert entry.observed_at.tzinfo == timezone.utc
    assert entry.metadata == inventory.FileMetadata(len(content), info.st_uid, info.st_gid, 0o640, info.st_mtime_ns)
    assert entry.digest == file_integrity.FileDigest('HASHED', hashlib.sha256(content).digest(), len(content))
    assert read.call_count == 2
    assert read.call_args_list[0].args[1] == file_integrity.CHUNK_BYTES


def test_standalone_hash_respects_limits_and_can_hash_an_empty_file(tmp_path):
    path = tmp_path / 'empty'
    path.touch()
    with file_integrity.open_parent(os.fsencode(path)) as (parent, name):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        digest = file_integrity.hash_regular_file(parent, name, info, max_file_bytes=1, max_bytes=0)
        assert digest == file_integrity.FileDigest('HASHED', hashlib.sha256(b'').digest(), 0)
        with pytest.raises(ValueError):
            file_integrity.hash_regular_file(parent, b'../empty', info, max_file_bytes=1, max_bytes=1)


def test_missing_file_and_missing_directory_are_known_absences(tmp_path):
    file_result = scan_files(tmp_path / 'absent-parent' / 'file')
    directory_result = scan_directory(tmp_path / 'missing')
    for result in (file_result, directory_result):
        assert result.status == 'SUCCESS'
        entry, = result.entries
        assert entry.status == 'MISSING' and entry.metadata is None and entry.digest is None


def test_hash_permission_denial_is_not_reported_as_missing(tmp_path, monkeypatch):
    blocked = tmp_path / 'blocked'
    blocked.write_bytes(b'restricted')
    good = tmp_path / 'good'
    good.write_bytes(b'readable')
    original = os.open

    def open_file(path, flags, *args, **kwargs):
        if path == b'blocked':
            raise PermissionError(errno.EACCES, 'blocked')
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_integrity.os, 'open', open_file)
    partial = scan_files(blocked, good)
    assert partial.status == 'PARTIAL'
    assert partial.entries[0].status == 'DENIED'
    assert partial.entries[0].digest == file_integrity.FileDigest('DENIED')
    assert partial.entries[0].metadata.size_bytes == len(b'restricted')
    assert scan_files(blocked).status == 'FAILED'


def test_symlinks_in_leaf_or_ancestor_are_never_followed(tmp_path, monkeypatch):
    directory = tmp_path / 'real'
    directory.mkdir()
    target = directory / 'target'
    target.write_bytes(b'private')
    leaf = tmp_path / 'leaf'
    leaf.symlink_to(target)
    ancestor = tmp_path / 'ancestor'
    ancestor.symlink_to(directory, target_is_directory=True)
    read = Mock(side_effect=AssertionError('Symlink content must not be read.'))
    monkeypatch.setattr(file_integrity.os, 'read', read)

    result = scan_files(leaf, ancestor / 'target')

    assert result.status == 'FAILED'
    assert [item.status for item in result.entries] == ['UNSUPPORTED', 'UNSUPPORTED']
    assert result.entries[1].file_type == 'symlink'
    read.assert_not_called()


@pytest.mark.parametrize('settings,reason', [({'max_file_bytes': 3}, 'TOO_LARGE'), ({'hash_content': False}, 'DISABLED')])
def test_metadata_only_policies_do_not_read_content(tmp_path, monkeypatch, settings, reason):
    path = tmp_path / 'tracked'
    path.write_bytes(b'data')
    read = Mock(side_effect=AssertionError('Content must not be read.'))
    monkeypatch.setattr(file_integrity.os, 'read', read)

    result = scan_files(path, **settings)

    assert result.status == 'SUCCESS'
    entry, = result.entries
    assert entry.status == 'FOUND' and entry.metadata.size_bytes == 4
    assert entry.digest == file_integrity.FileDigest(reason)
    read.assert_not_called()


@pytest.mark.parametrize('change', ['overwrite', 'replace'])
def test_file_changed_during_read_has_no_trusted_digest(tmp_path, monkeypatch, change):
    path = tmp_path / 'tracked'
    path.write_bytes(b'data')
    replacement = tmp_path / 'replacement'
    replacement.write_bytes(b'data')
    original_read = os.read

    def read_and_change(descriptor, size):
        chunk = original_read(descriptor, size)
        if change == 'overwrite':
            path.write_bytes(b'edit')
            os.utime(path, ns=(0, 0))
        else:
            replacement.replace(path)
        return chunk

    monkeypatch.setattr(file_integrity.os, 'read', read_and_change)
    result = scan_files(path)

    assert result.status == 'FAILED'
    entry, = result.entries
    assert entry.status == 'CHANGED' and entry.metadata is None
    assert entry.digest == file_integrity.FileDigest('CHANGED', bytes_read=4)


def test_directory_inventory_respects_depth_and_skips_symlinks(tmp_path):
    root = tmp_path / 'approved'
    child = root / 'child'
    nested = child / 'nested'
    nested.mkdir(parents=True)
    for path in (root / 'a', child / 'b', nested / 'c'):
        path.write_bytes(b'example')
    link = root / 'link'
    link.symlink_to(nested, target_is_directory=True)

    result = scan_directory(root, max_depth=1)

    entries = {}
    for entry in result.entries:
        entries[os.fsdecode(entry.path)] = entry.status
    assert result.status == 'SUCCESS'
    assert entries == {str(root): 'SCANNED', str(root / 'a'): 'FOUND', str(link): 'SKIPPED_TYPE',
                       str(child): 'SCANNED', str(child / 'b'): 'FOUND', str(nested): 'DEPTH_LIMIT'}


def test_file_limit_marks_directory_incomplete(tmp_path):
    directory = tmp_path / 'approved'
    directory.mkdir()
    (directory / 'a').touch()
    (directory / 'b').touch()

    result = scan_directory(directory, max_files=1)

    assert result.status == 'PARTIAL'
    first, scope = result.entries
    assert first.status == 'FOUND'
    assert scope.path == os.fsencode(directory) and scope.status == 'FILE_LIMIT'


def test_directory_entry_limit_counts_nonregular_entries(tmp_path, monkeypatch):
    directory = tmp_path / 'approved'
    directory.mkdir()
    (directory / 'one').symlink_to('missing')
    (directory / 'two').symlink_to('missing')
    monkeypatch.setattr(inventory, 'MAX_DIRECTORY_ENTRIES', 1)

    result = scan_directory(directory)

    assert result.status == 'FAILED'
    assert [entry.status for entry in result.entries] == ['SKIPPED_TYPE', 'ENTRY_LIMIT']


def test_total_hash_budget_cannot_be_exceeded(tmp_path, monkeypatch):
    first = tmp_path / 'a'
    second = tmp_path / 'b'
    first.write_bytes(b'data')
    second.write_bytes(b'more')
    read = Mock(wraps=os.read)
    monkeypatch.setattr(file_integrity.os, 'read', read)

    result = scan_files(first, second, max_hash_bytes=6)

    assert result.status == 'PARTIAL'
    assert result.entries[1].status == 'BYTE_LIMIT'
    assert result.entries[1].digest == file_integrity.FileDigest('BYTE_LIMIT')
    read.assert_called_once()
    assert read.call_args.args[1] == 4


@pytest.mark.parametrize('after_entry,expected', [(False, 'FAILED'), (True, 'PARTIAL')])
def test_directory_iteration_error_leaves_no_complete_coverage(tmp_path, monkeypatch, after_entry, expected):
    directory = tmp_path / 'approved'
    directory.mkdir()
    (directory / 'available').touch()
    original = os.scandir

    @contextmanager
    def interrupted_scandir(descriptor):
        with original(descriptor) as entries:
            def interrupted_entries():
                if after_entry:
                    yield next(entries)
                raise PermissionError(errno.EACCES, 'directory read failed')
            yield interrupted_entries()

    with monkeypatch.context() as context:
        context.setattr(inventory.os, 'scandir', interrupted_scandir)
        result = scan_directory(directory)

    assert result.status == expected
    assert result.entries[-1].path == os.fsencode(directory)
    assert result.entries[-1].status == 'DENIED'


def test_directory_change_during_inventory_prevents_success(tmp_path, monkeypatch):
    directory = tmp_path / 'approved'
    directory.mkdir()
    (directory / 'tracked').write_bytes(b'one')
    original = os.read

    def read_and_create(descriptor, size):
        chunk = original(descriptor, size)
        (directory / 'new').touch()
        os.utime(directory, ns=(0, 0))
        return chunk

    monkeypatch.setattr(file_integrity.os, 'read', read_and_create)
    result = scan_directory(directory)

    assert result.status == 'PARTIAL'
    assert result.entries[-1].path == os.fsencode(directory) and result.entries[-1].status == 'CHANGED'


@pytest.mark.parametrize('settings', [
    {'files': ['relative']}, {'files': ['/etc/../tmp/x']}, {'files': ['//etc/passwd']},
    {'files': ['/etc/passwd\0']}, {'files': ['/proc/self/status']}, {'files': []},
    {'directories': ['/etc']}, {'directories': ['/']},
    {'files': ['/etc/passwd', '/etc/passwd']}, {'files': ['/etc/ssh/config'], 'directories': ['/etc/ssh']},
    {'max_depth': -1}, {'max_depth': 9}, {'max_files': 0}, {'max_files': True},
    {'max_file_bytes': file_integrity.MAX_FILE_BYTES + 1}, {'max_hash_bytes': 0}, {'hash_content': 'false'},
])
def test_invalid_config_is_rejected_before_path_access(monkeypatch, settings):
    open_parent = Mock(side_effect=AssertionError('Invalid config must not open paths.'))
    monkeypatch.setattr(inventory, 'open_parent', open_parent)
    with pytest.raises(ValueError):
        inventory.collect_inventory(inventory.InventoryConfig(**settings))
    open_parent.assert_not_called()


def test_config_digest_represents_scope_and_policy(tmp_path):
    first = tmp_path / 'a'
    second = tmp_path / 'b'
    initial = scan_files(first, second)
    assert len(initial.config_sha256) == 32
    assert scan_files(second, first).config_sha256 == initial.config_sha256
    assert scan_files(first).config_sha256 != initial.config_sha256
    assert scan_files(first, second, hash_content=False).config_sha256 != initial.config_sha256


def test_config_rejects_a_string_in_place_of_a_target_list():
    with pytest.raises(TypeError):
        inventory.collect_inventory(inventory.InventoryConfig(files='/etc/passwd'))
