import os
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from metrics.processes import executable, get


def file_stat(**changes):
    fields = {'st_dev': 258, 'st_ino': 12345, 'st_uid': 1000, 'st_gid': 40,
              'st_mode': stat.S_IFREG | 0o4750, 'st_size': 4096, 'st_mtime_ns': 1234567890123456789,
              'st_ctime_ns': 1234567890999999999, 'st_nlink': 1}
    fields.update(changes)
    return SimpleNamespace(**fields)


def mock_proc(monkeypatch, info, path='/usr/bin/worker', *, live=None):
    if live is None:
        live = info
    operations = SimpleNamespace(open=Mock(return_value=6), fstat=Mock(return_value=info), stat=Mock(return_value=live),
                                 readlink=Mock(return_value=path), close=Mock(), path=os.path,
                                 O_PATH=os.O_PATH, O_CLOEXEC=os.O_CLOEXEC)
    monkeypatch.setattr(executable, 'os', operations)
    return operations


def observed_process():
    return SimpleNamespace(pid=12, is_running=Mock(return_value=True))


def test_metadata_uses_only_the_process_magic_link_and_pinned_descriptor(monkeypatch):
    operations = mock_proc(monkeypatch, file_stat())
    process = observed_process()
    state = executable.observe(process, '/different/worker')
    assert state == {'executable_path': '/usr/bin/worker', 'executable_device': 258, 'executable_inode': 12345,
                     'executable_uid': 1000, 'executable_gid': 40, 'executable_mode': stat.S_IFREG | 0o4750,
                     'executable_size': 4096, 'executable_mtime_ns': 1234567890123456789,
                     'executable_deleted': False, 'executable_identity_status': 'VERIFIED'}
    operations.open.assert_called_once_with(f'{psutil.PROCFS_PATH}/12/exe', os.O_PATH | os.O_CLOEXEC)
    operations.fstat.assert_called_once_with(6)
    operations.readlink.assert_called_once_with('/proc/self/fd/6')
    operations.stat.assert_called_once_with(f'{psutil.PROCFS_PATH}/12/exe')
    operations.close.assert_called_once_with(6)
    assert process.is_running.call_count == 2


def test_two_processes_use_their_own_proc_links(monkeypatch):
    first = observed_process()
    second = SimpleNamespace(pid=13, is_running=Mock(return_value=True))
    operations = mock_proc(monkeypatch, file_stat())
    proc_root = psutil.PROCFS_PATH
    reads = {f'{proc_root}/12/exe': file_stat(st_ino=12), f'{proc_root}/13/exe': file_stat(st_ino=13)}
    operations.open.side_effect = lambda path, _flags: reads[path].st_ino
    operations.fstat.side_effect = lambda descriptor: file_stat(st_ino=descriptor)
    operations.stat.side_effect = reads.__getitem__
    assert executable.observe(first, '/same')['executable_inode'] == 12
    assert executable.observe(second, '/same')['executable_inode'] == 13


@pytest.mark.parametrize('path,links,deleted,display', [
    ('/usr/bin/worker (deleted)', 0, True, '/usr/bin/worker'),
    ('/usr/bin/worker (deleted)', 2, None, '/usr/bin/worker (deleted)'),
    ('/memfd:worker (deleted)', 0, None, '/memfd:worker'),
    ('/tmp/#12345 (deleted)', 0, None, '/tmp/#12345'),
    ('/tmp/invalid-\udcff', 1, False, None),
])
def test_deleted_ambiguous_and_anonymous_programs(monkeypatch, path, links, deleted, display):
    mock_proc(monkeypatch, file_stat(st_nlink=links), path)
    state = executable.observe(observed_process(), None)
    assert state['executable_path'] == display
    assert state['executable_deleted'] is deleted
    assert state['executable_identity_status'] == 'VERIFIED'


@pytest.mark.parametrize('reported,status', [('/usr/bin/worker', 'PATH_ONLY'), (None, 'UNKNOWN')])
def test_permission_denied_keeps_only_the_observed_path(monkeypatch, reported, status):
    operations = mock_proc(monkeypatch, file_stat())
    operations.open.side_effect = PermissionError()
    state = executable.observe(observed_process(), reported)
    assert state['executable_identity_status'] == status
    assert state['executable_path'] == reported
    for field in executable.METADATA_FIELDS:
        assert state[field] is None
    operations.close.assert_not_called()


@pytest.mark.parametrize('check', [[False], [True, False], [True, psutil.NoSuchProcess(12)]])
def test_disappearance_or_pid_reuse_discards_the_object(monkeypatch, check):
    operations = mock_proc(monkeypatch, file_stat())
    process = observed_process()
    process.is_running.side_effect = check
    assert executable.observe(process, '/old/path') == executable.unverified()
    if check[0]:
        operations.close.assert_called_once_with(6)
    else:
        operations.open.assert_not_called()


@pytest.mark.parametrize('operation', ['fstat', 'readlink', 'stat'])
def test_descriptor_closed_on_read_error(monkeypatch, operation):
    operations = mock_proc(monkeypatch, file_stat())
    getattr(operations, operation).side_effect = FileNotFoundError()
    assert executable.observe(observed_process(), '/path') == executable.unverified('/path')
    operations.close.assert_called_once_with(6)


@pytest.mark.parametrize('changes', [{'st_ino': 999}, {'st_nlink': 0}, {'st_ctime_ns': 3}])
def test_exec_or_file_change_during_verification_is_unknown(monkeypatch, changes):
    operations = mock_proc(monkeypatch, file_stat(), live=file_stat(**changes))
    assert executable.observe(observed_process(), '/old/path') == executable.unverified()
    operations.close.assert_called_once_with(6)


def test_same_path_replacement_preserves_object_history_and_process_key(monkeypatch):
    operations = mock_proc(monkeypatch, file_stat())
    process = observed_process()
    before = executable.observe(process, None)
    operations.open.side_effect = PermissionError()
    gap = {}
    executable.set_observation(gap, before, executable.observe(process, '/usr/bin/worker'))
    assert gap['executable_inode'] is None
    assert gap['last_known_executable'] == before
    assert get.get_events({'key': gap}, {'key': before}) == []

    operations.open.side_effect = None
    info = file_stat(st_ino=999)
    operations.fstat.return_value = operations.stat.return_value = info
    latest = executable.observe(process, None)
    assert latest['executable_path'] == before['executable_path']
    assert get.get_events({'key': latest}, {'key': gap}) == [('key', 'CHANGED', gap, latest)]
    stable, _ = get.split_process_snapshot({'key': gap})
    stable['key']['last_known_executable']['executable_inode'] = 7
    assert gap['last_known_executable']['executable_inode'] == 12345


@pytest.mark.parametrize('changes', [{'st_mtime_ns': 42}, {'st_size': 8192}])
def test_size_or_mtime_updates_current_state_without_a_history_event(monkeypatch, changes):
    mock_proc(monkeypatch, file_stat())
    process = observed_process()
    before = {'key': executable.observe(process, None)}
    mock_proc(monkeypatch, file_stat(**changes))
    current = {'key': executable.observe(process, None)}
    assert get.get_events(current, before) == []
    assert current != before
