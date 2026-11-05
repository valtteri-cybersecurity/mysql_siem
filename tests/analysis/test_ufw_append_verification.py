"""Concurrent appends preserve a fixed snapshot; rewrites still abort verification."""
import hashlib

import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw
from tests.analysis.test_ufw_collector import line, saved_position
from tests.analysis.test_ufw_continuity import cursor_for_files


@pytest.mark.parametrize('partial', [False, True])
def test_append_then_stable_verification_commits_only_the_initial_snapshot(tmp_path, monkeypatch, partial):
    path = tmp_path / 'ufw.log'
    initial = line(0)
    if partial:
        initial += line(1).rstrip(b'\n')
    path.write_bytes(initial)
    cursor = cursor_for_files()
    original = continuity.digest_prefixes
    calls = []
    def append(source, sizes, deadline):
        result = original(source, sizes, deadline)
        calls.append(tuple(sizes))
        if len(calls) == 2:
            with path.open('ab') as output:
                output.write(b'\n' + line(len(calls)))
        return result
    monkeypatch.setattr(continuity, 'digest_prefixes', append)
    stats = {'lines_read': 0}
    assert ufw.process_file(cursor, str(path), stats=stats) == 1
    assert saved_position(cursor) == len(line(0))
    assert stats['file_state'] == 'READING'
    assert len(calls) == 3  # Initial snapshot, final verification, bounded growth recheck.
    assert calls[1] == calls[2] == (len(line(0)), len(initial))
    monkeypatch.setattr(continuity, 'digest_prefixes', original)
    expected = 1
    if partial:
        expected = 2
    assert ufw.process_file(cursor, str(path)) == expected
    assert saved_position(cursor) == path.stat().st_size


@pytest.mark.parametrize('change', ['rewrite_and_append', 'truncate', 'replace', 'same_size_rewrite'])
def test_source_change_during_verification_does_not_publish_checkpoint(tmp_path, monkeypatch, change):
    path = tmp_path / 'ufw.log'
    initial = line(0)
    path.write_bytes(initial)
    cursor = cursor_for_files()
    original = continuity.digest_prefixes
    calls = [0]
    def mutate(source, sizes, deadline):
        result = original(source, sizes, deadline)
        calls[0] += 1
        if calls[0] == 2:
            if change == 'rewrite_and_append':
                path.write_bytes(line(1) + line(2))
            elif change == 'truncate':
                path.write_bytes(b'')
            elif change == 'replace':
                path.rename(tmp_path / 'untracked-old-file')
                path.write_bytes(initial)
            else:
                path.write_bytes(line(1))
        return result
    monkeypatch.setattr(continuity, 'digest_prefixes', mutate)
    monkeypatch.setattr(ufw, 'get_logfiles', list)
    with pytest.raises(OSError):
        ufw.process_file(cursor, str(path))
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith(('INSERT INTO ufw_file_checkpoints',
                                           'UPDATE ufw_file_checkpoints SET filename'))


def test_growth_recheck_obeys_the_same_deadline(tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    path.write_bytes(line(0))
    cursor = cursor_for_files()
    original = continuity.digest_prefixes
    calls = [0]
    def append_then_expire(source, sizes, deadline):
        calls[0] += 1
        if calls[0] == 3:
            assert deadline == 100
            raise TimeoutError('CHECKPOINT_VERIFY_TIME_LIMIT')
        result = original(source, sizes, deadline)
        if calls[0] == 2:
            with path.open('ab') as output:
                output.write(line(1))
        return result
    monkeypatch.setattr(continuity.time, 'monotonic', lambda: 1)
    monkeypatch.setattr(continuity, 'digest_prefixes', append_then_expire)
    with pytest.raises(TimeoutError, match='CHECKPOINT_VERIFY_TIME_LIMIT'):
        ufw.process_file(cursor, str(path), deadline=100)
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith('INSERT INTO ufw_file_checkpoints')


def test_idle_snapshot_still_requires_only_two_passes(tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    content = line(0)
    path.write_bytes(content)
    cursor = cursor_for_files()
    original = continuity.digest_prefixes
    calls = []
    def count(source, sizes, deadline):
        calls.append(tuple(sizes))
        return original(source, sizes, deadline)
    monkeypatch.setattr(continuity, 'digest_prefixes', count)
    ufw.process_file(cursor, str(path))
    assert len(calls) == 2
    assert hashlib.sha256(path.read_bytes()).hexdigest() == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize('change', ['truncate', 'rewrite'])
def test_change_during_growth_recheck_still_aborts(tmp_path, monkeypatch, change):
    path = tmp_path / 'ufw.log'
    path.write_bytes(line(0))
    cursor = cursor_for_files()
    original = continuity.digest_prefixes
    calls = [0]
    def mutate(source, sizes, deadline):
        result = original(source, sizes, deadline)
        calls[0] += 1
        if calls[0] == 2:
            with path.open('ab') as output:
                output.write(line(1))
        elif calls[0] == 3:
            if change == 'truncate':
                path.write_bytes(b'')
            else:
                with path.open('r+b') as output:
                    output.write(b'X')
        return result
    monkeypatch.setattr(continuity, 'digest_prefixes', mutate)
    with pytest.raises(OSError, match='SOURCE_CHANGED'):
        ufw.process_file(cursor, str(path))
    assert calls[0] == 3
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith('INSERT INTO ufw_file_checkpoints')
