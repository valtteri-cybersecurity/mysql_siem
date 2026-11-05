"""Measure verification bytes while retaining full-prefix and snapshot checks."""
import hashlib
import os

import pytest

from ingestion import ufw_continuity as continuity
from tests.analysis.test_ufw_continuity import cursor_for_files


class CountingFile:
    def __init__(self, source):
        self.source = source
        self.bytes_read = 0

    def read(self, size):
        block = self.source.read(size)
        self.bytes_read += len(block)
        return block

    def seek(self, position):
        return self.source.seek(position)

    def tell(self):
        return self.source.tell()

    def fileno(self):
        return self.source.fileno()


def seed(cursor, path, content, position):
    info = path.stat()
    cursor.execute('INSERT INTO ufw_file_checkpoints ',
                   (str(path), position, hashlib.sha256(content[:position]).hexdigest(),
                    len(content), hashlib.sha256(content).hexdigest(), 'CAUGHT_UP',
                    7, info.st_dev, info.st_ino))
    cursor.execute('UPDATE ufw_file_checkpoints SET generation_key', (b'g' * 32, info.st_mtime_ns, 1, 7))


@pytest.mark.parametrize('size', [0, 1024 * 1024])
def test_unchanged_snapshot_is_read_only_twice(tmp_path, size):
    path = tmp_path / 'ufw.log'
    content = b'x' * size
    path.write_bytes(content)
    cursor = cursor_for_files()
    seed(cursor, path, content, len(content))
    with path.open('rb') as source:
        counted = CountingFile(source)
        info = path.stat()
        key, prefix, observed, generation = continuity.start(cursor, counted, str(path), info, 7, None)
        assert counted.tell() == len(content)
        assert counted.bytes_read == len(content)
        assert continuity.finish(cursor, counted, str(path), info, 7, key, prefix, observed, None,
                                 generation=generation) == 'CAUGHT_UP'
        assert counted.bytes_read == 2 * len(content)


@pytest.mark.parametrize('position', [0, 13, 65535, 65536, 65537])
def test_distinct_prefix_boundaries_share_one_streaming_pass(tmp_path, position):
    path = tmp_path / 'ufw.log'
    content = b'0123456789abcdef' * 8193
    path.write_bytes(content)
    cursor = cursor_for_files()
    seed(cursor, path, content, position)
    with path.open('rb') as source:
        counted = CountingFile(source)
        key, prefix, observed, _generation = continuity.start(cursor, counted, str(path), path.stat(), 7, None)
        assert key == 1
        assert prefix.hexdigest() == hashlib.sha256(content[:position]).hexdigest()
        assert observed == hashlib.sha256(content).hexdigest()
        assert counted.tell() == position
        assert counted.bytes_read == len(content)


def test_full_observation_detects_changed_unread_tail(tmp_path):
    path = tmp_path / 'ufw.log'
    original = b'committed\nunread tail\n'
    path.write_bytes(original)
    cursor = cursor_for_files()
    seed(cursor, path, original, len(b'committed\n'))
    path.write_bytes(b'committed\nCHANGED tail\n')
    with path.open('rb') as source:
        key, prefix, _observed, _generation = continuity.start(cursor, source, str(path), path.stat(), 7, None)
        assert key is None
        assert source.tell() == 0
        assert prefix.hexdigest() == hashlib.sha256(b'').hexdigest()


@pytest.mark.parametrize('position', [0, 10])
def test_finish_still_detects_changes_outside_the_committed_prefix(tmp_path, position):
    path = tmp_path / 'ufw.log'
    content = b'original complete snapshot\n'
    path.write_bytes(content)
    cursor = cursor_for_files()
    seed(cursor, path, content, position)
    with path.open('rb') as source:
        info = path.stat()
        key, prefix, observed, generation = continuity.start(cursor, source, str(path), info, 7, None)
        path.write_bytes(content[:-2] + b'X\n')
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        cursor.reset_mock()
        with pytest.raises(OSError, match='SOURCE_CHANGED'):
            continuity.finish(cursor, source, str(path), info, 7, key, prefix, observed, None,
                              generation=generation)
        for call in cursor.execute.call_args_list:
            assert not call.args[0].startswith('UPDATE ')


def test_valid_whole_snapshot_does_not_hide_a_bad_committed_prefix(tmp_path):
    path = tmp_path / 'ufw.log'
    content = b'committed\nunread tail\n'
    path.write_bytes(content)
    cursor = cursor_for_files()
    seed(cursor, path, content, 10)
    cursor.execute('UPDATE ufw_file_checkpoints SET filename',
                   (str(path), 10, 'a' * 64, len(content), hashlib.sha256(content).hexdigest(), 'READING', 1, 7))
    with path.open('rb') as source:
        key, prefix, observed, _generation = continuity.start(cursor, source, str(path), path.stat(), 7, None)
        assert key is None
        assert source.tell() == 0
        assert prefix.hexdigest() == hashlib.sha256(b'').hexdigest()
        assert observed == hashlib.sha256(content).hexdigest()


def test_appended_snapshot_verifies_old_observation_and_partial_prefix_in_one_pass(tmp_path):
    path = tmp_path / 'ufw.log'
    original = b'original message\n' * 10000
    path.write_bytes(original)
    cursor = cursor_for_files()
    seed(cursor, path, original, 70000)
    tail = b'appended message\n' * 5000
    with path.open('ab') as output:
        output.write(tail)
    content = original + tail
    with path.open('rb') as source:
        counted = CountingFile(source)
        info = path.stat()
        key, prefix, observed, generation = continuity.start(cursor, counted, str(path), info, 7, None)
        assert key == 1
        assert prefix.hexdigest() == hashlib.sha256(content[:70000]).hexdigest()
        assert observed == hashlib.sha256(content).hexdigest()
        assert counted.bytes_read == len(content)
        assert counted.tell() == 70000
        assert continuity.finish(cursor, counted, str(path), info, 7, key, prefix, observed, None,
                                 generation=generation) == 'READING'
        assert counted.bytes_read == 2 * len(content)
