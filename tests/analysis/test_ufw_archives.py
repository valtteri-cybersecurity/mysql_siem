"""Synthetic bounded gzip extraction, CRC, cache safety and worker restart tests."""
import gzip
import hashlib
import time

import pytest

from ingestion import ufw_archives as archives

RAW = b'2026-10-25T13:35:58Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=ICMP\n'


@pytest.fixture
def cache(tmp_path, monkeypatch):
    folder = tmp_path / 'cache'
    monkeypatch.setattr(archives, 'CACHE', folder)
    archives.cache_directory()
    return folder


def run_worker(tmp_path, cache, content):
    path = tmp_path / 'ufw.log.2.gz'
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    result = archives.worker(str(path), cache, digest)
    return result, digest, archives.read_manifest(cache / (digest + '.json'))


@pytest.mark.parametrize('content,raw', [(gzip.compress(RAW), RAW), (gzip.compress(b''), b''),
                                      (gzip.compress(RAW) + gzip.compress(RAW), RAW + RAW),
                                      (gzip.compress(b'\x00' * 3000 + RAW), b'\x00' * 3000 + RAW)])
def test_verified_spool_and_members(tmp_path, cache, content, raw):
    result, digest, record = run_worker(tmp_path, cache, content)
    assert result == 0
    assert record['status'] == 'READY'
    assert (cache / (digest + '.data')).read_bytes() == raw
    assert record['expanded_sha256'] == hashlib.sha256(raw).hexdigest()
    assert (cache / (digest + '.data')).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('damage', ['header', 'truncated', 'crc'])
def test_corruption_is_never_published(tmp_path, cache, damage):
    content = gzip.compress(RAW)
    if damage == 'header':
        content = b'not gzip'
    elif damage == 'truncated':
        content = content[:-4]
    else:
        content = content[:-8] + b'\0\0\0\0' + content[-4:]
    result, digest, record = run_worker(tmp_path, cache, content)
    assert result == 1
    assert record['status'] == 'ERROR'
    assert not (cache / (digest + '.data')).exists()


@pytest.mark.parametrize('kind', ['ratio', 'expanded', 'disk', 'compressed', 'time'])
def test_resource_limits_preserve_incomplete_state(tmp_path, cache, monkeypatch, kind):
    if kind == 'ratio':
        monkeypatch.setattr(archives, 'MAX_RATIO', 1)
    elif kind == 'expanded':
        monkeypatch.setattr(archives, 'MAX_EXPANDED', 10)
    elif kind == 'disk':
        monkeypatch.setattr(archives, 'MAX_CACHE', 1)
    elif kind == 'compressed':
        monkeypatch.setattr(archives, 'MAX_COMPRESSED', 1)
    else:
        monkeypatch.setattr(archives, 'WORKER_SECONDS', 0)
    result, digest, record = run_worker(tmp_path, cache, gzip.compress(RAW * 30))
    assert result == 1
    assert record['status'] == 'ERROR'
    assert not (cache / (digest + '.data')).exists()


def test_exact_discovery_gaps_and_symlink(tmp_path):
    logfile = tmp_path / 'ufw.log'
    for name in ('ufw.log.1.gz', 'ufw.log.9.gz', 'ufw.log.3.gz', 'other.gz', 'ufw.log.x.gz', 'ufw.log.0.gz'):
        (tmp_path / name).write_bytes(gzip.compress(RAW))
    assert [item[0] for item in archives.discover(logfile)] == [9, 3, 1]
    (tmp_path / 'ufw.log.2.gz').symlink_to(tmp_path / 'other.gz')
    with pytest.raises(OSError):
        archives.discover(logfile)


def test_single_worker_survives_collectors_and_publishes(cache, tmp_path):
    path = tmp_path / 'ufw.log.1.gz'
    content = gzip.compress(RAW)
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    assert archives.prepare(str(path), digest)['status'] == 'WORKING'
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        record = archives.read_manifest(cache / (digest + '.json'))
        if record['status'] == 'READY':
            break
        time.sleep(0.02)
    assert record['status'] == 'READY'
    assert archives.prepare(str(path), digest) == record


def test_cache_and_source_symlinks_are_rejected(tmp_path, cache):
    target = tmp_path / 'target'
    target.write_bytes(RAW)
    link = cache / 'evil'
    link.symlink_to(target)
    with pytest.raises(OSError):
        archives.private_file(link)
    with pytest.raises(OSError):
        archives.archive_digest(link, time.monotonic() + 5)


def test_source_sha_cache_revalidates_modified_content(tmp_path, cache, monkeypatch):
    path = tmp_path / 'ufw.log.1.gz'
    path.write_bytes(gzip.compress(RAW))
    original = archives.archive_digest
    calls = []
    def count(filename, deadline):
        calls.append(filename)
        return original(filename, deadline)
    monkeypatch.setattr(archives, 'archive_digest', count)
    first = archives.identify_archive(str(path), time.monotonic() + 5)[0]
    assert archives.identify_archive(str(path), time.monotonic() + 5)[0] == first
    assert len(calls) == 1
    path.write_bytes(gzip.compress(RAW + RAW))
    assert archives.identify_archive(str(path), time.monotonic() + 5)[0] != first
    assert len(calls) == 2


def test_many_small_archives_are_discovered_in_numeric_order(tmp_path):
    for index in range(1, 45):
        (tmp_path / ('ufw.log.' + str(index) + '.gz')).write_bytes(gzip.compress(RAW))
    found = archives.discover(tmp_path / 'ufw.log')
    assert len(found) == 44
    assert found[0][0] == 44
    assert found[-1][0] == 1


def test_interrupted_worker_restarts_once_and_never_replays_while_locked(tmp_path, cache, monkeypatch):
    import fcntl
    import os
    path = tmp_path / 'ufw.log.1.gz'
    content = gzip.compress(RAW)
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    calls = []
    monkeypatch.setattr(archives.subprocess, 'Popen', lambda *args, **kwargs: calls.append(args))
    assert archives.prepare(str(path), digest)['status'] == 'WORKING'
    lock = archives.regular(cache / '.worker.lock', os.O_RDWR)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert archives.prepare(str(path), digest)['status'] == 'BUSY'
        assert len(calls) == 1
    finally:
        os.close(lock)
    partial = cache / (digest + '.part')
    partial.write_bytes(b'unverified partial extraction')
    partial.chmod(0o600)
    assert archives.prepare(str(path), digest)['status'] == 'WORKING'
    assert len(calls) == 2
    assert archives.worker(str(path), cache, digest) == 0
    assert archives.prepare(str(path), digest)['status'] == 'READY'
    assert len(calls) == 2


def test_archive_changed_during_decompression_is_not_ready(tmp_path, cache, monkeypatch):
    path = tmp_path / 'ufw.log.2.gz'
    content = gzip.compress(RAW)
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    original = gzip.GzipFile
    class MutatingReader:
        def __init__(self, **kwargs):
            self.reader = original(**kwargs)
            self.changed = False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.reader.close()
        def read(self, size):
            block = self.reader.read(size)
            if not self.changed:
                self.changed = True
                path.write_bytes(gzip.compress(RAW + RAW))
            return block
    monkeypatch.setattr(archives.gzip, 'GzipFile', MutatingReader)
    assert archives.worker(str(path), cache, digest) == 1
    assert archives.read_manifest(cache / (digest + '.json'))['status'] == 'ERROR'
    assert not (cache / (digest + '.data')).exists()
