"""Transient extraction failures are bounded; corruption never becomes retryable."""
import errno
import gzip
import hashlib
from unittest.mock import Mock

import pytest

from ingestion import ufw_archives as archives
from tests.analysis.test_ufw_archives import RAW
from tests.analysis.test_ufw_archives import cache as cache  # noqa: PLC0414 -- fixture re-export


@pytest.fixture
def source(tmp_path):
    path = tmp_path / 'ufw.log.1.gz'
    path.write_bytes(gzip.compress(RAW))
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def inline_worker(command, **kwargs):
    filename, folder, digest, _lock = command[-4:]
    archives.worker(filename, folder, digest)


def test_disk_pressure_recovers_only_after_delay_with_full_crc_check(cache, source, monkeypatch):
    path, digest = source
    original = path.read_bytes()
    now = [1000]
    monkeypatch.setattr(archives.time, 'time', lambda: now[0])
    with monkeypatch.context() as pressure:
        pressure.setattr(archives, 'MAX_CACHE', 1)
        assert archives.worker(str(path), cache, digest) == 1
    manifest = cache / (digest + '.json')
    failed = archives.read_manifest(manifest)
    assert failed['reason'] == 'ARCHIVE_DISK_LIMIT'
    launch = Mock(side_effect=inline_worker)
    monkeypatch.setattr(archives.subprocess, 'Popen', launch)
    assert archives.prepare(str(path), digest) == failed
    launch.assert_not_called()
    now[0] += archives.RETRY_SECONDS + 1
    assert archives.prepare(str(path), digest)['status'] == 'WORKING'
    ready = archives.prepare(str(path), digest)
    assert ready['status'] == 'READY'
    assert ready['attempts'] == 2
    assert (cache / (digest + '.data')).read_bytes() == RAW
    assert path.read_bytes() == original
    assert launch.call_count == 1


@pytest.mark.parametrize('reason', ['GZIP_CRC_OR_HEADER', 'GZIP_TRUNCATED', 'GZIP_DEFLATE', 'ARCHIVE_CHANGED',
                                  'ARCHIVE_EXPANSION_LIMIT', 'ARCHIVE_COMPRESSED_LIMIT', 'ARCHIVE_IO_ERROR',
                                  'UNSAFE_ARCHIVE_FILE', 'ARCHIVE_SPOOL_CHANGED', 'unknown'])
def test_permanent_and_unknown_errors_never_retry(cache, source, monkeypatch, reason):
    path, digest = source
    record = {'status': 'ERROR', 'reason': reason, 'attempts': 1, 'retry_after': 0}
    archives.write_manifest(cache / (digest + '.json'), record)
    launch = Mock()
    monkeypatch.setattr(archives.subprocess, 'Popen', launch)
    for _attempt in range(4):
        assert archives.prepare(str(path), digest) == record
    launch.assert_not_called()


def test_three_total_extractions_survive_collector_restarts_and_then_stop(cache, source, monkeypatch):
    path, digest = source
    now = [1000]
    monkeypatch.setattr(archives.time, 'time', lambda: now[0])
    monkeypatch.setattr(archives, 'MAX_CACHE', 1)
    launch = Mock(side_effect=inline_worker)
    monkeypatch.setattr(archives.subprocess, 'Popen', launch)
    assert archives.worker(str(path), cache, digest) == 1
    for _attempt in range(6):
        now[0] += archives.RETRY_SECONDS + 1
        archives.prepare(str(path), digest)
    assert launch.call_count == archives.MAX_ATTEMPTS - 1
    assert archives.read_manifest(cache / (digest + '.json'))['attempts'] == archives.MAX_ATTEMPTS
    assert not (cache / (digest + '.data')).exists()


def test_failed_spawn_is_persisted_and_not_busy_forever(cache, source, monkeypatch):
    path, digest = source
    launch = Mock(side_effect=OSError(errno.EMFILE, 'synthetic descriptor pressure'))
    monkeypatch.setattr(archives.subprocess, 'Popen', launch)
    record = archives.prepare(str(path), digest)
    assert record['status'] == 'ERROR'
    assert record['reason'] == 'ARCHIVE_IO_TRANSIENT'
    assert record['attempts'] == 1
    assert archives.prepare(str(path), digest) == record
    assert launch.call_count == 1


def test_cleanup_error_prevents_automatic_retry(cache, source, monkeypatch):
    path, digest = source
    record = {'status': 'ERROR', 'reason': 'ARCHIVE_DISK_LIMIT', 'cleanup_error': 'PermissionError', 'attempts': 1}
    archives.write_manifest(cache / (digest + '.json'), record)
    launch = Mock()
    monkeypatch.setattr(archives.subprocess, 'Popen', launch)
    assert archives.prepare(str(path), digest) == record
    launch.assert_not_called()


@pytest.mark.parametrize('number,expected', [(errno.EIO, 'ARCHIVE_IO_TRANSIENT'),
                                           (errno.ENOSPC, 'ARCHIVE_IO_TRANSIENT'),
                                           (errno.EACCES, 'ARCHIVE_IO_TRANSIENT'), (errno.EINVAL, None)])
def test_only_explicit_os_errors_are_transient(number, expected):
    assert archives.error_reason(OSError(number, 'synthetic')) == expected
    assert archives.error_reason(OSError('unknown')) is None


@pytest.mark.parametrize('status,count,waiting,due,expected', [
    ('FAILED', 0, 1, 1, False), ('COMPLETE', 0, 1, 0, False),
    ('COMPLETE', 2, 1, 1, False), ('COMPLETE', 1, 1, 1, True), ('COMPLETE', 2, 0, None, True),
])
def test_completed_source_rechecks_have_a_persistent_bound(status, count, waiting, due, expected):
    from types import SimpleNamespace

    from ingestion import ufw_archive_retry as retry
    cursor = Mock()
    cursor.fetchone.return_value = ('a' * 64, status, 'ARCHIVE_IO_TRANSIENT', count, waiting, due)
    info = SimpleNamespace(st_dev=1, st_ino=2, st_mtime_ns=3)
    assert retry.discovery_allowed(cursor, 7, info) == expected
    mutations = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('UPDATE'):
            mutations.append(call)
    if expected and waiting:
        assert len(mutations) == 1
        assert mutations[0].args[1] == (archives.RETRY_SECONDS, 7, 'a' * 64)
    else:
        assert not mutations


@pytest.mark.parametrize('record', [None, {'status': 'ERROR', 'class': 'OSError'},
                                    {'status': 'ERROR', 'reason': 'GZIP_CRC_OR_HEADER'},
                                    {'status': 'ERROR', 'reason': 'ARCHIVE_DISK_LIMIT', 'restarts': 'unknown'},
                                    {'status': 'ERROR', 'reason': 'ARCHIVE_DISK_LIMIT', 'cleanup_error': 'OSError'}])
def test_unknown_legacy_failures_are_not_promoted(record):
    from ingestion import ufw_archive_retry as retry
    cursor = Mock()
    retry.adopt_legacy(cursor, 7, 'a' * 64, record)
    cursor.execute.assert_not_called()
