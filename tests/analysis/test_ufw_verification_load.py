"""Opt-in real-file load measurements; no production logs or database connections."""
import hashlib
import json
import os
import shutil
import time

import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw
from tests.analysis.test_ufw_continuity import cursor_for_files
from tests.analysis.test_ufw_verification_reads import CountingFile

MIB = 1024 * 1024
LINE = (b'2026-11-05T12:00:00Z host [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.1 '
        b'DST=198.51.100.1 PROTO=TCP SPT=12345 DPT=443\n')


def sizes():
    result = []
    for value in os.getenv('SIEM_UFW_LOAD_SIZES_MIB', '2,10,16,64,256,512').split(','):
        size = int(value)
        if size < 1 or size > 2048:
            raise ValueError('Load-test sizes must be within 1..2048 MiB.')
        result.append(size)
    return result


def create_source(path, size):
    block = LINE * (65536 // len(LINE))
    remaining = size * MIB // len(LINE) * len(LINE)
    digest = hashlib.sha256()
    with path.open('wb') as output:
        while remaining:
            part = block[:min(len(block), remaining)]
            output.write(part)
            digest.update(part)
            remaining -= len(part)
        output.flush()
        os.fsync(output.fileno())
    return digest.hexdigest()


@pytest.mark.skipif(os.getenv('SIEM_TEST_UFW_LOAD') != '1', reason='Set SIEM_TEST_UFW_LOAD=1 for real-file load tests.')
@pytest.mark.parametrize('size', sizes())
@pytest.mark.parametrize('mode', ['idle', 'backlog', 'growth_recheck'])
def test_verification_load(tmp_path, monkeypatch, size, mode):
    if shutil.disk_usage(tmp_path).free < (size + 256) * MIB:
        pytest.fail('Load test requires space for its own file and a 256 MiB reserve.')
    path = tmp_path / 'ufw.log'
    budget = float(os.getenv('SIEM_UFW_LOAD_BUDGET_SECONDS', '7.5'))
    if not 1 <= budget <= 50:
        raise ValueError('Load-test budget must be within 1..50 seconds.')
    try:
        digest = create_source(path, size)
        info = path.stat()
        position = 0
        prefix = hashlib.sha256(b'').hexdigest()
        if mode == 'idle':
            position = info.st_size
            prefix = digest
        cursor = cursor_for_files()
        cursor.execute('INSERT INTO ufw_file_checkpoints ',
                       (str(path), position, prefix, info.st_size, digest, 'READING', 0, info.st_dev, info.st_ino))
        cursor.execute('UPDATE ufw_file_checkpoints SET generation_key', (b'g' * 32, info.st_mtime_ns, 1, 0))
        counted = {'bytes': 0, 'passes': 0}
        original_digest = continuity.digest_prefixes
        original_finish = continuity.finish
        def measure(source, boundaries, deadline):
            reader = CountingFile(source)
            result = original_digest(reader, boundaries, deadline)
            counted['bytes'] += reader.bytes_read
            counted['passes'] += 1
            if mode == 'growth_recheck' and counted['passes'] == 2:
                with path.open('ab') as output:
                    output.write(LINE)
            return result
        def finish(*args, **kwargs):
            if mode == 'growth_recheck':
                with path.open('ab') as output:
                    output.write(LINE)
            return original_finish(*args, **kwargs)
        monkeypatch.setattr(continuity, 'digest_prefixes', measure)
        monkeypatch.setattr(continuity, 'finish', finish)
        cold_requested = False
        if hasattr(os, 'posix_fadvise'):
            with path.open('rb') as source:
                os.posix_fadvise(source.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            cold_requested = True
        stats = {'lines_read': 0}
        started = time.monotonic()
        ufw.process_file(cursor, str(path), stats=stats, deadline=started + budget, batch=True)
        elapsed = time.monotonic() - started
        writes = []
        for call in cursor.execute.call_args_list:
            if call.args[0].startswith('UPDATE ufw_file_checkpoints SET filename'):
                writes.append(call.args[1])
        assert len(writes) == 1
        if mode != 'idle':
            assert writes[0][1] > position
            assert stats['lines_read'] == ufw.MAX_LINES
        else:
            assert writes[0][1] == position
            assert stats['lines_read'] == 0
        assert elapsed < budget
        expected_passes = 2
        if mode == 'growth_recheck':
            expected_passes = 3
        assert counted['passes'] == expected_passes
        assert counted['bytes'] == expected_passes * info.st_size
        print(json.dumps({'size_mib': size, 'mode': mode, 'seconds': round(elapsed, 4),
                          'verification_mib': counted['bytes'] / MIB, 'passes': counted['passes'],
                          'lines': stats['lines_read'], 'budget_seconds': budget, 'cold_cache_requested': cold_requested,
                          'database': 'in-memory SQL model'}))
    finally:
        path.unlink(missing_ok=True)
