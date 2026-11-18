"""Opt-in read-only Linux ABI checks. No database, logs or service changes."""

import os
import statistics
import time

import pytest

from metrics.processes.get import get_processes, read_boot_id
from metrics.services.get import get_services


@pytest.mark.skipif(os.getenv('SIEM_TEST_SNAPSHOT_LIVE') != '1', reason='Opt in to live read-only Linux observations.')
@pytest.mark.parametrize('kind', ['processes', 'services'])
def test_live_snapshot_observations(kind):
    elapsed = []
    counts = []
    rejected = 0
    for _ in range(3):
        started = time.perf_counter()
        coverage = {}
        if kind == 'processes':
            current = get_processes(boot_id=read_boot_id(), coverage=coverage, measurements={})
            if coverage.get('incomplete_process_count'):
                rejected += 1
                continue
        else:
            current = get_services(coverage=coverage)
        counts.append(len(current))
        elapsed.append((time.perf_counter() - started) * 1000)
    assert counts and min(counts) > 0
    print(kind, 'accepted_counts', counts, 'rejected', rejected,
          'median_min_max_ms', [round(value, 1) for value in
                                (statistics.median(elapsed), min(elapsed), max(elapsed))])
