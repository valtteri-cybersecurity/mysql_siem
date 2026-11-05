"""Preserve window semantics and bound work independently of wall-clock timing."""

import random
from datetime import datetime, timedelta

import pytest

from detection.port_scan.detector import MIN_DISTINCT_PORTS, WINDOW, _find_scan_windows

START = datetime(2026, 10, 22, 12)


def reference_windows(events):
    """Original exhaustive calculation, retained only as a small test oracle."""
    windows = []
    for end, event in enumerate(events):
        start = end
        while start > 0 and event['event_time'] - events[start - 1]['event_time'] <= WINDOW:
            start -= 1
        ports = set()
        for index in range(start, end + 1):
            ports.add(events[index]['dst_port'])
        if len(ports) >= MIN_DISTINCT_PORTS:
            if windows and start <= windows[-1][1]:
                windows[-1][1] = end
            else:
                windows.append([start, end])
    return windows


@pytest.mark.parametrize('seed', range(40))
def test_repeated_ports_gaps_and_boundaries_match_reference(seed):
    source = random.Random(seed)
    events = []
    clock = START
    for _ in range(250):
        clock += timedelta(microseconds=source.choice((0, 0, 1, 1000000, 60000000, 60000001)))
        events.append({'event_time': clock, 'dst_port': source.randrange(1, 21)})
    assert _find_scan_windows(events) == reference_windows(events)


class CountedEvent(dict):
    def __init__(self, timestamp, port, reads):
        super().__init__(event_time=timestamp, dst_port=port)
        self.reads = reads

    def __getitem__(self, key):
        if key == 'dst_port':
            self.reads[0] += 1
        return super().__getitem__(key)


@pytest.mark.parametrize('step', [0, 1, 61])
@pytest.mark.parametrize('port_count', [1, 9, 10, 100])
def test_port_accesses_grow_linearly_for_dense_and_expiring_windows(step, port_count):
    reads = [0]
    events = []
    for index in range(5000):
        timestamp = START + timedelta(seconds=index * step)
        events.append(CountedEvent(timestamp, 1000 + index % port_count, reads))
    _find_scan_windows(events)
    assert reads[0] <= 2 * len(events)
