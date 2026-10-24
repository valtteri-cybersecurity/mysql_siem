"""Processes use their own source, current state and shared transaction protocol."""

import psutil

from metrics.processes.get import get_events, get_processes
from metrics.snapshot import SnapshotError, collect_snapshot


def collect_processes(connection):
    try:
        return collect_snapshot(connection, 'processes', get_processes, get_events)
    except psutil.Error as error:
        raise SnapshotError('Process observation failed.') from error
