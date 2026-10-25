"""Process identity is PID + creation time, independent of mutable process names."""

import math
import time
from datetime import datetime, timezone

import psutil

from metrics.snapshot import SnapshotError

FIELDS = ['pid', 'name', 'username', 'memory_percent', 'memory_info',
          'status', 'exe', 'create_time']


def sample_cpu(processes, current, deadline):
    """Discard the first sample and share one short wait across all processes."""
    ready = {}
    for key, process in processes.items():
        if time.monotonic() >= deadline:
            raise SnapshotError('Process observation time budget exceeded.')
        try:
            process.cpu_percent(interval=None)
            ready[key] = process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if not ready:
        return
    if deadline - time.monotonic() < 0.1:
        raise SnapshotError('Process CPU sampling time budget exceeded.')
    time.sleep(0.1)
    for key, process in ready.items():
        if time.monotonic() >= deadline:
            raise SnapshotError('Process observation time budget exceeded.')
        try:
            value = process.cpu_percent(interval=None)
            # is_running also checks process identity, so a reused PID is unknown.
            if process.is_running() and math.isfinite(value) and value >= 0:
                current[key]['cpu_percent'] = value
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue


def get_processes(previous=None):
    previous = previous or {}
    current = {}
    cpu_processes = {}
    deadline = time.monotonic() + 40
    # Keep denied or racing observations for still-visible PIDs. Failure to read
    # process metadata is not evidence that the process exited.
    visible = set(psutil.pids())
    if not visible or len(visible) > 65536:
        raise SnapshotError('Empty or excessive process inventory.')
    previous_pids = {}
    for key, state in previous.items():
        previous_pids.setdefault(state['pid'], {})[key] = state
    psutil.process_iter.cache_clear()
    for process in psutil.process_iter(FIELDS, ad_value=None):
        if time.monotonic() > deadline:
            raise SnapshotError('Process observation time budget exceeded.')
        if process.pid not in visible:
            continue
        try:
            info = process.info
            pid, created = info['pid'], info['create_time']
            if created is None or not info['name'] or info['status'] is None:
                current.update(previous_pids.get(process.pid, {}))
                continue
            key = f'{pid}:{created:.6f}'
            old = previous.get(key, {})
            memory = info['memory_info']
            current[key] = {
                'pid': pid, 'process_name': info['name'],
                'username': info['username'] if info['username'] is not None else old.get('username'),
                'cpu_percent': None, 'memory_percent': info['memory_percent'],
                'memory_mb': round(memory.rss / 1024 / 1024, 2) if memory else None,
                'status': info['status'],
                'executable_path': info['exe'] if info['exe'] is not None else old.get('executable_path'),
                'start_time': datetime.fromtimestamp(created, timezone.utc).isoformat(),
            }
            cpu_processes[key] = process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            current.update(previous_pids.get(process.pid, {}))
    # An iterator can omit a process that was visible at the start of the scan.
    observed_pids = {state['pid'] for state in current.values()}
    for pid in visible:
        if pid not in observed_pids:
            current.update(previous_pids.get(pid, {}))
    if not current:
        raise SnapshotError('No process metadata could be observed.')
    sample_cpu(cpu_processes, current, deadline)
    return current


def get_events(current, previous):
    events = []
    for key in sorted(current.keys() | previous.keys()):
        before, after = previous.get(key), current.get(key)
        if before is None:
            event = 'STARTED'
        elif after is None:
            event = 'STOPPED'
        elif any(before.get(field) != after.get(field)
                 for field in ('process_name', 'username', 'status', 'executable_path')):
            event = 'CHANGED'
        else:
            continue
        events.append((key, event, before, after))
    return events
