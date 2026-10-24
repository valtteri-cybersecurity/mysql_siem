"""Process identity is PID + creation time, independent of mutable process names."""

import time
from datetime import datetime, timezone

import psutil

from metrics.snapshot import SnapshotError

FIELDS = ['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'memory_info',
          'status', 'exe', 'create_time']


def get_processes(previous=None):
    previous = previous or {}
    current = {}
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
                'cpu_percent': info['cpu_percent'], 'memory_percent': info['memory_percent'],
                'memory_mb': round(memory.rss / 1024 / 1024, 2) if memory else None,
                'status': info['status'],
                'executable_path': info['exe'] if info['exe'] is not None else old.get('executable_path'),
                'start_time': datetime.fromtimestamp(created, timezone.utc).isoformat(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            current.update(previous_pids.get(process.pid, {}))
    # An iterator can omit a process that was visible at the start of the scan.
    observed_pids = {state['pid'] for state in current.values()}
    for pid in visible:
        if pid not in observed_pids:
            current.update(previous_pids.get(pid, {}))
    if not current:
        raise SnapshotError('No process metadata could be observed.')
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
