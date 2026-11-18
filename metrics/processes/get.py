"""Process identity is boot ID, PID and creation time within a registered host."""

import hashlib
import math
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import psutil

from config.snapshot_policy import collection_seconds, inventory_limit
from metrics.processes import executable
from metrics.snapshot import ObservationError, ResourceLimitError, SnapshotError

BOOT_ID_PATH = Path('/proc/sys/kernel/random/boot_id')
FIELDS = ['pid', 'name', 'username', 'memory_percent', 'memory_info',
          'status', 'exe', 'create_time', 'ppid', 'uids', 'gids']
CREDENTIAL_FIELDS = ('uid', 'euid', 'gid', 'egid')
STABLE_STATE_FIELDS = ('pid', 'process_name', 'username', 'status', 'start_time',
                       'ppid', 'parent_process_key', 'parent_identity_status', 'last_known_parent',
                       'last_known_credentials', executable.LAST_KNOWN) + CREDENTIAL_FIELDS + executable.STATE_FIELDS
MEASUREMENT_FIELDS = ('cpu_percent', 'memory_percent', 'memory_mb')


class BootIdentityError(ObservationError):
    """A complete process observation requires a reliable Linux boot ID."""

    def __init__(self, message, *, code='INVALID_OBSERVATION'):
        super().__init__(code, message)


def normalize_boot_id(value):
    if not isinstance(value, str):
        raise BootIdentityError('Invalid Linux boot ID.')
    try:
        parsed = UUID(value)
    except ValueError:
        raise BootIdentityError('Invalid Linux boot ID.') from None
    normalized = str(parsed)
    if parsed.int == 0 or value.lower() != normalized:
        raise BootIdentityError('Invalid Linux boot ID.')
    return normalized


def read_boot_id(path=BOOT_ID_PATH):
    try:
        with path.open(encoding='ascii') as handle:
            value = handle.read(38).removesuffix('\n')
    except PermissionError:
        raise BootIdentityError('Cannot read Linux boot ID.', code='PERMISSION_DENIED') from None
    except OSError:
        raise BootIdentityError('Cannot read Linux boot ID.', code='SOURCE_UNAVAILABLE') from None
    except UnicodeError:
        raise BootIdentityError('Invalid Linux boot ID encoding.') from None
    return normalize_boot_id(value)


def process_key(boot_id, pid, created):
    # Keep the previous microsecond precision and store the full boot ID only in the checkpoint.
    value = f'{boot_id}:{pid}:{created:.6f}'
    return hashlib.sha256(value.encode('ascii')).hexdigest()[:32]


def split_process_snapshot(current):
    """Return (stable_state, measurements), both keyed by the original process identifiers.

    Preserve explicit None values and leave absent fields absent in older snapshots.
    """
    if not isinstance(current, Mapping):
        raise SnapshotError('Process snapshot must be a mapping.')

    stable_state = {}
    measurements = {}
    for key, state in current.items():
        if not isinstance(key, str) or not isinstance(state, Mapping):
            raise SnapshotError('Process snapshot entries require a string key and a state mapping.')
        stable_fields = {}
        measurement_fields = {}
        for field, value in state.items():
            if field in STABLE_STATE_FIELDS:
                if field in ('last_known_parent', 'last_known_credentials', executable.LAST_KNOWN) and isinstance(value, Mapping):
                    value = dict(value)
                stable_fields[field] = value
            elif field in MEASUREMENT_FIELDS:
                measurement_fields[field] = value
            else:
                raise SnapshotError('Process snapshot contains an unknown field.')
        stable_state[key] = stable_fields
        measurements[key] = measurement_fields
    return stable_state, measurements


def sample_cpu(processes, current, deadline):
    """Discard the first sample and share one short wait across all processes."""
    ready = {}
    for key, process in processes.items():
        if time.monotonic() >= deadline:
            raise ObservationError('OBSERVATION_TIMEOUT', 'Process observation time budget exceeded.')
        try:
            process.cpu_percent(interval=None)
            ready[key] = process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if not ready:
        return
    if deadline - time.monotonic() < 0.1:
        raise ObservationError('OBSERVATION_TIMEOUT', 'Process CPU sampling time budget exceeded.')
    time.sleep(0.1)
    for key, process in ready.items():
        if time.monotonic() >= deadline:
            raise ObservationError('OBSERVATION_TIMEOUT', 'Process observation time budget exceeded.')
        try:
            value = process.cpu_percent(interval=None)
            # is_running also checks process identity, so a reused PID is unknown.
            if process.is_running() and math.isfinite(value) and value >= 0:
                current[key]['cpu_percent'] = value
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue


def verified_parent_key(ppid, created, observed):
    candidate = observed.get(ppid)
    if candidate is None or ppid == 0:
        return None
    parent_key, parent_created, parent = candidate
    if parent.pid != ppid or parent_created > created:
        return None
    try:
        # Check the same parent instance after reading the child's live PPID.
        if parent.status() in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD) or not parent.is_running():
            return None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    return parent_key


def observe_parent(process, ppid, created, observed):
    """Verify the child's current parent using identities captured in this boot's inventory."""
    if type(ppid) is not int or ppid < 0 or ppid == process.pid:
        return None, None
    try:
        confirmed_ppid = process.ppid()
        if type(confirmed_ppid) is not int or confirmed_ppid != ppid:
            return None, None
        parent_key = verified_parent_key(ppid, created, observed)
        if not process.is_running():
            return None, None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None, None
    return ppid, parent_key


def last_known_parent(state):
    ppid = state.get('ppid')
    key = state.get('parent_process_key')
    last = state.get('last_known_parent', {})
    if ppid is None:
        return last.get('ppid'), last.get('parent_process_key')
    if key is None and ppid == last.get('ppid'):
        key = last.get('parent_process_key')
    return ppid, key


def set_parent_observations(current, previous, observed, deadline):
    for key, state in current.items():
        if time.monotonic() >= deadline:
            raise ObservationError('OBSERVATION_TIMEOUT', 'Process observation time budget exceeded.')
        entry = observed.get(state['pid'])
        ppid = parent_key = None
        if entry is not None and entry[0] == key:
            _, created, process = entry
            ppid, parent_key = observe_parent(process, state['ppid'], created, observed)
        else:
            # A carried row still has its last known state, with no fresh parent observation.
            state = state.copy()
            state.pop('last_known_parent', None)
            current[key] = state

        status = 'UNKNOWN'
        if parent_key is not None:
            status = 'VERIFIED'
        elif ppid == 0:
            status = 'NO_PARENT'
        state.update(ppid=ppid, parent_process_key=parent_key, parent_identity_status=status)
        if status == 'UNKNOWN':
            old_ppid, old_key = last_known_parent(previous.get(key, {}))
            if old_ppid is not None and (ppid is None or (ppid == old_ppid and old_key is not None)):
                state['last_known_parent'] = {'ppid': old_ppid, 'parent_process_key': old_key}


def observe_credentials(process, info):
    credentials = {}
    for group, real_field, effective_field in (('uids', 'uid', 'euid'), ('gids', 'gid', 'egid')):
        ids = info.get(group)
        for kind, field in (('real', real_field), ('effective', effective_field)):
            value = getattr(ids, kind, None)
            if type(value) is int and value >= 0:
                credentials[field] = value
    if not credentials:
        return credentials
    try:
        # The inventory values belong to this process instance only while its identity still matches.
        if process.is_running():
            return credentials
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {}
    return {}


def last_known_credential(state, field):
    value = state.get(field)
    if value is None:
        return state.get('last_known_credentials', {}).get(field)
    return value


def set_credentials(state, previous, credentials):
    last_known = {}
    for field in CREDENTIAL_FIELDS:
        value = credentials.get(field)
        state[field] = value
        if value is None:
            old_value = last_known_credential(previous, field)
            if old_value is not None:
                last_known[field] = old_value
    if last_known:
        state['last_known_credentials'] = last_known
    else:
        state.pop('last_known_credentials', None)


def carry_process_state(previous, credentials, execution):
    state = {}
    for field in STABLE_STATE_FIELDS + MEASUREMENT_FIELDS:
        if field in previous:
            state[field] = previous[field]
    set_credentials(state, previous, credentials)
    executable.set_observation(state, previous, execution)
    return state


def optional_coverage(current, observed, carried, coverage):
    partial_metadata = unknown_parent = unverified_executable = 0
    for key, state in current.items():
        entry = observed.get(state['pid'])
        has_gap = key in carried
        if not has_gap and (entry is None or entry[0] != key):
            continue
        if state['parent_identity_status'] == 'UNKNOWN':
            unknown_parent += 1
            has_gap = True
        if state['executable_identity_status'] != 'VERIFIED':
            unverified_executable += 1
            has_gap = True
        for field in CREDENTIAL_FIELDS:
            if state[field] is None:
                has_gap = True
                break
        if has_gap:
            partial_metadata += 1
    coverage.update(partial_metadata_count=partial_metadata, unknown_parent_count=unknown_parent,
                    unverified_executable_count=unverified_executable)


def capture_measurements(current, observed, carried, measurements, deadline=None):
    for key, _, process in observed.values():
        if deadline is not None and time.monotonic() >= deadline:
            raise ObservationError('OBSERVATION_TIMEOUT', 'Process observation time budget exceeded.')
        state = current[key]
        if state['cpu_percent'] is None:
            # CPU sampling already checked identity for measured values. RSS
            # must also belong to this process when CPU is unavailable.
            try:
                if not process.is_running():
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        measurements[key] = state
    for key in carried:
        # A verified instance can carry old state for change tracking, but
        # its previous status and resource readings cannot become samples.
        state = current[key].copy()
        state.update(status=None, cpu_percent=None, memory_mb=None)
        measurements[key] = state


def get_processes(previous=None, *, boot_id, coverage=None, measurements=None):
    previous = previous or {}
    current = {}
    cpu_processes = {}
    observed = {}
    carried = set()
    deadline = time.monotonic() + collection_seconds()
    limit = inventory_limit('processes')
    # Keep denied or racing observations for still-visible PIDs. Failure to read
    # process metadata is not evidence that the process exited.
    visible = set(psutil.pids())
    if coverage is not None:
        coverage['visible_pid_count'] = len(visible)
    if len(visible) > limit:
        raise ResourceLimitError()
    if not visible:
        raise SnapshotError('Empty process inventory.')
    previous_pids = {}
    for key, state in previous.items():
        previous_pids.setdefault(state['pid'], {})[key] = state
    identified_pids = set()
    psutil.process_iter.cache_clear()
    for process in psutil.process_iter(FIELDS, ad_value=None):
        if time.monotonic() > deadline:
            raise ObservationError('OBSERVATION_TIMEOUT', 'Process observation time budget exceeded.')
        if process.pid not in visible:
            continue
        try:
            info = process.info
            pid, created = info['pid'], info['create_time']
            if type(created) not in (int, float) or not math.isfinite(created) or created < 0:
                continue
            key = process_key(boot_id, pid, created)
            # psutil's cached creation time and newly read fields can span
            # PID reuse. Treat the entire observation as uncertain.
            if pid != process.pid or not process.is_running():
                continue
            old = previous.get(key, {})
            if not info['name'] or info['status'] is None:
                if old:
                    execution = executable.observe(process, info.get('exe'))
                    current[key] = carry_process_state(old, observe_credentials(process, info), execution)
                    # Verified membership still allows the existing metadata fallback.
                    if process.is_running():
                        carried.add(key)
                identified_pids.add(pid)
                continue
            memory = info['memory_info']
            state = {
                'pid': pid, 'process_name': info['name'],
                'username': info['username'] if info['username'] is not None else old.get('username'),
                'cpu_percent': None, 'memory_percent': info['memory_percent'],
                'memory_mb': round(memory.rss / 1024 / 1024, 2) if memory else None,
                'status': info['status'],
                'start_time': datetime.fromtimestamp(created, timezone.utc).isoformat(),
                'ppid': info.get('ppid'),
            }
            set_credentials(state, old, observe_credentials(process, info))
            executable.set_observation(state, old, executable.observe(process, info.get('exe')))
            if not process.is_running():
                continue
            current[key] = state
            cpu_processes[key] = process
            observed[pid] = (key, created, process)
            identified_pids.add(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    # An iterator can omit a process that was visible at the start of the scan.
    for pid in visible - identified_pids:
        for key, state in previous_pids.get(pid, {}).items():
            current[key] = carry_process_state(state, {}, executable.unverified())
    if coverage is not None:
        observed_count = len(observed) + len(carried)
        coverage.update(observed_count=observed_count, identified_process_count=len(identified_pids),
                        unverified_identity_count=len(visible - identified_pids),
                        incomplete_process_count=len(visible) - observed_count)
    if not current:
        raise ObservationError('INCOMPLETE_OBSERVATION', 'No process metadata could be observed.')
    sample_cpu(cpu_processes, current, deadline)
    set_parent_observations(current, previous, observed, deadline)
    if coverage is not None:
        optional_coverage(current, observed, carried, coverage)
    if measurements is not None:
        capture_measurements(current, observed, carried, measurements, deadline)
    return current


def process_changed(before, after):
    for field in ('process_name', 'username', 'status'):
        if before.get(field) != after.get(field):
            return True
    if executable.changed(before, after):
        return True
    for field in CREDENTIAL_FIELDS:
        old_value = last_known_credential(before, field)
        new_value = after.get(field)
        if old_value is not None and new_value is not None and old_value != new_value:
            return True
    old_ppid, old_key = last_known_parent(before)
    ppid = after.get('ppid')
    if old_ppid is None or ppid is None:
        return False
    if ppid != old_ppid:
        return True
    parent_key = after.get('parent_process_key')
    return old_key is not None and parent_key is not None and old_key != parent_key


def get_events(current, previous):
    events = []
    for key in sorted(current.keys() | previous.keys()):
        before, after = previous.get(key), current.get(key)
        if before is None:
            event = 'STARTED'
        elif after is None:
            event = 'STOPPED'
        elif process_changed(before, after):
            event = 'CHANGED'
        else:
            continue
        events.append((key, event, before, after))
    return events
