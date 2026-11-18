"""Accumulate process observations inside the existing snapshot transaction."""

import hashlib
import math

from config.snapshot_policy import positive_setting
from metrics.measurement_window import add_metrics, update_window

DETAIL_LIMIT = 64
MAX_PATH_BYTES = 4096
STATUS_COUNTS = {'running': 'running_count', 'sleeping': 'sleeping_count', 'zombie': 'zombie_count'}
COUNT_FIELDS = (
    'process_count', 'inventory_process_count', 'unverified_process_count',
    'running_count', 'sleeping_count', 'zombie_count', 'other_status_count', 'unknown_status_count',
    'root_euid_count', 'non_root_euid_count', 'unknown_euid_count', 'distinct_uid_count',
    'measured_cpu_process_count', 'measured_memory_process_count',
    'executable_identified_count', 'executable_detail_omitted_count',
    'verified_parent_count', 'unknown_parent_count', 'no_parent_count',
    'pair_identified_count', 'pair_detail_omitted_count',
)
RESOURCE_FIELDS = (
    ('cpu_percent', 'cpu_percent_sum', 'measured_cpu_process_count'),
    ('memory_mb', 'memory_rss_mb_sum', 'measured_memory_process_count'),
)


def executable_identity(state):
    path = state.get('executable_path')
    status = state.get('executable_identity_status')
    if status == 'VERIFIED':
        device = state.get('executable_device')
        inode = state.get('executable_inode')
        modified = state.get('executable_mtime_ns')
        if type(device) is not int or type(inode) is not int or type(modified) is not int:
            return None, None
        return f'file:{device}:{inode}:{modified}', path
    if status == 'PATH_ONLY' and path and path.startswith('/'):
        digest = hashlib.sha256(path.encode('utf-8')).hexdigest()
        return f'path:{digest}', path
    return None, None


def count_process(counts, state, uids):
    status = state.get('status')
    if status in STATUS_COUNTS:
        counts[STATUS_COUNTS[status]] += 1
    elif not status or status in ('?', 'unknown'):
        counts['unknown_status_count'] += 1
    else:
        counts['other_status_count'] += 1
    uid = state.get('uid')
    if type(uid) is int and uid >= 0:
        uids.add(uid)
    euid = state.get('euid')
    if type(euid) is not int or euid < 0:
        counts['unknown_euid_count'] += 1
    elif euid == 0:
        counts['root_euid_count'] += 1
    else:
        counts['non_root_euid_count'] += 1
    for field, total, measured in RESOURCE_FIELDS:
        value = state.get(field)
        if type(value) in (int, float) and math.isfinite(value) and value >= 0:
            counts[total] = counts.get(total, 0) + value
            counts[measured] += 1


def count_executables(observations, previous, counts):
    identities = {}
    programs = {}
    for key, state in observations.items():
        identity, path = executable_identity(state)
        if identity is None:
            continue
        identities[key] = identity
        counts['executable_identified_count'] += 1
        group = programs.get(identity)
        if group is None:
            group = {'path': path, 'instances': 0, 'new_since_previous_snapshot_count': 0}
            programs[identity] = group
        group['instances'] += 1
        if previous is not None and key not in previous:
            group['new_since_previous_snapshot_count'] += 1
    return identities, programs


def count_pairs(observations, identities, counts):
    pairs = {}
    for key, state in observations.items():
        status = state.get('parent_identity_status')
        if status == 'NO_PARENT':
            counts['no_parent_count'] += 1
            continue
        parent = state.get('parent_process_key')
        if status != 'VERIFIED' or parent not in observations or parent == key:
            counts['unknown_parent_count'] += 1
            continue
        counts['verified_parent_count'] += 1
        if parent not in identities or key not in identities:
            continue
        pair = identities[parent], identities[key]
        pairs[pair] = pairs.get(pair, 0) + 1
        counts['pair_identified_count'] += 1
    return pairs


def record_occurrence(details, key, count, timestamp, limit):
    record = details.get(key)
    if record is None:
        if len(details) >= limit:
            return None
        record = {'snapshot_count': 0, 'instance_observation_count': 0,
                  'first_observed_at': timestamp, 'max_concurrent_instances': 0}
        details[key] = record
    record['snapshot_count'] += 1
    record['instance_observation_count'] += count
    record['last_observed_at'] = timestamp
    record['max_concurrent_instances'] = max(record['max_concurrent_instances'], count)
    return record


def record_programs(details, programs, counts, timestamp, limit):
    for key, group in programs.items():
        record = record_occurrence(details, key, group['instances'], timestamp, limit)
        if record is None:
            counts['executable_detail_omitted_count'] += group['instances']
            continue
        path = group['path']
        if path and 'path' not in record:
            if len(path.encode('utf-8')) <= MAX_PATH_BYTES:
                record['path'] = path
            else:
                record['path_omitted'] = True
        new_instances = group['new_since_previous_snapshot_count']
        record['new_since_previous_snapshot_count'] = record.get('new_since_previous_snapshot_count', 0) + new_instances


def record_pairs(details, programs, pairs, counts, timestamp, limit):
    for (parent, child), count in pairs.items():
        if parent not in programs or child not in programs:
            counts['pair_detail_omitted_count'] += count
            continue
        key = f'{parent}/{child}'
        if record_occurrence(details, key, count, timestamp, limit) is None:
            counts['pair_detail_omitted_count'] += count


def add_sample(metrics, executables, parent_child, observed_at, observations, previous, inventory_count):
    counts = dict.fromkeys(COUNT_FIELDS, 0)
    counts['process_count'] = len(observations)
    counts['inventory_process_count'] = inventory_count
    counts['unverified_process_count'] = inventory_count - len(observations)
    uids = set()
    for state in observations.values():
        count_process(counts, state, uids)
    counts['distinct_uid_count'] = len(uids)
    identities, programs = count_executables(observations, previous, counts)
    pairs = count_pairs(observations, identities, counts)
    timestamp = observed_at.isoformat(timespec='microseconds') + 'Z'
    limit = positive_setting('SIEM_SNAPSHOT_PROCESS_WINDOW_DETAILS', DETAIL_LIMIT, DETAIL_LIMIT)
    record_programs(executables, programs, counts, timestamp, limit)
    record_pairs(parent_child, executables, pairs, counts, timestamp, limit)
    add_metrics(metrics, counts)


def save_window(connection, identity, observed_at, observations, previous, inventory_count):
    def accumulate(metrics, executables, parent_child):
        add_sample(metrics, executables, parent_child, observed_at, observations, previous, inventory_count)

    return update_window(connection, 'processes', identity, observed_at, accumulate)
