from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from database.identity import EventIdentity
from metrics.measurement_window import window_bounds
from metrics.processes import windows
from metrics.snapshot import SnapshotError

START = datetime(2026, 11, 17, 10)


@pytest.mark.parametrize(('observed_at', 'start'), [
    (START, START),
    (START + timedelta(minutes=4, seconds=59, microseconds=999999), START),
    (START + timedelta(minutes=5), START + timedelta(minutes=5)),
    (datetime(2026, 11, 17, 12, 2, tzinfo=timezone(timedelta(hours=2))), START),
])
def test_window_is_aligned_in_utc(observed_at, start):
    assert window_bounds(observed_at) == (start, start + timedelta(minutes=5))


def program(path, *, file_id=None, **state):
    state.update(executable_path=path, executable_identity_status='PATH_ONLY')
    if file_id is not None:
        state.update(executable_identity_status='VERIFIED', executable_device=1,
                     executable_inode=file_id, executable_mtime_ns=10)
    return state


def test_machine_aggregates_skip_missing_resources_and_keep_zero_measurements():
    metrics, executables, pairs = {}, {}, {}
    first = {
        'one': {'status': 'running', 'uid': 1000, 'euid': 0, 'cpu_percent': 155.5, 'memory_mb': 42.5},
        'two': {'status': 'sleeping', 'uid': 1000, 'cpu_percent': 0, 'memory_mb': 7.5},
        'three': {'status': 'zombie', 'uid': 0, 'euid': 5},
    }
    second = {'four': {'cpu_percent': None, 'memory_mb': None, 'euid': 0}}
    third = {'five': {'cpu_percent': 44.5, 'memory_mb': 10}, 'six': {'memory_mb': 0}}
    windows.add_sample(metrics, executables, pairs, START, first, None, 4)
    windows.add_sample(metrics, executables, pairs, START + timedelta(minutes=1), second, first, 1)
    windows.add_sample(metrics, executables, pairs, START + timedelta(minutes=3), third, second, 2)
    assert metrics['process_count'] == {'sum': 6, 'min': 1, 'max': 3, 'count': 3}
    assert metrics['process_count']['sum'] / metrics['process_count']['count'] == 2
    assert metrics['inventory_process_count']['sum'] == 7
    assert metrics['unverified_process_count']['sum'] == 1
    assert metrics['cpu_percent_sum'] == {'sum': 200, 'min': 44.5, 'max': 155.5, 'count': 2}
    assert metrics['memory_rss_mb_sum'] == {'sum': 60, 'min': 10, 'max': 50, 'count': 2}
    assert metrics['measured_cpu_process_count']['sum'] == 3
    assert metrics['measured_memory_process_count']['sum'] == 4
    assert metrics['root_euid_count'] == {'sum': 2, 'min': 0, 'max': 1, 'count': 3}
    assert metrics['non_root_euid_count']['sum'] == 1
    assert metrics['unknown_euid_count']['sum'] == 3
    assert metrics['distinct_uid_count']['max'] == 2
    assert metrics['running_count']['sum'] == metrics['sleeping_count']['sum'] == metrics['zombie_count']['sum'] == 1
    missing = {}
    windows.add_sample(missing, {}, {}, START, second, first, 1)
    assert 'cpu_percent_sum' not in missing and 'memory_rss_mb_sum' not in missing


def test_program_and_pair_occurrences_use_fresh_identity_and_observed_membership():
    metrics, executables, pairs = {}, {}, {}
    first = {
        'parent': program('/bin/parent', file_id=1, parent_identity_status='NO_PARENT'),
        'child': program('/bin/child', file_id=2, parent_identity_status='VERIFIED', parent_process_key='parent'),
        'unknown': program('/bin/child', parent_identity_status='UNKNOWN', parent_process_key='parent'),
    }
    second = first.copy()
    second['another'] = first['child']
    second['uncaptured'] = program('/bin/child', file_id=2, parent_identity_status='VERIFIED',
                                   parent_process_key='missing')
    last = START + timedelta(minutes=1)
    windows.add_sample(metrics, executables, pairs, START, first, None, len(first))
    windows.add_sample(metrics, executables, pairs, last, second, first, len(second))
    assert len(executables) == 3
    file_id = 'file:1:2:10'
    assert executables[file_id] == {
        'path': '/bin/child', 'snapshot_count': 2, 'instance_observation_count': 4, 'max_concurrent_instances': 3,
        'first_observed_at': '2026-11-17T10:00:00.000000Z', 'last_observed_at': '2026-11-17T10:01:00.000000Z',
        'new_since_previous_snapshot_count': 2,
    }
    path_id, _ = windows.executable_identity(first['unknown'])
    assert path_id.startswith('path:') and executables[path_id]['snapshot_count'] == 2
    assert executables[path_id]['new_since_previous_snapshot_count'] == 0
    relation, = pairs.values()
    assert relation['snapshot_count'] == 2
    assert relation['instance_observation_count'] == 3
    assert metrics['verified_parent_count']['sum'] == 3
    assert metrics['no_parent_count']['sum'] == 2
    assert metrics['unknown_parent_count']['sum'] == 3


def test_detail_caps_are_independent_and_omissions_do_not_change_totals(monkeypatch):
    monkeypatch.setattr(windows, 'DETAIL_LIMIT', 2)
    states = {
        'one': program('/one', parent_identity_status='VERIFIED', parent_process_key='two'),
        'two': program('/two', parent_identity_status='VERIFIED', parent_process_key='one'),
        'three': program('/three', parent_identity_status='VERIFIED', parent_process_key='one'),
        'four': program('/two', parent_identity_status='VERIFIED', parent_process_key='two'),
    }
    metrics, executables, pairs = {}, {}, {}
    windows.add_sample(metrics, executables, pairs, START, states, None, len(states))
    windows.add_sample(metrics, executables, pairs, START + timedelta(minutes=1), states, states, len(states))
    assert len(executables) == len(pairs) == 2
    assert metrics['executable_identified_count']['sum'] == 8
    assert metrics['executable_detail_omitted_count']['sum'] == 2
    assert metrics['pair_identified_count']['sum'] == 8
    assert metrics['pair_detail_omitted_count']['sum'] == 4
    total = 0
    for record in pairs.values():
        total += record['instance_observation_count']
    assert total == 4


def test_replayed_or_older_measurement_cannot_update_window():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (START, START, 1, '{}', '{}', '{}')
    identity = EventIdentity(1, 2, 3)
    assert not windows.save_window(connection, identity, START, {}, None, 0)
    cursor.execute.assert_called_once()
    cursor.reset_mock()
    with pytest.raises(SnapshotError, match='predates'):
        windows.save_window(connection, identity, START - timedelta(seconds=1), {}, None, 0)
    cursor.execute.assert_called_once()
