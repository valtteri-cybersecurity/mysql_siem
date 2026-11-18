from types import SimpleNamespace
from unittest.mock import MagicMock, call

import psutil
import pytest

from metrics.processes import get
from metrics.snapshot import SnapshotError, plan_state_delta

BOOT_ID = '5a9a2c37-3d94-455e-97cf-c20d4d8b1040'
OTHER_BOOT_ID = '5b9a2c37-3d94-455e-97cf-c20d4d8b1040'
KEY = get.process_key(BOOT_ID, 12, 1000.25)


def process(pid=12, **changes):
    info = {'pid': pid, 'name': 'worker', 'username': 'user', 'cpu_percent': 0, 'memory_percent': 1,
                'memory_info': SimpleNamespace(rss=1048576), 'status': 'running', 'exe': '/bin/worker', 'create_time': 1000.25}
    info['ppid'] = None
    info.update(changes)
    return SimpleNamespace(pid=pid, info=info, cpu_percent=MagicMock(return_value=0.0),
                           is_running=MagicMock(return_value=True), ppid=MagicMock(return_value=info['ppid']),
                           status=MagicMock(return_value=info['status']))


def collect(monkeypatch, processes, previous=None, visible=None, *, boot_id=BOOT_ID, coverage=None):
    iterator = MagicMock(return_value=processes)
    monkeypatch.setattr(get.psutil, 'process_iter', iterator)
    monkeypatch.setattr(get.psutil, 'pids', lambda: visible or [p.pid for p in processes])
    monkeypatch.setattr(get.time, 'sleep', MagicMock())
    monkeypatch.setattr(get.executable, 'read_executable', MagicMock(side_effect=FileNotFoundError))
    return get.get_processes(previous, boot_id=boot_id, coverage=coverage)


def test_boot_id_is_normalized(tmp_path):
    path = tmp_path / 'boot_id'
    path.write_text(BOOT_ID.upper() + '\n', encoding='ascii')
    assert get.read_boot_id(path) == BOOT_ID


@pytest.mark.parametrize('data', [b'', b'not-a-uuid\n', b'\xff', b'0' * 100,
                                 b'00000000-0000-0000-0000-000000000000\n', BOOT_ID.encode() + b'\n\n'])
def test_invalid_boot_id_is_rejected(tmp_path, data):
    path = tmp_path / 'boot_id'
    path.write_bytes(data)
    with pytest.raises(get.BootIdentityError):
        get.read_boot_id(path)


def test_missing_boot_id_is_rejected(tmp_path):
    with pytest.raises(get.BootIdentityError, match='Cannot read'):
        get.read_boot_id(tmp_path / 'missing')


@pytest.mark.parametrize('failure,code', [
    (FileNotFoundError(), 'SOURCE_UNAVAILABLE'), (PermissionError(), 'PERMISSION_DENIED'),
])
def test_boot_id_read_failure_carries_a_bounded_health_code(failure, code):
    path = MagicMock()
    path.open.side_effect = failure
    with pytest.raises(get.BootIdentityError) as error:
        get.read_boot_id(path)
    assert error.value.code == code


def test_identity_and_timestamp_are_stable_utc(monkeypatch):
    current = collect(monkeypatch, [process()])
    assert list(current) == [KEY]
    assert len(KEY) == 32 and KEY.isascii()
    assert current[KEY]['start_time'].endswith('+00:00')
    renamed = collect(monkeypatch, [process(name='renamed')], current)
    assert list(renamed) == [KEY]
    assert get.get_events(renamed, current)[0][1] == 'CHANGED'
    assert get.get_events(current, current) == []


def test_pid_reuse_is_a_new_process(monkeypatch):
    old = collect(monkeypatch, [process()])
    new = collect(monkeypatch, [process(create_time=2000.0)], old)
    assert {event[1] for event in get.get_events(new, old)} == {'STARTED', 'STOPPED'}
    assert get.process_key(BOOT_ID, 12, 1000.250001) != KEY


def test_same_pid_and_creation_time_on_another_boot_gets_a_new_key(monkeypatch):
    current = collect(monkeypatch, [process()], boot_id=OTHER_BOOT_ID)
    assert current.keys() == {get.process_key(OTHER_BOOT_ID, 12, 1000.25)}
    assert KEY not in current


def test_parent_is_verified_after_a_fresh_child_ppid_read(monkeypatch):
    child = process(ppid=7)
    parent = process(pid=7, create_time=900.0, ppid=0)
    parent_key = get.process_key(BOOT_ID, 7, 900.0)
    checks = MagicMock()
    checks.attach_mock(child.ppid, 'child_ppid')
    checks.attach_mock(child.is_running, 'child_running')
    checks.attach_mock(parent.status, 'parent_status')
    current = collect(monkeypatch, [child, parent])
    assert current[KEY]['ppid'] == 7
    assert current[KEY]['parent_process_key'] == parent_key
    assert current[KEY]['parent_identity_status'] == 'VERIFIED'
    assert current[parent_key]['ppid'] == 0
    assert current[parent_key]['parent_process_key'] is None
    assert current[parent_key]['parent_identity_status'] == 'NO_PARENT'
    assert checks.mock_calls[-3:] == [call.child_ppid(), call.parent_status(), call.child_running()]
    assert collect(monkeypatch, [parent, child], current) == current


@pytest.mark.parametrize('ppid', [None, -1, True, '7', 12, 7.0])
def test_missing_invalid_or_self_referential_ppid_is_unknown(monkeypatch, ppid):
    child = process(ppid=ppid)
    current = collect(monkeypatch, [child])
    assert current[KEY]['ppid'] is None
    assert current[KEY]['parent_process_key'] is None
    assert current[KEY]['parent_identity_status'] == 'UNKNOWN'
    child.ppid.assert_not_called()


@pytest.mark.parametrize('failure', ['missing', 'newer', 'invalid-time', 'reused', 'gone', 'denied', 'zombie'])
def test_unverified_parent_retains_only_current_ppid(monkeypatch, failure):
    child = process(ppid=7)
    parent = process(pid=7, create_time=900.0)
    processes = [child, parent]
    if failure == 'missing':
        processes = [child]
    elif failure == 'newer':
        parent.info['create_time'] = 1001.0
    elif failure == 'invalid-time':
        parent.info['create_time'] = float('nan')
    elif failure == 'reused':
        parent.is_running.return_value = False
    elif failure == 'gone':
        parent.status.side_effect = psutil.NoSuchProcess(7)
    elif failure == 'denied':
        parent.status.side_effect = psutil.AccessDenied(7)
    elif failure == 'zombie':
        parent.status.return_value = psutil.STATUS_ZOMBIE

    current = collect(monkeypatch, processes)
    assert current[KEY]['ppid'] == 7
    assert current[KEY]['parent_process_key'] is None
    assert current[KEY]['parent_identity_status'] == 'UNKNOWN'
    assert 'last_known_parent' not in current[KEY]


@pytest.mark.parametrize('failure', ['denied', 'gone', 'reused', 'reparented-during-scan', 'unseen', 'partial'])
def test_child_without_a_fresh_parent_observation_keeps_separate_evidence(monkeypatch, failure):
    parent = process(pid=7, create_time=900.0)
    old = collect(monkeypatch, [parent, process(ppid=7)])
    parent_key = get.process_key(BOOT_ID, 7, 900.0)
    original_child = dict(old[KEY])
    child = process(ppid=7)
    processes = [child, parent]
    if failure == 'denied':
        child.ppid.side_effect = psutil.AccessDenied(12)
    elif failure == 'gone':
        child.ppid.side_effect = psutil.NoSuchProcess(12)
    elif failure == 'reused':
        child.is_running.return_value = False
    elif failure == 'reparented-during-scan':
        child.ppid.return_value = 8
    elif failure == 'unseen':
        processes = [parent]
    elif failure == 'partial':
        child.info['name'] = None
    current = collect(monkeypatch, processes, old, visible=[7, 12])
    assert current[KEY]['ppid'] is None
    assert current[KEY]['parent_process_key'] is None
    assert current[KEY]['parent_identity_status'] == 'UNKNOWN'
    assert current[KEY]['last_known_parent'] == {'ppid': 7, 'parent_process_key': parent_key}
    assert old[KEY] == original_child
    assert get.get_events(current, old) == []
    assert collect(monkeypatch, processes, current, visible=[7, 12]) == current

    stable, _ = get.split_process_snapshot(current)
    stable[KEY]['last_known_parent']['ppid'] = 99
    assert current[KEY]['last_known_parent']['ppid'] == 7


def test_parent_from_carried_inventory_row_cannot_be_verified(monkeypatch):
    parent = process(pid=7, create_time=900.0)
    old = collect(monkeypatch, [parent, process(ppid=7)])
    current = collect(monkeypatch, [process(ppid=7)], old, visible=[7, 12])
    parent_key = get.process_key(BOOT_ID, 7, 900.0)
    assert parent_key in current
    assert current[KEY]['parent_process_key'] is None
    assert current[KEY]['parent_identity_status'] == 'UNKNOWN'
    assert current[KEY]['last_known_parent'] == {'ppid': 7, 'parent_process_key': parent_key}
    assert get.get_events(current, old) == []


def test_child_that_exits_during_parent_verification_remains_unknown(monkeypatch):
    parent = process(pid=7, create_time=900.0)
    old = collect(monkeypatch, [parent, process(ppid=7)])
    child = process(ppid=7)

    def parent_status():
        child.is_running.return_value = False
        return psutil.STATUS_RUNNING

    parent.status.side_effect = parent_status
    current = collect(monkeypatch, [parent, child], old)
    assert current[KEY]['ppid'] is None
    assert current[KEY]['parent_process_key'] is None
    assert current[KEY]['parent_identity_status'] == 'UNKNOWN'
    assert current[KEY]['last_known_parent']['parent_process_key'] == old[KEY]['parent_process_key']
    assert get.get_events(current, old) == []


def test_reparenting_changes_state_without_changing_the_child_identity(monkeypatch):
    first_parent = process(pid=7, create_time=900.0)
    next_parent = process(pid=8, create_time=950.0)
    old = collect(monkeypatch, [first_parent, next_parent, process(ppid=7)])
    unavailable = collect(monkeypatch, [first_parent, next_parent, process()], old)
    recovered = collect(monkeypatch, [first_parent, next_parent, process(ppid=7)], unavailable)
    assert recovered == old
    assert get.get_events(recovered, unavailable) == []

    reparented = collect(monkeypatch, [first_parent, next_parent, process(ppid=8)], unavailable)
    assert reparented.keys() == old.keys()
    assert reparented[KEY]['parent_process_key'] == get.process_key(BOOT_ID, 8, 950.0)
    assert get.get_events(reparented, unavailable) == [(KEY, 'CHANGED', unavailable[KEY], reparented[KEY])]
    assert plan_state_delta(old, reparented)['changed'] == {KEY: (old[KEY], reparented[KEY])}
    added = get.get_events(reparented, {})
    assert (KEY, 'STARTED', None, reparented[KEY]) in added


def test_changed_ppid_with_unknown_parent_identity_is_meaningful(monkeypatch):
    old = collect(monkeypatch, [process(ppid=7)])
    unavailable = collect(monkeypatch, [process()], old)
    assert unavailable[KEY]['last_known_parent'] == {'ppid': 7, 'parent_process_key': None}
    assert get.get_events(unavailable, old) == []
    current = collect(monkeypatch, [process(ppid=8)], unavailable)
    assert current[KEY]['parent_identity_status'] == 'UNKNOWN'
    assert get.get_events(current, unavailable) == [(KEY, 'CHANGED', unavailable[KEY], current[KEY])]


def test_changed_verified_identity_at_same_ppid_uses_last_known_parent():
    old_parent = get.process_key(BOOT_ID, 7, 900.0)
    new_parent = get.process_key(BOOT_ID, 7, 950.0)
    unavailable = {'ppid': 7, 'parent_process_key': None, 'parent_identity_status': 'UNKNOWN',
                   'last_known_parent': {'ppid': 7, 'parent_process_key': old_parent}}
    current = {'ppid': 7, 'parent_process_key': new_parent, 'parent_identity_status': 'VERIFIED'}
    assert get.get_events({KEY: current}, {KEY: unavailable}) == [(KEY, 'CHANGED', unavailable, current)]


def test_enriching_a_legacy_process_row_does_not_create_an_event(monkeypatch):
    current = collect(monkeypatch, [process(ppid=7), process(pid=7, create_time=900.0)])
    legacy = {}
    for key, state in current.items():
        legacy[key] = state.copy()
        for field in ('ppid', 'parent_process_key', 'parent_identity_status'):
            del legacy[key][field]
    assert get.get_events(current, legacy) == []


def test_parent_key_uses_only_the_current_boot(monkeypatch):
    parent = process(pid=7, create_time=900.0)
    old = collect(monkeypatch, [parent, process(ppid=7)])
    current = collect(monkeypatch, [parent, process(ppid=7)], boot_id=OTHER_BOOT_ID)
    child_key = get.process_key(OTHER_BOOT_ID, 12, 1000.25)
    assert current[child_key]['parent_process_key'] == get.process_key(OTHER_BOOT_ID, 7, 900.0)
    assert current[child_key]['parent_process_key'] not in old


def test_denied_or_racing_process_does_not_stop(monkeypatch):
    old = collect(monkeypatch, [process()])
    partial = collect(monkeypatch, [process(create_time=None)], old)
    missing = collect(monkeypatch, [], old, visible=[12])
    assert partial == missing
    assert partial[KEY]['executable_identity_status'] == 'UNKNOWN'
    assert partial[KEY]['last_known_executable']['executable_path'] == old[KEY]['executable_path']
    assert get.get_events(partial, old) == []
    assert collect(monkeypatch, [process(pid=99)], old, visible=[99]).keys() != old.keys()


def test_coverage_counts_unique_visible_pids_and_existing_metadata_gaps(monkeypatch):
    coverage = {}
    processes = [process(), process(pid=13, name=None)]
    assert len(collect(monkeypatch, processes, visible=[12, 13, 14, 14], coverage=coverage)) == 1
    assert coverage == {'visible_pid_count': 3, 'observed_count': 1, 'identified_process_count': 2,
                        'unverified_identity_count': 1, 'incomplete_process_count': 2,
                        'partial_metadata_count': 1, 'unknown_parent_count': 1, 'unverified_executable_count': 1}


def test_known_pid_reuse_does_not_carry_old_process_with_missing_metadata(monkeypatch):
    old = collect(monkeypatch, [process(), process(pid=99)])
    same_process = collect(monkeypatch, [process(name=None), process(pid=99)], old)
    assert same_process == old
    reused = collect(monkeypatch, [process(name=None, create_time=2000.0), process(pid=99)], old)
    assert KEY not in reused
    assert get.get_events(reused, old) == [(KEY, 'STOPPED', old[KEY], None)]


@pytest.mark.parametrize('expected', [(1000, 1000, 100, 100), (0, 0, 0, 0), (1000, 0, 100, 0)])
def test_collects_real_and_effective_credentials(monkeypatch, expected):
    uid, euid, gid, egid = expected
    observed = process(uids=SimpleNamespace(real=uid, effective=euid, saved=999),
                       gids=SimpleNamespace(real=gid, effective=egid, saved=999))
    current = collect(monkeypatch, [observed])
    stable, measurements = get.split_process_snapshot(current)
    assert stable[KEY]['uid'] == uid
    assert stable[KEY]['euid'] == euid
    assert stable[KEY]['gid'] == gid
    assert stable[KEY]['egid'] == egid
    assert 'uids' not in stable[KEY] and 'gids' not in stable[KEY]
    assert measurements[KEY] == {'cpu_percent': 0.0, 'memory_percent': 1, 'memory_mb': 1.0}


@pytest.mark.parametrize('groups,expected', [
    ('uid', {'uid': 1000, 'euid': 0, 'gid': None, 'egid': None}),
    ('gid', {'uid': None, 'euid': None, 'gid': 100, 'egid': 0}),
    ('none', {'uid': None, 'euid': None, 'gid': None, 'egid': None}),
])
def test_missing_credential_groups_remain_unknown_independently(monkeypatch, groups, expected):
    # psutil's ad_value supplies None when an individual attribute is inaccessible.
    uids = gids = None
    if groups == 'uid':
        uids = SimpleNamespace(real=1000, effective=0)
    if groups == 'gid':
        gids = SimpleNamespace(real=100, effective=0)
    current = collect(monkeypatch, [process(uids=uids, gids=gids)])
    assert current[KEY]['username'] == 'user'
    for field, value in expected.items():
        assert current[KEY][field] == value


@pytest.mark.parametrize('invalid', [-1, True, 1.5, '1000', None])
def test_invalid_individual_credentials_do_not_replace_valid_observations(monkeypatch, invalid):
    observed = process(username=None, uids=SimpleNamespace(real=invalid, effective=0),
                       gids=SimpleNamespace(real=100, effective=invalid))
    current = collect(monkeypatch, [observed])
    assert current[KEY]['username'] is None
    assert current[KEY]['uid'] is None
    assert current[KEY]['euid'] == 0
    assert current[KEY]['gid'] == 100
    assert current[KEY]['egid'] is None


@pytest.mark.parametrize('failure', ['gone', 'denied', 'reused', 'unseen', 'partial'])
def test_unverified_process_keeps_credentials_only_as_last_known(monkeypatch, failure):
    uids = SimpleNamespace(real=1000, effective=0)
    old = collect(monkeypatch, [process(uids=uids)])
    new = process(uids=SimpleNamespace(real=2000, effective=2000))
    processes = [new]
    if failure == 'gone':
        new.is_running.side_effect = psutil.NoSuchProcess(12)
    elif failure == 'denied':
        new.is_running.side_effect = psutil.AccessDenied(12)
    elif failure == 'reused':
        new.is_running.return_value = False
    elif failure == 'unseen':
        processes = []
    elif failure == 'partial':
        new.info['name'] = None
        new.info['uids'] = None
    current = collect(monkeypatch, processes, old, visible=[12])
    assert current[KEY]['uid'] is None
    assert current[KEY]['euid'] is None
    assert current[KEY]['last_known_credentials'] == {'uid': 1000, 'euid': 0}
    assert old[KEY]['euid'] == 0
    assert 'last_known_credentials' not in old[KEY]
    assert get.get_events(current, old) == []


def test_partial_process_metadata_can_still_refresh_verified_credentials(monkeypatch):
    initial = process(uids=SimpleNamespace(real=1000, effective=0))
    old = collect(monkeypatch, [initial])
    observed = process(name=None, uids=SimpleNamespace(real=1000, effective=1000))
    current = collect(monkeypatch, [observed], old)
    assert current[KEY]['process_name'] == old[KEY]['process_name']
    assert current[KEY]['euid'] == 1000
    assert get.get_events(current, old) == [(KEY, 'CHANGED', old[KEY], current[KEY])]


@pytest.mark.parametrize('field', ['uid', 'euid', 'gid', 'egid'])
def test_credential_changes_survive_availability_gaps_with_a_stable_process_key(monkeypatch, field):
    uids = SimpleNamespace(real=1000, effective=0)
    gids = SimpleNamespace(real=100, effective=0)
    old = collect(monkeypatch, [process(uids=uids, gids=gids)])
    unavailable = collect(monkeypatch, [process()], old)
    assert unavailable[KEY]['last_known_credentials'] == {'uid': 1000, 'euid': 0, 'gid': 100, 'egid': 0}
    assert get.get_events(unavailable, old) == []
    assert collect(monkeypatch, [process()], unavailable) == unavailable
    assert get.get_events(collect(monkeypatch, [process(uids=uids, gids=gids)], unavailable), unavailable) == []

    if field == 'uid':
        uids.real = 2000
    elif field == 'euid':
        uids.effective = 2000
    elif field == 'gid':
        gids.real = 2000
    else:
        gids.effective = 2000
    new = collect(monkeypatch, [process(uids=uids, gids=gids)], unavailable)
    assert new.keys() == old.keys()
    assert new[KEY][field] == 2000
    assert 'last_known_credentials' not in new[KEY]
    assert get.get_events(new, unavailable) == [(KEY, 'CHANGED', unavailable[KEY], new[KEY])]
    assert get.get_events(new, old) == [(KEY, 'CHANGED', old[KEY], new[KEY])]

    stable, _ = get.split_process_snapshot(unavailable)
    stable[KEY]['last_known_credentials']['uid'] = 99
    assert unavailable[KEY]['last_known_credentials']['uid'] == 1000


def test_first_credential_observation_and_username_are_independent(monkeypatch):
    legacy = collect(monkeypatch, [process()])
    for field in get.CREDENTIAL_FIELDS:
        del legacy[KEY][field]
    uids = SimpleNamespace(real=1000, effective=0)
    gids = SimpleNamespace(real=100, effective=0)
    first = collect(monkeypatch, [process(username=None, uids=uids, gids=gids)], legacy)
    assert first[KEY]['username'] == 'user'
    assert first[KEY]['euid'] == 0
    assert get.get_events(first, legacy) == []
    changed_name = collect(monkeypatch, [process(username='renamed', uids=uids, gids=gids)], first)
    assert changed_name[KEY]['euid'] == first[KEY]['euid']
    assert get.get_events(changed_name, first) == [(KEY, 'CHANGED', first[KEY], changed_name[KEY])]


def test_first_cpu_sample_is_ignored(monkeypatch):
    observed = process()
    observed.cpu_percent.side_effect = [0.0, 75.5]
    current = collect(monkeypatch, [observed])
    assert current[KEY]['cpu_percent'] == 75.5
    assert observed.cpu_percent.call_count == 2
    get.time.sleep.assert_called_once_with(0.1)


def test_all_processes_share_one_sampling_wait(monkeypatch):
    first = process(pid=12)
    second = process(pid=13)
    first.cpu_percent.side_effect = [0.0, 100.0]
    second.cpu_percent.side_effect = [0.0, 0.0]
    current = collect(monkeypatch, [first, second])
    assert current[KEY]['cpu_percent'] == 100.0
    assert current[get.process_key(BOOT_ID, 13, 1000.25)]['cpu_percent'] == 0.0
    get.time.sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize('failure', ['first-denied', 'second-denied', 'gone', 'reused'])
def test_unavailable_cpu_measurement_is_unknown(monkeypatch, failure):
    observed = process()
    if failure == 'first-denied':
        observed.cpu_percent.side_effect = psutil.AccessDenied(12)
    elif failure == 'second-denied':
        observed.cpu_percent.side_effect = [0.0, psutil.AccessDenied(12)]
    elif failure == 'gone':
        observed.cpu_percent.side_effect = [0.0, psutil.NoSuchProcess(12)]
    else:
        def reused_during_cpu(interval):
            if observed.cpu_percent.call_count == 2:
                observed.is_running.return_value = False
                return 99.0
            return 0.0

        observed.cpu_percent.side_effect = reused_during_cpu
    current = collect(monkeypatch, [observed])
    assert current[KEY]['cpu_percent'] is None
    assert current[KEY]['process_name'] == 'worker'


def test_split_process_snapshot_preserves_all_collected_fields(monkeypatch):
    current = collect(monkeypatch, [process()])
    key = KEY
    before = dict(current[key])

    stable_state, measurements = get.split_process_snapshot(current)

    assert stable_state == {key: {'pid': 12, 'process_name': 'worker', 'username': 'user',
                                  'status': 'running', 'executable_path': '/bin/worker',
                                  'start_time': '1970-01-01T00:16:40.250000+00:00', 'ppid': None,
                                  'parent_process_key': None, 'parent_identity_status': 'UNKNOWN',
                                  'uid': None, 'euid': None, 'gid': None, 'egid': None,
                                  'executable_identity_status': 'PATH_ONLY',
                                  **dict.fromkeys(get.executable.METADATA_FIELDS)}}
    assert measurements == {key: {'cpu_percent': 0.0, 'memory_percent': 1, 'memory_mb': 1.0}}
    assert stable_state[key] | measurements[key] == before
    assert current == {key: before}
    assert get.split_process_snapshot(current) == (stable_state, measurements)

    stable_state[key]['process_name'] = 'changed in result'
    measurements[key]['cpu_percent'] = 20.0
    assert current == {key: before}


def test_process_measurement_changes_do_not_change_stable_state(monkeypatch):
    key = KEY
    previous = collect(monkeypatch, [process()])
    observed = process(memory_percent=20, memory_info=SimpleNamespace(rss=2 * 1048576))
    observed.cpu_percent.return_value = 55.0
    current = collect(monkeypatch, [observed])
    before_state, before_measurements = get.split_process_snapshot(previous)
    after_state, after_measurements = get.split_process_snapshot(current)

    assert plan_state_delta(before_state, after_state)['unchanged'] == before_state
    assert plan_state_delta(before_measurements, after_measurements)['changed'] == {
        key: (before_measurements[key], after_measurements[key]),
    }
    assert get.get_events(current, previous) == []


@pytest.mark.parametrize('observed_changes', [{'name': 'renamed'}, {'exe': '/bin/replacement'}, {'status': 'sleeping'}])
def test_process_state_changes_remain_visible_in_stable_state(monkeypatch, observed_changes):
    key = KEY
    previous = collect(monkeypatch, [process()])
    current = collect(monkeypatch, [process(**observed_changes)])
    before_state, before_measurements = get.split_process_snapshot(previous)
    after_state, after_measurements = get.split_process_snapshot(current)

    assert plan_state_delta(before_state, after_state)['changed'] == {key: (before_state[key], after_state[key])}
    assert before_measurements == after_measurements
    assert get.get_events(current, previous) == [(key, 'CHANGED', previous[key], current[key])]


def test_split_process_snapshot_preserves_pid_reuse_identity_and_unknown_measurements():
    old_key = '12:1000.250000'
    new_key = '12:2000.000000'
    previous = {old_key: {'pid': 12, 'cpu_percent': None, 'memory_percent': None, 'memory_mb': None}}
    current = {new_key: {'pid': 12, 'cpu_percent': 0.0}}
    before_state, before_measurements = get.split_process_snapshot(previous)
    after_state, after_measurements = get.split_process_snapshot(current)

    assert before_measurements == {old_key: {'cpu_percent': None, 'memory_percent': None, 'memory_mb': None}}
    assert after_measurements == {new_key: {'cpu_percent': 0.0}}
    delta = plan_state_delta(before_state, after_state)
    assert delta['removed'] == {old_key: {'pid': 12}}
    assert delta['added'] == {new_key: {'pid': 12}}


def test_split_empty_process_snapshot():
    assert get.split_process_snapshot({}) == ({}, {})


@pytest.mark.parametrize('invalid', [None, {'12:1000.250000': []}, {12: {'pid': 12}}])
def test_split_process_snapshot_rejects_invalid_structure(invalid):
    with pytest.raises(SnapshotError, match='mapping'):
        get.split_process_snapshot(invalid)


def test_split_process_snapshot_rejects_unknown_fields_without_discarding_data():
    key = '12:1000.250000'
    current = {key: {'pid': 12, 'cpu_percent': None, 'unexpected': 'keep'}}
    with pytest.raises(SnapshotError, match='unknown field'):
        get.split_process_snapshot(current)
    assert current == {key: {'pid': 12, 'cpu_percent': None, 'unexpected': 'keep'}}


def test_measurements_exclude_cached_resources_and_unverified_instances():
    current = {
        'fresh': {'cpu_percent': 120, 'memory_mb': 42, 'status': 'running'},
        'rss_only': {'cpu_percent': None, 'memory_mb': 25},
        'gone': {'cpu_percent': None, 'memory_mb': 13},
        'carried': {'cpu_percent': 80, 'memory_mb': 12, 'status': 'running', 'euid': 0},
    }
    observed = {
        1: ('fresh', 1, MagicMock()),
        2: ('rss_only', 1, MagicMock(is_running=MagicMock(return_value=True))),
        3: ('gone', 1, MagicMock(is_running=MagicMock(return_value=False))),
    }
    measurements = {}
    get.capture_measurements(current, observed, {'carried'}, measurements)
    assert measurements == {
        'fresh': current['fresh'], 'rss_only': current['rss_only'],
        'carried': {'cpu_percent': None, 'memory_mb': None, 'status': None, 'euid': 0},
    }
    assert current['carried']['cpu_percent'] == 80


def test_carried_process_only_copies_known_metadata():
    previous = {'pid': 12, 'cpu_percent': 35, 'environ': {'PRIVATE': 'marker'}, 'cmdline': ['marker']}
    carried = get.carry_process_state(previous, {}, get.executable.unverified())
    assert carried['pid'] == 12 and carried['cpu_percent'] == 35
    assert 'cmdline' not in carried and 'environ' not in carried
    assert 'cmdline' not in get.FIELDS and 'environ' not in get.FIELDS


def test_reused_pid_cannot_publish_metadata_under_the_old_process_key(monkeypatch):
    old = collect(monkeypatch, [process()])
    raced = process(name='new-owner')
    raced.is_running.return_value = False
    coverage = {}
    current = collect(monkeypatch, [raced], old, coverage=coverage)
    assert current[KEY]['process_name'] == old[KEY]['process_name']
    assert get.get_events(current, old) == []
    assert coverage['incomplete_process_count'] == coverage['unverified_identity_count'] == 1
