from types import SimpleNamespace
from unittest.mock import MagicMock

import psutil
import pytest

from metrics.processes import get


def process(pid=12, **changes):
    info = {'pid': pid, 'name': 'worker', 'username': 'user', 'cpu_percent': 0, 'memory_percent': 1,
                'memory_info': SimpleNamespace(rss=1048576), 'status': 'running', 'exe': '/bin/worker', 'create_time': 1000.25}
    info.update(changes)
    return SimpleNamespace(pid=pid, info=info, cpu_percent=MagicMock(return_value=0.0),
                           is_running=MagicMock(return_value=True))


def collect(monkeypatch, processes, previous=None, visible=None):
    iterator = MagicMock(return_value=processes)
    monkeypatch.setattr(get.psutil, 'process_iter', iterator)
    monkeypatch.setattr(get.psutil, 'pids', lambda: visible or [p.pid for p in processes])
    monkeypatch.setattr(get.time, 'sleep', MagicMock())
    return get.get_processes(previous)


def test_identity_and_timestamp_are_stable_utc(monkeypatch):
    current = collect(monkeypatch, [process()])
    assert list(current) == ['12:1000.250000']
    assert current['12:1000.250000']['start_time'].endswith('+00:00')
    renamed = collect(monkeypatch, [process(name='renamed')], current)
    assert get.get_events(renamed, current)[0][1] == 'CHANGED'
    assert get.get_events(current, current) == []


def test_pid_reuse_is_a_new_process(monkeypatch):
    old = collect(monkeypatch, [process()])
    new = collect(monkeypatch, [process(create_time=2000.0)], old)
    assert {event[1] for event in get.get_events(new, old)} == {'STARTED', 'STOPPED'}


def test_denied_or_racing_process_does_not_stop(monkeypatch):
    old = collect(monkeypatch, [process()])
    assert collect(monkeypatch, [process(create_time=None)], old) == old
    assert collect(monkeypatch, [], old, visible=[12]) == old
    assert collect(monkeypatch, [process(pid=99)], old, visible=[99]).keys() != old.keys()


def test_first_cpu_sample_is_ignored(monkeypatch):
    observed = process()
    observed.cpu_percent.side_effect = [0.0, 75.5]
    current = collect(monkeypatch, [observed])
    assert current['12:1000.250000']['cpu_percent'] == 75.5
    assert observed.cpu_percent.call_count == 2
    get.time.sleep.assert_called_once_with(0.1)


def test_all_processes_share_one_sampling_wait(monkeypatch):
    first = process(pid=12)
    second = process(pid=13)
    first.cpu_percent.side_effect = [0.0, 100.0]
    second.cpu_percent.side_effect = [0.0, 0.0]
    current = collect(monkeypatch, [first, second])
    assert current['12:1000.250000']['cpu_percent'] == 100.0
    assert current['13:1000.250000']['cpu_percent'] == 0.0
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
        observed.cpu_percent.side_effect = [0.0, 99.0]
        observed.is_running.return_value = False
    current = collect(monkeypatch, [observed])
    assert current['12:1000.250000']['cpu_percent'] is None
    assert current['12:1000.250000']['process_name'] == 'worker'
