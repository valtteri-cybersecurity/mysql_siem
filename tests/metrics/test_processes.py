from types import SimpleNamespace
from unittest.mock import MagicMock

from metrics.processes import get


def process(pid=12, **changes):
    info = {'pid': pid, 'name': 'worker', 'username': 'user', 'cpu_percent': 0, 'memory_percent': 1,
                'memory_info': SimpleNamespace(rss=1048576), 'status': 'running', 'exe': '/bin/worker', 'create_time': 1000.25}
    info.update(changes)
    return SimpleNamespace(pid=pid, info=info)


def collect(monkeypatch, processes, previous=None, visible=None):
    iterator = MagicMock(return_value=processes)
    monkeypatch.setattr(get.psutil, 'process_iter', iterator)
    monkeypatch.setattr(get.psutil, 'pids', lambda: visible or [p.pid for p in processes])
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
