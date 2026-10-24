"""systemctl is always mocked. These tests never operate host services."""

import subprocess
from types import SimpleNamespace

import pytest

from metrics.services import get
from metrics.snapshot import SnapshotError


def state(active='inactive', enablement='disabled', **changes):
    return dict(description='Example', load_state='loaded', active_state=active,
                sub_state='running' if active == 'active' else 'dead',
                unit_file_state=enablement, **changes)


def properties(name='example.service', active='inactive', load='loaded'):
    return f'Id={name}\nNames={name}\nDescription=Example\nLoadState={load}\nActiveState={active}\nSubState=dead\n\n'


def fake_systemctl(monkeypatch, *, units='example.service loaded inactive dead Example\n',
                   files='example.service disabled enabled\n', show=None):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if 'list-units' in args:
            output = units
        elif 'list-unit-files' in args:
            output = files
        else:
            names = args[args.index('--') + 1:]
            output = ''.join(properties(name) for name in names) if show is None else show
        return SimpleNamespace(returncode=0, stdout=output, stderr='Warning on stderr\n')

    monkeypatch.setattr(get.subprocess, 'run', run)
    return calls


@pytest.mark.parametrize('before,after,event', [
    (state(), state('active'), 'STARTED'),
    (state('active'), state(), 'STOPPED'),
    (state('active'), state('failed'), 'FAILED'),
    (state('failed'), state('active'), 'STARTED'),
    (state(), state(enablement='enabled'), 'CHANGED'),
    (state(enablement='enabled'), state(), 'CHANGED'),
    (state(enablement='static'), state(enablement='masked'), 'CHANGED'),
    (None, state('active'), 'APPEARED'), (state('active'), None, 'REMOVED'),
])
def test_exact_transition_meaning(before, after, event):
    previous = {'example.service': before} if before is not None else {}
    current = {'example.service': after} if after is not None else {}
    assert get.get_events(current, previous) == [('example.service', event, before, after)]


def test_order_is_irrelevant_and_inactive_definition_is_observed(monkeypatch):
    calls = fake_systemctl(monkeypatch, units='', files='example.service static -\n')
    current = get.get_services()
    assert current['example.service']['unit_file_state'] == 'static'
    assert get.get_events(current, dict(reversed(list(current.items())))) == []
    assert len(calls) == 5
    for args, kwargs in calls:
        assert args[0] == '/usr/bin/systemctl'
        assert kwargs['timeout'] <= get.COMMAND_SECONDS
        assert kwargs['env']['LC_ALL'] == 'C'
        assert not kwargs.get('shell')


@pytest.mark.parametrize('output', ['', 'WARNING: incomplete\n', 'example.timer enabled -\n'])
def test_empty_or_malformed_inventory_is_failure(monkeypatch, output):
    fake_systemctl(monkeypatch, units='', files=output)
    with pytest.raises(SnapshotError):
        get.get_services({'example.service': state('active')})


@pytest.mark.parametrize('fault', ['exit', 'timeout', 'missing'])
def test_command_failure_is_not_a_stop(monkeypatch, fault):
    def fail(*args, **kwargs):
        if fault == 'timeout':
            raise subprocess.TimeoutExpired(args[0], 5)
        if fault == 'missing':
            raise FileNotFoundError
        return SimpleNamespace(returncode=1, stdout='', stderr='failure')

    monkeypatch.setattr(get.subprocess, 'run', fail)
    with pytest.raises(SnapshotError):
        get.get_services({'example.service': state('active')})


def test_partial_properties_reject_entire_snapshot(monkeypatch):
    fake_systemctl(monkeypatch, show=properties().replace('ActiveState=inactive\n', ''))
    with pytest.raises(SnapshotError):
        get.get_services()


def test_removed_unit_requires_explicit_not_found(monkeypatch):
    calls = fake_systemctl(monkeypatch)
    original = get.subprocess.run

    def run(args, **kwargs):
        if 'show' in args and 'gone.service' in args:
            return SimpleNamespace(returncode=1, stdout=properties('gone.service', load='not-found'), stderr='')
        return original(args, **kwargs)

    monkeypatch.setattr(get.subprocess, 'run', run)
    previous = {'gone.service': state('active'), 'example.service': state()}
    current = get.get_services(previous)
    assert 'gone.service' not in current
    assert get.get_events(current, previous) == [('gone.service', 'REMOVED', previous['gone.service'], None)]
    assert all('gone.service' not in args or 'example.service' not in args for args, _ in calls)


def test_absence_alone_does_not_prove_removal(monkeypatch):
    fake_systemctl(monkeypatch)
    with pytest.raises(SnapshotError, match='inventory changed'):
        get.get_services({'gone.service': state('active')})


def test_templates_masked_and_not_found_units(monkeypatch):
    fake_systemctl(monkeypatch, units='● example.service not-found failed failed Example\n',
                   files='worker@.service static -\nmasked.service masked enabled\n',
                   show=properties(load='not-found') + properties('masked.service', load='masked'))
    current = get.get_services()
    assert current['worker@.service']['active_state'] is None
    assert current['masked.service']['unit_file_state'] == 'masked'
    assert current['example.service']['load_state'] == 'not-found'


def test_batched_commands_and_global_budget(monkeypatch):
    files = ''.join(f'unit{i}.service disabled -\n' for i in range(260))
    calls = fake_systemctl(monkeypatch, units='', files=files)
    assert len(get.get_services()) == 260
    assert len(calls) == 7  # four inventories and three property batches
    monkeypatch.setattr(get.time, 'monotonic', lambda: 100)
    with pytest.raises(SnapshotError, match='budget'):
        get.run_systemctl(['list-units'], 99)


def test_inventory_race_is_rejected(monkeypatch):
    fake_systemctl(monkeypatch)
    original = get.inventory
    seen = []

    def race(deadline):
        loaded, files = original(deadline)
        if seen:
            files['new.service'] = 'static'
        seen.append(True)
        return loaded, files

    monkeypatch.setattr(get, 'inventory', race)
    with pytest.raises(SnapshotError, match='inventory changed'):
        get.get_services()


def test_show_loading_inactive_definitions_does_not_invalidate_inventory(monkeypatch):
    fake_systemctl(monkeypatch, units='', files='example.service static -\n')
    original = get.inventory
    seen = []

    def after_show(deadline):
        loaded, files = original(deadline)
        if seen:
            loaded.add('example.service')
        seen.append(True)
        return loaded, files

    monkeypatch.setattr(get, 'inventory', after_show)
    assert get.get_services()['example.service']['active_state'] == 'inactive'
