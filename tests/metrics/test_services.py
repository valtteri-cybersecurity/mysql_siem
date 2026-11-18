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


def properties(name='example.service', active='inactive', load='loaded', *, names=None, sub='dead', **metadata):
    if names is None:
        names = name
    lines = [f'Id={name}', f'Names={names}', 'Description=Example', f'LoadState={load}',
             f'ActiveState={active}', f'SubState={sub}']
    for field, value in metadata.items():
        lines.append(f'{field}={value}')
    return '\n'.join(lines) + '\n\n'


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

    monkeypatch.setattr(get, 'bounded_output', run)
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
    monkeypatch.setenv('DB_PASSWORD', 'synthetic-private-marker')
    calls = fake_systemctl(monkeypatch, units='', files='example.service static -\n')
    current = get.get_services()
    assert current['example.service']['unit_file_state'] == 'static'
    assert get.get_events(current, dict(reversed(list(current.items())))) == []
    assert len(calls) == 5
    for args, kwargs in calls:
        assert args[0] == '/usr/bin/systemctl'
        assert kwargs['timeout'] <= get.COMMAND_SECONDS
        assert kwargs['env']['LC_ALL'] == 'C'
        assert 'DB_PASSWORD' not in kwargs['env']
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

    monkeypatch.setattr(get, 'bounded_output', fail)
    with pytest.raises(SnapshotError):
        get.get_services({'example.service': state('active')})


def test_partial_properties_reject_entire_snapshot(monkeypatch):
    fake_systemctl(monkeypatch, show=properties().replace('ActiveState=inactive\n', ''))
    with pytest.raises(SnapshotError):
        get.get_services()


def test_removed_unit_requires_explicit_not_found(monkeypatch):
    calls = fake_systemctl(monkeypatch)
    original = get.bounded_output

    def run(args, **kwargs):
        if 'show' in args and 'gone.service' in args:
            return SimpleNamespace(returncode=1, stdout=properties('gone.service', load='not-found'), stderr='')
        return original(args, **kwargs)

    monkeypatch.setattr(get, 'bounded_output', run)
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

    def race(deadline, coverage, limit):
        loaded, files = original(deadline, coverage, limit)
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

    def after_show(deadline, coverage, limit):
        loaded, files = original(deadline, coverage, limit)
        if seen:
            loaded.add('example.service')
        seen.append(True)
        return loaded, files

    monkeypatch.setattr(get, 'inventory', after_show)
    assert get.get_services()['example.service']['active_state'] == 'inactive'


def test_collects_unit_metadata_in_the_existing_show_batch(monkeypatch):
    calls = fake_systemctl(monkeypatch, show=properties(
        MainPID=241, User='worker', Group='2001', FragmentPath='/run/systemd/generator/example.service',
        DropInPaths='/etc/systemd/system/example.service.d/10-settings.conf'))
    current = get.get_services()['example.service']
    assert current['unit_id'] == 'example.service'
    assert current['unit_names'] == ['example.service']
    assert current['main_pid'] == 241
    assert current['configured_user'] == 'worker'
    assert current['configured_group'] == '2001'
    assert current['fragment_path'] == '/run/systemd/generator/example.service'
    assert current['drop_in_paths'] == ['/etc/systemd/system/example.service.d/10-settings.conf']
    assert len(calls) == 5
    for args, _ in calls:
        if 'show' in args:
            assert '--property=' + ','.join(get.PROPERTIES) in args
            assert 'ExecStart' not in ' '.join(args)


def test_empty_metadata_is_distinct_from_unavailable_metadata(monkeypatch):
    fake_systemctl(monkeypatch, files='', show=properties(
        MainPID=0, User='', Group='', FragmentPath='', DropInPaths=''))
    empty = get.get_services()
    row = empty['example.service']
    assert row['main_pid'] == 0
    assert row['configured_user'] == row['configured_group'] == row['fragment_path'] == ''
    assert row['drop_in_paths'] == []
    fake_systemctl(monkeypatch, files='', show=properties(FragmentPath='[unprintable]'))
    missing = get.get_services(empty)
    row = missing['example.service']
    assert row['main_pid'] is None
    for field in ('configured_user', 'configured_group', 'fragment_path', 'drop_in_paths'):
        assert row[field] is None
    assert row['last_known_config'] == {'configured_user': '', 'configured_group': '',
                                       'fragment_path': '', 'drop_in_paths': []}
    assert get.get_events(missing, empty) == []


def test_service_coverage_counts_optional_gaps_without_counting_templates_or_empty_values(monkeypatch):
    files = 'example.service static -\nother.service static -\nworker@.service static -\n'
    show = properties(MainPID=0, User='', Group='', FragmentPath='', DropInPaths='') + properties('other.service')
    fake_systemctl(monkeypatch, files=files, show=show)
    coverage = {}
    assert len(get.get_services(coverage=coverage)) == 3
    assert coverage == {'observed_count': 3, 'inventory_count': 3, 'optional_metadata_missing_count': 1,
                        'systemctl_failed_queries': 0, 'systemctl_timeouts': 0}


def test_service_coverage_counts_a_single_timed_out_query(monkeypatch):
    def timeout(args, **_kwargs):
        raise subprocess.TimeoutExpired(args, 5)

    monkeypatch.setattr(get, 'bounded_output', timeout)
    coverage = {}
    with pytest.raises(get.ObservationError) as error:
        get.get_services(coverage=coverage)
    assert error.value.code == 'OBSERVATION_TIMEOUT'
    assert coverage == {'systemctl_failed_queries': 1, 'systemctl_timeouts': 1}


def test_only_main_pid_change_updates_state_without_history(monkeypatch):
    fake_systemctl(monkeypatch, show=properties(MainPID=0))
    previous = get.get_services()
    fake_systemctl(monkeypatch, show=properties(MainPID=123))
    current = get.get_services(previous)
    assert previous.keys() == current.keys()
    assert current['example.service']['main_pid'] == 123
    assert get.get_events(current, previous) == []


def test_drop_in_order_and_systemd_quoting_are_deterministic(monkeypatch):
    spaced = r'"/run/worker folder/10 \$worker\\name.conf"'
    simple = '/etc/systemd/system/example.service.d/20.conf'
    fake_systemctl(monkeypatch, show=properties(DropInPaths=f'{spaced} {simple}'))
    previous = get.get_services()
    assert previous['example.service']['drop_in_paths'] == [simple, r'/run/worker folder/10 $worker\name.conf']
    fake_systemctl(monkeypatch, show=properties(DropInPaths=f'{simple} {spaced}'))
    current = get.get_services(previous)
    assert current == previous
    assert get.get_events(current, previous) == []


@pytest.mark.parametrize('field,old,new', [
    ('User', '', 'worker'), ('Group', 'users', 'root'),
    ('FragmentPath', '/usr/lib/systemd/system/example.service', '/run/systemd/transient/example.service'),
    ('DropInPaths', '/etc/example.service.d/10.conf', '/etc/example.service.d/20.conf'),
])
def test_config_change_is_recorded_after_missing_observation(monkeypatch, field, old, new):
    fake_systemctl(monkeypatch, show=properties(**{field: old}))
    previous = get.get_services()
    fake_systemctl(monkeypatch, show=properties())
    unavailable = get.get_services(previous)
    assert get.get_events(unavailable, previous) == []
    assert get.get_services(unavailable) == unavailable
    fake_systemctl(monkeypatch, show=properties(**{field: old}))
    assert get.get_events(get.get_services(unavailable), unavailable) == []
    fake_systemctl(monkeypatch, show=properties(**{field: new}))
    current = get.get_services(unavailable)
    assert get.get_events(current, unavailable) == [
        ('example.service', 'CHANGED', unavailable['example.service'], current['example.service']),
    ]


def test_first_enrichment_does_not_create_history(monkeypatch):
    fake_systemctl(monkeypatch, show=properties(User='worker', Group='', DropInPaths='', MainPID=123))
    previous = {'example.service': state()}
    assert get.get_events(get.get_services(previous), previous) == []


@pytest.mark.parametrize('metadata', [
    {'MainPID': '-1'}, {'MainPID': '4294967295'}, {'MainPID': '٤٢'}, {'MainPID': 'two'},
    {'FragmentPath': '../example.service'}, {'FragmentPath': '/' + 'å' * 2048},
    {'DropInPaths': '"/etc/unfinished.conf'}, {'DropInPaths': '"/etc/a.conf"/etc/b.conf'},
    {'DropInPaths': '/etc/ok.conf relative.conf'}, {'DropInPaths': '/etc/long' * 700},
    {'DropInPaths': '/etc/repeat.conf ' * 65}, {'Names': 'unsafe.socket'},
])
def test_malformed_metadata_rejects_instead_of_committing(monkeypatch, metadata):
    names = metadata.get('Names')
    fields = metadata.copy()
    fields.pop('Names', None)
    fake_systemctl(monkeypatch, show=properties(names=names, **fields))
    with pytest.raises(SnapshotError):
        get.get_services()


def test_unrequested_execstart_payload_cannot_enter_an_observation(monkeypatch):
    secret = 'fake-test-token'
    fake_systemctl(monkeypatch, show=properties(ExecStart='{ path=/bin/worker ; argv[]=' + secret + ' }'))
    with pytest.raises(SnapshotError, match='Invalid systemctl property output') as error:
        get.get_services()
    assert secret not in str(error.value)


def test_generated_and_instantiated_units_keep_their_inventory_entries(monkeypatch):
    fake_systemctl(monkeypatch, units='temp.service loaded active running Transient\n',
                   files='worker@.service static -\nworker@job.service generated -\n',
                   show=properties('temp.service', active='active', MainPID=20, FragmentPath='')
                   + properties('worker@job.service', FragmentPath='/run/systemd/generator/worker@job.service'))
    current = get.get_services()
    assert current['temp.service']['fragment_path'] == ''
    assert current['worker@job.service']['unit_file_state'] == 'generated'
    assert current['worker@.service']['active_state'] is None


@pytest.mark.parametrize('before,after,event', [
    ('inactive', 'active', 'STARTED'), ('active', 'inactive', 'STOPPED'), ('active', 'failed', 'FAILED'),
])
def test_aliases_share_one_canonical_runtime_event(monkeypatch, before, after, event):
    files = 'alias.service alias -\nexample.service enabled enabled\n'
    names = 'example.service alias.service'
    fake_systemctl(monkeypatch, files=files, show=properties(active=before, names=names))
    previous = get.get_services()
    fake_systemctl(monkeypatch, files=files, show=properties(active=after, names=names))
    current = get.get_services(previous)
    assert current['alias.service']['unit_id'] == current['example.service']['unit_id']
    assert current['alias.service']['unit_file_state'] == 'alias'
    assert get.get_events(current, previous) == [
        ('example.service', event, previous['example.service'], current['example.service']),
    ]


def test_alias_rebind_is_not_a_stop_or_start():
    before = {'alias.service': state('active', unit_id='first.service')}
    after = {'alias.service': state('inactive', unit_id='second.service')}
    assert get.get_events(after, before) == [('alias.service', 'CHANGED', before['alias.service'], after['alias.service'])]


def test_conflicts_and_optional_gaps_across_alias_batches(monkeypatch):
    monkeypatch.setattr(get, 'BATCH_SIZE', 1)
    files = 'alias.service alias -\nexample.service enabled enabled\n'
    fake_systemctl(monkeypatch, files=files)
    original = get.bounded_output
    update = None

    def run(args, **kwargs):
        if 'show' not in args:
            return original(args, **kwargs)
        names = 'example.service alias.service'
        if args[-1] == 'alias.service':
            output = properties(names=names, User='worker')
        elif update is None:
            output = properties(names='alias.service example.service')
        else:
            output = properties(names=names, User=update)
        return SimpleNamespace(returncode=0, stdout=output, stderr='')

    monkeypatch.setattr(get, 'bounded_output', run)
    current = get.get_services()
    assert current['alias.service']['configured_user'] == current['example.service']['configured_user'] == 'worker'
    update = 'other'
    with pytest.raises(SnapshotError, match='Conflicting'):
        get.get_services()


def test_successful_show_with_truncated_last_property_rejects_inventory(monkeypatch):
    fake_systemctl(monkeypatch, show=properties(User='example').rstrip('\n')[:-2])
    with pytest.raises(SnapshotError, match='Truncated'):
        get.get_services()


def test_unit_that_disappears_between_successful_inventories_rejects_snapshot(monkeypatch):
    fake_systemctl(monkeypatch, files='')
    original = get.inventory
    calls = []

    def inventory(deadline, coverage, limit):
        loaded, files = original(deadline, coverage, limit)
        if calls:
            loaded.clear()
        calls.append(True)
        return loaded, files

    monkeypatch.setattr(get, 'inventory', inventory)
    coverage = {}
    with pytest.raises(SnapshotError, match='inventory changed'):
        get.get_services(coverage=coverage)
    assert coverage['uncertain_inventory_count'] == 1


def test_quoted_systemd_alias_is_matched_to_the_inventory_name(monkeypatch):
    alias = r'example@dev\x2ddisk.service'
    quoted = r'"example@dev\\x2ddisk.service"'
    fake_systemctl(monkeypatch, files=f'example.service enabled -\n{alias} alias -\n',
                   show=properties(names=f'example.service {quoted}'))
    current = get.get_services()
    assert current[alias]['unit_id'] == 'example.service'
    assert current[alias]['unit_names'] == ['example.service', alias]
