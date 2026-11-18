import json
from datetime import datetime, timedelta, timezone

from metrics.measurement_window import utc_datetime, window_bounds
from metrics.services import windows
from metrics.services.get import get_events

START = datetime(2026, 11, 17, 10)


def service(active='inactive', definition='disabled', **fields):
    state = {'active_state': active, 'unit_file_state': definition, 'sub_state': 'running'}
    state.update(fields)
    return state


def test_counts_canonical_activity_templates_definitions_and_main_pid():
    states = {
        'alias.service': service('active', 'alias', unit_id='one.service', main_pid=12),
        'one.service': service('active', 'enabled', unit_id='one.service', main_pid=12),
        'two.service': service('inactive', 'disabled', main_pid=0),
        'three.service': service('failed', 'masked'),
        'four.service': service('activating', 'static'),
        'five.service': service('deactivating', 'generated'),
        'six.service': service('unrecognized', 'future-state'),
        'only-alias.service': service('reloading', 'alias', unit_id='missing-name.service'),
        'worker@.service': service(None, 'disabled'),
    }
    metrics, activity = {}, {}
    windows.add_sample(metrics, activity, START, states, [])
    counts = {**metrics}
    counts.pop('observed_utc_minute_mask')
    expected = {
        'service_count': 7, 'inventory_entry_count': 9, 'template_count': 1, 'alias_count': 2,
        'active_count': 1, 'inactive_count': 1, 'failed_count': 1, 'activating_count': 1,
        'deactivating_count': 1, 'unknown_active_state_count': 1, 'other_active_state_count': 1,
        'enabled_count': 1, 'disabled_count': 1, 'masked_count': 1, 'static_count': 1,
        'unknown_unit_file_state_count': 1, 'missing_unit_file_state_count': 1,
        'unit_file_generated_count': 1, 'unit_file_alias_count': 0,
        'positive_main_pid_count': 1, 'zero_main_pid_count': 1, 'missing_main_pid_count': 5,
        'sample_with_failed_service_count': 1,
    }
    for key, value in expected.items():
        assert counts[key] == {'sum': value, 'min': value, 'max': value, 'count': 1}
    assert set(activity) == {'three.service'}


def test_sparse_activity_uses_existing_events_and_explicit_observation_coverage():
    metrics, activity = {}, {}
    first = {
        'start.service': service(),
        'stop.service': service('active'),
        'fail.service': service('active'),
        'change.service': service('active', 'enabled', configured_user='private-worker-before'),
        'removed.service': service(),
        'quiet.service': service('active', main_pid=0),
    }
    second = {
        'start.service': service('active'),
        'stop.service': service(),
        'fail.service': service('failed'),
        'change.service': service('active', 'enabled', configured_user='private-worker-after'),
        'new.service': service(),
        'quiet.service': service('active', main_pid=50),
    }
    third = {**second, 'added.service': service()}
    samples = (
        (START, first, []),
        (START + timedelta(minutes=1), second, get_events(second, first)),
        (START + timedelta(minutes=1, seconds=30), second, get_events(second, second)),
        (START + timedelta(minutes=4), third, get_events(third, second)),
    )
    for timestamp, states, events in samples:
        windows.add_sample(metrics, activity, timestamp, states, events)
    assert metrics['observed_utc_minute_mask'] == 0b10011
    assert metrics['service_count'] == {'sum': 25, 'min': 6, 'max': 7, 'count': 4}
    assert metrics['service_count']['sum'] / metrics['service_count']['count'] == 6.25
    assert metrics['sample_with_failed_service_count']['sum'] == 3
    for field in ('started', 'stopped', 'failed', 'changed', 'removed', 'config_change'):
        assert metrics['observed_' + field + '_count']['sum'] == 1
    assert metrics['observed_appeared_count']['sum'] == 2
    assert activity['fail.service']['failed_count'] == activity['fail.service']['sample_count'] == 3
    assert activity['start.service']['active_count'] == 3
    assert activity['stop.service']['inactive_count'] == 3
    assert activity['start.service']['first_observed_at'] == '2026-11-17T10:01:00.000000Z'
    assert activity['start.service']['last_observed_at'] == '2026-11-17T10:04:00.000000Z'
    assert 'quiet.service' not in activity and 'removed.service' not in activity
    serialized = json.dumps((metrics, activity))
    assert 'private-worker' not in serialized and 'restart' not in serialized


def test_activity_limit_leaves_machine_and_event_counts_intact(monkeypatch):
    monkeypatch.setattr(windows, 'MAX_UNITS', 1)
    first = {'already.service': service('failed')}
    second = {**first, 'new.service': service('failed')}
    metrics, activity = {}, {}
    windows.add_sample(metrics, activity, START, first, [])
    windows.add_sample(metrics, activity, START + timedelta(minutes=1), second, get_events(second, first))
    assert len(activity) == 1
    assert activity['already.service']['sample_count'] == 2
    assert metrics['service_activity_omitted_count']['sum'] == 1
    assert metrics['observed_appeared_count']['sum'] == 1 and metrics['failed_count']['sum'] == 3


def test_service_samples_share_utc_window_bounds():
    offset = timezone(timedelta(hours=-2))
    before = datetime(2026, 11, 17, 8, 4, 59, 999999, tzinfo=offset)
    boundary = datetime(2026, 11, 17, 8, 5, tzinfo=offset)
    metrics = {}
    windows.add_sample(metrics, {}, utc_datetime(before), {'one.service': service()}, [])
    assert window_bounds(before) == (START, START + timedelta(minutes=5))
    assert window_bounds(boundary) == (START + timedelta(minutes=5), START + timedelta(minutes=10))
    assert metrics['observed_utc_minute_mask'] == 0b10000
