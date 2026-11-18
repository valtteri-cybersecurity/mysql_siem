from copy import deepcopy

import pytest

from metrics.snapshot import plan_state_delta


@pytest.mark.parametrize(
    'previous,current,expected',
    [
        ({}, {}, {}),
        ({}, {'example': {}}, {'added': {'example': {}}}),
        ({'example': {}}, {}, {'removed': {'example': {}}}),
        ({'example': {'value': 1}}, {'example': {'value': 2}},
         {'changed': {'example': ({'value': 1}, {'value': 2})}}),
        ({'example': {'value': 1, 'nested': [2]}}, {'example': {'nested': [2], 'value': 1}},
         {'unchanged': {'example': {'value': 1, 'nested': [2]}}}),
    ],
)
def test_plan_state_delta_classifies_each_case(previous, current, expected):
    assert plan_state_delta(previous, current) == (
        {'added': {}, 'removed': {}, 'changed': {}, 'unchanged': {}} | expected
    )


def test_plan_state_delta_orders_all_groups_and_preserves_input_states():
    before = {'values': [1]}
    after = {'values': [1, 2]}
    same = {'values': [3]}
    previous = {'z-removed': before, 'b-changed': before, 'z-unchanged': same,
                'a-changed': before, 'a-removed': before, 'a-unchanged': same}
    current = {'z-added': after, 'b-changed': after, 'a-unchanged': same,
               'z-unchanged': same, 'a-changed': after, 'a-added': after}
    previous_copy = deepcopy(previous)
    current_copy = deepcopy(current)

    delta = plan_state_delta(previous, current)
    assert list(delta['added'].items()) == [('a-added', after), ('z-added', after)]
    assert list(delta['removed'].items()) == [('a-removed', before), ('z-removed', before)]
    assert list(delta['changed'].items()) == [('a-changed', (before, after)), ('b-changed', (before, after))]
    assert list(delta['unchanged'].items()) == [('a-unchanged', same), ('z-unchanged', same)]
    assert list(previous.items()) == list(previous_copy.items())
    assert list(current.items()) == list(current_copy.items())

    reordered = plan_state_delta(dict(reversed(previous.items())), dict(reversed(current.items())))
    assert list(reordered) == list(delta)
    for group in delta:
        assert list(reordered[group].items()) == list(delta[group].items())


def test_process_identity_distinguishes_reused_pid():
    state = {'pid': 42, 'process_name': 'worker'}
    delta = plan_state_delta({'42:1700000000.000000': state}, {'42:1700000001.000000': state})
    assert delta == {'added': {'42:1700000001.000000': state},
                     'removed': {'42:1700000000.000000': state}, 'changed': {}, 'unchanged': {}}


@pytest.mark.parametrize('field', ['cpu_percent', 'memory_percent', 'memory_mb'])
def test_process_measurement_delta_compares_all_fields(field):
    key = '42:1700000000.000000'
    before = {field: 1.0}
    after = {field: 2.0}
    delta = plan_state_delta({key: before}, {key: after})
    assert delta['changed'] == {key: (before, after)}
    assert delta['unchanged'] == {}


def test_service_instances_use_full_systemd_unit_names():
    inactive = {'active_state': 'inactive'}
    active = {'active_state': 'active'}
    delta = plan_state_delta(
        {'worker@east.service': inactive, 'worker@west.service': inactive},
        {'worker@east.service': active, 'worker@north.service': inactive},
    )
    assert delta == {'added': {'worker@north.service': inactive}, 'removed': {'worker@west.service': inactive},
                     'changed': {'worker@east.service': (inactive, active)}, 'unchanged': {}}


@pytest.mark.parametrize('previous,current,message', [
    (None, {}, 'mappings'),
    ({}, [], 'mappings'),
    ({42: {}}, {'example': {}}, 'identifiers must be strings'),
])
def test_plan_state_delta_rejects_invalid_input(previous, current, message):
    with pytest.raises(TypeError, match=message):
        plan_state_delta(previous, current)
