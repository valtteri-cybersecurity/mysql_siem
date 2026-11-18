"""Aggregates of accepted systemd snapshots and their existing events."""

from config.snapshot_policy import positive_setting
from metrics.measurement_window import add_metrics, update_window
from metrics.services.get import MAX_UNITS, config_changed, unit_identity_changed

ACTIVE_STATES = ('active', 'inactive', 'failed', 'activating', 'deactivating')
OTHER_ACTIVE_STATES = ('reloading', 'maintenance', 'refreshing')
FILE_STATES = ('enabled', 'disabled', 'masked', 'static')
OTHER_FILE_STATES = ('enabled-runtime', 'masked-runtime', 'linked', 'linked-runtime',
                     'indirect', 'generated', 'transient', 'bad', 'alias')
EVENT_TYPES = ('APPEARED', 'REMOVED', 'STARTED', 'STOPPED', 'FAILED', 'CHANGED')


def canonical_units(current):
    units = {}
    templates, aliases = 0, 0
    for name, state in current.items():
        if name.endswith('@.service'):
            templates += 1
            continue
        unit = state.get('unit_id') or name
        if name != unit:
            aliases += 1
        if unit not in units or name == unit:
            units[unit] = state
    return units, templates, aliases


def active_field(state):
    value = state.get('active_state')
    if value in ACTIVE_STATES:
        return value + '_count'
    if value in OTHER_ACTIVE_STATES:
        return 'other_active_state_count'
    return 'unknown_active_state_count'


def file_state_field(value):
    if value in FILE_STATES:
        return value + '_count'
    if value in OTHER_FILE_STATES:
        return 'unit_file_' + value.replace('-', '_') + '_count'
    if value is None or value == '':
        return 'missing_unit_file_state_count'
    return 'unknown_unit_file_state_count'


def count_units(current, units, templates, aliases):
    counts = dict.fromkeys((
        'missing_unit_file_state_count', 'unknown_unit_file_state_count',
        'other_active_state_count', 'unknown_active_state_count',
        'positive_main_pid_count', 'zero_main_pid_count', 'missing_main_pid_count',
    ), 0)
    for value in ACTIVE_STATES + FILE_STATES:
        counts[value + '_count'] = 0
    for value in OTHER_FILE_STATES:
        counts[file_state_field(value)] = 0
    counts.update(service_count=len(units), template_count=templates, alias_count=aliases,
                  inventory_entry_count=len(current))
    for unit, state in units.items():
        counts[active_field(state)] += 1
        definition = current.get(unit, {})
        counts[file_state_field(definition.get('unit_file_state'))] += 1
        main_pid = state.get('main_pid')
        if main_pid is None:
            counts['missing_main_pid_count'] += 1
        elif main_pid == 0:
            counts['zero_main_pid_count'] += 1
        else:
            counts['positive_main_pid_count'] += 1
    counts['sample_with_failed_service_count'] = int(counts['failed_count'] > 0)
    return counts


def has_config_change(before, after):
    old_file_state, new_file_state = before.get('unit_file_state'), after.get('unit_file_state')
    if old_file_state and new_file_state and old_file_state != new_file_state:
        return True
    if unit_identity_changed(before, after):
        return False
    return config_changed(before, after)


def count_events(counts, events):
    for event in EVENT_TYPES:
        counts['observed_' + event.lower() + '_count'] = 0
    counts['observed_config_change_count'] = 0
    affected_units = set()
    for name, event, before, after in events:
        counts['observed_' + event.lower() + '_count'] += 1
        if event == 'CHANGED' and has_config_change(before, after):
            counts['observed_config_change_count'] += 1
        state = after
        if state is None:
            state = before
        affected_units.add(state.get('unit_id') or name)
    return affected_units


def record_activity(activity, units, affected_units, observed_at):
    timestamp = observed_at.isoformat(timespec='microseconds') + 'Z'
    omitted = 0
    limit = positive_setting('SIEM_SNAPSHOT_SERVICE_WINDOW_DETAILS', MAX_UNITS, MAX_UNITS)
    for unit, state in units.items():
        field = active_field(state)
        record = activity.get(unit)
        if record is None:
            if unit not in affected_units and field != 'failed_count':
                continue
            if len(activity) >= limit:
                omitted += 1
                continue
            record = {'first_observed_at': timestamp, 'sample_count': 0}
            activity[unit] = record
        record['sample_count'] += 1
        record[field] = record.get(field, 0) + 1
        record['last_observed_at'] = timestamp
    return omitted


def add_sample(metrics, activity, observed_at, current, events):
    units, templates, aliases = canonical_units(current)
    counts = count_units(current, units, templates, aliases)
    affected_units = count_events(counts, events)
    counts['service_activity_omitted_count'] = record_activity(activity, units, affected_units, observed_at)
    add_metrics(metrics, counts)
    # Bits 0 to 4 indicate minutes containing at least one accepted snapshot.
    mask = metrics.get('observed_utc_minute_mask', 0)
    metrics['observed_utc_minute_mask'] = mask | (1 << (observed_at.minute % 5))


def save_window(connection, identity, observed_at, current, events):
    def accumulate(metrics, activity):
        add_sample(metrics, activity, observed_at, current, events)

    return update_window(connection, 'services', identity, observed_at, accumulate)
