"""Read-only systemd observations. Incomplete inventories fail as a whole."""

import re
import subprocess  # nosec B404
import time

from config.snapshot_policy import (
    MAX_SERVICES,
    MAX_SYSTEMCTL_BYTES,
    MAX_SYSTEMCTL_SECONDS,
    collection_seconds,
    inventory_limit,
    positive_setting,
)
from metrics.bounded_output import OutputLimitError, bounded_output
from metrics.snapshot import ObservationError, ResourceLimitError, SnapshotError

SYSTEMCTL = '/usr/bin/systemctl'
MAX_UNITS = MAX_SERVICES
BATCH_SIZE = 128
COMMAND_SECONDS = MAX_SYSTEMCTL_SECONDS
REQUIRED_PROPERTIES = ('Id', 'Names', 'Description', 'LoadState', 'ActiveState', 'SubState')
# Keep argument-bearing properties outside the show query.
PROPERTIES = REQUIRED_PROPERTIES + ('MainPID', 'User', 'Group', 'FragmentPath', 'DropInPaths')
UNIT_NAME = re.compile(r'[A-Za-z0-9:_.@\\\-]+\.service\Z')
# Decode the literal quoting systemctl uses for string arrays.
DROP_IN_WORD = re.compile(r'"((?:[^"\\]|\\["\\$`])*)"|([^"\\\s]+)')
DROP_IN_ESCAPE = re.compile(r'\\(["\\$`])')
MAX_PATH_BYTES = 4096
MAX_DROP_INS = 64
MAX_DROP_IN_OUTPUT = 64 * 1024
CONFIG_FIELDS = ('unit_names', 'configured_user', 'configured_group', 'fragment_path', 'drop_in_paths')


def valid_name(name):
    return len(name) <= 255 and UNIT_NAME.fullmatch(name) is not None


def run_systemctl(arguments, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ObservationError('OBSERVATION_TIMEOUT', 'systemctl collection time budget exceeded.')
    try:
        # Fixed executable and read-only verbs; no shell or interactive authorization.
        result = bounded_output(
            [SYSTEMCTL, '--system', '--no-pager', '--no-legend', '--plain', '--full',
             '--no-ask-password', *arguments],
            env={'LC_ALL': 'C', 'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'},
            timeout=min(positive_setting('SIEM_SNAPSHOT_SYSTEMCTL_SECONDS', COMMAND_SECONDS, COMMAND_SECONDS), remaining),
            max_bytes=positive_setting('SIEM_SNAPSHOT_SYSTEMCTL_BYTES', MAX_SYSTEMCTL_BYTES, MAX_SYSTEMCTL_BYTES),
        )
    except subprocess.TimeoutExpired as error:
        raise ObservationError('OBSERVATION_TIMEOUT', 'systemctl observation timed out.') from error
    except PermissionError as error:
        raise ObservationError('PERMISSION_DENIED', 'systemctl execution denied.') from error
    except OutputLimitError:
        raise ResourceLimitError() from None
    except UnicodeError as error:
        raise SnapshotError('Invalid systemctl encoding.') from error
    except (OSError, subprocess.SubprocessError) as error:
        raise ObservationError('SOURCE_UNAVAILABLE', 'systemctl observation unavailable.') from error
    return result


def query(arguments, deadline, coverage):
    try:
        return run_systemctl(arguments, deadline)
    except SnapshotError as error:
        coverage['systemctl_failed_queries'] += 1
        if isinstance(error, ObservationError) and error.code == 'OBSERVATION_TIMEOUT':
            coverage['systemctl_timeouts'] += 1
        raise


def inventory(deadline, coverage, limit):
    loaded = query(['list-units', '--all', '--type=service'], deadline, coverage)
    files = query(['list-unit-files', '--type=service'], deadline, coverage)
    if loaded.returncode or files.returncode:
        coverage['systemctl_failed_queries'] += int(bool(loaded.returncode)) + int(bool(files.returncode))
        raise ObservationError('SOURCE_UNAVAILABLE', 'systemctl inventory failed.')
    units, definitions = set(), {}
    for line in loaded.stdout.splitlines():
        columns = line.split()
        # --plain suppresses the failed-unit bullet; tolerate older versions.
        if columns and columns[0] in ('●', '○', '×'):
            columns = columns[1:]
        if len(columns) < 4 or not valid_name(columns[0]):
            raise SnapshotError('Incomplete systemctl unit inventory.')
        if columns[0] in units:
            raise SnapshotError('Duplicate systemctl unit.')
        units.add(columns[0])
        if len(units) > limit:
            raise ResourceLimitError()
    for line in files.stdout.splitlines():
        columns = line.split()
        # Older systemd has two columns; newer releases add the preset column.
        if len(columns) not in (2, 3) or not valid_name(columns[0]):
            raise SnapshotError('Incomplete systemctl unit-file inventory.')
        if columns[0] in definitions:
            raise SnapshotError('Duplicate systemctl unit file.')
        definitions[columns[0]] = columns[1]
        if len(definitions) > limit:
            raise ResourceLimitError()
    if not units and not definitions:
        raise SnapshotError('Empty systemctl inventory is not a valid snapshot.')
    if len(units | definitions.keys()) > limit:
        raise ResourceLimitError()
    return units, definitions


def parse_properties(text):
    if text and not text.endswith('\n'):
        raise SnapshotError('Truncated systemctl property output.')
    blocks = []
    block = {}
    for line in text.split('\n') + ['']:
        if not line:
            if block:
                if not set(REQUIRED_PROPERTIES) <= block.keys():
                    raise SnapshotError('Missing systemctl properties.')
                blocks.append(block)
                block = {}
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in PROPERTIES or key in block:
            raise SnapshotError('Invalid systemctl property output.')
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise SnapshotError('Invalid systemctl property value.')
        block[key] = value
    return blocks


def optional_property(block, field):
    value = block.get(field)
    if value == '[unprintable]':
        return None
    return value


def validate_path(path):
    if path and (not path.startswith('/') or len(path.encode('utf-8')) > MAX_PATH_BYTES):
        raise SnapshotError('Invalid systemd metadata path.')
    return path


def parse_drop_in_paths(value):
    if value is None:
        return None
    if len(value) > MAX_DROP_IN_OUTPUT:
        raise SnapshotError('systemd drop-in metadata exceeds the observation limit.')
    paths = set()
    position = 0
    count = 0
    while position < len(value):
        match = DROP_IN_WORD.match(value, position)
        if match is None:
            raise SnapshotError('Invalid systemd drop-in list.')
        quoted, plain = match.groups()
        path = plain
        if quoted is not None:
            path = DROP_IN_ESCAPE.sub(r'\1', quoted)
        if not path:
            raise SnapshotError('Empty path in systemd drop-in list.')
        paths.add(validate_path(path))
        count += 1
        if count > MAX_DROP_INS:
            raise SnapshotError('Too many systemd drop-in paths.')
        position = match.end()
        if position < len(value) and value[position] != ' ':
            raise SnapshotError('Invalid systemd drop-in separator.')
        while position < len(value) and value[position] == ' ':
            position += 1
    return sorted(paths)


def parse_service_state(block):
    unit_id = block['Id']
    names = block['Names'].split()
    if not valid_name(unit_id) or len(names) > MAX_UNITS:
        raise SnapshotError('Invalid systemd unit identity.')
    aliases = set()
    for name in names:
        # systemctl quotes string-array members containing a backslash.
        if name.startswith('"'):
            match = DROP_IN_WORD.fullmatch(name)
            if match is None or match.group(1) is None:
                raise SnapshotError('Invalid systemd alias.')
            name = DROP_IN_ESCAPE.sub(r'\1', match.group(1))
        if not valid_name(name):
            raise SnapshotError('Invalid systemd alias.')
        aliases.add(name)
    main_pid = optional_property(block, 'MainPID')
    if main_pid is not None:
        if len(main_pid) > 10 or not main_pid.isascii() or not main_pid.isdecimal():
            raise SnapshotError('Invalid systemd MainPID.')
        main_pid = int(main_pid)
        if main_pid > 2**31 - 1:
            raise SnapshotError('Invalid systemd MainPID.')
    user = optional_property(block, 'User')
    group = optional_property(block, 'Group')
    for value in (user, group):
        if value is not None and len(value.encode('utf-8')) > 255:
            raise SnapshotError('systemd user or group exceeds the observation limit.')
    return {
        'unit_id': unit_id,
        'unit_names': sorted(aliases),
        'description': block['Description'],
        'load_state': block['LoadState'],
        'active_state': block['ActiveState'],
        'sub_state': block['SubState'],
        'main_pid': main_pid,
        'configured_user': user,
        'configured_group': group,
        'fragment_path': validate_path(optional_property(block, 'FragmentPath')),
        'drop_in_paths': parse_drop_in_paths(optional_property(block, 'DropInPaths')),
    }


def unit_identity_changed(before, after):
    original = before.get('unit_id')
    latest = after.get('unit_id')
    return original is not None and latest is not None and original != latest


def last_known_config(state, field):
    value = state.get(field)
    if value is None:
        return state.get('last_known_config', {}).get(field)
    return value


def retain_missing_config(state, previous):
    if unit_identity_changed(previous, state):
        return
    known = {}
    for field in CONFIG_FIELDS:
        if state.get(field) is None:
            value = last_known_config(previous, field)
            if value is not None:
                known[field] = value
    if known:
        state['last_known_config'] = known


def merge_unit_observation(current, latest):
    for field, value in latest.items():
        if value is None:
            continue
        prior = current[field]
        if prior is not None and prior != value:
            raise SnapshotError('Conflicting systemctl unit properties.')
        current[field] = value


def get_services(previous=None, *, coverage=None):
    previous = previous or {}
    if coverage is None:
        coverage = {}
    coverage.update(systemctl_failed_queries=0, systemctl_timeouts=0)
    deadline = time.monotonic() + collection_seconds()
    limit = inventory_limit('services')
    loaded, files = inventory(deadline, coverage, limit)
    # Templates are definitions, not runnable instances; show cannot query them.
    # Aliases retain their own definition identity and share runtime properties.
    selected = loaded | files.keys()
    coverage.update(inventory_count=len(selected), observed_count=0)
    names = selected | previous.keys()
    if len(names) > limit:
        raise ResourceLimitError()
    if any(not valid_name(name) for name in names):
        raise SnapshotError('Invalid service scope.')
    current = {}
    canonical = {}
    selected_states = {}
    batches = []
    # Query missing units separately: systemd may return nonzero for not-found.
    for group in (selected, names - selected):
        runnable = sorted(name for name in group if not name.endswith('@.service'))
        batches.extend(runnable[offset:offset + BATCH_SIZE]
                       for offset in range(0, len(runnable), BATCH_SIZE))
    for batch in batches:
        result = query(['show', '--all', '--property=' + ','.join(PROPERTIES), '--', *batch], deadline, coverage)
        if result.returncode not in (0, 1, 4):
            coverage['systemctl_failed_queries'] += 1
            raise ObservationError('SOURCE_UNAVAILABLE', 'systemctl show failed.')
        mapped = {}
        for block in parse_properties(result.stdout):
            state = parse_service_state(block)
            unit_id = state['unit_id']
            aliases = set(state['unit_names']) | {unit_id}
            matches = aliases.intersection(batch)
            if not matches or not state['load_state'] or not state['active_state'] or not state['sub_state']:
                raise SnapshotError('Unmatched or incomplete systemctl unit properties.')
            shared = canonical.setdefault(unit_id, state)
            if shared is not state:
                merge_unit_observation(shared, state)
            for name in matches:
                # systemctl may show the same canonical unit for an alias.
                if name in mapped and mapped[name] is not shared:
                    raise SnapshotError('Conflicting systemctl unit properties.')
                mapped[name] = shared
        if set(mapped) != set(batch):
            coverage['uncertain_inventory_count'] = len(set(batch) - mapped.keys())
            raise ObservationError('INCOMPLETE_OBSERVATION', 'Partial systemctl show response.')
        # Some versions return nonzero for explicit not-found queries. Accept
        # only fully parsed, exclusively not-found responses in that case.
        if result.returncode:
            for state in mapped.values():
                if state['load_state'] != 'not-found':
                    coverage['systemctl_failed_queries'] += 1
                    raise ObservationError('SOURCE_UNAVAILABLE', 'systemctl show failed.')
        for name in batch:
            state = mapped[name]
            if name not in selected:
                if state['load_state'] != 'not-found':
                    raise SnapshotError('Unit inventory changed during collection.')
                continue  # absence plus explicit not-found proves removal
            selected_states[name] = state
        coverage['observed_count'] = len(selected_states)
    missing_metadata = 0
    for name, state in selected_states.items():
        current[name] = {**state, 'unit_file_state': files.get(name)}
        retain_missing_config(current[name], previous.get(name, {}))
        for field in ('main_pid',) + CONFIG_FIELDS:
            if state[field] is None:
                missing_metadata += 1
                break
    for name in sorted(selected):
        if name.endswith('@.service'):
            current[name] = {'description': None, 'load_state': None, 'active_state': None,
                             'sub_state': None, 'unit_file_state': files.get(name)}
    coverage.update(observed_count=len(current), optional_metadata_missing_count=missing_metadata)
    loaded_after, files_after = inventory(deadline, coverage, limit)
    if time.monotonic() >= deadline:
        raise ObservationError('OBSERVATION_TIMEOUT', 'systemctl collection time budget exceeded.')
    # show may load previously unloaded definitions into manager memory. That
    # expected read side effect must not invalidate an otherwise complete scan.
    uncertain = ((loaded_after - loaded) - files.keys()) | (loaded - loaded_after)
    if files_after != files or uncertain:
        for name in files.keys() | files_after.keys():
            if files.get(name) != files_after.get(name):
                uncertain.add(name)
        coverage['uncertain_inventory_count'] = len(uncertain)
        raise ObservationError('INCOMPLETE_OBSERVATION', 'Unit inventory changed during collection; retry next run.')
    return current


def config_changed(before, after):
    for field in CONFIG_FIELDS:
        prior = last_known_config(before, field)
        latest = after.get(field)
        if prior is not None and latest is not None and prior != latest:
            return True
    return False


def shared_event(before, after):
    # MainPID is runtime context. The systemd states drive lifecycle events.
    if before['active_state'] in ('inactive', 'failed') and after['active_state'] == 'active':
        return 'STARTED'
    if before['active_state'] == 'active' and after['active_state'] == 'inactive':
        return 'STOPPED'
    if before['active_state'] != 'failed' and after['active_state'] == 'failed':
        return 'FAILED'
    for field in ('description', 'load_state', 'active_state', 'sub_state'):
        if before.get(field) != after.get(field):
            return 'CHANGED'
    if config_changed(before, after):
        return 'CHANGED'
    return None


def get_events(current, previous):
    # Prefer the canonical name among existing rows. Aliases keep their own definition events.
    representative = {}
    for name in sorted(current.keys() & previous.keys()):
        state = current[name]
        if unit_identity_changed(previous[name], state):
            continue
        unit_id = state.get('unit_id') or name
        if unit_id not in representative or name == unit_id:
            representative[unit_id] = name
    events = []
    for name in sorted(current.keys() | previous.keys()):
        before, after = previous.get(name), current.get(name)
        if before == after:
            continue
        if before is None:
            event = 'APPEARED'
        elif after is None:
            event = 'REMOVED'
        elif unit_identity_changed(before, after):
            event = 'CHANGED'
        else:
            event = None
            unit_id = after.get('unit_id') or name
            if representative.get(unit_id) == name:
                event = shared_event(before, after)
            if event is None and before['unit_file_state'] != after['unit_file_state']:
                event = 'CHANGED'
            if event is None:
                continue
        events.append((name, event, before, after))
    return events
