"""Read-only systemd observations. Incomplete inventories fail as a whole."""

import os
import re
import subprocess  # nosec B404
import time

from metrics.snapshot import SnapshotError

SYSTEMCTL = '/usr/bin/systemctl'
MAX_UNITS = 4096
BATCH_SIZE = 128
BUDGET_SECONDS = 40
COMMAND_SECONDS = 5
PROPERTIES = ('Id', 'Names', 'Description', 'LoadState', 'ActiveState', 'SubState')
UNIT_NAME = re.compile(r'[A-Za-z0-9:_.@\\\-]+\.service\Z')


def valid_name(name):
    return len(name) <= 255 and UNIT_NAME.fullmatch(name) is not None


def run_systemctl(arguments, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SnapshotError('systemctl collection time budget exceeded.')
    try:
        # Fixed executable and read-only verbs; no shell or interactive authorization.
        result = subprocess.run(  # nosec B603
            [SYSTEMCTL, '--system', '--no-pager', '--no-legend', '--plain', '--full',
             '--no-ask-password', *arguments],
            capture_output=True, text=True, encoding='utf-8', errors='strict',
            env=dict(os.environ, LC_ALL='C', SYSTEMD_COLORS='0', SYSTEMD_PAGER='cat'),
            timeout=min(COMMAND_SECONDS, remaining), check=False,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise SnapshotError('systemctl observation failed or timed out.') from error
    if len(result.stdout) > 8 * 1024 * 1024:
        raise SnapshotError('systemctl output exceeds the observation limit.')
    return result


def inventory(deadline):
    loaded = run_systemctl(['list-units', '--all', '--type=service'], deadline)
    files = run_systemctl(['list-unit-files', '--type=service'], deadline)
    if loaded.returncode or files.returncode:
        raise SnapshotError('systemctl inventory failed.')
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
    for line in files.stdout.splitlines():
        columns = line.split()
        # Older systemd has two columns; newer releases add the preset column.
        if len(columns) not in (2, 3) or not valid_name(columns[0]):
            raise SnapshotError('Incomplete systemctl unit-file inventory.')
        if columns[0] in definitions:
            raise SnapshotError('Duplicate systemctl unit file.')
        definitions[columns[0]] = columns[1]
    if not units and not definitions:
        raise SnapshotError('Empty systemctl inventory is not a valid snapshot.')
    if len(units | definitions.keys()) > MAX_UNITS:
        raise SnapshotError('Too many service units for the bounded collector.')
    return units, definitions


def parse_properties(text):
    blocks = []
    block = {}
    for line in text.splitlines() + ['']:
        if not line:
            if block:
                if set(block) != set(PROPERTIES):
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


def get_services(previous=None):
    previous = previous or {}
    deadline = time.monotonic() + BUDGET_SECONDS
    loaded, files = inventory(deadline)
    # Templates are definitions, not runnable instances; show cannot query them.
    # Aliases retain their own definition identity and share runtime properties.
    selected = loaded | files.keys()
    names = selected | previous.keys()
    if len(names) > MAX_UNITS or any(not valid_name(name) for name in names):
        raise SnapshotError('Invalid or excessive service scope.')
    current = {}
    batches = []
    # Query missing units separately: systemd may return nonzero for not-found.
    for group in (selected, names - selected):
        runnable = sorted(name for name in group if not name.endswith('@.service'))
        batches.extend(runnable[offset:offset + BATCH_SIZE]
                       for offset in range(0, len(runnable), BATCH_SIZE))
    for batch in batches:
        result = run_systemctl(['show', '--all', '--property=' + ','.join(PROPERTIES), '--', *batch], deadline)
        mapped = {}
        for block in parse_properties(result.stdout):
            aliases = set(block['Names'].split()) | {block['Id']}
            matches = aliases.intersection(batch)
            if not matches or not block['LoadState'] or not block['ActiveState'] or not block['SubState']:
                raise SnapshotError('Unmatched or incomplete systemctl unit properties.')
            for name in matches:
                # systemctl may show the same canonical unit for an alias.
                if name in mapped and mapped[name] != block:
                    raise SnapshotError('Conflicting systemctl unit properties.')
                mapped[name] = block
        if set(mapped) != set(batch):
            raise SnapshotError('Partial systemctl show response.')
        # Some versions return nonzero for explicit not-found queries. Accept
        # only fully parsed, exclusively not-found responses in that case.
        if result.returncode and (result.returncode not in (1, 4)
                                  or any(b['LoadState'] != 'not-found' for b in mapped.values())):
            raise SnapshotError('systemctl show failed.')
        for name in batch:
            block = mapped[name]
            if name not in selected:
                if block['LoadState'] != 'not-found':
                    raise SnapshotError('Unit inventory changed during collection.')
                continue  # absence plus explicit not-found proves removal
            current[name] = {
                'description': block['Description'], 'load_state': block['LoadState'],
                'active_state': block['ActiveState'], 'sub_state': block['SubState'],
                'unit_file_state': files.get(name),
            }
    for name in sorted(selected):
        if name.endswith('@.service'):
            current[name] = {'description': None, 'load_state': None, 'active_state': None,
                             'sub_state': None, 'unit_file_state': files.get(name)}
    loaded_after, files_after = inventory(deadline)
    # show may load previously unloaded definitions into manager memory. That
    # expected read side effect must not invalidate an otherwise complete scan.
    if files_after != files or (loaded_after - loaded) - files.keys():
        raise SnapshotError('Unit inventory changed during collection; retry next run.')
    return current


def get_events(current, previous):
    events = []
    for name in sorted(current.keys() | previous.keys()):
        before, after = previous.get(name), current.get(name)
        if before == after:
            continue
        if before is None:
            event = 'APPEARED'
        elif after is None:
            event = 'REMOVED'
        elif before['active_state'] in ('inactive', 'failed') and after['active_state'] == 'active':
            event = 'STARTED'
        elif before['active_state'] == 'active' and after['active_state'] == 'inactive':
            event = 'STOPPED'
        elif before['active_state'] != 'failed' and after['active_state'] == 'failed':
            event = 'FAILED'
        else:
            event = 'CHANGED'
        events.append((name, event, before, after))
    return events
