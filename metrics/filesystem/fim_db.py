"""Store the FIM baseline, observations and checkpoint in one transaction."""

import hashlib
import json

from database.connection import get_connection
from database.identity import (
    IdentityError,
    configured_identity,
    identity_schema_enabled,
)
from metrics.filesystem.fim import (
    FileState,
    FimError,
    RebaselineRequired,
    detect_changes,
    prepare_inventory,
)
from metrics.filesystem.inventory import (
    DEFAULT_CONFIG,
    InventoryResult,
    collect_inventory,
)
from metrics.filesystem.permissions import DEFAULT_RULES, analyze_permissions
from metrics.snapshot import CollectionBusy, release_snapshot_lock

EVENT_WRITER_LOCK = 'mysql_siem_fim_event_writer'

INSERT_EVENT = '''INSERT INTO filesystem_file_events
    (host_id, source_id, collector_id, sender_id, file_path, event_type, previous_state, current_state, observed_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'''

INSERT_STATE = '''INSERT INTO filesystem_file_state
    (host_id, source_id, file_path, content_sha256, size_bytes, owner_uid, group_gid, mode, observed_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'''


def _get_identity(connection, cursor):
    if not identity_schema_enabled(connection):
        raise IdentityError('FIM requires registered identities.')
    cursor.execute("SELECT status FROM schema_migrations WHERE version = '034'")
    if cursor.fetchone() != ('APPLIED',):
        raise FimError('Filesystem migration 034 is incomplete.')
    identity = configured_identity(cursor, 'filesystem')
    if identity is None:
        raise IdentityError('A registered filesystem source is required.')
    return identity


def _digest_hex(state):
    if state.content_sha256 is None:
        return None
    return state.content_sha256.hex()


def _event_state(state):
    if state is None:
        return None
    return json.dumps({'content_sha256': _digest_hex(state), 'size_bytes': state.size_bytes,
                       'owner_uid': state.owner_uid, 'group_gid': state.group_gid, 'mode': state.mode})


def _read_baseline(cursor, scope, config_sha256):
    cursor.execute('SELECT last_successful_scan_at, config_sha256, baseline_complete FROM filesystem_scan_state '
                   'WHERE host_id = %s AND source_id = %s', scope)
    checkpoint = cursor.fetchone()
    cursor.execute('SELECT file_path, content_sha256, size_bytes, owner_uid, group_gid, mode, observed_at '
                   'FROM filesystem_file_state WHERE host_id = %s AND source_id = %s', scope)
    previous = {}
    for path, digest, size, uid, gid, mode, stamp in cursor.fetchall():
        previous[path] = FileState(digest, size, uid, gid, mode, stamp)

    if checkpoint is None:
        if previous:
            raise FimError('File state exists without a verified checkpoint.')
    else:
        last_scan, stored_config, baseline_complete = checkpoint
        if stored_config != config_sha256:
            raise RebaselineRequired('FIM configuration changed. Administrative rebaseline is required.')
        if not baseline_complete or last_scan is None:
            raise FimError('The FIM baseline is incomplete.')
    return checkpoint, previous


def _write_inventory(cursor, identity, inventory, prepared, *, report=False):
    current, coverage, scan_at, first_observed = prepared
    scope = (identity.host_id, identity.source_id)
    checkpoint, previous = _read_baseline(cursor, scope, inventory.config_sha256)
    changes = []
    if checkpoint is not None:
        last_scan = checkpoint[0]
        if scan_at == last_scan and previous == current:
            if report:
                return _inventory_report(inventory, 0, previous)
            return 0
        if first_observed <= last_scan:
            raise FimError('File inventory is stale, overlapping or conflicts with the checkpoint.')
        changes = detect_changes(previous, current, coverage)

    if changes:
        events = []
        for path, kind, before, after in changes:
            events.append(identity.values() + (path, kind, _event_state(before), _event_state(after), scan_at))
        cursor.executemany(INSERT_EVENT, events)

    if previous:
        cursor.execute('DELETE FROM filesystem_file_state WHERE host_id = %s AND source_id = %s', scope)
    if current:
        states = []
        for path, state in current.items():
            states.append(scope + (path, state.content_sha256, state.size_bytes, state.owner_uid,
                                   state.group_gid, state.mode, state.observed_at))
        cursor.executemany(INSERT_STATE, states)

    if checkpoint is None:
        cursor.execute('INSERT INTO filesystem_scan_state '
                       '(host_id, source_id, last_successful_scan_at, config_sha256, baseline_complete) '
                       'VALUES (%s, %s, %s, %s, TRUE)', scope + (scan_at, inventory.config_sha256))
    else:
        cursor.execute('UPDATE filesystem_scan_state SET last_successful_scan_at = %s '
                       'WHERE host_id = %s AND source_id = %s', (scan_at,) + scope)
    if report:
        if checkpoint is None:
            previous = None
        return _inventory_report(inventory, len(changes), previous)
    return len(changes)


def _inventory_report(inventory, changes, previous=None):
    files = 0
    unhashed = 0
    missing = 0
    uncovered = 0
    for entry in inventory.entries:
        if entry.status == 'FOUND':
            files += 1
            if entry.digest.status != 'HASHED':
                unhashed += 1
        elif entry.status == 'MISSING':
            missing += 1
        elif entry.status != 'SCANNED':
            uncovered += 1
    coverage = f'files={files} unhashed={unhashed} missing={missing} uncovered={uncovered}'
    if inventory.status != 'SUCCESS':
        return inventory.status, coverage
    assessment = analyze_permissions(inventory, previous=previous)
    return 'SUCCESS', (f'{coverage} changes={changes} risks={len(assessment.findings)} '
                       f'unassessed_policy_paths={len(assessment.unassessed)}')


def _run_fim(observe, process=None, *, write=True, report=False):
    connection = get_connection(quiet=True, binary_parameters=True)
    if connection is None:
        raise FimError('Could not connect to the FIM database.')
    lock = None
    writer_lock = None
    try:
        with connection.cursor() as cursor:
            identity = _get_identity(connection, cursor)
            connection.rollback()
            cursor.execute('SELECT DATABASE()')
            database = cursor.fetchone()[0]
            scope = f'{database}:{identity.host_id}:{identity.source_id}'
            name = 'siem.fs.fim.' + hashlib.sha256(scope.encode()).hexdigest()[:48]
            cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
            if cursor.fetchone() != (1,):
                raise CollectionBusy('Another run holds the filesystem inventory lock.')
            lock = name

            inventory = observe()
            if report and inventory.status != 'SUCCESS':
                return _inventory_report(inventory, 0)
            prepared = prepare_inventory(inventory)
            # A global ID checkpoint requires event IDs to become visible in commit order.
            if write:
                cursor.execute('SELECT GET_LOCK(%s, 0)', (EVENT_WRITER_LOCK,))
                if cursor.fetchone() != (1,):
                    raise CollectionBusy('Another FIM writer is committing an inventory.')
                writer_lock = EVENT_WRITER_LOCK
            connection.begin()
            if _get_identity(connection, cursor) != identity:
                raise IdentityError('Filesystem identity changed during the inventory.')
            if process is None:
                result = _write_inventory(cursor, identity, inventory, prepared, report=report)
            else:
                result = process(cursor, identity, inventory, prepared)
        connection.commit()
        return result
    except BaseException:
        if connection.open:
            connection.rollback()
        raise
    finally:
        try:
            if lock is not None and connection.open:
                try:
                    release_snapshot_lock(connection, writer_lock)
                finally:
                    release_snapshot_lock(connection, lock)
        finally:
            connection.close()


def collect_fim(config=DEFAULT_CONFIG):
    """Inventory and store while holding the host/source lock."""
    return _run_fim(lambda: collect_inventory(config))


def collect_fim_report(config):
    """Report coverage and risks using the same observation and baseline as the write."""
    return _run_fim(lambda: collect_inventory(config), report=True)


def save_fim_inventory(inventory):
    """Store a completed inventory, including a retry of the last committed inventory."""
    return _run_fim(lambda: inventory)


def assess_fim_permissions(inventory, *, rules=DEFAULT_RULES):
    """Assess an existing inventory against the stored baseline before saving it."""
    if not isinstance(inventory, InventoryResult) or not inventory.entries or inventory.status != 'SUCCESS':
        return analyze_permissions(inventory, rules=rules)

    def assess(cursor, identity, observed, prepared):
        scope = (identity.host_id, identity.source_id)
        checkpoint, previous = _read_baseline(cursor, scope, observed.config_sha256)
        if checkpoint is None:
            previous = None
        elif prepared[3] <= checkpoint[0]:
            raise FimError('Permission assessment requires a newer, nonoverlapping inventory.')
        return analyze_permissions(observed, previous=previous, identity=identity, rules=rules)

    return _run_fim(lambda: inventory, process=assess, write=False)
