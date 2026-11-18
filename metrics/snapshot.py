"""Shared transactional snapshot protocol for local state collectors.

Only Processes and Services use these SQL and locking helpers. SQL identifiers are constants;
payloads and identities are always parameters. No runtime DDL or registry writes.
"""

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone

import pymysql

from config.snapshot_policy import MAX_WRITES, inventory_limit, positive_setting
from database.identity import (
    IdentityError,
    configured_identity,
    identity_schema_enabled,
)

TABLES = {
    'processes': ('042', 'process_events', 'process_state', 'process_key'),
    'services': ('043', 'service_events', 'service_state', 'service_name'),
}


class SnapshotError(ValueError):
    """An incomplete observation or incompatible snapshot must not be committed."""


class CollectionBusy(SnapshotError):
    """Another run owns this host's collector lock."""


class ObservationError(SnapshotError):
    def __init__(self, code, message, *, partial=False):
        super().__init__(message)
        self.code = code
        self.partial = partial


class ResourceLimitError(ObservationError):
    def __init__(self):
        super().__init__('INCOMPLETE_OBSERVATION', 'Snapshot resource limit exceeded.')


def plan_state_delta(previous, current):
    """Compare snapshots keyed by string identifiers, ordered by key in each group.

    Changed entries contain (previous_state, current_state). The states in the
    result refer to the input states, which this function leaves untouched.
    """
    if not isinstance(previous, Mapping) or not isinstance(current, Mapping):
        raise TypeError('Snapshots must be mappings.')

    keys = previous.keys() | current.keys()
    for key in keys:
        if not isinstance(key, str):
            raise TypeError('Snapshot identifiers must be strings.')

    delta = {'added': {}, 'removed': {}, 'changed': {}, 'unchanged': {}}
    for key in sorted(keys):
        if key not in previous:
            delta['added'][key] = current[key]
        elif key not in current:
            delta['removed'][key] = previous[key]
        elif previous[key] != current[key]:
            delta['changed'][key] = (previous[key], current[key])
        else:
            delta['unchanged'][key] = current[key]
    return delta


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_identity(connection, kind):
    if not identity_schema_enabled(connection):
        raise IdentityError('Snapshot collection requires registered identities.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT status FROM schema_migrations WHERE version = %s', (TABLES[kind][0],))
        if cursor.fetchone() != ('APPLIED',):
            raise IdentityError('Snapshot migration is incomplete; keep collection stopped.')
        identity = configured_identity(cursor, kind)
    if identity is None:
        raise IdentityError(f'A registered {kind} source is required.')
    return identity


def get_previous(connection, kind, identity):
    """Read current state and its checkpoint, with a boot ID for processes."""
    _, _, table, key = TABLES[kind]
    fields = 'source_id'
    if kind == 'processes':
        fields = 'source_id, process_boot_id'
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT {fields} FROM collector_snapshots WHERE host_id = %s AND source_type = %s',  # nosec B608
                       (identity.host_id, kind))
        marker = cursor.fetchone()
        if marker is not None and marker[0] != identity.source_id:
            raise IdentityError('Snapshot belongs to a different source; administrative recovery required.')
        # Identifiers come exclusively from TABLES; identity values are parameters.
        limit = inventory_limit(kind)
        cursor.execute(f'SELECT {key}, state FROM {table} WHERE host_id = %s AND source_id = %s LIMIT %s',  # nosec B608
                       (identity.host_id, identity.source_id, limit + 1))
        rows = cursor.fetchall()
        if len(rows) > limit:
            raise ResourceLimitError()
        previous = {name: json.loads(state) for name, state in rows}
    if marker is None and previous:
        raise SnapshotError('Current state has no completed baseline.')
    return previous, marker


STATE_BATCH_ROWS = 128
STATE_BATCH_BYTES = 512 * 1024


def update_state_batch(cursor, table, key, identity, observed_at, batch):
    cases = ' '.join(['WHEN %s THEN %s'] * len(batch))
    placeholders = ', '.join(['%s'] * len(batch))
    values = [identity.collector_id, identity.sender_id, observed_at]
    names = []
    for name, state in batch:
        values.extend((name, state))
        names.append(name)
    values.extend((identity.host_id, identity.source_id))
    values.extend(names)
    cursor.execute(
        f'UPDATE {table} SET collector_id = %s, sender_id = %s, observed_at = %s, '  # nosec B608
        f'state = CASE {key} {cases} ELSE state END '
        f'WHERE host_id = %s AND source_id = %s AND {key} IN ({placeholders})', values,
    )


def save_state_delta(cursor, table, key, identity, delta, observed_at):
    scope = (identity.host_id, identity.source_id)
    added = []
    for name, state in delta['added'].items():
        added.append(identity.values() + (name, json.dumps(state), observed_at))
    if added:
        cursor.executemany(
            f'INSERT INTO {table} (host_id, source_id, collector_id, sender_id, {key}, state, observed_at) '  # nosec B608
            'VALUES (%s, %s, %s, %s, %s, %s, %s)', added,
        )

    batch = []
    size = 0
    for name, (_, state) in delta['changed'].items():
        payload = json.dumps(state)
        # JSON is ASCII-escaped already. Allow space for SQL escaping and the key.
        row_size = 4 * len(name) + 2 * len(payload) + 32
        if batch and (len(batch) >= STATE_BATCH_ROWS or size + row_size > STATE_BATCH_BYTES):
            update_state_batch(cursor, table, key, identity, observed_at, batch)
            batch, size = [], 0
        batch.append((name, payload))
        size += row_size
    if batch:
        update_state_batch(cursor, table, key, identity, observed_at, batch)

    removed = list(delta['removed'])
    for offset in range(0, len(removed), STATE_BATCH_ROWS):
        batch_names = removed[offset:offset + STATE_BATCH_ROWS]
        placeholders = ', '.join(['%s'] * len(batch_names))
        cursor.execute(
            f'DELETE FROM {table} WHERE host_id = %s AND source_id = %s '  # nosec B608
            f'AND {key} IN ({placeholders})', scope + tuple(batch_names),
        )


def save_checkpoint(cursor, kind, identity, observed_at, process_boot_id):
    args = (identity.host_id, kind, identity.source_id, identity.collector_id, identity.sender_id, observed_at)
    sql = ('INSERT INTO collector_snapshots '
           '(host_id, source_type, source_id, collector_id, sender_id, observed_at')
    values = 'VALUES (%s, %s, %s, %s, %s, %s'
    updates = ('collector_id = VALUES(collector_id), sender_id = VALUES(sender_id), '
               'observed_at = VALUES(observed_at)')
    if process_boot_id is not None:
        if kind != 'processes':
            raise SnapshotError('Only process checkpoints may store a boot ID.')
        sql += ', process_boot_id'
        values += ', %s'
        updates += ', process_boot_id = VALUES(process_boot_id)'
        args += (process_boot_id,)
    cursor.execute(sql + ') ' + values + ') ON DUPLICATE KEY UPDATE ' + updates, args)


def save_snapshot(connection, kind, identity, previous, current, events, observed_at, *, process_boot_id=None):
    """Write history, current state and completion marker in the caller's transaction."""
    _, history, table, key = TABLES[kind]
    # Compare the full stored payload, including process measurements.
    # Only a complete observation may reach this function under the snapshot lock.
    delta = plan_state_delta(previous, current)
    write_limit = positive_setting('SIEM_SNAPSHOT_MAX_WRITE_ROWS', MAX_WRITES, MAX_WRITES)
    write_count = len(events) + len(delta['added']) + len(delta['changed']) + len(delta['removed'])
    if write_count > write_limit:
        raise ResourceLimitError()
    scope = identity.values()
    with connection.cursor() as cursor:
        if events:
            history_rows = []
            for name, event, before, after in events:
                if before is not None:
                    before = json.dumps(before)
                if after is not None:
                    after = json.dumps(after)
                history_rows.append(scope + (name, event, observed_at, before, after))
            cursor.executemany(
                f'INSERT INTO {history} '  # nosec B608
                f'(host_id, source_id, collector_id, sender_id, {key}, event_type, event_time, previous_state, current_state) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                history_rows,
            )
        # State rows keep their last write time. The marker records every complete observation.
        save_state_delta(cursor, table, key, identity, delta, observed_at)
        save_checkpoint(cursor, kind, identity, observed_at, process_boot_id)
    return delta


def acquire_snapshot_lock(connection, kind, host_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        digest = hashlib.sha256(f'{database}:{kind}:{host_id}'.encode()).hexdigest()
        name = 'siem.snapshot.' + digest[:48]
        cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
        if cursor.fetchone() != (1,):
            raise CollectionBusy('Another snapshot operation is active.')
    return name


def begin_snapshot_transaction(connection):
    # The named lock protects snapshot reads. READ COMMITTED avoids locking
    # the gap around a missing health row shared by unrelated first runs.
    with connection.cursor() as cursor:
        cursor.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
    connection.begin()


def begin_snapshot(connection, kind, attempt=None):
    """Read the last snapshot inside a fresh transaction and a host-specific lock."""
    lock = None
    try:
        identity = get_identity(connection, kind)
        connection.rollback()
        if attempt is not None:
            attempt.bind(connection, identity)
        lock = acquire_snapshot_lock(connection, kind, identity.host_id)
        # Discard preliminary reads so repeatable-read cannot reuse stale state.
        connection.rollback()
        begin_snapshot_transaction(connection)
        if get_identity(connection, kind) != identity:
            raise IdentityError('Identity changed while acquiring the snapshot lock.')
        previous, marker = get_previous(connection, kind, identity)
        return identity, previous, marker, lock
    except BaseException:
        try:
            connection.rollback()
            release_snapshot_lock(connection, lock)
        except (pymysql.MySQLError, SnapshotError):
            pass
        raise


def release_snapshot_lock(connection, lock):
    if lock is not None:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (lock,))
            if cursor.fetchone() != (1,):
                raise SnapshotError('Snapshot lock release failed.')
