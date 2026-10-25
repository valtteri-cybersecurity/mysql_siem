"""Shared transactional snapshot protocol for local state collectors.

Only Processes and Services use these SQL and locking helpers. SQL identifiers are constants;
payloads and identities are always parameters. No runtime DDL or registry writes.
"""

import hashlib
import json
from datetime import datetime, timezone

from database.identity import (
    IdentityError,
    configured_identity,
    identity_schema_enabled,
)

TABLES = {
    'processes': ('018', 'process_events', 'process_state', 'process_key'),
    'services': ('019', 'service_events', 'service_state', 'service_name'),
}


class SnapshotError(ValueError):
    """An incomplete observation or incompatible snapshot must not be committed."""


class CollectionBusy(SnapshotError):
    """Another run owns this host's collector lock."""


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
    _, _, table, key = TABLES[kind]
    with connection.cursor() as cursor:
        cursor.execute('SELECT source_id FROM collector_snapshots WHERE host_id = %s AND source_type = %s',
                       (identity.host_id, kind))
        marker = cursor.fetchone()
        if marker is not None and marker[0] != identity.source_id:
            raise IdentityError('Snapshot belongs to a different source; administrative recovery required.')
        # Identifiers come exclusively from TABLES; identity values are parameters.
        cursor.execute(f'SELECT {key}, state FROM {table} WHERE host_id = %s AND source_id = %s',  # nosec B608
                       (identity.host_id, identity.source_id))
        previous = {name: json.loads(state) for name, state in cursor.fetchall()}
    if marker is None and previous:
        raise SnapshotError('Current state has no completed baseline.')
    return previous, marker is not None


def save_snapshot(connection, kind, identity, current, events, observed_at):
    """Write history, current state and completion marker in the caller's transaction."""
    _, history, table, key = TABLES[kind]
    scope = identity.values()
    with connection.cursor() as cursor:
        if events:
            cursor.executemany(
                f'INSERT INTO {history} '  # nosec B608
                f'(host_id, source_id, collector_id, sender_id, {key}, event_type, event_time, previous_state, current_state) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                [scope + (name, event, observed_at,
                          json.dumps(before) if before is not None else None,
                          json.dumps(after) if after is not None else None)
                 for name, event, before, after in events],
            )
        cursor.execute(f'DELETE FROM {table} WHERE host_id = %s AND source_id = %s',  # nosec B608
                       (identity.host_id, identity.source_id))
        if current:
            cursor.executemany(
                f'INSERT INTO {table} (host_id, source_id, collector_id, sender_id, {key}, state, observed_at) '  # nosec B608
                'VALUES (%s, %s, %s, %s, %s, %s, %s)',
                [scope + (name, json.dumps(state), observed_at) for name, state in sorted(current.items())],
            )
        cursor.execute(
            'INSERT INTO collector_snapshots '
            '(host_id, source_type, source_id, collector_id, sender_id, observed_at) '
            'VALUES (%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE '
            'collector_id = VALUES(collector_id), sender_id = VALUES(sender_id), observed_at = VALUES(observed_at)',
            (identity.host_id, kind, identity.source_id, identity.collector_id, identity.sender_id, observed_at),
        )


def begin_snapshot(connection, kind):
    """Read the last snapshot inside a fresh transaction and a host-specific lock."""
    lock = None
    try:
        identity = get_identity(connection, kind)
        connection.rollback()
        with connection.cursor() as cursor:
            cursor.execute('SELECT DATABASE()')
            database = cursor.fetchone()[0]
            digest = hashlib.sha256(f'{database}:{kind}:{identity.host_id}'.encode()).hexdigest()
            name = 'siem.snapshot.' + digest[:48]
            cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
            if cursor.fetchone() != (1,):
                raise CollectionBusy('Another snapshot collection is running.')
            lock = name
        # Discard preliminary reads so repeatable-read cannot reuse stale state.
        connection.rollback()
        connection.begin()
        if get_identity(connection, kind) != identity:
            raise IdentityError('Identity changed while acquiring the snapshot lock.')
        previous, baseline = get_previous(connection, kind, identity)
        return identity, previous, baseline, lock
    except BaseException:
        connection.rollback()
        release_snapshot_lock(connection, lock)
        raise


def release_snapshot_lock(connection, lock):
    if lock is not None:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (lock,))
            if cursor.fetchone() != (1,):
                raise SnapshotError('Snapshot lock release failed.')
