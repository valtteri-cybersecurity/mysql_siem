"""Approved identities, immutable event history and transactional read positions."""

import json
from datetime import datetime, timezone

import pymysql

from database.identity import (
    IdentityError,
    configured_identity,
    identity_schema_enabled,
)
from ingestion.audit.targets import validate_targets

EVENT_FIELDS = {
    'source_id', 'node', 'event_id', 'serial', 'event_time', 'event_hash', 'targets', 'paths',
    'auid', 'uid', 'euid', 'pid', 'ppid', 'program', 'executable', 'arch', 'syscall_number',
    'syscall', 'operation', 'success', 'exit_code', 'rule_key',
}


def begin_collection(connection):
    """The caller must roll back and release the named lock on every failure."""
    if not identity_schema_enabled(connection):
        raise IdentityError('Audit requires the registered identity schema.')
    connection.rollback()
    connection.begin()
    with connection.cursor() as cursor:
        cursor.execute("SELECT status FROM schema_migrations WHERE version = '020'")
        if cursor.fetchone() != ('APPLIED',):
            raise IdentityError('Audit migration 020 is incomplete.')
        identity = configured_identity(cursor, 'audit')
        if identity is None:
            raise IdentityError('SIEM_AUDIT_SOURCE_ID and SIEM_COLLECTOR_ID are required.')
        name = f'mysql_siem_audit_{identity.host_id}:{identity.source_id}'
        cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
        row = cursor.fetchone()
        if row != (1,):
            connection.rollback()
            return None, None
    return identity, name


def release_lock(connection, name):
    if name is not None:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (name,))


def load_targets(cursor):
    cursor.execute('SELECT target_name, audit_key, definition FROM audit_targets '
                   'WHERE enabled = 1 ORDER BY target_name FOR SHARE')
    targets = []
    for name, key, raw in cursor.fetchall():
        definition = json.loads(raw)
        if not isinstance(definition, dict) or set(definition) != {'files', 'directories', 'executables'}:
            raise ValueError('Invalid stored Audit target definition.')
        targets.append(dict(definition, name=name, audit_key=key))
    return validate_targets(targets)


def load_checkpoint(cursor, identity):
    cursor.execute('SELECT collector_id, sender_id, position FROM audit_checkpoints '
                   'WHERE host_id = %s AND source_id = %s FOR UPDATE', (identity.host_id, identity.source_id))
    row = cursor.fetchone()
    if row is None:
        return None
    if row[:2] != (identity.collector_id, identity.sender_id):
        raise IdentityError('Audit checkpoint belongs to another approved writer; maintenance required.')
    return json.loads(row[2])


def event_values(event, identity):
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        raise ValueError('Unexpected Audit event fields; raw data must not be stored.')
    if event['source_id'] != str(identity.source_id) or not event['targets'] or not event['paths']:
        raise IdentityError('Audit event source or targets do not match the approved identity.')
    instant = event['event_time']
    if not isinstance(instant, datetime) or instant.utcoffset() is None:
        raise ValueError('Audit event time must include UTC timezone information.')
    for field in ('auid', 'uid', 'euid', 'pid', 'ppid'):
        value = event[field]
        if value is not None and (type(value) is not int or not 0 <= value < 2**64):
            raise ValueError('Invalid Audit numeric metadata.')
    metadata = dict(event)
    metadata['event_time'] = instant.astimezone(timezone.utc).isoformat()
    metadata = json.dumps(metadata, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
    # One row per audit event. Primary target/path are deterministic conveniences;
    # metadata retains ALL matched paths and target groups, including replacements.
    paths = sorted(event['paths'], key=lambda path: path['path'])
    target = min(event['targets'])
    success = None if event['success'] is None else int(event['success'])
    return (*identity.values(), target, paths[0]['path'], event['rule_key'] or '',
            instant.astimezone(timezone.utc).replace(tzinfo=None), event['event_id'], event['event_hash'],
            None, event['auid'], event['uid'], event['euid'], event['pid'], event['ppid'],
            event['executable'], event['operation'], success, metadata)


def save_batch(cursor, identity, events, checkpoint):
    """No commit here: the caller commits history and position together."""
    if len(events) > 10000 or not isinstance(checkpoint, dict) or checkpoint.get('version') != 2:
        raise ValueError('Invalid Audit batch or checkpoint.')
    from ingestion.audit.get import validate_log_position

    validate_log_position(checkpoint, str(identity.source_id))
    inserted = 0
    for event in events:
        values = event_values(event, identity)
        try:
            cursor.execute(
                'INSERT INTO audit_events '
                '(host_id, source_id, collector_id, sender_id, target_type, target_path, audit_key, '
                'event_time, audit_event_id, event_hash, boot_id, auid, uid, euid, pid, ppid, '
                'executable, operation, success, metadata) VALUES '
                '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', values)
            inserted += 1
        except pymysql.IntegrityError as error:
            if error.args[0] != 1062:
                raise
            # INSERT-only history privileges suffice; never overwrite an old row.
            cursor.execute('SELECT host_id, metadata FROM audit_events WHERE source_id = %s AND event_hash = %s',
                           (identity.source_id, event['event_hash']))
            row = cursor.fetchone()
            if row is None or row[0] != identity.host_id or json.loads(row[1]) != json.loads(values[-1]):
                raise ValueError('Conflicting Audit event identity; checkpoint unchanged.') from None
    cursor.execute('INSERT INTO audit_checkpoints '
                   '(host_id, source_id, collector_id, sender_id, position, updated_at) '
                   'VALUES (%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE '
                   'position = VALUES(position), updated_at = VALUES(updated_at)',
                   (*identity.values(), json.dumps(checkpoint, sort_keys=True),
                    datetime.now(timezone.utc).replace(tzinfo=None)))
    return inserted
