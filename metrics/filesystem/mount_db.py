"""Transactional storage for complete local mount observations."""

import hashlib
from datetime import datetime, timedelta
from os.path import normpath

from database.connection import get_connection
from database.identity import (
    IdentityError,
    configured_identity,
    identity_schema_enabled,
)
from metrics.filesystem.mounts import (
    LOCAL_FILESYSTEMS,
    MountCollection,
    MountMeasurement,
)
from metrics.snapshot import release_snapshot_lock

INSERT_MEASUREMENT = '''INSERT INTO filesystem_mount_metrics
    (host_id, source_id, collector_id, sender_id, measured_at, mount_point, filesystem_type,
     total_bytes, available_bytes, total_inodes, free_inodes, read_only, mount_options)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

SELECT_MEASUREMENTS = '''SELECT collector_id, sender_id, measured_at, mount_point, filesystem_type,
    total_bytes, available_bytes, total_inodes, free_inodes, read_only, mount_options
    FROM filesystem_mount_metrics
    WHERE host_id = %s AND source_id = %s AND measured_at IN %s'''


class MountStorageError(ValueError):
    """The observation batch cannot be stored safely."""


def _validate_measurement(row):
    if not isinstance(row, MountMeasurement):
        raise MountStorageError('Invalid mount measurement.')
    path = row.mount_point
    if (not isinstance(path, bytes) or len(path) > 4096 or not path.startswith(b'/')
            or b'\0' in path or path.startswith(b'//') or normpath(path) != path):
        raise MountStorageError('Invalid mount point.')
    stamp = row.measured_at
    if not isinstance(stamp, datetime) or stamp.year < 1000 or stamp.utcoffset() != timedelta(0):
        raise MountStorageError('Mount measurement requires a UTC timestamp.')
    if not isinstance(row.filesystem_type, str) or row.filesystem_type not in LOCAL_FILESYSTEMS:
        raise MountStorageError('Invalid filesystem type.')
    options = row.mount_options
    if not isinstance(options, str) or options.split(',', 1)[0] not in ('ro', 'rw') or '\0' in options:
        raise MountStorageError('Invalid mount options.')
    if len(options.encode('utf-8')) > 65535 or type(row.read_only) is not bool:
        raise MountStorageError('Invalid mount options or read-only flag.')

    for value in (row.total_bytes, row.used_bytes, row.free_bytes, row.available_bytes,
                  row.total_inodes, row.used_inodes, row.free_inodes):
        if type(value) is not int or not 0 <= value < 2**64:
            raise MountStorageError('Invalid filesystem counter.')
    if row.available_bytes > row.free_bytes or row.used_bytes + row.free_bytes != row.total_bytes:
        raise MountStorageError('Inconsistent filesystem capacity.')
    if row.used_inodes + row.free_inodes != row.total_inodes:
        raise MountStorageError('Inconsistent filesystem inode counts.')


def _validated_rows(collection):
    if not isinstance(collection, MountCollection) or collection.status != 'complete' or not collection.measurements:
        raise MountStorageError('A complete, nonempty mount collection is required.')
    rows = {}
    paths = set()
    for row in collection.measurements:
        _validate_measurement(row)
        if row.mount_point in paths:
            raise MountStorageError('Duplicate mount point in the collection.')
        paths.add(row.mount_point)
        key = (row.measured_at.replace(tzinfo=None), row.mount_point)
        rows[key] = key + (row.filesystem_type, row.total_bytes, row.available_bytes,
                           row.total_inodes, row.free_inodes, row.read_only, row.mount_options)
    return rows


def _get_identity(connection, cursor):
    if not identity_schema_enabled(connection):
        raise IdentityError('Mount measurements require registered identities.')
    cursor.execute("SELECT status FROM schema_migrations WHERE version = '034'")
    if cursor.fetchone() != ('APPLIED',):
        raise MountStorageError('Filesystem migration 034 is incomplete.')
    identity = configured_identity(cursor, 'filesystem')
    if identity is None:
        raise IdentityError('A registered filesystem source is required.')
    return identity


def _insert_measurements(cursor, identity, rows):
    timestamps = set()
    for stamp, _ in rows:
        timestamps.add(stamp)
    cursor.execute(SELECT_MEASUREMENTS, (identity.host_id, identity.source_id, tuple(sorted(timestamps))))
    matched = set()
    scope = identity.values()
    for stored in cursor.fetchall():
        key = stored[2:4]
        if key not in rows:
            continue
        if key in matched or stored != scope[2:] + rows[key]:
            raise MountStorageError('Conflicting mount measurement in history.')
        matched.add(key)
    if matched:
        if len(matched) != len(rows):
            raise MountStorageError('Only part of this mount collection already exists.')
        return 0

    values = []
    for row in rows.values():
        values.append(scope + row)
    cursor.executemany(INSERT_MEASUREMENT, values)
    return len(values)


def save_mount_metrics(collection):
    """Commit a collection on a dedicated connection. Return zero for an exact replay."""
    rows = _validated_rows(collection)
    connection = get_connection(quiet=True, binary_parameters=True)
    if connection is None:
        raise MountStorageError('Could not connect to the mount history database.')

    lock = None
    try:
        with connection.cursor() as cursor:
            identity = _get_identity(connection, cursor)
            connection.rollback()
            cursor.execute('SELECT DATABASE()')
            database = cursor.fetchone()[0]
            scope = f'{database}:{identity.host_id}:{identity.source_id}'
            name = 'siem.fs.mount.' + hashlib.sha256(scope.encode()).hexdigest()[:48]
            cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
            if cursor.fetchone() != (1,):
                raise MountStorageError('Another writer holds the mount history lock.')
            lock = name

            # Refresh the read view and registry binding after serializing writers.
            connection.begin()
            if _get_identity(connection, cursor) != identity:
                raise IdentityError('Filesystem identity changed while acquiring the lock.')
            inserted = _insert_measurements(cursor, identity, rows)
        connection.commit()
        return inserted
    except BaseException:
        if connection.open:
            connection.rollback()
        raise
    finally:
        try:
            if lock is not None and connection.open:
                release_snapshot_lock(connection, lock)
        finally:
            connection.close()
