"""Auth event and read-position SQL. The caller owns the transaction."""

import pymysql

from database.identity import identity_schema_enabled
from ingestion.auth.identity import AuthCollectionError


def _save_legacy_event(cursor, event, *, identity=None):
    """Insert a parsed event; suppress only a duplicate event_hash error."""
    try:
        fields = ("event_time", "hostname", "source_ip", "username", "event_type",
                  "service", "raw_message", "event_hash")
        values = []
        for key in fields:
            values.append(event[key])
        fields += ("auth_method", "source_port")
        values.append(event.get("auth_method"))
        values.append(event.get("source_port"))
        values = tuple(values)
        if identity is not None:
            fields += ("host_id", "source_id", "collector_id", "sender_id", "source_scope")
            values += identity.values() + (identity.source_id,)
        placeholders = ", ".join(["%s"] * len(fields))
        sql = f"INSERT INTO auth_events ({', '.join(fields)}) VALUES ({placeholders})"
        cursor.execute(sql, values)
    except pymysql.IntegrityError as error:
        if error.args[0] != 1062:
            raise
        source_scope = 0
        if identity is not None:
            source_scope = identity.source_id
        scoped = source_scope != 0 or identity_schema_enabled(cursor.connection)
        sql = ("SELECT event_time, hostname, source_ip, username, event_type, service "
               "FROM auth_events WHERE event_hash = %s")
        parameters = (event["event_hash"],)
        if scoped:
            sql += " AND source_scope = %s"
            parameters += (source_scope,)
        cursor.execute(sql + " FOR SHARE", parameters)
        stored = cursor.fetchone()
        expected = (event["event_time"], event["hostname"], event["source_ip"],
                    event["username"], event["event_type"], event["service"])
        if stored != expected:
            raise
        return 0
    return 1



def save_event(cursor, event, *, identity=None, generation=None, position=None):
    """The collector writes verified occurrences; old direct callers stay legacy."""
    if generation is None and position is None:
        return _save_legacy_event(cursor, event, identity=identity)
    if (not isinstance(generation, bytes) or len(generation) != 32 or generation == bytes(32)
            or type(position) is not int or not 0 <= position < 2**64):
        raise AuthCollectionError('Invalid Auth event occurrence identity.')
    scope = 0
    if identity is not None:
        scope = identity.source_id
    fields = ('event_time', 'hostname', 'source_ip', 'username', 'event_type', 'service',
              'raw_message', 'event_hash', 'auth_method', 'source_port')
    values = []
    for field in fields:
        values.append(event.get(field))
    expected = tuple(values)
    lookup = ('SELECT ' + ','.join(fields) + ' FROM auth_events WHERE source_scope=%s '
              'AND file_generation=%s AND file_position=%s FOR SHARE')
    origin = (scope, generation, position)
    cursor.execute(lookup, origin)
    stored = cursor.fetchone()
    if stored is not None:
        if stored != expected:
            raise AuthCollectionError('Auth occurrence content changed; checkpoint retained.')
        return 0
    cursor.execute('SELECT 1 FROM auth_events WHERE source_scope=%s AND event_hash=%s '
                   'AND (file_generation IS NULL OR file_generation<>%s) LIMIT 1 FOR SHARE',
                   (scope, event['event_hash'], generation))
    if cursor.fetchone() is not None:
        raise AuthCollectionError('Ambiguous Auth occurrence origin; checkpoint retained.')
    fields += ('file_generation', 'file_position')
    values.extend((generation, position))
    if identity is not None:
        fields += ('host_id', 'source_id', 'collector_id', 'sender_id', 'source_scope')
        values.extend(identity.values() + (scope,))
    placeholders = ','.join(['%s'] * len(fields))
    try:
        cursor.execute('INSERT INTO auth_events (' + ','.join(fields) + ') VALUES (' + placeholders + ')', tuple(values))
    except pymysql.IntegrityError as error:
        if error.args[0] != 1062:
            raise
        cursor.execute(lookup, origin)
        if cursor.fetchone() != expected:
            raise
        return 0
    return 1

def load_position(cursor, collector_id, device, inode, *, source_scope=0, with_origin=False):
    fields = 'last_position, position_hash'
    if with_origin:
        fields += ', generation_key, prefix_sha, observed_size, observed_sha, file_mtime_ns'
    scoped = source_scope != 0 or identity_schema_enabled(cursor.connection)
    scope_filter = " AND source_scope = %s" if scoped else ""
    values = (collector_id, device, inode)
    if scoped:
        values += (source_scope,)
    cursor.execute(
        f"""
        SELECT {fields} FROM auth_ingestion_state
        WHERE collector_id = %s AND file_device = %s AND file_inode = %s
          {scope_filter}
        """,
        values,
    )
    return cursor.fetchone()


def save_position(cursor, collector_id, device, inode, filename, position, digest, *, source_scope=0,
                  generation=None, prefix_sha=None, observed_size=None, observed_sha=None, mtime_ns=None):
    fields = ("collector_id", "file_device", "file_inode", "logfile", "last_position", "position_hash")
    values = (collector_id, device, inode, filename, position, digest)
    if source_scope != 0 or identity_schema_enabled(cursor.connection):
        fields += ("source_scope",)
        values += (source_scope,)
    updates = 'logfile=%s,last_position=%s,position_hash=%s'
    updated_values = (filename, position, digest)
    if generation is not None:
        origin = (generation, prefix_sha, observed_size, observed_sha, mtime_ns)
        fields += ('generation_key', 'prefix_sha', 'observed_size', 'observed_sha', 'file_mtime_ns')
        values += origin
        updates += ',generation_key=%s,prefix_sha=%s,observed_size=%s,observed_sha=%s,file_mtime_ns=%s'
        updated_values += origin
    placeholders = ", ".join(["%s"] * len(fields))
    cursor.execute(
        f"INSERT INTO auth_ingestion_state ({', '.join(fields)}) VALUES ({placeholders}) "
        'ON DUPLICATE KEY UPDATE ' + updates,
        values + updated_values,
    )
