"""Auth event and read-position SQL. The caller owns the transaction."""

import pymysql

from database.identity import identity_schema_enabled


def save_event(cursor, event, *, identity=None):
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
        return 0
    return 1


def load_position(cursor, collector_id, device, inode, *, source_scope=0):
    scoped = source_scope != 0 or identity_schema_enabled(cursor.connection)
    scope_filter = " AND source_scope = %s" if scoped else ""
    values = (collector_id, device, inode)
    if scoped:
        values += (source_scope,)
    cursor.execute(
        f"""
        SELECT last_position, position_hash FROM auth_ingestion_state
        WHERE collector_id = %s AND file_device = %s AND file_inode = %s
          {scope_filter}
        """,
        values,
    )
    return cursor.fetchone()


def save_position(cursor, collector_id, device, inode, filename, position, digest, *, source_scope=0):
    fields = ("collector_id", "file_device", "file_inode", "logfile", "last_position", "position_hash")
    values = (collector_id, device, inode, filename, position, digest)
    if source_scope != 0 or identity_schema_enabled(cursor.connection):
        fields += ("source_scope",)
        values += (source_scope,)
    placeholders = ", ".join(["%s"] * len(fields))
    cursor.execute(
        f"INSERT INTO auth_ingestion_state ({', '.join(fields)}) VALUES ({placeholders}) "
        "ON DUPLICATE KEY UPDATE logfile = %s, last_position = %s, position_hash = %s",
        values + (filename, position, digest),
    )
