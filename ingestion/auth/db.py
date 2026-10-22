"""Auth event and read-position SQL. The caller owns the transaction."""

import pymysql


def save_event(cursor, event):
    """Insert a parsed event; suppress only a duplicate event_hash error."""
    try:
        cursor.execute(
            """
            INSERT INTO auth_events
                (event_time, hostname, source_ip, username, event_type,
                 service, raw_message, event_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            tuple(event[key] for key in (
                "event_time", "hostname", "source_ip", "username", "event_type",
                "service", "raw_message", "event_hash",
            )),
        )
    except pymysql.IntegrityError as error:
        if error.args[0] != 1062:
            raise
        return 0
    return 1


def load_position(cursor, collector_id, device, inode):
    cursor.execute(
        """
        SELECT last_position, position_hash FROM auth_ingestion_state
        WHERE collector_id = %s AND file_device = %s AND file_inode = %s
        """,
        (collector_id, device, inode),
    )
    return cursor.fetchone()


def save_position(cursor, collector_id, device, inode, filename, position, digest):
    cursor.execute(
        """
        INSERT INTO auth_ingestion_state
            (collector_id, file_device, file_inode, logfile, last_position, position_hash)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            logfile = %s, last_position = %s, position_hash = %s
        """,
        (collector_id, device, inode, filename, position, digest,
         filename, position, digest),
    )
