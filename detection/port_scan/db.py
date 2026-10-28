"""Read a bounded selection of UFW rows for the existing detector."""

from datetime import datetime

from database.identity import identity_schema_enabled


def validate_time_range(start_time, end_time):
    for value in (start_time, end_time):
        if not isinstance(value, datetime) or value.tzinfo is not None:
            raise ValueError(
                "Use timezone-naive datetime values matching UFW event_time."
            )
        if value.year < 1000:
            raise ValueError("Time is outside the MySQL DATETIME range.")
    if start_time >= end_time:
        raise ValueError("Start time must be before end time.")


def get_db_data(connection, start_time, end_time):
    """Return dictionaries for [start_time, end_time), ordered by time and ID.

    The caller owns the connection and read transaction. Database errors are
    propagated; a failed query must never look like an empty successful run.
    """
    validate_time_range(start_time, end_time)
    from database.ufw_history import active_filter
    utc_only = active_filter(connection)
    identity_fields = ", host_id, source_id" if identity_schema_enabled(connection) else ""
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"""
            SELECT id, event_time, action, src_ip, dst_ip, protocol, dst_port{identity_fields}
            FROM ufw_log
            WHERE event_time >= %s AND event_time < %s{utc_only}
              AND action IN (%s, %s, %s)
              AND protocol IN (%s, %s)
            ORDER BY event_time, id
            """,
            (start_time, end_time, "BLOCK", "AUDIT", "ALLOW", "TCP", "UDP"),
        )
        events = []
        for row in cursor.fetchall():
            event = {
                    "id": row[0],
                    "event_time": row[1],
                    "action": row[2],
                    "src_ip": row[3],
                    "dst_ip": row[4],
                    "protocol": row[5],
                    "dst_port": row[6],
                }
            if len(row) > 7:
                event.update(host_id=row[7], source_id=row[8])
            events.append(event)
        return events
    finally:
        cursor.close()


def get_new_events(connection, last_event_id, batch_size):
    """Read IDs, not event times: delayed events must still be visited.

    Read every action so unsupported rows also advance the ID checkpoint.
    The existing collector serializes its writes through commit with GET_LOCK.
    """
    from database.ufw_history import active_filter
    utc_only = active_filter(connection)
    identity_fields = ", host_id, source_id" if identity_schema_enabled(connection) else ""
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT id, event_time, action, src_ip, dst_ip, protocol, dst_port{identity_fields}
            FROM ufw_log WHERE id > %s{utc_only} ORDER BY id LIMIT %s
            """,
            (last_event_id, batch_size),
        )
        events = []
        for row in cursor.fetchall():
            events.append(
                dict(
                    zip(
                        (
                            "id",
                            "event_time",
                            "action",
                            "src_ip",
                            "dst_ip",
                            "protocol",
                            "dst_port",
                            "host_id",
                            "source_id",
                        ),
                        row,
                    )
                )
            )
    return events
