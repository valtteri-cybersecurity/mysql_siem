from datetime import datetime, timedelta, timezone

from database.identity import configured_identity, identity_schema_enabled


def get_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_day_bounds(observed_at):
    if not isinstance(observed_at, datetime) or observed_at.utcoffset() is None:
        raise ValueError("Security measurement time must include a timezone.")
    observed_at = observed_at.astimezone(timezone.utc)
    start = observed_at.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=1)


def count_today(connection, sql_message, observed_at):
    if observed_at is None:
        observed_at = get_timestamp()
    start, end = utc_day_bounds(observed_at)
    # MySQL DATETIME parameters are UTC-naive only at this database boundary.
    parameters = (start.replace(tzinfo=None), end.replace(tzinfo=None))
    cursor = connection.cursor()
    try:
        identity = configured_identity(cursor, "security")
        if identity_schema_enabled(connection):
            sql_message += " AND host_id <=> %s"
            parameters += (identity.host_id if identity is not None else None,)
        cursor.execute(sql_message, parameters)
        return cursor.fetchone()[0]
    finally:
        cursor.close()


def get_failed_logins(connection, observed_at=None):
    # Count ingested, deduplicated SSH attempts; never infer UTC from log text.
    sql_message = """
    SELECT COUNT(*) FROM auth_events
    WHERE event_type = 'SSH_AUTH_FAILURE' AND service = 'sshd'
      AND event_time >= %s AND event_time < %s
    """
    return count_today(connection, sql_message, observed_at)


def get_blocks_today(connection, observed_at=None):
    sql_message = """
    SELECT COUNT(*) AS block_count_today FROM ufw_log
    WHERE action = 'BLOCK' AND event_time >= %s AND event_time < %s
    """
    return count_today(connection, sql_message, observed_at)


def get_unique_ips_today(connection, observed_at=None):
    sql_message = """
    SELECT COUNT(DISTINCT src_ip) AS unique_ips_today FROM ufw_log
    WHERE action = 'BLOCK' AND event_time >= %s AND event_time < %s
    """
    return count_today(connection, sql_message, observed_at)


def get_uptime():
    tiedosto = "/proc/uptime"

    with open(tiedosto, 'r') as infile:
        uptime = float(infile.readline().strip().split()[0])
        uptime = round(uptime / 3600, 2)
    return uptime


def get_data(connection):
    observed_at = get_timestamp()
    uptime = get_uptime()
    unique_ips = get_unique_ips_today(connection, observed_at)
    blocks = get_blocks_today(connection, observed_at)
    failed_logins = get_failed_logins(connection, observed_at)

    return {
        'uptime': uptime,
        'blocks': blocks,
        'failed_logins': failed_logins,
        'unique_ips': unique_ips,
        'date': observed_at,
    }
