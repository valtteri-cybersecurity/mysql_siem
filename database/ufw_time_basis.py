"""Read-only UFW time-basis classification, never an upgrade approval."""

import time
from datetime import datetime, timedelta

from database.migrate import ufw_timestamp_schema
from ingestion.splitter import parse_ufw_line
from ingestion.ufw_to_mysql import convert_timestamp

UTC_VERIFIED = 'UTC_VERIFIED'
LOCAL_TIME_VERIFIED = 'LOCAL_TIME_VERIFIED'
UNVERIFIED = 'UNVERIFIED'


def matches_precision(stored, expected, precision):
    """Allow only truncation or MySQL rounding at the known column precision."""
    quantum = 10 ** (6 - precision)
    truncated = expected.replace(microsecond=expected.microsecond // quantum * quantum)
    if stored == truncated:
        return True
    if expected.microsecond % quantum * 2 < quantum:
        return False
    try:
        rounded = truncated + timedelta(microseconds=quantum)
    except OverflowError:
        return False
    return stored == rounded


def classify_event_time(raw_line, event_time, precision):
    """Classify one row using proven DATETIME precision (0..6), without I/O.

    After a precision migration, do not assume the former precision was zero.
    Supply an older precision only when independent evidence establishes it.
    """
    if type(precision) is not int or not 0 <= precision <= 6:
        return UNVERIFIED
    if not isinstance(event_time, datetime) or event_time.tzinfo is not None:
        return UNVERIFIED
    if not isinstance(raw_line, str) or len(raw_line) > 65536:
        return UNVERIFIED
    timestamp = parse_ufw_line(raw_line)['timestamp']
    if not isinstance(timestamp, str):
        return UNVERIFIED
    if timestamp.endswith('Z'):
        local_time = timestamp[:-1]
    else:
        zone = timestamp[-6:]
        if len(zone) != 6 or zone[0] not in ('+', '-') or zone[3] != ':':
            return UNVERIFIED
        if not zone[1:3].isascii() or not zone[1:3].isdigit():
            return UNVERIFIED
        if not zone[4:6].isascii() or not zone[4:6].isdigit():
            return UNVERIFIED
        if zone == '-00:00' or int(zone[1:3]) > 23 or int(zone[4:6]) > 59:
            return UNVERIFIED
        local_time = timestamp[:-6]
    base_time, point, fraction = local_time.partition('.')
    if len(base_time) != 19 or base_time[10] != 'T':
        return UNVERIFIED
    if point:
        if not 1 <= len(fraction) <= 6:
            return UNVERIFIED
        if not fraction.isascii() or not fraction.isdigit():
            return UNVERIFIED
    try:
        utc = convert_timestamp(timestamp)
        local = datetime.fromisoformat(local_time)
    except (ValueError, OverflowError):
        return UNVERIFIED
    if local.year < 1000:
        return UNVERIFIED
    utc_matches = matches_precision(event_time, utc, precision)
    local_matches = matches_precision(event_time, local, precision)
    if utc_matches:
        if local_matches and utc != local:
            return UNVERIFIED
        return UTC_VERIFIED
    if local_matches:
        return LOCAL_TIME_VERIFIED
    return UNVERIFIED


def classify_history(connection, *, after_id=0, max_rows=5000, max_seconds=20):
    """Return bounded counts and a continuation ID; never write checkpoints.

    Uses current column precision. The result is diagnostic, not proof that
    original migration rows survive. complete=False requires another pass.
    Collection should be paused or a stable snapshot used for a stable report.
    """
    if type(after_id) is not int or not 0 <= after_id < 2**64:
        raise ValueError('after_id must be an unsigned event ID.')
    if type(max_rows) is not int or not 1 <= max_rows <= 100000:
        raise ValueError('max_rows must be within 1..100000.')
    if type(max_seconds) is not int or not 1 <= max_seconds <= 120:
        raise ValueError('max_seconds must be within 1..120.')
    deadline = time.monotonic() + max_seconds
    column = ufw_timestamp_schema(connection)
    if column is None or column[0] != 'datetime':
        raise ValueError('UFW event_time must be DATETIME.')
    precision = column[1]
    if type(precision) is not int or not 0 <= precision <= 6:
        raise ValueError('Unknown UFW DATETIME precision.')
    result = {UTC_VERIFIED: 0, LOCAL_TIME_VERIFIED: 0, UNVERIFIED: 0,
              'last_id': after_id, 'complete': False}
    with connection.cursor() as cursor:
        cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(1000) */ COALESCE(MAX(id),0) FROM ufw_log')
        upper = cursor.fetchone()[0]
    processed = 0
    while result['last_id'] < upper and processed < max_rows:
        if time.monotonic() >= deadline:
            break
        limit = min(256, max_rows - processed)
        with connection.cursor() as cursor:
            cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(1000) */ id,event_time,raw_line FROM ufw_log '
                           'WHERE id > %s AND id <= %s ORDER BY id LIMIT %s',
                           (result['last_id'], upper, limit))
            rows = cursor.fetchall()
        if not rows:
            break
        for event_id, stored, raw_line in rows:
            if time.monotonic() >= deadline:
                return result
            basis = classify_event_time(raw_line, stored, precision)
            result[basis] += 1
            result['last_id'] = event_id
            processed += 1
    result['complete'] = result['last_id'] >= upper
    return result
