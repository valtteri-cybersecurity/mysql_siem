"""Source-scoped Query Log reads for a future UI; detection queries stay unchanged."""

from datetime import datetime, timezone

from ingestion.dns.db import transaction, utc_datetime, validate_id

QUERY_LOG_COLUMNS = (
    "id",
    "source_id",
    "event_time",
    "raw_timestamp",
    "client_ip",
    "domain",
    "query_type",
    "response_code",
    "filtering_result",
    "filtering_reason",
    "upstream",
    "elapsed_ms",
    "cached",
    "created_at",
)


def get_dns_query_log(
    connection, source_id, limit=100, include_hidden=False, *, before=None
):
    """Return event dictionaries, newest first, after applying active hide rules.

    For the next page, pass before=(last_row["event_time"], last_row["id"]).
    Naive cursor times are database UTC; aware cursor times are converted to UTC.
    Each call owns its read transaction, as with the existing DNS storage helpers.
    This is a visibility view, not a detection query or an authorization boundary.
    """
    validate_id(source_id)
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Query Log limit must be within 1..1000.")
    if type(include_hidden) is not bool:
        raise ValueError("include_hidden must be a boolean.")
    before_time = before_id = None
    if before is not None:
        if not isinstance(before, tuple) or len(before) != 2:
            raise ValueError("Query Log cursor must contain a UTC time and event ID.")
        before_time, before_id = before
        if not isinstance(before_time, datetime):
            raise ValueError("Invalid Query Log cursor time.")
        if type(before_id) is not int or not 1 <= before_id < 2**64:
            raise ValueError("Invalid Query Log cursor event ID.")
        if before_time.tzinfo is None:
            before_time = before_time.replace(tzinfo=timezone.utc)
        before_time = utc_datetime(before_time)
    # Binary conversion handles IPv6 spellings. Dotted-part round trips below
    # reject leading-zero IPv4 parts that MySQL accepts but ipaddress rejects.
    with transaction(connection) as cursor:
        cursor.execute(
            """
            SELECT e.id, e.source_id, e.event_time, e.raw_timestamp, e.client_ip,
                   e.domain, e.query_type, e.response_code, e.filtering_result,
                   e.filtering_reason, e.upstream, e.elapsed_ms, e.cached, e.created_at
            FROM dns_events e
            WHERE e.source_id = %s
              AND (%s IS NULL OR e.event_time < %s
                   OR (e.event_time = %s AND e.id < %s))
              AND (%s = TRUE OR NOT EXISTS (
                  SELECT 1 FROM dns_client_filters f
                  WHERE f.source_id = e.source_id
                    AND f.enabled = TRUE AND f.hide_from_query_log = TRUE
                    AND INET6_ATON(f.client_ip) = INET6_ATON(e.client_ip)
                    AND (LOCATE('.', f.client_ip) = 0 OR
                         BINARY SUBSTRING_INDEX(f.client_ip, ':', -1) =
                         BINARY INET6_NTOA(INET6_ATON(SUBSTRING_INDEX(f.client_ip, ':', -1))))
                    AND (LOCATE('.', e.client_ip) = 0 OR
                         BINARY SUBSTRING_INDEX(e.client_ip, ':', -1) =
                         BINARY INET6_NTOA(INET6_ATON(SUBSTRING_INDEX(e.client_ip, ':', -1))))
              ))
            ORDER BY e.event_time DESC, e.id DESC
            LIMIT %s
            """,
            (
                source_id,
                before_time,
                before_time,
                before_time,
                before_id,
                include_hidden,
                limit,
            ),
        )
        events = []
        for row in cursor.fetchall():
            event = dict(zip(QUERY_LOG_COLUMNS, row))
            if event["cached"] is not None:
                event["cached"] = bool(event["cached"])
            events.append(event)
    return events
