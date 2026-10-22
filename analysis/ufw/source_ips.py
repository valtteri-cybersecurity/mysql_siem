"""Source-IP metrics for explicit UFW time intervals, without threat labels."""

from datetime import datetime
from ipaddress import ip_address

import pymysql

MAX_EVENTS = 100000
LOCK_NAME = "mysql_siem_analysis_source_ips"
EVENT_FIELDS = ("event_time", "src_ip", "action", "protocol", "dst_port", "dst_ip")
RESULT_FIELDS = (
    "period_start", "period_end", "source_ip", "total_events", "blocked_events",
    "allowed_events", "audited_events", "unique_destination_ports",
    "unique_destination_ips", "first_seen", "last_seen", "tcp_events", "udp_events",
)


class SourceIPAnalysisError(RuntimeError):
    """A safe-to-display analysis limit or locking failure."""


def validate_time_range(start_time, end_time):
    """Use the existing UFW naive DATETIME basis; do not assume SSH/DNS UTC."""
    for value in (start_time, end_time):
        if not isinstance(value, datetime) or value.tzinfo is not None or value.year < 1000:
            raise ValueError("Use naive datetimes matching UFW event_time, within the MySQL range.")
    if start_time >= end_time:
        raise ValueError("Start time must be before end time.")


def normalize_ip(value):
    """Canonical IPv4/IPv6, including private addresses; reject missing/scoped IPs."""
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def aggregate_source_ips(events, start_time, end_time, *, max_events=MAX_EVENTS):
    """Summarize an iterable of event dictionaries for [start_time, end_time).

    Every valid-source event contributes to total_events, including unknown
    actions/protocols. Only the named action/protocol counters are selective.
    Invalid/missing destinations affect their unique counts, not the event total.
    All raw rows count toward the safety limit. An over-limit result is never partial.
    """
    validate_time_range(start_time, end_time)
    if type(max_events) is not int or not 1 <= max_events <= 1000000:
        raise ValueError("max_events must be within 1..1000000.")
    groups = {}
    for count, event in enumerate(events, start=1):
        if count > max_events:
            raise SourceIPAnalysisError("Too many UFW events; use a shorter interval or a higher --max-events limit.")
        if not isinstance(event, dict):
            continue
        source_ip = normalize_ip(event.get("src_ip"))
        event_time = event.get("event_time")
        if (source_ip is None or not isinstance(event_time, datetime)
                or event_time.tzinfo is not None or not start_time <= event_time < end_time):
            continue
        if source_ip not in groups:
            groups[source_ip] = {
                "period_start": start_time, "period_end": end_time, "source_ip": source_ip,
                "total_events": 0, "blocked_events": 0, "allowed_events": 0, "audited_events": 0,
                "tcp_events": 0, "udp_events": 0,
                "first_seen": event_time, "last_seen": event_time,
                "destination_ports": set(), "destination_ips": set(),
            }
        group = groups[source_ip]
        group["total_events"] += 1
        group["first_seen"] = min(group["first_seen"], event_time)
        group["last_seen"] = max(group["last_seen"], event_time)
        for action, metric in (("BLOCK", "blocked_events"), ("ALLOW", "allowed_events"), ("AUDIT", "audited_events")):
            if event.get("action") == action:
                group[metric] += 1
        for protocol, metric in (("TCP", "tcp_events"), ("UDP", "udp_events")):
            if event.get("protocol") == protocol:
                group[metric] += 1
        port = event.get("dst_port")
        # UFW stores 0 for a missing port. bool must not become port 1.
        if type(port) is int and 1 <= port <= 65535:
            group["destination_ports"].add(port)
        destination_ip = normalize_ip(event.get("dst_ip"))
        if destination_ip is not None:
            group["destination_ips"].add(destination_ip)

    results = []
    for source_ip in sorted(groups):
        group = groups[source_ip]
        group["unique_destination_ports"] = len(group.pop("destination_ports"))
        group["unique_destination_ips"] = len(group.pop("destination_ips"))
        results.append(group)
    return results


def analyze_source_ips(connection, start_time, end_time, *, max_events=MAX_EVENTS):
    """Read-only API returning dictionaries; the caller owns the read transaction.

    SSCursor streams the bounded query instead of loading raw history into a
    list. Only per-IP counters and distinct destination sets stay in memory.
    """
    validate_time_range(start_time, end_time)
    if type(max_events) is not int or not 1 <= max_events <= 1000000:
        raise ValueError("max_events must be within 1..1000000.")
    with connection.cursor(pymysql.cursors.SSCursor) as cursor:
        cursor.execute(
            """
            SELECT event_time, src_ip, action, protocol, dst_port, dst_ip
            FROM ufw_log
            WHERE event_time >= %s AND event_time < %s
            ORDER BY event_time, id LIMIT %s
            """,
            (start_time, end_time, max_events + 1),
        )
        events = (dict(zip(EVENT_FIELDS, row)) for row in cursor)
        return aggregate_source_ips(events, start_time, end_time, max_events=max_events)


def run_source_ip_analysis(connection, start_time, end_time, *, max_events=MAX_EVENTS):
    """Atomically replace only this interval's summary; use a dedicated connection.

    Serializing summary runs prevents an older snapshot overwriting a newer
    recomputation. Raw UFW rows and all other summary intervals are preserved.
    """
    validate_time_range(start_time, end_time)
    if type(max_events) is not int or not 1 <= max_events <= 1000000:
        raise ValueError("max_events must be within 1..1000000.")
    summary = {"period_start": start_time, "period_end": end_time,
               "source_count": 0, "total_events": 0, "status": "SKIPPED"}
    locked = committed = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
            row = cursor.fetchone()
        if row is None or row[0] is None:
            raise SourceIPAnalysisError("Unable to acquire the Source IP Analysis lock.")
        if row[0] != 1:
            summary["reason"] = "Another Source IP Analysis run holds the lock."
            return summary
        locked = True
        connection.begin()
        results = analyze_source_ips(connection, start_time, end_time, max_events=max_events)
        with connection.cursor() as cursor:
            # Exact replacement also removes stale IPs after a corrected source
            # or an empty rerun. It never deletes other historical periods.
            cursor.execute(
                "DELETE FROM analysis_source_ips WHERE period_start = %s AND period_end = %s",
                (start_time, end_time),
            )
            if results:
                cursor.executemany(
                    """
                    INSERT INTO analysis_source_ips (
                        period_start, period_end, source_ip, total_events, blocked_events,
                        allowed_events, audited_events, unique_destination_ports,
                        unique_destination_ips, first_seen, last_seen, tcp_events, udp_events
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [tuple(result[field] for field in RESULT_FIELDS) for result in results],
                )
        connection.commit()
        committed = True
        summary.update(source_count=len(results), total_events=sum(item["total_events"] for item in results),
                       status="SUCCESS")
        return summary
    finally:
        try:
            if not committed:
                connection.rollback()
        finally:
            if locked:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))
                    row = cursor.fetchone()
                if row is None or row[0] != 1:
                    raise SourceIPAnalysisError("Source IP Analysis lock was lost.")
