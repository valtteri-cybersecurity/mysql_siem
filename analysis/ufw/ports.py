"""Descriptive UFW activity per destination IP, service port and protocol."""

from datetime import datetime

import pymysql

from analysis.ufw.source_ips import MAX_EVENTS, normalize_ip, validate_time_range

LOCK_NAME = "mysql_siem_analysis_ufw_ports"
EVENT_FIELDS = ("event_time", "dst_ip", "dst_port", "protocol", "action", "src_ip")
RESULT_FIELDS = (
    "period_start", "period_end", "destination_ip", "destination_port", "protocol",
    "total_events", "blocked_events", "allowed_events", "audited_events",
    "unique_source_ips", "first_seen", "last_seen",
)


class PortAnalysisError(RuntimeError):
    """A safe-to-display port analysis limit or locking failure."""



def validate_ports_schema(connection):
    """Read-only installer preflight, matching migration 011's required schema.

    Never repair or drop a table here. A mismatch requires explicit review of
    the migration before grants or scheduling can proceed.
    """
    table = "analysis_ufw_ports"
    with connection.cursor() as cursor:
        cursor.execute("""SELECT engine, table_type, table_collation FROM information_schema.tables
                       WHERE table_schema = DATABASE() AND table_name = %s""", (table,))
        if cursor.fetchone() != ("InnoDB", "BASE TABLE", "utf8mb4_bin"):
            raise PortAnalysisError("analysis_ufw_ports: missing table or wrong engine; inspect migration 011.")
        cursor.execute("""SELECT column_name, column_type, is_nullable, collation_name, column_default, extra
                       FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = %s""", (table,))
        actual = {name: (kind.lower(), nullable, collation, default.lower() if isinstance(default, str) else default, extra.lower())
                  for name, kind, nullable, collation, default, extra in cursor.fetchall()}
        expected = {}
        for name in ("period_start", "period_end", "first_seen", "last_seen"):
            expected[name] = ("datetime(6)", "NO", None, None, "")
        for name in ("total_events", "blocked_events", "allowed_events", "audited_events", "unique_source_ips"):
            expected[name] = ("bigint unsigned", "NO", None, None, "")
        expected.update({
            "id": ("bigint unsigned", "NO", None, None, "auto_increment"),
            "destination_ip": ("varchar(45)", "NO", "ascii_bin", None, ""),
            "destination_port": ("smallint unsigned", "NO", None, None, ""),
            "protocol": ("varchar(3)", "NO", "ascii_bin", None, ""),
            "updated_at": ("timestamp(6)", "NO", None, "current_timestamp(6)", "default_generated on update current_timestamp(6)"),
        })
        if actual != expected:
            raise PortAnalysisError("analysis_ufw_ports: column mismatch; inspect migration 011.")
        cursor.execute("""SELECT index_name, non_unique, column_name, sub_part, index_type, is_visible
                       FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = %s
                       ORDER BY index_name, seq_in_index""", (table,))
        indexes = {}
        for name, non_unique, column, prefix, kind, visible in cursor.fetchall():
            if prefix is not None or kind != "BTREE" or visible != "YES":
                raise PortAnalysisError("analysis_ufw_ports: invalid index; inspect migration 011.")
            indexes.setdefault(name, (non_unique, []))[1].append(column)
        if indexes != {
            "PRIMARY": (0, ["id"]),
            "uq_ufw_ports_period": (0, ["period_start", "period_end", "destination_ip", "destination_port", "protocol"]),
            "idx_ufw_ports_history": (1, ["destination_port", "protocol", "destination_ip", "period_start", "period_end"]),
        }:
            raise PortAnalysisError("analysis_ufw_ports: index mismatch; inspect migration 011.")
        cursor.execute("""SELECT tc.constraint_name, tc.constraint_type, tc.enforced, cc.check_clause
                       FROM information_schema.table_constraints AS tc
                       LEFT JOIN information_schema.check_constraints AS cc
                         ON cc.constraint_schema = tc.constraint_schema AND cc.constraint_name = tc.constraint_name
                       WHERE tc.table_schema = DATABASE() AND tc.table_name = %s""", (table,))
        constraints = {}
        for name, kind, enforced, clause in cursor.fetchall():
            if clause is not None:
                clause = clause.lower()
                for token in ("`", " ", "(", ")", chr(92), "\t", "\n", "\r", "_ascii", "_utf8mb4"):
                    clause = clause.replace(token, "")
            constraints[name] = (kind, enforced, clause)
        if constraints != {
            "PRIMARY": ("PRIMARY KEY", "YES", None),
            "uq_ufw_ports_period": ("UNIQUE", "YES", None),
            "chk_ufw_ports_period": ("CHECK", "YES", "period_start<period_end"),
            "chk_ufw_ports_seen": ("CHECK", "YES", "first_seen>=period_startandfirst_seen<=last_seenandlast_seen<period_end"),
            "chk_ufw_ports_port": ("CHECK", "YES", "destination_portbetween1and65535"),
            "chk_ufw_ports_protocol": ("CHECK", "YES", "protocolin'tcp','udp'"),
        }:
            raise PortAnalysisError("analysis_ufw_ports: constraint mismatch; inspect migration 011.")

def aggregate_ports(events, start_time, end_time, *, max_events=MAX_EVENTS):
    """Summarize [start, end); skip invalid targets, ports and non-TCP/UDP rows.

    Missing/invalid sources still count as target activity but not as unique IPs.
    Unknown actions count toward totals. The row limit includes rejected events.
    """
    validate_time_range(start_time, end_time)
    if type(max_events) is not int or not 1 <= max_events <= 1000000:
        raise ValueError("max_events must be within 1..1000000.")
    groups = {}
    for count, event in enumerate(events, start=1):
        if count > max_events:
            raise PortAnalysisError("Too many UFW events; use a shorter interval or a higher --max-events limit.")
        if not isinstance(event, dict):
            continue
        event_time = event.get("event_time")
        destination_ip = normalize_ip(event.get("dst_ip"))
        port = event.get("dst_port")
        protocol = event.get("protocol")
        if (destination_ip is None or type(port) is not int or not 1 <= port <= 65535
                or protocol not in ("TCP", "UDP") or not isinstance(event_time, datetime)
                or event_time.tzinfo is not None or not start_time <= event_time < end_time):
            continue
        key = (destination_ip, port, protocol)
        if key not in groups:
            groups[key] = {
                "period_start": start_time, "period_end": end_time,
                "destination_ip": destination_ip, "destination_port": port, "protocol": protocol,
                "total_events": 0, "blocked_events": 0, "allowed_events": 0, "audited_events": 0,
                "first_seen": event_time, "last_seen": event_time, "source_ips": set(),
            }
        group = groups[key]
        group["total_events"] += 1
        group["first_seen"] = min(group["first_seen"], event_time)
        group["last_seen"] = max(group["last_seen"], event_time)
        for action, metric in (("BLOCK", "blocked_events"), ("ALLOW", "allowed_events"), ("AUDIT", "audited_events")):
            if event.get("action") == action:
                group[metric] += 1
        source_ip = normalize_ip(event.get("src_ip"))
        if source_ip is not None:
            group["source_ips"].add(source_ip)
    results = []
    for key in sorted(groups):
        group = groups[key]
        group["unique_source_ips"] = len(group.pop("source_ips"))
        results.append(group)
    return results


def analyze_ports(connection, start_time, end_time, *, max_events=MAX_EVENTS):
    """Read-only bounded streaming API; the caller owns its read transaction."""
    validate_time_range(start_time, end_time)
    if type(max_events) is not int or not 1 <= max_events <= 1000000:
        raise ValueError("max_events must be within 1..1000000.")
    with connection.cursor(pymysql.cursors.SSCursor) as cursor:
        cursor.execute(
            """
            SELECT event_time, dst_ip, dst_port, protocol, action, src_ip
            FROM ufw_log
            WHERE event_time >= %s AND event_time < %s
            ORDER BY event_time, id LIMIT %s
            """,
            (start_time, end_time, max_events + 1),
        )
        events = (dict(zip(EVENT_FIELDS, row)) for row in cursor)
        return aggregate_ports(events, start_time, end_time, max_events=max_events)


def run_port_analysis(connection, start_time, end_time, *, max_events=MAX_EVENTS):
    """Replace only the exact interval in one transaction; dedicated connection.

    A separate port-analysis lock serializes reruns without sharing detection or
    Source IP state. Empty reruns remove stale groups only from this interval.
    """
    validate_time_range(start_time, end_time)
    if type(max_events) is not int or not 1 <= max_events <= 1000000:
        raise ValueError("max_events must be within 1..1000000.")
    summary = {"period_start": start_time, "period_end": end_time,
               "group_count": 0, "total_events": 0, "status": "SKIPPED"}
    locked = committed = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
            row = cursor.fetchone()
        if row is None or row[0] is None:
            raise PortAnalysisError("Unable to acquire the Port Activity Analysis lock.")
        if row[0] != 1:
            summary["reason"] = "Another Port Activity Analysis run holds the lock."
            return summary
        locked = True
        connection.begin()
        results = analyze_ports(connection, start_time, end_time, max_events=max_events)
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM analysis_ufw_ports WHERE period_start = %s AND period_end = %s",
                           (start_time, end_time))
            if results:
                cursor.executemany(
                    """INSERT INTO analysis_ufw_ports (
                        period_start, period_end, destination_ip, destination_port, protocol,
                        total_events, blocked_events, allowed_events, audited_events,
                        unique_source_ips, first_seen, last_seen
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    [tuple(result[field] for field in RESULT_FIELDS) for result in results],
                )
        connection.commit()
        committed = True
        summary.update(group_count=len(results), total_events=sum(item["total_events"] for item in results),
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
                    raise PortAnalysisError("Port Activity Analysis lock was lost.")
