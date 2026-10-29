"""Hourly/daily UFW event history; these are log events, not connections.

New UFW events use naive UTC DATETIME, as do Source IP and Port Activity Analysis.
Legacy local-time history must remain offline; see docs/phase3-utc.md.
The collector's file offsets have no observation times or heartbeat history.
Consequently coverage_status is always UNKNOWN, even for a closed, nonempty
period. OPEN/CLOSED describes the clock only, never ingestion completeness.
Rerun a historical range to repair late arrivals beyond the recent window.
"""

from datetime import datetime, timedelta, timezone

from analysis.ufw.source_ips import validate_time_range
from database.identity import identity_schema_enabled, validate_id

LOCK_NAME = "mysql_siem_analysis_ufw_traffic"
METRICS = (
    "total_events", "blocked_events", "allowed_events", "audited_events",
    "other_events", "tcp_events", "udp_events", "unique_source_ips",
    "unique_destination_ips", "unique_destination_ports",
)

# COUNT(*) includes rows with missing IPs/actions/protocols. INET6_ATON ignores
# invalid/missing IPs and canonicalizes equivalent IPv6 spellings. Port 0 is
# the collector's missing-port sentinel. Every nonempty protocol can identify
# a port; named TCP/UDP counters use the same exact spelling as other analyses.
AGGREGATE_SQL = """
    SELECT COUNT(*),
        COALESCE(SUM(BINARY action = 'BLOCK'), 0),
        COALESCE(SUM(BINARY action = 'ALLOW'), 0),
        COALESCE(SUM(BINARY action = 'AUDIT'), 0),
        COALESCE(SUM(action IS NULL OR BINARY action NOT IN ('BLOCK', 'ALLOW', 'AUDIT')), 0),
        COALESCE(SUM(BINARY protocol = 'TCP'), 0),
        COALESCE(SUM(BINARY protocol = 'UDP'), 0),
        COUNT(DISTINCT INET6_ATON(src_ip)),
        COUNT(DISTINCT INET6_ATON(dst_ip)),
        COUNT(DISTINCT CASE WHEN dst_port BETWEEN 1 AND 65535 AND protocol <> ''
            THEN CONCAT(BINARY protocol, ':', dst_port) END),
        MIN(event_time), MAX(event_time)
    FROM ufw_log
    WHERE event_time >= %s AND event_time < %s
"""


class TrafficAnalysisError(RuntimeError):
    """A safe-to-display traffic analysis locking or schema failure."""


def hour_periods(start_time, end_time):
    """Whole clock hours intersecting a range; never save partial hourly keys."""
    validate_time_range(start_time, end_time)
    start = start_time.replace(minute=0, second=0, microsecond=0)
    while start < end_time:
        end = start + timedelta(hours=1)
        yield start, end
        start = end


def analyze_traffic(connection, start_time, end_time, *, host_id=None):
    """One indexed range query, including empty intervals; caller owns transaction.

    No LIMIT: truncation would silently corrupt totals and daily distinct counts.
    SQL aggregation does not load the raw event history into Python memory.
    """
    validate_time_range(start_time, end_time)
    if host_id is not None:
        validate_id(host_id)
    from database.ufw_history import active_filter
    sql = AGGREGATE_SQL + active_filter(connection)
    parameters = (start_time, end_time)
    if identity_schema_enabled(connection):
        sql += " AND host_id <=> %s"
        parameters += (host_id,)
    elif host_id is not None:
        raise TrafficAnalysisError("Host-specific traffic requires the phase-2 migrations.")
    with connection.cursor() as cursor:
        cursor.execute(sql, parameters)
        row = cursor.fetchone()
    result = {name: int(value) for name, value in zip(METRICS, row[:10])}
    result.update(first_seen=row[10], last_seen=row[11])
    return result


def save_traffic(connection, start_time, end_time, *, daily, now, host_id=None):
    """Save one bucket atomically. Table/column names are internal constants."""
    connection.begin()
    try:
        result = analyze_traffic(connection, start_time, end_time, host_id=host_id)
        if daily:
            table = "analysis_ufw_traffic_daily"
            fields = ("analysis_date",) + METRICS
            values = (start_time.date(),) + tuple(result[name] for name in METRICS)
        else:
            table = "analysis_ufw_traffic"
            fields = ("period_start", "period_end") + METRICS + ("first_seen", "last_seen")
            values = (start_time, end_time) + tuple(result[name] for name in METRICS) + (result["first_seen"], result["last_seen"])
        from database.ufw_analysis_history import protect_interval
        protect_interval(connection, table, start_time, end_time)
        fields += ("period_status", "coverage_status")
        values += ("OPEN" if now < end_time else "CLOSED", "UNKNOWN")
        if identity_schema_enabled(connection):
            fields += ("host_id", "host_scope")
            values += (host_id, host_id or 0)
        updates = ", ".join(f"{name} = VALUES({name})" for name in fields)
        with connection.cursor() as cursor:
            cursor.execute(
                # Identifiers come only from the fixed branches above; values are bound.
                f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({', '.join(['%s'] * len(fields))}) "  # nosec B608
                f"ON DUPLICATE KEY UPDATE {updates}, updated_at = CURRENT_TIMESTAMP(6)", values,
            )
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise


def run_traffic_analysis(connection, start_time, end_time, *, now=None, previous_day=False):
    """Refresh intersecting whole hours and calendar days from raw UFW events.

    One lock spans the run, acquired before starting any read snapshot. This
    prevents older concurrent recomputations from overwriting newer history.
    Each bucket commits separately; a failed bucket rolls back in full.
    Scheduled runs also refresh yesterday, including older late arrivals there.
    Never infer coverage from offsets, event counts or the latest event time.
    """
    validate_time_range(start_time, end_time)
    now = datetime.now(timezone.utc).replace(tzinfo=None) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is not None or now.year < 1000:
        raise ValueError("Use the naive UTC UFW time basis.")
    summary = {"status": "SKIPPED", "total_events": 0, "hour_count": 0, "day_count": 0,
               "coverage_status": "UNKNOWN"}
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
            row = cursor.fetchone()
        if row is None or row[0] is None:
            raise TrafficAnalysisError("Unable to acquire the Traffic Analysis lock.")
        if row[0] != 1:
            summary["reason"] = "Another Traffic Analysis run holds the lock."
            return summary
        locked = True
        host_ids = set()
        if identity_schema_enabled(connection):
            with connection.cursor() as cursor:
                cursor.execute("SELECT host_id FROM log_sources WHERE source_type = 'ufw' "
                               "UNION SELECT DISTINCT host_id FROM ufw_log")
                host_ids = {row[0] for row in cursor.fetchall()}
        # Retain the legacy empty-period behavior without assigning a machine.
        host_ids.add(None)
        days = set()
        for start, end in hour_periods(start_time, end_time):
            total_events = 0
            for host_id in host_ids:
                result = save_traffic(connection, start, end, daily=False, now=now, host_id=host_id)
                total_events += result["total_events"]
            days.add(start.replace(hour=0))
            summary["total_events"] += total_events
            summary["hour_count"] += 1
        if previous_day:
            days.add(now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1))
        for start in sorted(days):
            for host_id in host_ids:
                save_traffic(connection, start, start + timedelta(days=1), daily=True, now=now, host_id=host_id)
            summary["day_count"] += 1
        from ingestion.ufw_filters import coverage_notice
        summary.update(coverage_notice(connection, start_time, end_time))
        summary["status"] = "SUCCESS"
        return summary
    finally:
        if locked:
            with connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))
                row = cursor.fetchone()
            if row is None or row[0] != 1:
                raise TrafficAnalysisError("Traffic Analysis lock was lost.")


def validate_traffic_schema(connection):
    """Installer preflight: fail closed on incompatible existing summary tables."""
    for table, keys in (("analysis_ufw_traffic", ["period_start", "period_end"]),
                        ("analysis_ufw_traffic_daily", ["analysis_date"])):
        with connection.cursor() as cursor:
            cursor.execute("""SELECT engine FROM information_schema.tables
                           WHERE table_schema = DATABASE() AND table_name = %s AND table_type = 'BASE TABLE'""", (table,))
            if cursor.fetchone() != ("InnoDB",):
                raise TrafficAnalysisError(f"{table}: inspect database/schema.sql before installation.")
            cursor.execute("""SELECT column_name, column_type, is_nullable, extra FROM information_schema.columns
                           WHERE table_schema = DATABASE() AND table_name = %s""", (table,))
            actual = {name: (kind.lower(), nullable, extra.lower()) for name, kind, nullable, extra in cursor.fetchall()}
            expected = {name: ("bigint unsigned", "NO", "") for name in METRICS}
            expected.update({"id": ("bigint unsigned", "NO", "auto_increment"),
                             "updated_at": ("timestamp(6)", "NO", "default_generated on update current_timestamp(6)"),
                             "period_status": ("varchar(6)", "NO", ""), "coverage_status": ("varchar(16)", "NO", "")})
            expected.update({name: ("date" if name == "analysis_date" else "datetime(6)", "NO", "") for name in keys})
            if table == "analysis_ufw_traffic":
                expected.update({name: ("datetime(6)", "YES", "") for name in ("first_seen", "last_seen")})
            scoped = "host_id" in actual
            if scoped:
                expected["host_id"] = ("bigint unsigned", "YES", "")
                expected["host_scope"] = ("bigint unsigned", "NO", "")
            if "time_basis" in actual:
                expected["time_basis"] = ("varchar(24)", "NO", "")
            if actual != expected:
                raise TrafficAnalysisError(f"{table}: incompatible columns; inspect database/schema.sql.")
            cursor.execute("""SELECT index_name, non_unique, column_name, sub_part, is_visible
                           FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = %s
                           ORDER BY index_name, seq_in_index""", (table,))
            indexes = {}
            for name, non_unique, column, prefix, visible in cursor.fetchall():
                if prefix is not None or visible != "YES":
                    raise TrafficAnalysisError(f"{table}: incompatible index; inspect database/schema.sql.")
                indexes.setdefault(name, (non_unique, []))[1].append(column)
            expected_indexes = {"PRIMARY": (0, ["id"]), "uq_traffic_period": (0, list(keys))}
            if scoped:
                expected_indexes["uq_traffic_period"][1].append("host_scope")
                expected_indexes[f"fk_{table}_host"] = (1, ["host_id"])
            if indexes != expected_indexes:
                raise TrafficAnalysisError(f"{table}: incompatible period keys; inspect database/schema.sql.")
