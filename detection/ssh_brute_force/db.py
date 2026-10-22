"""Bounded SSH event reads and source-reference checks; no detection state."""

from datetime import datetime

from detection.ssh_brute_force.detector import RULE_KEY

MAX_EVENTS = 100000
LOCK_NAME = "mysql_siem_detection_SSH_BRUTE_FORCE_001"
FIELDS = ("id", "event_time", "hostname", "source_ip", "username", "event_type", "service", "event_hash")


class SSHDetectionError(RuntimeError):
    """An expected configuration, data consistency or run-limit failure."""


def validate_time_range(start_time, end_time):
    for value in (start_time, end_time):
        if not isinstance(value, datetime) or value.tzinfo is not None or value.year < 1000:
            raise ValueError("Use UTC datetime values without an offset, within the MySQL range.")
    if start_time >= end_time:
        raise ValueError("Start time must be before end time.")


def get_db_data(connection, start_time, end_time):
    """Return only SSH failures in [start_time, end_time), ordered by time/ID."""
    validate_time_range(start_time, end_time)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, event_time, hostname, source_ip, username, event_type, service, event_hash
            FROM auth_events
            WHERE event_time >= %s AND event_time < %s
              AND event_type = %s AND service = %s
            ORDER BY event_time, id LIMIT %s
            """,
            (start_time, end_time, "SSH_AUTH_FAILURE", "sshd", MAX_EVENTS + 1),
        )
        rows = cursor.fetchall()
    if len(rows) > MAX_EVENTS:
        raise SSHDetectionError("Too many SSH events; retry with a shorter time range.")
    return [dict(zip(FIELDS, row)) for row in rows]


def get_rule(connection, *, lock=False):
    sql = "SELECT id, severity, enabled FROM detection_rules WHERE rule_key = %s"
    if lock:
        sql += " FOR SHARE"
    with connection.cursor() as cursor:
        cursor.execute(sql, (RULE_KEY,))
        rule = cursor.fetchone()
    if rule is None:
        raise SSHDetectionError("SSH_BRUTE_FORCE_001 is missing; apply migration 008 after approval.")
    if rule[2] and rule[1] != "HIGH":
        raise SSHDetectionError("SSH_BRUTE_FORCE_001 must use HIGH severity in this version.")
    return rule


def validate_evidence_ids(event_ids):
    if not event_ids or len(event_ids) > MAX_EVENTS:
        raise SSHDetectionError("SSH evidence is empty or exceeds the run limit.")
    for event_id in event_ids:
        if type(event_id) is not int or not 1 <= event_id < 2**64:
            raise SSHDetectionError("SSH evidence must reference saved auth_events IDs.")
    return sorted(set(event_ids))


def get_evidence_events(connection, event_ids):
    """Lock actual source rows until the caller commits alert/evidence writes."""
    event_ids = validate_evidence_ids(event_ids)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, event_time, hostname, source_ip, username, event_type, service, event_hash
            FROM auth_events WHERE id IN %s
              AND event_type = %s AND service = %s
            ORDER BY event_time, id FOR SHARE
            """,
            (tuple(event_ids), "SSH_AUTH_FAILURE", "sshd"),
        )
        rows = cursor.fetchall()
    if len(rows) != len(event_ids):
        raise SSHDetectionError("SSH evidence is missing or has an unsupported event type/service.")
    return [dict(zip(FIELDS, row)) for row in rows]


def get_related_alert_ids(connection, evidence):
    """Notice ambiguous historical merges before modifying an existing alert."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT DISTINCT a.id FROM detection_alerts a
            JOIN detection_rules r ON r.id = a.rule_id
            JOIN alert_evidence e ON e.alert_id = a.id
            WHERE r.rule_key = %s AND (e.event_type, e.event_id) IN %s
            ORDER BY a.id
            """,
            (RULE_KEY, tuple(evidence)),
        )
        return [row[0] for row in cursor.fetchall()]


def get_alert_evidence_ids(connection, alert_id):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT event_type, event_id FROM alert_evidence WHERE alert_id = %s LIMIT %s",
            (alert_id, MAX_EVENTS + 1),
        )
        rows = cursor.fetchall()
    if any(event_type != "AUTH" for event_type, _ in rows):
        raise SSHDetectionError("An existing SSH alert has an unexpected evidence source.")
    return validate_evidence_ids([event_id for _, event_id in rows])


def acquire_lock(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
        row = cursor.fetchone()
    if row is None or row[0] is None:
        raise SSHDetectionError("Unable to acquire the SSH detection lock.")
    return row[0] == 1


def release_lock(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))
        row = cursor.fetchone()
    if row is None or row[0] != 1:
        raise SSHDetectionError("SSH detection lock was lost.")


def get_new_events(connection, last_event_id, batch_size):
    """Visit every increasing ID, including unsupported events, without a time cutoff.

    Auth collectors serialize ID allocation through commit with their common
    writer lock. External writers must follow that same contract.
    """
    if (type(last_event_id) is not int or not 0 <= last_event_id < 2**64
            or type(batch_size) is not int or not 1 <= batch_size <= 10000):
        raise SSHDetectionError("Invalid SSH checkpoint or batch size.")
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, event_time, hostname, source_ip, username, event_type, service, event_hash
            FROM auth_events WHERE id > %s ORDER BY id LIMIT %s
            """,
            (last_event_id, batch_size),
        )
        return [dict(zip(FIELDS, row)) for row in cursor.fetchall()]
