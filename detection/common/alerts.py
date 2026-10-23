"""Shared alert storage; callers supply rule-specific content and evidence."""

import hashlib
import json

import pymysql

from database.identity import validate_id, validate_text


def link_alert_hosts(cursor, alert_id, hosts):
    """Link one stored alert to several machines, with caller-supplied roles."""
    validate_id(alert_id)
    for host_id, role in hosts:
        validate_id(host_id)
        validate_text(role, maximum=32)
        if not role.isascii():
            raise ValueError("Alert host roles must use ASCII characters.")
        cursor.execute("""INSERT INTO alert_hosts (alert_id, host_id, host_role)
            VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE host_role = alert_hosts.host_role""",
                       (alert_id, host_id, role))


class AlertStorageError(RuntimeError):
    """A database or rule configuration failure safe to display to the user."""


def make_alert_fingerprint(rule_key, identity):
    """Hash a versioned JSON identity; the caller supplies stable JSON values."""
    payload = json.dumps(
        [1, rule_key, identity], sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def save_alert(connection, alert, evidence, *, manage_transaction=True):
    """Commit one alert and all evidence together; return False for a duplicate.

    With manage_transaction=False the caller owns commit and rollback.
    Otherwise use a dedicated connection without pending writes. Evidence consists of
    (event_type, event_id) pairs; event IDs reference their original source table
    at the application level. Rule registration belongs to the SQL migration.
    """
    details_json = json.dumps(alert["details"], sort_keys=True, allow_nan=False)
    evidence_rows = []
    seen = set()
    for event_type, event_id in evidence:
        if not isinstance(event_type, str) or not event_type or len(event_type) > 32:
            raise ValueError("Evidence event type must contain 1 to 32 characters.")
        if not event_type.isascii():
            raise ValueError("Evidence event type must use ASCII characters.")
        if type(event_id) is not int or not 1 <= event_id < 2**64:
            raise ValueError("Evidence event ID must be a positive MySQL BIGINT.")
        pair = (event_type, event_id)
        if pair not in seen:
            evidence_rows.append(pair)
            seen.add(pair)
    if not evidence_rows:
        raise ValueError("An alert must have at least one evidence event.")

    values = (
        alert["title"],
        alert["description"],
        alert.get("source_ip"),
        alert["first_seen"],
        alert["last_seen"],
        alert["alert_fingerprint"],
        details_json,
    )
    cursor = None
    committed = False
    try:
        if manage_transaction:
            connection.begin()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id, severity, enabled FROM detection_rules WHERE rule_key = %s FOR SHARE",
            (alert["rule_key"],),
        )
        rule = cursor.fetchone()
        if rule is None or not rule[2]:
            raise AlertStorageError("Detection rule is missing or disabled.")

        cursor.execute(
            "SELECT id FROM detection_alerts WHERE alert_fingerprint = %s",
            (alert["alert_fingerprint"],),
        )
        if cursor.fetchone() is not None:
            if manage_transaction:
                connection.commit()
            committed = True
            return False

        try:
            cursor.execute(
                """
                INSERT INTO detection_alerts (
                    rule_id, severity, status, title, description, source_ip,
                    first_seen, last_seen, alert_fingerprint, details
                ) VALUES (%s, %s, 'NEW', %s, %s, %s, %s, %s, %s, %s)
                """,
                (rule[0], rule[1]) + values,
            )
        except pymysql.IntegrityError as error:
            if error.args[0] != 1062:
                raise
            # A concurrent run may have inserted this fingerprint after our
            # first lookup. A locking read sees its committed row in InnoDB.
            cursor.execute(
                "SELECT id FROM detection_alerts WHERE alert_fingerprint = %s FOR SHARE",
                (alert["alert_fingerprint"],),
            )
            if cursor.fetchone() is None:
                raise
            if manage_transaction:
                connection.commit()
            committed = True
            return False

        alert_id = cursor.lastrowid
        host_id = alert.get("host_id")
        hosts = list(alert.get("hosts", ()))
        if host_id is not None:
            validate_id(host_id)
            cursor.execute("UPDATE detection_alerts SET host_id = %s WHERE id = %s", (host_id, alert_id))
            hosts.append((host_id, "TARGET"))
        if hosts:
            link_alert_hosts(cursor, alert_id, hosts)
        rows = []
        for event_type, event_id in evidence_rows:
            rows.append((alert_id, event_type, event_id))
        cursor.executemany(
            "INSERT INTO alert_evidence (alert_id, event_type, event_id) VALUES (%s, %s, %s)",
            rows,
        )
        if manage_transaction:
            connection.commit()
        committed = True
        return True
    except pymysql.MySQLError:
        raise AlertStorageError("Alert database operation failed.") from None
    finally:
        try:
            if manage_transaction and not committed:
                connection.rollback()
        finally:
            if cursor is not None:
                cursor.close()


def find_related_alert(connection, rule_key, evidence):
    """Find an existing alert sharing original events; caller owns transaction."""
    if not evidence:
        return None
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT a.id
            FROM detection_alerts a
            JOIN detection_rules r ON r.id = a.rule_id
            JOIN alert_evidence e ON e.alert_id = a.id
            WHERE r.rule_key = %s AND (e.event_type, e.event_id) IN %s
            ORDER BY a.id LIMIT 1
            """,
            (rule_key, tuple(evidence)),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        # Lock only the alert being updated. Locking the join would also need
        # write privileges on rule and evidence tables in MySQL.
        cursor.execute(
            "SELECT id, first_seen, last_seen, details FROM detection_alerts WHERE id = %s FOR UPDATE",
            (row[0],),
        )
        row = cursor.fetchone()
    if row is None:
        raise AlertStorageError("The related alert disappeared during processing.")
    return {
        "id": row[0],
        "first_seen": row[1],
        "last_seen": row[2],
        "details": json.loads(row[3]),
    }


def update_alert(connection, alert_id, first_seen, last_seen, details, evidence):
    """Extend content and evidence without changing identity, severity or status.

    The caller must hold the alert row lock and own commit and rollback.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT event_type, event_id FROM alert_evidence "
            "WHERE alert_id = %s AND (event_type, event_id) IN %s",
            (alert_id, tuple(evidence)),
        )
        known = set(cursor.fetchall())
        new_rows = []
        for pair in evidence:
            if pair not in known:
                new_rows.append((alert_id, pair[0], pair[1]))
                known.add(pair)
        if not new_rows:
            return False
        cursor.execute(
            "UPDATE detection_alerts SET first_seen = %s, last_seen = %s, details = %s WHERE id = %s",
            (
                first_seen,
                last_seen,
                json.dumps(details, sort_keys=True, allow_nan=False),
                alert_id,
            ),
        )
        cursor.executemany(
            "INSERT INTO alert_evidence (alert_id, event_type, event_id) VALUES (%s, %s, %s)",
            new_rows,
        )
    return True
