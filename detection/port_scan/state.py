"""Durable ID checkpoint and a bounded buffer; no detector algorithm here."""

import json
from datetime import datetime

from detection.port_scan.config import DetectionRunError

LOCK_NAME = "mysql_siem_detection_PORT_SCAN_001"


def acquire_lock(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT GET_LOCK(%s, 0)", (LOCK_NAME,))
        row = cursor.fetchone()
    if row is None or row[0] is None:
        raise DetectionRunError("Unable to acquire the port-scan lock.")
    return row[0] == 1


def release_lock(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))
        row = cursor.fetchone()
    if row is None or row[0] != 1:
        raise DetectionRunError("Port-scan lock was lost.")


def get_rule(connection, *, lock=False):
    sql = "SELECT id, enabled FROM detection_rules WHERE rule_key = %s"
    if lock:
        sql += " FOR SHARE"
    with connection.cursor() as cursor:
        cursor.execute(sql, ("PORT_SCAN_001",))
        row = cursor.fetchone()
    if row is None:
        raise DetectionRunError(
            "PORT_SCAN_001 is missing; apply the detection migration."
        )
    return row


def load_state(connection, rule_id):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT last_event_id, state_data FROM detection_state WHERE rule_id = %s",
            (rule_id,),
        )
        row = cursor.fetchone()
    if row is None:
        return 0, []
    try:
        last_id, raw = row
        if type(last_id) is not int or not 0 <= last_id < 2**64:
            raise ValueError
        data = json.loads(raw)
        if data["version"] != 1 or not isinstance(data["events"], list):
            raise ValueError
        records = []
        seen_ids = set()
        for item in data["events"]:
            event = dict(item["event"])
            event_id = event["id"]
            if (
                type(event_id) is not int
                or not 0 < event_id <= last_id
                or event_id in seen_ids
            ):
                raise ValueError
            seen_ids.add(event_id)
            event["event_time"] = datetime.fromisoformat(event["event_time"])
            observed_at = datetime.fromisoformat(item["observed_at"])
            if event["event_time"].tzinfo is not None or observed_at.tzinfo is not None:
                raise ValueError
            for field in ("action", "src_ip", "dst_ip", "protocol", "dst_port"):
                event[field]
            records.append({"event": event, "observed_at": observed_at})
        return last_id, records
    except (ValueError, TypeError, KeyError):
        raise DetectionRunError(
            "Stored detection state is invalid; checkpoint was not reset."
        ) from None


def save_state(connection, rule_id, last_id, records):
    items = []
    for record in records:
        event = dict(record["event"])
        event["event_time"] = event["event_time"].isoformat(
            sep=" ", timespec="microseconds"
        )
        items.append({"event": event, "observed_at": record["observed_at"].isoformat()})
    payload = json.dumps(
        {"version": 1, "events": items}, sort_keys=True, allow_nan=False
    )
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO detection_state (rule_id, last_event_id, state_data)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE last_event_id = %s, state_data = %s
            """,
            (rule_id, last_id, payload, last_id, payload),
        )
