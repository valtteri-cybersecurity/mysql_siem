"""SSH's own durable ID checkpoint and bounded event buffer in detection_state."""

import json
from datetime import datetime

from detection.ssh_brute_force.db import FIELDS, MAX_EVENTS, SSHDetectionError


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
        last_id, payload = row
        if type(last_id) is not int or not 0 <= last_id < 2**64:
            raise ValueError
        data = json.loads(payload)
        if (not isinstance(data, dict) or data.get("version") != 1
                or not isinstance(data.get("events"), list)
                or len(data["events"]) > MAX_EVENTS):
            raise ValueError
        records = []
        seen = set()
        for item in data["events"]:
            event = dict(item["event"])
            if set(event) != set(FIELDS):
                raise ValueError
            event_id = event["id"]
            if type(event_id) is not int or not 0 < event_id <= last_id or event_id in seen:
                raise ValueError
            seen.add(event_id)
            event["event_time"] = datetime.fromisoformat(event["event_time"])
            observed_at = datetime.fromisoformat(item["observed_at"])
            if (event["event_time"].tzinfo is not None or observed_at.tzinfo is not None
                    or event["event_time"].year < 1000
                    or event["event_type"] != "SSH_AUTH_FAILURE" or event["service"] != "sshd"):
                raise ValueError
            for name in ("hostname", "source_ip", "event_hash"):
                if not isinstance(event[name], str):
                    raise TypeError
            if event["username"] is not None and not isinstance(event["username"], str):
                raise ValueError
            records.append({"event": event, "observed_at": observed_at})
        return last_id, records
    except (ValueError, TypeError, KeyError, OverflowError):
        raise SSHDetectionError("Stored SSH state is invalid; checkpoint was not reset.") from None


def save_state(connection, rule_id, last_id, records):
    items = []
    for record in records:
        event = dict(record["event"])
        event["event_time"] = event["event_time"].isoformat(timespec="microseconds")
        items.append({"event": event, "observed_at": record["observed_at"].isoformat(timespec="microseconds")})
    payload = json.dumps({"version": 1, "events": items}, sort_keys=True, allow_nan=False)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO detection_state (rule_id, last_event_id, state_data)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE last_event_id = %s, state_data = %s
            """,
            (rule_id, last_id, payload, last_id, payload),
        )
