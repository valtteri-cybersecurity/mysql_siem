"""One bounded automatic pass, with atomic alerts and checkpoint updates."""

from datetime import datetime, timedelta, timezone

from detection.common.alerts import (
    AlertStorageError,
    find_related_alert,
    save_alert,
    update_alert,
)
from detection.port_scan.config import DetectionRunError
from detection.port_scan.db import get_new_events
from detection.port_scan.detector import WINDOW, detect_port_scans
from detection.port_scan.formatting import build_alert
from detection.port_scan.state import (
    acquire_lock,
    get_rule,
    load_state,
    release_lock,
    save_state,
)


def run_automatic(connection, config, *, now=None):
    summary = {
        "events_analyzed": 0,
        "scans_detected": 0,
        "new_alerts_saved": 0,
        "existing_alerts_skipped": 0,
        "alerts_updated": 0,
        "state_updated": False,
        "status": "SKIPPED",
    }
    if not acquire_lock(connection):
        summary["reason"] = "Another port-scan run holds the lock."
        return summary
    committed = False
    try:
        rule_id, enabled = get_rule(connection)
        if not enabled:
            summary["reason"] = "PORT_SCAN_001 is disabled."
            return summary
        last_id, records = load_state(connection, rule_id)
        new_events = get_new_events(connection, last_id, config["batch_size"])
        summary["new_events_fetched"] = len(new_events)
        connection.rollback()  # End the read snapshot before CPU work.
        if now is None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
        for event in new_events:
            last_id = event["id"]
            event_time = event["event_time"]
            if isinstance(event_time, datetime) and event_time.tzinfo is None:
                records.append({"event": event, "observed_at": now})
        events = []
        for record in records:
            events.append(record["event"])
        # Process the stored tail before expiring it, including after a restart.
        if len(events) > config["max_buffer_events"] + config["batch_size"]:
            raise DetectionRunError(
                "Detection buffer limit exceeded; checkpoint unchanged."
            )
        detections = detect_port_scans(events)
        retention = WINDOW + timedelta(seconds=config["late_seconds"])
        retained = []
        for record in records:
            if now - record["observed_at"] <= retention:
                retained.append(record)
        if len(retained) > config["max_buffer_events"]:
            raise DetectionRunError(
                "Detection buffer limit exceeded; checkpoint unchanged."
            )
        summary["events_analyzed"] = len(events)
        summary["scans_detected"] = len(detections)

        connection.begin()
        current_rule_id, enabled = get_rule(connection, lock=True)
        if current_rule_id != rule_id or not enabled:
            summary["reason"] = "Rule configuration changed during the run."
            return summary
        for detection in detections:
            outcome = store_detection(connection, detection)
            summary[outcome] += 1
        save_state(connection, rule_id, last_id, retained)
        connection.commit()
        committed = True
        summary["state_updated"] = True
        summary["status"] = "SUCCESS"
        return summary
    finally:
        try:
            if not committed:
                connection.rollback()
        finally:
            release_lock(connection)


def store_detection(connection, detection):
    """Save or extend one finding inside the caller's transaction."""
    _rule_id, enabled = get_rule(connection, lock=True)
    if not enabled:
        raise AlertStorageError("Detection rule is disabled.")
    alert, evidence = build_alert(detection)
    previous = find_related_alert(connection, alert["rule_key"], evidence)
    if previous is None:
        if save_alert(connection, alert, evidence, manage_transaction=False):
            return "new_alerts_saved"
        return "existing_alerts_skipped"
    ports = set(previous["details"]["destination_ports"])
    ports.update(alert["details"]["destination_ports"])
    alert["details"]["destination_ports"] = sorted(ports)
    alert["details"]["distinct_port_count"] = len(ports)
    changed = update_alert(
        connection,
        previous["id"],
        min(previous["first_seen"], detection["first_seen"]),
        max(previous["last_seen"], detection["last_seen"]),
        alert["details"],
        evidence,
    )
    return "alerts_updated" if changed else "existing_alerts_skipped"
