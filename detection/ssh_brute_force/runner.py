"""Manual and automatic SSH detection using the shared SOC storage."""

from datetime import datetime, timedelta, timezone

from detection.common.alerts import find_related_alert, save_alert, update_alert
from detection.ssh_brute_force.db import (
    SSHDetectionError,
    acquire_lock,
    get_alert_evidence_ids,
    get_db_data,
    get_evidence_events,
    get_new_events,
    get_related_alert_ids,
    get_rule,
    release_lock,
    validate_evidence_ids,
    validate_time_range,
)
from detection.ssh_brute_force.detector import WINDOW, detect_ssh_brute_force
from detection.ssh_brute_force.formatting import build_alert
from detection.ssh_brute_force.state import load_state, save_state


def _confirm_detection(connection, detection):
    """Re-use the existing detector to verify the actual, locked source events."""
    events = get_evidence_events(connection, detection["evidence_ids"])
    findings = detect_ssh_brute_force(events)
    if len(findings) != 1:
        raise SSHDetectionError("SSH evidence does not describe one qualifying episode.")
    confirmed = findings[0]
    fields = ("rule_key", "source_ip", "hostname", "failure_count", "first_seen", "last_seen")
    if confirmed.get("host_id") != detection.get("host_id"):
        raise SSHDetectionError("The SSH finding does not match its registered host.")
    if (any(confirmed[key] != detection[key] for key in fields)
            or sorted(confirmed["evidence_ids"]) != validate_evidence_ids(detection["evidence_ids"])):
        raise SSHDetectionError("The SSH finding no longer matches its source events.")
    # Usernames and all stored details come from the source rows, not caller metadata.
    return confirmed


def store_detection(connection, detection):
    """Caller owns transaction and the SSH rule's named run lock.

    Shared SOC functions own the SQL writes. AUTH references auth_events.id.
    Related episodes are extended without changing alert identity or status.
    """
    _rule_id, _severity, enabled = get_rule(connection, lock=True)
    if not enabled:
        raise SSHDetectionError("SSH_BRUTE_FORCE_001 was disabled during the run.")
    detection = _confirm_detection(connection, detection)
    alert, evidence = build_alert(detection)
    related_ids = get_related_alert_ids(connection, evidence)
    if len(related_ids) > 1:
        raise SSHDetectionError(
            "This finding connects multiple saved SSH alerts; review them before retrying."
        )
    if not related_ids:
        if save_alert(connection, alert, evidence, manage_transaction=False):
            return "new_alerts_saved"
        return "existing_alerts_skipped"

    previous = find_related_alert(connection, alert["rule_key"], evidence)
    if previous is None or previous["id"] != related_ids[0]:
        raise SSHDetectionError("The related SSH alert changed during processing.")
    if (previous["details"].get("host_id") != detection.get("host_id")
            or (detection.get("host_id") is None
                and previous["details"].get("hostname") != detection["hostname"])):
        raise SSHDetectionError("The related SSH alert has an inconsistent target host.")
    previous_ids = get_alert_evidence_ids(connection, previous["id"])
    # Count the union of source events, never the sum of overlapping window counts.
    combined_ids = sorted(set(previous_ids) | set(detection["evidence_ids"]))
    events = get_evidence_events(connection, combined_ids)
    merged = detect_ssh_brute_force(events)
    if (len(merged) != 1 or sorted(merged[0]["evidence_ids"]) != combined_ids
            or merged[0]["source_ip"] != detection["source_ip"]
            or merged[0].get("host_id") != detection.get("host_id")
            or (detection.get("host_id") is None and merged[0]["hostname"] != detection["hostname"])):
        raise SSHDetectionError("Saved and new SSH evidence do not form one consistent episode.")
    alert, evidence = build_alert(merged[0])
    changed = update_alert(connection, previous["id"], alert["first_seen"], alert["last_seen"],
                           alert["details"], evidence)
    return "alerts_updated" if changed else "existing_alerts_skipped"


def run_detection(connection, start_time, end_time):
    """Use a dedicated connection; each alert and its evidence commit atomically."""
    validate_time_range(start_time, end_time)
    summary = {
        "events_analyzed": 0,
        "detections_found": 0,
        "new_alerts_saved": 0,
        "alerts_updated": 0,
        "existing_alerts_skipped": 0,
        "status": "SKIPPED",
    }
    if not acquire_lock(connection):
        summary["reason"] = "Another SSH detection run holds the lock."
        return summary
    try:
        _rule_id, _severity, enabled = get_rule(connection)
        if not enabled:
            summary["reason"] = "SSH_BRUTE_FORCE_001 is disabled."
            return summary
        events = get_db_data(connection, start_time, end_time)
        connection.rollback()  # Release the read snapshot before CPU work.
        findings = detect_ssh_brute_force(events)
        summary["events_analyzed"] = len(events)
        summary["detections_found"] = len(findings)
        for detection in findings:
            committed = False
            try:
                connection.begin()
                outcome = store_detection(connection, detection)
                connection.commit()
                committed = True
                summary[outcome] += 1
            finally:
                if not committed:
                    connection.rollback()
        summary["status"] = "SUCCESS"
        return summary
    finally:
        try:
            connection.rollback()  # End any rule/read transaction on early exits.
        finally:
            release_lock(connection)


def run_automatic(connection, config, *, now=None):
    """Commit all alerts, evidence and SSH state together for one bounded pass."""
    summary = {
        "new_events_fetched": 0, "events_analyzed": 0, "detections_found": 0,
        "new_alerts_saved": 0, "alerts_updated": 0, "existing_alerts_skipped": 0,
        "state_updated": False, "status": "SKIPPED",
    }
    if not acquire_lock(connection):
        summary["reason"] = "Another SSH detection run holds the lock."
        return summary
    committed = False
    try:
        rule_id, _severity, enabled = get_rule(connection)
        if not enabled:
            summary["reason"] = "SSH_BRUTE_FORCE_001 is disabled."
            return summary
        last_id, records = load_state(connection, rule_id)
        new_events = get_new_events(connection, last_id, config["batch_size"])
        connection.rollback()  # End read snapshot before sorting and detection.
        if now is None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
        if not isinstance(now, datetime) or now.tzinfo is not None:
            raise SSHDetectionError("Use a naive UTC processing time.")
        if any(record["observed_at"] > now for record in records):
            raise SSHDetectionError("Processing clock moved backwards; SSH checkpoint unchanged.")
        summary["new_events_fetched"] = len(new_events)
        for event in new_events:
            last_id = event["id"]
            if (event["event_type"] == "SSH_AUTH_FAILURE" and event["service"] == "sshd"
                    and isinstance(event["event_time"], datetime)
                    and event["event_time"].tzinfo is None):
                records.append({"event": event, "observed_at": now})
        if len(records) > config["max_buffer_events"] + config["batch_size"]:
            raise SSHDetectionError("SSH detection buffer limit exceeded; checkpoint unchanged.")
        events = [record["event"] for record in records]
        findings = detect_ssh_brute_force(events)
        # Inspect the persisted tail once before expiring it, including after downtime.
        retention = WINDOW + timedelta(seconds=config["late_seconds"])
        retained = [record for record in records if now - record["observed_at"] <= retention]
        if len(retained) > config["max_buffer_events"]:
            raise SSHDetectionError("SSH detection buffer limit exceeded; checkpoint unchanged.")
        summary["events_analyzed"] = len(events)
        summary["detections_found"] = len(findings)
        connection.begin()
        current_id, _severity, enabled = get_rule(connection, lock=True)
        if current_id != rule_id or not enabled:
            summary["reason"] = "SSH rule configuration changed during the run."
            return summary
        for detection in findings:
            summary[store_detection(connection, detection)] += 1
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
