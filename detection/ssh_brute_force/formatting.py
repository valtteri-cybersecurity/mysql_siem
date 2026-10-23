"""Convert the phase-1 finding into common SOC content, without raw auth logs."""

from detection.common.alerts import make_alert_fingerprint
from detection.ssh_brute_force.db import validate_evidence_ids
from detection.ssh_brute_force.detector import MIN_FAILURES, RULE_KEY, WINDOW


def build_alert(detection):
    evidence_ids = validate_evidence_ids(detection["evidence_ids"])
    identity = {
        "source_ip": detection["source_ip"],
        "hostname": detection["hostname"],
        "first_seen": detection["first_seen"].isoformat(timespec="microseconds"),
        "last_seen": detection["last_seen"].isoformat(timespec="microseconds"),
        "evidence_ids": evidence_ids,
    }
    if detection.get("host_id") is not None:
        identity["host_id"] = detection["host_id"]
        identity.pop("hostname")
    alert = {
        "host_id": detection.get("host_id"),
        "rule_key": RULE_KEY,
        "title": "SSH Brute Force Attempt",
        "description": (
            f"At least {MIN_FAILURES} failed SSH password attempts from the same source "
            f"to the same host in a {int(WINDOW.total_seconds())}-second window; "
            "overlapping qualifying windows are merged."
        ),
        "source_ip": detection["source_ip"],
        "first_seen": detection["first_seen"],
        "last_seen": detection["last_seen"],
        "alert_fingerprint": make_alert_fingerprint(RULE_KEY, identity),
        "details": {
            "host_id": detection.get("host_id"),
            "hostname": detection["hostname"],
            "failure_count": detection["failure_count"],
            "window_seconds": int(WINDOW.total_seconds()),
            "threshold": MIN_FAILURES,
            "usernames": sorted(set(detection.get("usernames", []))),
        },
    }
    if detection.get("host_id") is None:
        alert["details"].pop("host_id")
    return alert, [("AUTH", event_id) for event_id in evidence_ids]
