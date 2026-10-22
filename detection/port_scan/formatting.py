"""Port-scan findings converted to shared alert content."""

from detection.common.alerts import make_alert_fingerprint
from detection.port_scan.detector import MIN_DISTINCT_PORTS, WINDOW


def build_alert(detection):
    """Convert one port-scan finding into shared alert content and evidence."""
    ports = sorted(set(detection["distinct_ports"]))
    evidence_ids = sorted(set(detection["evidence_ids"]))
    identity = {
        "source_ip": detection["source_ip"],
        "destination_ip": detection["destination_ip"],
        "protocol": detection["protocol"],
        "first_seen": detection["first_seen"].isoformat(timespec="microseconds"),
        "last_seen": detection["last_seen"].isoformat(timespec="microseconds"),
        "distinct_ports": ports,
        "evidence_ids": evidence_ids,
    }
    alert = {
        "rule_key": detection["rule_key"],
        "title": "Possible Port Scanning",
        "description": (
            f"At least {MIN_DISTINCT_PORTS} distinct destination ports in a "
            f"{int(WINDOW.total_seconds())}-second window; "
            "overlapping qualifying windows are merged."
        ),
        "source_ip": detection["source_ip"],
        "first_seen": detection["first_seen"],
        "last_seen": detection["last_seen"],
        "alert_fingerprint": make_alert_fingerprint(detection["rule_key"], identity),
        "details": {
            "destination_ip": detection["destination_ip"],
            "protocol": detection["protocol"],
            "distinct_port_count": len(ports),
            "destination_ports": ports,
            "window_seconds": int(WINDOW.total_seconds()),
            "threshold": MIN_DISTINCT_PORTS,
        },
    }
    evidence = []
    for event_id in evidence_ids:
        evidence.append(("UFW", event_id))
    return alert, evidence
