"""Detect PORT_SCAN_001 from UFW rows without database access."""

from datetime import datetime, timedelta
from operator import itemgetter

from database.identity import event_scope
from ingestion.ip_addresses import canonical_ip

RULE_KEY = "PORT_SCAN_001"
MIN_DISTINCT_PORTS = 10
WINDOW = timedelta(seconds=60)


def _parse_event_time(value):
    """Accept naive MySQL datetimes or their text representation."""
    if isinstance(value, str):
        for time_format in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(value, time_format)
            except ValueError:
                continue
        return None

    if isinstance(value, datetime) and value.tzinfo is None:
        return value

    return None


def _normalize_event(event):
    """Return the required fields, or None for an unusable event."""
    if not isinstance(event, dict):
        return None

    if event.get("action") not in ("BLOCK", "AUDIT", "ALLOW"):
        return None
    if event.get("protocol") not in ("TCP", "UDP"):
        return None

    source_ip = event.get("src_ip")
    destination_ip = event.get("dst_ip")
    if not isinstance(source_ip, str) or not isinstance(destination_ip, str):
        return None
    try:
        source_ip = canonical_ip(source_ip)
        destination_ip = canonical_ip(destination_ip)
    except ValueError:
        return None

    port = event.get("dst_port")
    if isinstance(port, str):
        if not port.isascii() or not port.isdigit():
            return None
        try:
            port = int(port)
        except ValueError:
            return None
    # bool is a subclass of int; True must not become port 1.
    if type(port) is not int or not 1 <= port <= 65535:
        return None

    event_time = _parse_event_time(event.get("event_time"))
    if event_time is None:
        return None

    return {
        "host_id": event.get("host_id"),
        "source_id": event.get("source_id"),
        "id": event.get("id"),
        "event_time": event_time,
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "protocol": event["protocol"],
        "dst_port": port,
    }


def _find_scan_windows(events):
    """Find qualifying windows and merge those sharing at least one event."""
    scan_windows = []
    window_start = 0

    for window_end, event in enumerate(events):
        while event["event_time"] - events[window_start]["event_time"] > WINDOW:
            window_start += 1

        ports = set()
        for window_event in events[window_start:window_end + 1]:
            ports.add(window_event["dst_port"])

        if len(ports) < MIN_DISTINCT_PORTS:
            continue

        if scan_windows and window_start <= scan_windows[-1][1]:
            scan_windows[-1][1] = window_end
        else:
            scan_windows.append([window_start, window_end])

    return scan_windows


def _build_detection(events):
    """Summarize the union of one or more qualifying windows."""
    ports = set()
    evidence_ids = []
    seen_ids = set()

    for event in events:
        ports.add(event["dst_port"])
        event_id = event["id"]
        if type(event_id) is int and event_id > 0 and event_id not in seen_ids:
            evidence_ids.append(event_id)
            seen_ids.add(event_id)

    first = events[0]
    return {
        "rule_key": RULE_KEY,
        "host_id": first.get("host_id"),
        "source_ip": first["src_ip"],
        "destination_ip": first["dst_ip"],
        "protocol": first["protocol"],
        "distinct_ports": sorted(ports),
        "first_seen": first["event_time"],
        "last_seen": events[-1]["event_time"],
        "evidence_ids": evidence_ids,
    }


def detect_port_scans(events):
    """Return detections from a list of ufw_log dictionaries.

    Only BLOCK/AUDIT/ALLOW and TCP/UDP events with valid addresses, destination
    ports (1..65535) and naive event_time values participate. Invalid events
    are skipped. Input dictionaries and their ordering are left unchanged.

    Each finding contains at least one inclusive 60-second window with ten
    distinct ports. Qualifying windows sharing events are merged, so the
    complete finding can span longer than 60 seconds. A new finding starts
    when a qualifying window shares no events with the previous finding.
    """
    groups = {}
    for event in events:
        normalized = _normalize_event(event)
        if normalized is None:
            continue
        group_key = (
            event_scope(normalized),
            normalized["src_ip"],
            normalized["dst_ip"],
            normalized["protocol"],
        )
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(normalized)

    detections = []
    for group_events in groups.values():
        group_events.sort(key=itemgetter("event_time"))
        for start, end in _find_scan_windows(group_events):
            detection = _build_detection(group_events[start:end + 1])
            detections.append(detection)

    detections.sort(key=itemgetter("first_seen", "source_ip", "destination_ip", "protocol"))
    return detections
