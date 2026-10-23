"""Detect SSH_BRUTE_FORCE_001 from normalized events without database access."""

from datetime import datetime, timedelta, timezone
from operator import itemgetter

from database.identity import event_scope
from ingestion.ip_addresses import canonical_ip

RULE_KEY = "SSH_BRUTE_FORCE_001"
MIN_FAILURES = 5
WINDOW = timedelta(seconds=60)


def _parse_event_time(value):
    if isinstance(value, str):
        # Accept database strings and ISO timestamps; exclude date-only strings.
        if len(value) < 19 or value[10] not in (" ", "T"):
            return None
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        try:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        except (ValueError, OverflowError):
            return None
    return value


def _normalize_event(event):
    if not isinstance(event, dict):
        return None
    if event.get("event_type") != "SSH_AUTH_FAILURE" or event.get("service") != "sshd":
        return None
    hostname = event.get("hostname")
    source_ip = event.get("source_ip")
    if not isinstance(hostname, str) or not hostname.strip() or len(hostname) > 255:
        return None
    if not isinstance(source_ip, str) or "%" in source_ip:
        return None
    try:
        source_ip = canonical_ip(source_ip)
    except ValueError:
        return None
    event_time = _parse_event_time(event.get("event_time"))
    if event_time is None:
        return None
    normalized = dict(event)
    normalized.update(event_time=event_time, source_ip=source_ip)
    return normalized


def _identity_keys(event):
    """Use durable IDs/hashes; fall back to observable content for unsaved rows."""
    keys = []
    event_id = event.get("id")
    if type(event_id) is int and event_id > 0:
        keys.append(("id", event_id))
    event_hash = event.get("event_hash")
    if (isinstance(event_hash, str) and len(event_hash) == 64
            and all(char in "0123456789abcdef" for char in event_hash)):
        keys.append(("hash", event_hash))
    if not keys:
        username = event.get("username")
        raw_message = event.get("raw_message")
        keys.append(("content", event["event_time"], event["hostname"], event["source_ip"],
                     username if isinstance(username, str) else None,
                     raw_message if isinstance(raw_message, str) else None))
    return keys


def _find_windows(events):
    """Merge qualifying inclusive windows sharing at least one source event."""
    windows = []
    start = 0
    for end, event in enumerate(events):
        while event["event_time"] - events[start]["event_time"] > WINDOW:
            start += 1
        if end - start + 1 < MIN_FAILURES:
            continue
        if windows and start <= windows[-1][1]:
            windows[-1][1] = end
        else:
            windows.append([start, end])
    return windows


def _build_detection(events):
    ids = []
    usernames = set()
    for event in events:
        event_id = event.get("id")
        if type(event_id) is int and event_id > 0:
            ids.append(event_id)
        username = event.get("username")
        if isinstance(username, str) and username:
            usernames.add(username)
    return {
        "rule_key": RULE_KEY,
        "host_id": events[0].get("host_id"),
        "source_ip": events[0]["source_ip"],
        "hostname": events[0]["hostname"],
        "failure_count": len(events),
        "first_seen": events[0]["event_time"],
        "last_seen": events[-1]["event_time"],
        "evidence_ids": ids,
        "usernames": sorted(usernames),
    }


def detect_ssh_brute_force(events):
    """Find >=5 failures per (source_ip, hostname) in a sliding 60-second window.

    Naive event_time values mean UTC; aware times are converted to UTC. Invalid
    and duplicate source events are skipped. Input is never modified.
    Qualifying windows sharing events form one episode, possibly longer than
    60 seconds. A new episode starts with a qualifying window sharing no events
    with the previous episode. Nonqualifying tails are excluded from evidence.
    """
    groups = {}
    seen = set()
    for event in events:
        event = _normalize_event(event)
        if event is None:
            continue
        keys = _identity_keys(event)
        scope = event_scope(event)
        keys = [(scope, key) for key in keys]
        duplicate = any(key in seen for key in keys)
        seen.update(keys)
        if duplicate:
            continue
        group = (event["source_ip"], scope)
        groups.setdefault(group, []).append(event)
    detections = []
    for group_events in groups.values():
        group_events.sort(key=itemgetter("event_time"))
        for start, end in _find_windows(group_events):
            detections.append(_build_detection(group_events[start:end + 1]))
    detections.sort(key=itemgetter("first_seen", "source_ip", "hostname"))
    return detections
