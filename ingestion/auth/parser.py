"""Normalize supported rsyslog/OpenSSH password failures; no file or DB I/O."""

import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address

# Require a complete date and an explicit offset: never guess a missing year/zone.
LOG_LINE = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>[0-9]+)\]: (?P<message>.+)"
)
FAILURE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>\S+) port (?P<port>[0-9]{1,5}) ssh2(?: \[preauth\])?"
)


def parse_auth_line(line):
    """Return one SSH_AUTH_FAILURE, or None for unsupported/invalid input.

    event_time is a naive UTC datetime, suitable for MySQL DATETIME(6).
    Only the canonical Failed password message counts, not companion PAM,
    Invalid user, disconnect, or Accepted messages from the same attempt.
    """
    if not isinstance(line, str):
        return None
    raw_message = line.rstrip("\r\n")
    # Keep values within schema limits and do not store malformed encodings.
    if len(raw_message.encode("utf-8")) > 60000:
        return None
    match = LOG_LINE.fullmatch(raw_message)
    if match is None:
        return None
    failure = FAILURE.fullmatch(match["message"])
    if failure is None:
        return None
    hostname = match["host"]
    username = failure["username"]
    if len(hostname) > 255 or len(username) > 255:
        return None
    if not 1 <= int(failure["port"]) <= 65535 or "%" in failure["ip"]:
        return None
    try:
        event_time = datetime.fromisoformat(match["time"].replace("Z", "+00:00"))
        event_time = event_time.astimezone(timezone.utc).replace(tzinfo=None)
        source_ip = str(ip_address(failure["ip"]))
    except (ValueError, OverflowError):
        return None
    # MySQL DATETIME starts at year 1000; malformed old dates must not abort ingestion.
    if event_time.year < 1000:
        return None

    # Include PID/message so different attempts in the same second survive.
    # Exclude file path/inode so rotation and replay do not create new events.
    identity = [event_time.isoformat(), hostname, match["pid"], match["message"]]
    event_hash = hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()
    return {
        "event_time": event_time,
        "hostname": hostname,
        "source_ip": source_ip,
        "username": username,
        "event_type": "SSH_AUTH_FAILURE",
        "service": "sshd",
        "raw_message": raw_message,
        "event_hash": event_hash,
    }
