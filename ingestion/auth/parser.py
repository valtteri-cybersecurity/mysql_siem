"""Normalize explicit OpenSSH and local TTY login records without file or DB I/O."""

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ingestion.ip_addresses import canonical_ip

LOG_LINE = re.compile(
    r"(?P<time>\S+(?: +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})?)\s+(?P<host>\S+)\s+"
    r"(?P<process>sshd(?:-session|-auth)?|login)\[(?P<pid>[0-9]+)\]: (?P<message>.+)"
)
SUPPORTED_HEADER = re.compile(
    r"\S+(?: +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})?\s+\S+\s+"
    r"(?:sshd(?:-session|-auth)?|login)(?:\[[^\]\r\n]*\])?: "
    r"(?:Accepted (?:password|publickey) |Failed (?:password|publickey) |"
    r"LOGIN ON |ROOT LOGIN ON |pam_unix\(login:auth\): authentication failure;)"
)
ISO_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})"
)
SYSLOG_TIME = re.compile(
    r"(?P<month>[A-Z][a-z]{2}) +(?P<day>[0-9]{1,2}) "
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
)
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
SSH_EVENT = re.compile(
    r"(?P<result>Accepted|Failed) (?P<method>password|publickey) for "
    r"(?:invalid user )?(?P<username>\S+) from (?P<ip>\S+) "
    r"port (?P<port>\S+) ssh2(?P<extra>.*)"
)
TTY = r"(?:tty[0-9]+|ttyS[0-9]+|hvc[0-9]+|xvc[0-9]+|console)"
LOCAL_SUCCESS = re.compile(r"LOGIN ON " + TTY + r" BY (?P<username>\S+)")
ROOT_SUCCESS = re.compile(r"ROOT LOGIN ON " + TTY)
LOCAL_SUCCESS_PREFIX = re.compile(r"(?:ROOT )?LOGIN ON " + TTY + r"(?: |$)")
LOCAL_FAILURE = re.compile(r"pam_unix\(login:auth\): authentication failure; (?P<fields>.*)")


class AuthParseError(ValueError):
    """A supported record cannot be safely consumed; retain the source checkpoint."""


def validate_syslog_context(syslog_start, syslog_end, syslog_timezone):
    """Validate an operator-confirmed, half-open source interval, never the clock.

    The caller must verify that every yearless source record belongs to this
    interval and timezone. File mtime alone cannot establish its event year.
    """
    if not isinstance(syslog_start, datetime) or not isinstance(syslog_end, datetime):
        raise AuthParseError("Yearless auth timestamps require a confirmed source interval and timezone.")
    if syslog_start.utcoffset() is None or syslog_end.utcoffset() is None:
        raise AuthParseError("The auth source interval must include explicit UTC offsets.")
    start = syslog_start.astimezone(timezone.utc)
    end = syslog_end.astimezone(timezone.utc)
    if end <= start or end - start > timedelta(days=366):
        raise AuthParseError("The auth source interval must be positive and at most 366 days.")
    zone = syslog_timezone
    if isinstance(zone, str):
        try:
            zone = ZoneInfo(zone)
        except (ZoneInfoNotFoundError, ValueError):
            raise AuthParseError("The auth source timezone is invalid.") from None
    if not isinstance(zone, tzinfo):
        raise AuthParseError("Yearless auth timestamps require a confirmed source timezone.")
    return start, end, zone


def parse_event_time(value, syslog_start, syslog_end, syslog_timezone):
    if ISO_TIME.fullmatch(value) is not None:
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            result = result.astimezone(timezone.utc).replace(tzinfo=None)
        except (ValueError, OverflowError):
            raise AuthParseError("The auth event timestamp is invalid.") from None
        if result.year < 1000:
            raise AuthParseError("The auth event timestamp is outside the database range.")
        return result

    match = SYSLOG_TIME.fullmatch(value)
    if match is None or match["month"] not in MONTHS:
        raise AuthParseError("The auth event timestamp format is unsupported or invalid.")
    start, end, zone = validate_syslog_context(syslog_start, syslog_end, syslog_timezone)
    candidates = []
    first_year = start.astimezone(zone).year
    last_year = end.astimezone(zone).year
    for year in range(first_year, last_year + 1):
        try:
            local = datetime(year, MONTHS[match["month"]], int(match["day"]),
                             int(match["hour"]), int(match["minute"]), int(match["second"]))
            first = local.replace(tzinfo=zone, fold=0).astimezone(timezone.utc)
            second = local.replace(tzinfo=zone, fold=1).astimezone(timezone.utc)
            first_valid = first.astimezone(zone).replace(tzinfo=None) == local
            second_valid = second.astimezone(zone).replace(tzinfo=None) == local
        except (ValueError, OverflowError):
            continue
        first_in_range = first_valid and start <= first < end
        second_in_range = second_valid and start <= second < end
        # Reject repeated autumn times in the source interval, even when one
        # occurrence falls across its boundary. Missing spring times are invalid.
        if first_valid and second_valid and first != second and (first_in_range or second_in_range):
            raise AuthParseError("The yearless auth timestamp is ambiguous at a timezone transition.")
        if first_in_range:
            candidates.append(first)
    if len(candidates) != 1 or candidates[0].year < 1000:
        raise AuthParseError("The yearless auth timestamp has no unique UTC time in the source interval.")
    return candidates[0].replace(tzinfo=None)


def parse_event_fields(process, message):
    """Use one canonical record per attempt; ignore PAM/session companions."""
    if process != "login":
        match = SSH_EVENT.fullmatch(message)
        if match is None:
            if message.startswith(("Accepted password ", "Accepted publickey ",
                                   "Failed password ", "Failed publickey ")):
                raise AuthParseError("A supported SSH event has an invalid format.")
            if message.startswith(("Accepted ", "Failed ")):
                raise AuthParseError("An SSH authentication outcome has an unsupported method or format.")
            return None
        extra = match["extra"]
        if match["method"] == "publickey" and extra.startswith(": "):
            extra = ""
        if extra not in ("", " [preauth]"):
            raise AuthParseError("A supported SSH event has an invalid suffix.")
        if len(match["port"]) > 5 or not match["port"].isascii() or not match["port"].isdigit():
            raise AuthParseError("A supported SSH event has an invalid source port.")
        port = int(match["port"])
        if not 1 <= port <= 65535 or "%" in match["ip"]:
            raise AuthParseError("A supported SSH event has an invalid source address or port.")
        try:
            source_ip = canonical_ip(match["ip"])
        except ValueError:
            raise AuthParseError("A supported SSH event has an invalid source address.") from None
        event_type = "SSH_AUTH_FAILURE"
        if match["result"] == "Accepted":
            event_type = "SSH_LOGIN_SUCCESS"
        return {
            "username": match["username"], "source_ip": source_ip, "source_port": port,
            "auth_method": match["method"], "event_type": event_type, "service": "sshd",
        }

    match = LOCAL_SUCCESS.fullmatch(message)
    username = None
    if match is not None:
        username = match["username"]
    elif ROOT_SUCCESS.fullmatch(message) is not None:
        username = "root"
    if username is not None:
        return {"username": username, "source_ip": None, "source_port": None,
                "auth_method": None, "event_type": "LOCAL_LOGIN_SUCCESS", "service": "login"}

    if LOCAL_SUCCESS_PREFIX.match(message) is not None and " FROM " not in message:
        raise AuthParseError("A local TTY login success has an invalid format.")

    # login PAM sessions and LOGIN ON companions must not count twice. A session
    # alone lacks a terminal/remote origin, so only explicit TTY success counts.
    match = LOCAL_FAILURE.fullmatch(message)
    if match is None:
        if message.startswith("pam_unix(login:auth): authentication failure"):
            raise AuthParseError("A local authentication failure has an invalid format.")
        return None
    fields = {}
    for item in match["fields"].split():
        key, separator, value = item.partition("=")
        if not separator or key in fields:
            raise AuthParseError("A local authentication failure has invalid PAM fields.")
        if key not in ("logname", "uid", "euid", "tty", "ruser", "rhost", "user"):
            raise AuthParseError("A local authentication failure has unsupported PAM fields.")
        fields[key] = value
    if "rhost" not in fields:
        raise AuthParseError("A local authentication failure has no confirmed source context.")
    if fields["rhost"] or re.fullmatch(r"(?:/dev/)?" + TTY, fields.get("tty", "")) is None:
        return None
    username = fields.get("user")
    if not username:
        username = None
    return {"username": username, "source_ip": None, "source_port": None,
            "auth_method": "pam", "event_type": "LOCAL_LOGIN_FAILURE", "service": "login"}


def parse_auth_line(line, *, syslog_start=None, syslog_end=None, syslog_timezone=None):
    """Return a supported event, None for unrelated input, or AuthParseError.

    event_time is naive UTC for MySQL DATETIME(6). Yearless records require a
    confirmed source interval and timezone; DST folds/gaps remain replayable.
    Keep the historical password fingerprint unchanged for existing replay.
    """
    if not isinstance(line, str):
        return None
    raw_message = line.rstrip("\r\n")
    match = LOG_LINE.fullmatch(raw_message)
    if match is None:
        if SUPPORTED_HEADER.match(raw_message) is not None:
            raise AuthParseError("A supported auth event has an invalid source header.")
        return None
    fields = parse_event_fields(match["process"], match["message"])
    if fields is None:
        return None
    try:
        raw_size = len(raw_message.encode("utf-8"))
    except UnicodeEncodeError:
        raise AuthParseError("The auth event encoding is invalid.") from None
    if raw_size > 60000 or len(match["host"]) > 255:
        raise AuthParseError("The auth event exceeds database field limits.")
    if fields["username"] is not None and len(fields["username"]) > 255:
        raise AuthParseError("The auth event exceeds database field limits.")
    for character in raw_message:
        if ord(character) < 32 or ord(character) == 127:
            raise AuthParseError("The auth event contains invalid control characters.")
    event_time = parse_event_time(match["time"], syslog_start, syslog_end, syslog_timezone)
    identity = [event_time.isoformat(), match["host"], match["pid"], match["message"]]
    event_hash = hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()
    if fields["auth_method"] == "publickey":
        # New key events retain the canonical message but omit unnecessary key
        # fingerprints/certificate IDs. Existing password raw_message is intact.
        extra = SSH_EVENT.fullmatch(match["message"])["extra"]
        if extra:
            raw_message = raw_message[:-len(extra)]
    fields.update(event_time=event_time, hostname=match["host"],
                  raw_message=raw_message, event_hash=event_hash)
    return fields
