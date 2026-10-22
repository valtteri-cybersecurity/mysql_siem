"""RFC3339 timestamps with exact nanosecond comparison and Python 3.10 support."""

import re
from datetime import datetime, timezone

PATTERN = re.compile(
    r"(?P<time>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})"
)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_timestamp(value):
    match = PATTERN.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("Invalid DNS timestamp.")
    iso = match["time"]
    if match["fraction"]:
        iso += "." + match["fraction"][:6].ljust(6, "0")
    iso += "+00:00" if match["zone"] == "Z" else match["zone"]
    try:
        return datetime.fromisoformat(iso).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError("Invalid DNS timestamp.") from None


def timestamp_ns(value):
    parsed = parse_timestamp(value)
    delta = parsed.replace(microsecond=0) - EPOCH
    fraction = PATTERN.fullmatch(value)["fraction"] or "0"
    return (delta.days * 86400 + delta.seconds) * 10**9 + int(fraction.ljust(9, "0"))
