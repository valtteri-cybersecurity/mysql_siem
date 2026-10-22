"""Shared DNS data, without HTTP or database dependencies."""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal


@dataclass(frozen=True)
class DNSEvent:
    source_name: str
    event_time: datetime
    raw_timestamp: str
    client_ip: str | None
    domain: str
    query_type: str
    response_code: str | None
    filtering_result: str
    filtering_reason: str | None
    upstream: str | None
    elapsed_ms: Decimal | None
    cached: bool | None


@dataclass(frozen=True)
class DNSPage:
    # Keep order and multiplicity: identical entries may be separate requests.
    events: tuple[DNSEvent, ...]
    oldest: str | None
