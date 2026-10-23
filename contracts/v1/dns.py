"""DNS query values preserve the collector's timestamps and replay identities."""

import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)

from contracts.v1.types import UTC6, CanonicalUUIDv4, Hex256, SourceKey
from ingestion.dns.timestamps import parse_timestamp


def validate_elapsed_ms(value: str) -> str:
    if re.fullmatch(r"[0-9]+\.[0-9]{9}", value) is None:
        raise ValueError("Expected an unsigned decimal string with nine decimal places.")
    if Decimal(value) > Decimal("99999999999.999999999"):
        raise ValueError("DNS duration exceeds DECIMAL(20,9).")
    return value


ElapsedMilliseconds = Annotated[StrictStr, AfterValidator(validate_elapsed_ms)]


class DNSQueryPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    event_time: UTC6
    raw_timestamp: str = Field(min_length=1, max_length=64)
    client_ip: str | None = Field(min_length=1, max_length=45)
    domain: str = Field(min_length=1, max_length=1024)
    query_type: str = Field(min_length=1, max_length=32)
    response_code: str | None = Field(min_length=1, max_length=64)
    filtering_result: str = Field(min_length=1, max_length=32)
    filtering_reason: str | None = Field(min_length=1, max_length=128)
    upstream: str | None = Field(min_length=1, max_length=2048)
    elapsed_ms: ElapsedMilliseconds | None
    cached: bool | None
    dedup_key: Hex256

    @field_validator(
        "raw_timestamp", "client_ip", "domain", "query_type", "response_code",
        "filtering_result", "filtering_reason", "upstream",
    )
    @classmethod
    def validate_text_controls(cls, value: str | None) -> str | None:
        if value is not None:
            for char in value:
                if ord(char) < 32 or ord(char) == 127:
                    raise ValueError("Invalid DNS text field.")
        return value

    @model_validator(mode="after")
    def validate_event_time(self) -> "DNSQueryPayload":
        expected = parse_timestamp(self.raw_timestamp)
        actual = datetime.fromisoformat(self.event_time[:-1]).replace(tzinfo=timezone.utc)
        if actual != expected:
            raise ValueError("event_time must match raw_timestamp truncated to microseconds in UTC.")
        return self


class DNSQueryMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    message_id: CanonicalUUIDv4
    message_type: Literal["dns.query"]
    payload_version: int = Field(ge=1, le=1)
    source_key: SourceKey
    created_at: UTC6
    payload: DNSQueryPayload
