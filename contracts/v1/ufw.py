"""UFW payload and its fully formed API v1 message."""

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from contracts.v1.types import UTC6, CanonicalUUIDv4, Hex256, SourceKey


class UFWEventPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    event_time: UTC6
    action: str | None = Field(max_length=20)
    src_ip: str | None = Field(max_length=45)
    dst_ip: str | None = Field(max_length=45)
    protocol: str | None = Field(max_length=10)
    # SQL ports are NOT NULL; the collector writes 0 for missing ports.
    src_port: int = Field(ge=0, le=4294967295)
    dst_port: int = Field(ge=0, le=4294967295)
    raw_line: str
    event_hash: Hex256
    reported_hostname: str | None = Field(max_length=255)

    @field_validator("raw_line")
    @classmethod
    def validate_raw_line_size(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("raw_line must be valid UTF-8.") from None
        if len(encoded) > 65535:
            raise ValueError("raw_line exceeds 65535 UTF-8 bytes.")
        return value

    @model_validator(mode="after")
    def validate_event_hash(self) -> "UFWEventPayload":
        expected = hashlib.sha256(self.raw_line.encode("utf-8")).hexdigest()
        if self.event_hash != expected:
            raise ValueError("event_hash does not match raw_line.")
        return self


class UFWEventMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    message_id: CanonicalUUIDv4
    message_type: Literal["ufw.event"]
    payload_version: int = Field(ge=1, le=1)
    source_key: SourceKey
    created_at: UTC6
    payload: UFWEventPayload
