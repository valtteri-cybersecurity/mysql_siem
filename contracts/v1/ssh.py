"""SSH authentication observations and their API v1 message envelope."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from contracts.v1.types import UTC6, CanonicalUUIDv4, Hex256, SourceKey
from ingestion.ip_addresses import canonical_ip


class SSHAuthEventPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    event_time: UTC6
    hostname: str = Field(min_length=1, max_length=255)
    source_ip: str = Field(max_length=45)
    username: str | None = Field(max_length=255)
    event_type: Literal["SSH_AUTH_FAILURE"]
    service: Literal["sshd"]
    raw_message: str
    # The collector hashes time, hostname, PID and message, not raw_message alone.
    event_hash: Hex256

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        if "%" in value:
            raise ValueError("IPv6 zone IDs are not allowed.")
        if canonical_ip(value) != value:
            raise ValueError("Expected a canonical IPv4 or IPv6 address.")
        return value

    @field_validator("raw_message")
    @classmethod
    def validate_raw_message_size(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("raw_message must be valid UTF-8.") from None
        if len(encoded) > 60000:
            raise ValueError("raw_message exceeds 60000 UTF-8 bytes.")
        return value


class SSHAuthEventMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    message_id: CanonicalUUIDv4
    message_type: Literal["ssh.auth_event"]
    payload_version: int = Field(ge=1, le=1)
    source_key: SourceKey
    created_at: UTC6
    payload: SSHAuthEventPayload
