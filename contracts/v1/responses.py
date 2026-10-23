"""API v1 acknowledgement and error values; no delivery or HTTP behavior."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from contracts.v1.types import UTC6, CanonicalUUIDv4

ErrorCode = Literal[
    "invalid_json",
    "invalid_envelope",
    "invalid_credentials",
    "source_forbidden",
    "message_id_conflict",
    "revision_conflict",
    "event_identity_conflict",
    "batch_too_large",
    "invalid_message",
    "unsupported_message_type",
    "unsupported_payload_version",
    "rate_limited",
    "internal_error",
    "temporarily_unavailable",
    "writer_busy",
    "unsupported_media_type",
    "enrollment_conflict",
]


class EventResult(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    index: int = Field(ge=0)
    message_id: CanonicalUUIDv4
    status: Literal["accepted", "duplicate", "stale"]


class EventBatchResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    protocol_version: int = Field(ge=1, le=1)
    request_id: CanonicalUUIDv4
    collector_id: CanonicalUUIDv4
    received_at: UTC6
    committed: bool
    results: list[EventResult] = Field(min_length=1, max_length=100)

    @field_validator("committed")
    @classmethod
    def validate_committed(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("A successful response requires committed=true.")
        return value

    @model_validator(mode="after")
    def validate_result_order(self) -> "EventBatchResponse":
        for expected_index, result in enumerate(self.results):
            if result.index != expected_index:
                raise ValueError("Result indices must be ordered and contiguous from 0.")
        return self


class MessageValidationError(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    index: int | None = Field(ge=0)
    message_id: CanonicalUUIDv4 | None
    field: str | None
    code: ErrorCode


class APIError(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    code: ErrorCode
    message: str = Field(min_length=1)
    retryable: bool
    commit_state: Literal["not_committed", "unknown"]
    errors: list[MessageValidationError]


class APIErrorResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    protocol_version: int = Field(ge=1, le=1)
    request_id: CanonicalUUIDv4
    error: APIError
