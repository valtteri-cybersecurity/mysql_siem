"""Collector enrollment values; authentication and persistence belong elsewhere."""

import base64
import binascii
import re
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from contracts.v1.types import UTC6, CanonicalUUIDv4, SourceKey

MessageType = Literal[
    "ufw.event", "ssh.auth_event", "dns.query",
    "system.metrics", "filesystem.metrics", "security.metrics",
]
PayloadVersion = Annotated[int, Field(ge=1, le=1)]


def redact_validation_error(model_name, error):
    """Do not retain input values or exception contexts in public error details."""
    details = []
    for item in error.errors(include_input=False, include_context=False, include_url=False):
        location = item["loc"]
        if item["type"] in ("extra_forbidden", "invalid_key"):
            location = location[:-1] + ("<extra>",)
        details.append({
            "type": PydanticCustomError(item["type"], item["msg"]),
            "loc": location,
        })
    return ValidationError.from_exception_data(model_name, details, hide_input=True)


class _EnrollmentModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_without_input_disclosure(cls, value, handler):
        try:
            return handler(value)
        except ValidationError as error:
            raise redact_validation_error(cls.__name__, error) from None

    @classmethod
    def model_validate_json(cls, json_data, **kwargs):
        # Pydantic handles JSON parsing; redact its decoder errors as well.
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as error:
            raise redact_validation_error(cls.__name__, error) from None


class EnrollmentRequest(_EnrollmentModel):
    protocol_version: int = Field(ge=1, le=1)
    enrollment_request_id: CanonicalUUIDv4
    key_id: CanonicalUUIDv4
    api_key_secret: str = Field(repr=False)
    requested_source_keys: list[SourceKey] = Field(min_length=1, max_length=64)
    reported_hostname: str | None = Field(max_length=255)

    @field_validator("api_key_secret")
    @classmethod
    def validate_api_key_secret(cls, value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
            raise ValueError("Expected a canonical unpadded base64url secret of 32 bytes.")
        try:
            decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
        except binascii.Error:
            raise ValueError("Invalid base64url secret.") from None
        canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        if len(decoded) != 32 or canonical != value:
            raise ValueError("Expected a canonical unpadded base64url secret of 32 bytes.")
        return value

    @field_validator("requested_source_keys")
    @classmethod
    def validate_unique_source_keys(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("Requested source keys must be unique.")
        return value


class EnrollmentSourceBinding(_EnrollmentModel):
    source_key: SourceKey
    message_type: MessageType
    payload_versions: list[PayloadVersion] = Field(min_length=1)

    @field_validator("payload_versions")
    @classmethod
    def validate_unique_versions(cls, value: list[int]) -> list[int]:
        if len(set(value)) != len(value):
            raise ValueError("Payload versions must be unique.")
        return value


class EnrollmentResponse(_EnrollmentModel):
    protocol_version: int = Field(ge=1, le=1)
    request_id: CanonicalUUIDv4
    enrollment_request_id: CanonicalUUIDv4
    collector_id: CanonicalUUIDv4
    key_id: CanonicalUUIDv4
    recovery_until: UTC6
    source_bindings: list[EnrollmentSourceBinding] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_consistent_bindings(self) -> "EnrollmentResponse":
        bindings = {}
        for binding in self.source_bindings:
            definition = (binding.message_type, tuple(binding.payload_versions))
            if binding.source_key in bindings and bindings[binding.source_key] != definition:
                raise ValueError("A source key cannot have conflicting bindings.")
            bindings[binding.source_key] = definition
        return self
