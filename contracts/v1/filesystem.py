"""Filesystem measurement versions and their API v1 message envelope."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contracts.v1.types import U64, UTC6, CanonicalUUIDv4, Revision, SourceKey, UTCDate


class FilesystemMetricsPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    metric_date: UTCDate
    modified_last_day: U64
    total_files: U64
    observed_at: UTC6
    revision: Revision

    @model_validator(mode="after")
    def validate_observation_date(self) -> "FilesystemMetricsPayload":
        if self.observed_at[:10] != self.metric_date:
            raise ValueError("observed_at must fall on metric_date in UTC.")
        return self


class FilesystemMetricsMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    message_id: CanonicalUUIDv4
    message_type: Literal["filesystem.metrics"]
    payload_version: int = Field(ge=1, le=1)
    source_key: SourceKey
    created_at: UTC6
    payload: FilesystemMetricsPayload
