"""Security measurement versions and their API v1 message envelope."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contracts.v1.system import Decimal10_2
from contracts.v1.types import (
    U64,
    UTC6,
    CanonicalUUIDv4,
    Revision,
    SourceKey,
    UTCDate,
    UTCSecond,
)


class SecurityMetricsPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    date: UTCSecond
    uptime: Decimal10_2
    blocks: U64
    failed_logins: U64
    unique_ips: U64
    metric_day: UTCDate
    revision: Revision

    @model_validator(mode="after")
    def validate_metric_day(self) -> "SecurityMetricsPayload":
        if self.date[:10] != self.metric_day:
            raise ValueError("metric_day must match the UTC day of date.")
        return self


class SecurityMetricsMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    message_id: CanonicalUUIDv4
    message_type: Literal["security.metrics"]
    payload_version: int = Field(ge=1, le=1)
    source_key: SourceKey
    created_at: UTC6
    payload: SecurityMetricsPayload
