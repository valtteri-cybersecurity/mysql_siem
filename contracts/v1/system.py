"""System measurement samples and their API v1 message envelope."""

from functools import partial
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictStr

from contracts.v1.decimal_values import validate_decimal_string
from contracts.v1.types import UTC6, CanonicalUUIDv4, SourceKey, UTCSecond

Decimal10_2 = Annotated[StrictStr, AfterValidator(partial(validate_decimal_string, precision=10, scale=2))]
Decimal12_2 = Annotated[StrictStr, AfterValidator(partial(validate_decimal_string, precision=12, scale=2))]
Decimal14_2 = Annotated[StrictStr, AfterValidator(partial(validate_decimal_string, precision=14, scale=2))]


class SystemMetricsPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    timestamp: UTCSecond
    uptime_hours: Decimal12_2 | None
    cpuload1: Decimal10_2 | None
    cpuload5: Decimal10_2 | None
    cpuload15: Decimal10_2 | None
    cpu_usage: Decimal10_2 | None
    cpu_temperature: Decimal10_2 | None
    ram_free_mb: Decimal14_2 | None
    disk_used: Decimal14_2 | None
    disk_free: Decimal14_2 | None
    disk_usage: Decimal10_2 | None


class SystemMetricsMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    message_id: CanonicalUUIDv4
    message_type: Literal["system.metrics"]
    payload_version: int = Field(ge=1, le=1)
    source_key: SourceKey
    created_at: UTC6
    payload: SystemMetricsPayload
