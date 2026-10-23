"""API v1 event batches discriminated by their supported message types."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from contracts.v1.dns import DNSQueryMessage
from contracts.v1.filesystem import FilesystemMetricsMessage
from contracts.v1.security import SecurityMetricsMessage
from contracts.v1.ssh import SSHAuthEventMessage
from contracts.v1.system import SystemMetricsMessage
from contracts.v1.ufw import UFWEventMessage

EventMessage = Annotated[
    UFWEventMessage
    | DNSQueryMessage
    | SSHAuthEventMessage
    | SystemMetricsMessage
    | FilesystemMetricsMessage
    | SecurityMetricsMessage,
    Field(discriminator="message_type"),
]


class EventBatchRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    protocol_version: int = Field(ge=1, le=1)
    messages: list[EventMessage] = Field(min_length=1, max_length=100)
