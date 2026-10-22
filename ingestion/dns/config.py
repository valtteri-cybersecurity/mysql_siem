"""Validated environment-based settings for AdGuard Home."""

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class DNSConfigurationError(ValueError):
    """Invalid settings; messages must not contain credentials."""


@dataclass(frozen=True)
class AdGuardConfig:
    base_url: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    source_name: str = "adguard-home"
    connect_timeout: float = 5.0
    read_timeout: float = 30.0
    page_size: int = 1000
    ca_bundle: str | None = None

    def __post_init__(self):
        try:
            url = urlsplit(self.base_url)
            port = url.port
        except (TypeError, ValueError):
            raise DNSConfigurationError("Invalid ADGUARD_URL.") from None

        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or (port is not None and not 1 <= port <= 65535)
            or any(char.isspace() or ord(char) < 32 for char in self.base_url)
        ):
            raise DNSConfigurationError(
                "ADGUARD_URL must be HTTPS without credentials, query or fragment."
            )

        if not self.username or not self.password or ":" in self.username:
            raise DNSConfigurationError("AdGuard username and password are required.")
        try:
            # Requests uses Latin-1 for HTTP Basic authentication.
            self.username.encode("latin-1")
            self.password.encode("latin-1")
        except UnicodeEncodeError:
            raise DNSConfigurationError(
                "AdGuard Basic credentials must be Latin-1 encodable."
            ) from None

        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.source_name):
            raise DNSConfigurationError("Invalid ADGUARD_SOURCE_NAME.")

        for value in (self.connect_timeout, self.read_timeout):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 < value <= 300
            ):
                raise DNSConfigurationError("Timeouts must be within (0, 300] seconds.")

        if type(self.page_size) is not int or not 1 <= self.page_size <= 1000:
            raise DNSConfigurationError("ADGUARD_PAGE_SIZE must be within 1..1000.")

        if self.ca_bundle is not None and (
            not isinstance(self.ca_bundle, str)
            or not self.ca_bundle
            or not Path(self.ca_bundle).is_file()
        ):
            raise DNSConfigurationError("ADGUARD_CA_BUNDLE must name a CA file.")


def load_adguard_config():
    """Read process environment only; do not execute or load local files."""
    try:
        return AdGuardConfig(
            base_url=os.environ["ADGUARD_URL"],
            username=os.environ["ADGUARD_USERNAME"],
            password=os.environ["ADGUARD_PASSWORD"],
            source_name=os.getenv("ADGUARD_SOURCE_NAME", "adguard-home"),
            connect_timeout=float(os.getenv("ADGUARD_CONNECT_TIMEOUT", "5")),
            read_timeout=float(os.getenv("ADGUARD_READ_TIMEOUT", "30")),
            page_size=int(os.getenv("ADGUARD_PAGE_SIZE", "1000")),
            ca_bundle=os.getenv("ADGUARD_CA_BUNDLE") or None,
        )
    except DNSConfigurationError:
        raise
    except (KeyError, ValueError):
        raise DNSConfigurationError(
            "Missing or invalid AdGuard environment settings."
        ) from None


@dataclass(frozen=True)
class CollectorConfig:
    max_pages: int = 100
    max_seconds: int = 240
    overlap_seconds: int = 600
    settle_seconds: int = 30
    retention_days: int = 30
    max_group_events: int = 10000

    def __post_init__(self):
        for name, minimum, maximum in (
            ("max_pages", 1, 10000),
            ("max_seconds", 1, 240),
            ("overlap_seconds", 1, 86400),
            ("settle_seconds", 1, 3600),
            ("retention_days", 1, 36500),
            ("max_group_events", 1, 40000),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise DNSConfigurationError("Invalid DNS collector limit.")


def load_collector_config():
    try:
        return CollectorConfig(
            **{
                name: int(os.getenv("DNS_" + name.upper(), str(default)))
                for name, default in (
                    ("max_pages", 100),
                    ("max_seconds", 240),
                    ("overlap_seconds", 600),
                    ("settle_seconds", 30),
                    ("retention_days", 30),
                    ("max_group_events", 10000),
                )
            }
        )
    except (TypeError, ValueError):
        raise DNSConfigurationError(
            "Invalid DNS collector environment settings."
        ) from None
