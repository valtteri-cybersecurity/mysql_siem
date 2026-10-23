"""Read and normalize the official AdGuard Home query log API."""

import json
import time
from decimal import Decimal, InvalidOperation

import requests

from ingestion.dns.models import DNSEvent, DNSPage
from ingestion.dns.timestamps import parse_timestamp as parse_dns_timestamp
from ingestion.ip_addresses import canonical_ip

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
FILTERING_RESULTS = {
    "NotFilteredNotFound": "allowed",
    "NotFilteredWhiteList": "allowed",
    "NotFilteredError": "error",
    "FilteredBlackList": "blocked",
    "FilteredSafeBrowsing": "blocked",
    "FilteredParental": "blocked",
    "FilteredInvalid": "blocked",
    "FilteredSafeSearch": "rewritten",
    "FilteredBlockedService": "blocked",
    "Rewrite": "rewritten",
    "RewriteEtcHosts": "rewritten",
    "RewriteRule": "rewritten",
}


class AdGuardError(RuntimeError):
    """Safe-to-log adapter failure."""


class AdGuardAPIError(AdGuardError):
    """HTTP or transport failure."""


class AdGuardDataError(AdGuardError):
    """Malformed query log data; the page must not be checkpointed."""


def parse_timestamp(value):
    try:
        return parse_dns_timestamp(value)
    except ValueError:
        raise AdGuardDataError("Invalid query log timestamp.") from None


def get_text(data, key, *, required=False, max_length=2048):
    value = data.get(key)
    if value is None or value == "":
        if required:
            raise AdGuardDataError(f"Missing query log field: {key}.")
        return None
    if (
        not isinstance(value, str)
        or len(value) > max_length
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise AdGuardDataError(f"Invalid query log field: {key}.")
    return value


def normalize_event(data, source_name):
    if not isinstance(data, dict) or not isinstance(data.get("question"), dict):
        raise AdGuardDataError("Invalid query log event or question.")

    raw_timestamp = get_text(data, "time", required=True, max_length=64)
    event_time = parse_timestamp(raw_timestamp)
    client = get_text(data, "client", max_length=45)
    if client is not None:
        try:
            if "%" in client:
                raise ValueError
            client = canonical_ip(client)
        except ValueError:
            raise AdGuardDataError("Invalid query log client address.") from None

    question = data["question"]
    domain = get_text(question, "name", required=True, max_length=1024).lower()
    if domain != ".":
        domain = domain.removesuffix(".")
    query_type = get_text(question, "type", required=True, max_length=32).upper()
    reason = get_text(data, "reason", max_length=128)
    response_code = get_text(data, "status", max_length=64)

    elapsed = data.get("elapsedMs")
    if elapsed is not None:
        try:
            if isinstance(elapsed, bool):
                raise TypeError
            elapsed = Decimal(str(elapsed))
            if not elapsed.is_finite() or elapsed < 0:
                raise ValueError
            # AdGuard emits elapsedMs through float formatting. Remove sub-picosecond
            # float noise before persistence; source duration has nanosecond resolution.
            elapsed = elapsed.quantize(Decimal("0.000000001"))
        except (InvalidOperation, TypeError, ValueError):
            raise AdGuardDataError("Invalid query log duration.") from None

    cached = data.get("cached")
    if cached is not None and not isinstance(cached, bool):
        raise AdGuardDataError("Invalid query log cache flag.")

    return DNSEvent(
        source_name=source_name,
        event_time=event_time,
        raw_timestamp=raw_timestamp,
        client_ip=client,
        domain=domain,
        query_type=query_type,
        response_code=response_code.upper() if response_code else None,
        filtering_result=FILTERING_RESULTS.get(reason, "unknown"),
        filtering_reason=reason,
        upstream=get_text(data, "upstream"),
        elapsed_ms=elapsed,
        cached=cached,
    )


class AdGuardAdapter:
    def __init__(self, config):
        self.config = config
        self._session = requests.Session()
        self._session.trust_env = False

    def close(self):
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def fetch_page(self, *, limit=None, older_than=None, offset=None, deadline=None):
        """Fetch one page only. No deduplication, retries or durable state.

        `oldest` is API metadata, not a guaranteed unique or lossless cursor.
        The collection layer must handle timestamp ties and changing logs.
        """
        limit = self.config.page_size if limit is None else limit
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Page limit must be within 1..1000.")

        params = {"limit": limit}
        if older_than is not None:
            parse_timestamp(older_than)
            params["older_than"] = older_than
        if offset is not None:
            if type(offset) is not int or offset < 0:
                raise ValueError("Offset must be a nonnegative integer.")
            params["offset"] = offset

        timeout = (self.config.connect_timeout, self.config.read_timeout)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AdGuardAPIError("AdGuard request deadline exceeded.")
            timeout = tuple(min(value, remaining) for value in timeout)
        try:
            with self._session.get(
                self.config.base_url.rstrip("/") + "/control/querylog",
                params=params,
                auth=(self.config.username, self.config.password),
                timeout=timeout,
                verify=self.config.ca_bundle or True,
                allow_redirects=False,
                stream=True,
                headers={"Accept": "application/json"},
            ) as response:
                if response.status_code in (401, 403):
                    raise AdGuardAPIError("AdGuard authentication or access denied.")
                if response.status_code != 200:
                    raise AdGuardAPIError(
                        f"AdGuard returned HTTP {response.status_code}."
                    )
                body = bytearray()
                for chunk in response.iter_content(chunk_size=65536):
                    if deadline is not None and time.monotonic() >= deadline:
                        raise AdGuardAPIError("AdGuard request deadline exceeded.")
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise AdGuardDataError("AdGuard response exceeds size limit.")
        except requests.Timeout:
            raise AdGuardAPIError("AdGuard request timed out.") from None
        except requests.exceptions.SSLError:
            raise AdGuardAPIError("AdGuard TLS verification failed.") from None
        except requests.RequestException:
            raise AdGuardAPIError("AdGuard request failed.") from None

        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError, RecursionError):
            raise AdGuardDataError("AdGuard returned invalid JSON.") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise AdGuardDataError("AdGuard response must contain a data array.")
        if len(payload["data"]) > limit:
            raise AdGuardDataError("AdGuard returned more events than requested.")

        oldest = get_text(payload, "oldest", max_length=64)
        if oldest is not None:
            parse_timestamp(oldest)
        events = tuple(
            normalize_event(item, self.config.source_name) for item in payload["data"]
        )
        return DNSPage(events=events, oldest=oldest)
