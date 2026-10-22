import json
from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal

import pytest
import requests

from ingestion.dns.adapters import adguard
from ingestion.dns.adapters.adguard import (
    AdGuardAdapter,
    AdGuardAPIError,
    AdGuardDataError,
    normalize_event,
    parse_timestamp,
)
from ingestion.dns.config import AdGuardConfig


@pytest.fixture
def event():
    return {
        "time": "2026-10-21T12:34:56.123456789+03:00",
        "client": "2001:0db8::1",
        "question": {"name": "EXAMPLE.NET.", "type": "aaaa", "class": "IN"},
        "status": "NOERROR",
        "reason": "NotFilteredNotFound",
        "upstream": "tls://dns.example.net",
        "elapsedMs": "1.23456789",
        "cached": False,
    }


class FakeResponse:
    def __init__(self, payload=None, status=200, body=None):
        self.status_code = status
        self.body = json.dumps(payload).encode() if body is None else body
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]


@pytest.fixture
def transport(monkeypatch, event):
    state = {
        "response": FakeResponse({"data": [event], "oldest": event["time"]}),
        "calls": [],
        "error": None,
    }

    def get(session, url, **kwargs):
        state["calls"].append((session, url, kwargs))
        if state["error"] is not None:
            raise state["error"]
        return state["response"]

    monkeypatch.setattr(requests.Session, "get", get)
    return state


@pytest.fixture
def config():
    return AdGuardConfig(
        base_url="https://dns.example.net/proxy/",
        username="test-user",
        password="test-password",
        source_name="office-dns",
    )


def test_normalization_preserves_precision(event):
    result = normalize_event(event, "office-dns")
    assert result.source_name == "office-dns"
    assert result.event_time == datetime(
        2026, 10, 21, 9, 34, 56, 123456, tzinfo=timezone.utc
    )
    assert result.raw_timestamp == event["time"]
    assert result.client_ip == "2001:db8::1"
    assert result.domain == "example.net"
    assert result.query_type == "AAAA"
    assert result.response_code == "NOERROR"
    assert result.filtering_result == "allowed"
    assert result.filtering_reason == "NotFilteredNotFound"
    assert result.upstream == "tls://dns.example.net"
    assert result.elapsed_ms == Decimal("1.23456789")
    assert result.cached is False


@pytest.mark.parametrize(
    "reason,result",
    [
        ("FilteredBlackList", "blocked"),
        ("FilteredSafeBrowsing", "blocked"),
        ("FilteredParental", "blocked"),
        ("FilteredInvalid", "blocked"),
        ("FilteredBlockedService", "blocked"),
        ("FilteredSafeSearch", "rewritten"),
        ("Rewrite", "rewritten"),
        ("RewriteEtcHosts", "rewritten"),
        ("RewriteRule", "rewritten"),
        ("NotFilteredWhiteList", "allowed"),
        ("NotFilteredError", "error"),
        ("FutureReason", "unknown"),
        (None, "unknown"),
    ],
)
def test_filtering_results(event, reason, result):
    event["reason"] = reason
    normalized = normalize_event(event, "dns")
    assert normalized.filtering_result == result
    assert normalized.filtering_reason == reason


def test_optional_fields_and_root_domain(event):
    event = {"time": "2026-10-21T09:34:56Z", "question": {"name": ".", "type": "A"}}
    normalized = normalize_event(event, "dns")
    assert normalized.domain == "."
    for field in ("client_ip", "response_code", "upstream", "elapsed_ms", "cached"):
        assert getattr(normalized, field) is None
    event["client"] = ""
    assert normalize_event(event, "dns").client_ip is None
    event["client"] = "192.0.2.10"
    assert normalize_event(event, "dns").client_ip == "192.0.2.10"


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-21T12:00:00",
        "2026-10-21",
        "2026-02-30T12:00:00Z",
        "2026-10-21T12:00:00+24:00",
        "bad",
        "",
        None,
        123,
    ],
)
def test_invalid_timestamp(value):
    with pytest.raises(AdGuardDataError):
        parse_timestamp(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("time", None),
        ("client", "secret-not-an-ip"),
        ("client", []),
        ("question", None),
        ("question", {"name": "", "type": "A"}),
        ("question", {"name": "example.net", "type": None}),
        ("question", {"name": "example.net\nsecret", "type": "A"}),
        ("elapsedMs", "NaN"),
        ("elapsedMs", "Infinity"),
        ("elapsedMs", "-1"),
        ("elapsedMs", True),
        ("cached", "false"),
        ("reason", 123),
        ("upstream", {"secret": 1}),
    ],
)
def test_invalid_event_is_safe(event, field, value):
    event[field] = value
    with pytest.raises(AdGuardDataError) as error:
        normalize_event(event, "dns")
    assert "secret" not in str(error.value)


def test_secure_single_page_request(config, transport):
    with AdGuardAdapter(config) as adapter:
        page = adapter.fetch_page(limit=100)
    session, url, options = transport["calls"][0]
    assert session.trust_env is False
    assert url == "https://dns.example.net/proxy/control/querylog"
    assert options["auth"] == ("test-user", "test-password")
    assert options["verify"] is True
    assert options["timeout"] == (5, 30)
    assert options["allow_redirects"] is False
    assert options["stream"] is True
    assert options["params"] == {"limit": 100}
    assert len(page.events) == 1
    assert page.oldest == page.events[0].raw_timestamp
    assert transport["response"].closed
    assert len(transport["calls"]) == 1


def test_custom_ca_is_passed(config, transport, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("CA fixture")
    with AdGuardAdapter(replace(config, ca_bundle=str(ca))) as adapter:
        adapter.fetch_page()
    assert transport["calls"][0][2]["verify"] == str(ca)


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 429, 500, 503])
def test_http_errors_do_not_leak_body(config, transport, status):
    transport["response"] = FakeResponse(status=status, body=b"secret-password")
    with AdGuardAdapter(config) as adapter, pytest.raises(AdGuardAPIError) as error:
        adapter.fetch_page()
    assert "secret-password" not in str(error.value)
    assert transport["response"].closed
    assert len(transport["calls"]) == 1


@pytest.mark.parametrize(
    "exception,message",
    [
        (requests.Timeout, "timed out"),
        (requests.exceptions.SSLError, "TLS verification failed"),
        (requests.ConnectionError, "request failed"),
        (requests.exceptions.ChunkedEncodingError, "request failed"),
    ],
)
def test_transport_errors_are_safe(config, transport, exception, message):
    transport["error"] = exception("secret-password")
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardAPIError, match=message) as error,
    ):
        adapter.fetch_page()
    assert "secret-password" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": {}},
        {"data": [None]},
        {"data": [], "oldest": "bad"},
    ],
)
def test_invalid_payload(config, transport, payload):
    transport["response"] = FakeResponse(payload)
    with AdGuardAdapter(config) as adapter, pytest.raises(AdGuardDataError):
        adapter.fetch_page()


def test_invalid_json(config, transport):
    transport["response"] = FakeResponse(body=b"<html>secret</html>")
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardDataError, match="invalid JSON"),
    ):
        adapter.fetch_page()


def test_response_size_limit(config, transport, monkeypatch):
    monkeypatch.setattr(adguard, "MAX_RESPONSE_BYTES", 32)
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardDataError, match="size limit"),
    ):
        adapter.fetch_page()
    assert transport["response"].closed


def test_empty_page(config, transport):
    transport["response"] = FakeResponse({"data": [], "oldest": ""})
    with AdGuardAdapter(config) as adapter:
        page = adapter.fetch_page()
    assert page.events == ()
    assert page.oldest is None


def test_identical_events_are_not_deduplicated(config, transport, event):
    transport["response"] = FakeResponse({"data": [event, event]})
    with AdGuardAdapter(config) as adapter:
        page = adapter.fetch_page()
    assert len(page.events) == 2
    assert page.events[0] == page.events[1]


def test_excess_events_rejected(config, transport, event):
    transport["response"] = FakeResponse({"data": [event, event]})
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardDataError, match="more events"),
    ):
        adapter.fetch_page(limit=1)


@pytest.mark.parametrize(
    "params",
    [
        {"older_than": "2026-10-21T12:34:56.123456789+03:00"},
        {"offset": 0},
        {"offset": 1000},
    ],
)
def test_page_parameters_passed_without_precision_loss(config, transport, params):
    with AdGuardAdapter(config) as adapter:
        adapter.fetch_page(**params)
    assert transport["calls"][0][2]["params"] == {"limit": 1000, **params}


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 1001},
        {"limit": True},
        {"offset": -1},
        {"offset": True},
        {"offset": "1"},
    ],
)
def test_invalid_page_parameters_do_not_make_requests(config, transport, params):
    with AdGuardAdapter(config) as adapter, pytest.raises(ValueError):
        adapter.fetch_page(**params)
    assert transport["calls"] == []


@pytest.mark.parametrize(
    "fraction,microsecond",
    [
        ("1", 100000),
        ("12", 120000),
        ("123", 123000),
        ("1234", 123400),
        ("12345", 123450),
        ("123456", 123456),
        ("1234567", 123456),
        ("12345678", 123456),
        ("123456789", 123456),
    ],
)
def test_fractional_timestamp_lengths(fraction, microsecond):
    result = parse_timestamp(f"2026-10-21T12:00:00.{fraction}Z")
    assert result == datetime(2026, 10, 21, 12, 0, 0, microsecond, tzinfo=timezone.utc)


def test_malformed_event_fails_whole_page(config, transport, event):
    transport["response"] = FakeResponse({"data": [event, {"question": {}}]})
    with AdGuardAdapter(config) as adapter, pytest.raises(AdGuardDataError):
        adapter.fetch_page()
    assert transport["response"].closed


def test_interrupted_body_is_not_returned_as_a_page(config, transport, monkeypatch):
    def broken_stream(chunk_size):
        yield b'{"data": ['
        raise requests.ConnectionError("secret-password")

    response = transport["response"]
    monkeypatch.setattr(response, "iter_content", broken_stream)
    with AdGuardAdapter(config) as adapter, pytest.raises(AdGuardAPIError) as error:
        adapter.fetch_page()
    assert "secret-password" not in str(error.value)
    assert response.closed


def test_adapter_closes_on_caller_error(config, monkeypatch):
    closed = []
    monkeypatch.setattr(requests.Session, "close", lambda session: closed.append(True))
    with pytest.raises(RuntimeError), AdGuardAdapter(config):
        raise RuntimeError("caller error")
    assert closed == [True]


def test_fixed_fence_and_offset_supported(config, transport):
    with AdGuardAdapter(config) as adapter:
        adapter.fetch_page(older_than="2026-10-21T00:00:00Z", offset=10)
    assert transport["calls"][0][2]["params"] == {
        "limit": 1000,
        "older_than": "2026-10-21T00:00:00Z",
        "offset": 10,
    }


def test_elapsed_float_format_noise_is_normalized(event):
    event["elapsedMs"] = "0.0007140000000000001"
    assert normalize_event(event, "dns").elapsed_ms == Decimal("0.000714000")


def test_expired_request_deadline_does_not_send(config, transport, monkeypatch):
    monkeypatch.setattr(adguard.time, "monotonic", lambda: 10)
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardAPIError, match="deadline"),
    ):
        adapter.fetch_page(deadline=9)
    assert transport["calls"] == []


def test_collector_deadline_caps_http_timeouts(config, transport, monkeypatch):
    monkeypatch.setattr(adguard.time, "monotonic", lambda: 10)
    with AdGuardAdapter(config) as adapter:
        adapter.fetch_page(deadline=12)
    assert transport["calls"][0][2]["timeout"] == (2, 2)
