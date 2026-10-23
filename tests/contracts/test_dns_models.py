"""DNS contracts are checked with local values, without MySQL or HTTP."""

import copy
import hashlib
import json
from datetime import timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.dns import DNSQueryMessage, DNSQueryPayload

TEXT_LIMITS = (
    ("client_ip", 45), ("domain", 1024), ("query_type", 32),
    ("response_code", 64), ("filtering_result", 32),
    ("filtering_reason", 128), ("upstream", 2048),
)
NULLABLE_FIELDS = (
    "client_ip", "response_code", "filtering_reason", "upstream", "elapsed_ms", "cached",
)


@pytest.fixture
def payload():
    return {
        "event_time": "2026-10-23T11:59:59.123456Z",
        "raw_timestamp": "2026-10-23T11:59:59.123456789Z",
        "client_ip": "2001:db8::1",
        "domain": "example.org",
        "query_type": "AAAA",
        "response_code": "NOERROR",
        "filtering_result": "allowed",
        "filtering_reason": "NotFilteredNotFound",
        "upstream": "https://dns.example/dns-query",
        "elapsed_ms": "1.234567890",
        "cached": False,
        "dedup_key": "abcdef0123456789" * 4,
    }


@pytest.fixture
def message(payload):
    return {
        "message_id": "11111111-1111-4111-8111-111111111111",
        "message_type": "dns.query",
        "payload_version": 1,
        "source_key": "adguard.dns",
        "created_at": "2026-10-23T12:00:00.000000Z",
        "payload": payload,
    }


def assert_valid(model_type, values):
    original = copy.deepcopy(values)
    assert model_type.model_validate(values).model_dump() == original
    parsed = model_type.model_validate_json(json.dumps(values))
    assert json.loads(parsed.model_dump_json()) == original
    assert values == original


def assert_invalid(model_type, values):
    with pytest.raises(ValidationError):
        model_type.model_validate(values)
    with pytest.raises(ValidationError):
        model_type.model_validate_json(json.dumps(values))


def test_valid_payload_and_message_preserve_raw_timestamp_and_dedup_key(message):
    assert_valid(DNSQueryPayload, message["payload"])
    assert_valid(DNSQueryMessage, message)


@pytest.mark.parametrize("digits", range(10))
def test_timestamp_accepts_zero_to_nine_fraction_digits_without_rounding(payload, digits):
    fraction = "123456789"[:digits]
    raw_fraction = "." + fraction if fraction else ""
    payload["raw_timestamp"] = "2026-10-23T11:59:59" + raw_fraction + "Z"
    microseconds = fraction[:6].ljust(6, "0")
    payload["event_time"] = "2026-10-23T11:59:59." + microseconds + "Z"
    assert_valid(DNSQueryPayload, payload)


@pytest.mark.parametrize("raw,utc", [
    ("2026-10-23T11:59:59Z", "2026-10-23T11:59:59.000000Z"),
    ("2026-10-23T14:59:59.123456789+03:00", "2026-10-23T11:59:59.123456Z"),
    ("2026-10-23T06:29:59.123456789-05:30", "2026-10-23T11:59:59.123456Z"),
    ("2026-01-01T00:15:00.999999999+02:00", "2025-12-31T22:15:00.999999Z"),
    ("2026-12-31T23:45:00.999999999-00:30", "2027-01-01T00:15:00.999999Z"),
    ("2024-03-01T00:15:00+01:00", "2024-02-29T23:15:00.000000Z"),
    ("2026-10-23T11:59:59.000000001-00:00", "2026-10-23T11:59:59.000000Z"),
    ("2026-10-23T11:59:59.999999999+00:00", "2026-10-23T11:59:59.999999Z"),
    ("1000-01-01T00:00:00Z", "1000-01-01T00:00:00.000000Z"),
    ("9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59.999999Z"),
])
def test_timezone_and_day_changes(payload, raw, utc):
    payload.update(raw_timestamp=raw, event_time=utc)
    assert_valid(DNSQueryPayload, payload)


@pytest.mark.parametrize("raw", [
    "", "2026-10-23", "2026-10-23T11:59:59", "2026-10-23t11:59:59z",
    "2026-10-23 11:59:59Z", "2026-10-23T11:59:59.Z",
    "2026-10-23T11:59:59.1234567890Z", "2026-10-23T11:59:59+0300",
    "2026-10-23T11:59:59+24:00", "2026-02-29T11:59:59Z",
    "2026-13-23T11:59:59Z", "2026-10-23T11:59:60Z",
    "2026-10-23T11:59:59Z\n", " 2026-10-23T11:59:59Z", "a" * 65,
    "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00",
    None, 1, True,
])
def test_invalid_raw_timestamps_are_rejected(payload, raw):
    payload["raw_timestamp"] = raw
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("event_time", [
    "2026-10-23T11:59:59.123457Z", "2026-10-23T11:59:58.123456Z",
    "2026-10-24T11:59:59.123456Z", "2026-10-23T14:59:59.123456Z",
    "2026-10-23T11:59:59Z", "2026-10-23T11:59:59.123456+00:00",
    "0999-12-31T23:59:59.123456Z", None,
])
def test_event_time_must_match_and_use_utc6(payload, event_time):
    payload["event_time"] = event_time
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("field,limit", TEXT_LIMITS)
def test_text_length_and_unicode_boundaries(payload, field, limit):
    for value in ("ä" * limit, "😀" * limit, "  Ä.Example.  ", "\x85\u200d"):
        payload[field] = value
        assert_valid(DNSQueryPayload, payload)
    for value in ("", "ä" * (limit + 1)):
        payload[field] = value
        assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("field", ["raw_timestamp", "client_ip", "domain", "query_type", "response_code", "filtering_result", "filtering_reason", "upstream"])
@pytest.mark.parametrize("control", list(range(32)) + [127])
def test_text_rejects_exact_collector_control_character_set(payload, field, control):
    payload[field] += chr(control)
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("field", ["event_time", "raw_timestamp", "client_ip", "domain", "query_type", "response_code", "filtering_result", "filtering_reason", "upstream", "dedup_key"])
@pytest.mark.parametrize("value", [1, True, [], {}])
def test_text_fields_are_strict(payload, field, value):
    payload[field] = value
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("field", NULLABLE_FIELDS)
def test_nullable_fields_accept_null(payload, field):
    payload[field] = None
    assert_valid(DNSQueryPayload, payload)


@pytest.mark.parametrize("field", ["event_time", "raw_timestamp", "domain", "query_type", "filtering_result", "dedup_key"])
def test_other_fields_reject_null(payload, field):
    payload[field] = None
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("value", [True, False, None])
def test_cached_accepts_only_booleans_or_null(payload, value):
    payload["cached"] = value
    assert_valid(DNSQueryPayload, payload)


@pytest.mark.parametrize("value", [0, 1, 0.0, "true", "false", "", [], {}])
def test_cached_rejects_coercion(payload, value):
    payload["cached"] = value
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("value", [None, "0.000000000", "0.000000001", "1.000000000", "99999999999.999999999", "0001.234567890"])
def test_elapsed_is_exact_preserved_decimal_string(payload, value):
    payload["elapsed_ms"] = value
    assert_valid(DNSQueryPayload, payload)


@pytest.mark.parametrize("value", [
    "100000000000.000000000", "99999999999.9999999999", "-1.000000000",
    "-0.000000000", "+1.000000000", "1.00000000", "1.0000000000",
    "1", "1.", ".000000000", "1e-9", "1.000000000e0", "NaN", "Infinity",
    " 1.000000000", "1.000000000\n", "１.000000000", "1,000000000",
    1, 1.0, True, [], {},
])
def test_elapsed_rejects_wrong_precision_format_type_or_range(payload, value):
    payload["elapsed_ms"] = value
    assert_invalid(DNSQueryPayload, payload)


def test_elapsed_rejects_python_decimal_instead_of_wire_string(payload):
    payload["elapsed_ms"] = Decimal("1.000000000")
    with pytest.raises(ValidationError):
        DNSQueryPayload.model_validate(payload)


@pytest.mark.parametrize("value", ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, None])
def test_dedup_key_requires_hex256(payload, value):
    payload["dedup_key"] = value
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("value", ["0" * 64, "f" * 64, "0123456789abcdef" * 4])
def test_dedup_key_is_not_regenerated_or_matched_to_payload(payload, value):
    payload["dedup_key"] = value
    assert_valid(DNSQueryPayload, payload)


@pytest.mark.parametrize("model_type,fixture_name", [(DNSQueryPayload, "payload"), (DNSQueryMessage, "message")])
def test_every_field_is_required(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("field,value", [
    ("message_id", "bad"), ("message_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ("message_type", "ufw.event"), ("message_type", "DNS.QUERY"),
    ("payload_version", True), ("payload_version", False), ("payload_version", 1.0),
    ("payload_version", "1"), ("payload_version", 0), ("payload_version", 2),
    ("source_key", "Local.dns"), ("source_key", " invalid "),
    ("created_at", "2026-10-23T12:00:00Z"), ("payload", {}), ("payload", None),
])
def test_message_rejects_invalid_values(message, field, value):
    message[field] = value
    assert_invalid(DNSQueryMessage, message)


@pytest.mark.parametrize("location", ["payload", "message", "batch"])
@pytest.mark.parametrize("extra", ["source_id", "host_id", "unknown"])
def test_extras_and_local_source_identifiers_are_forbidden(message, location, extra):
    batch = {"protocol_version": 1, "messages": [message]}
    target = batch
    if location == "message":
        target = message
    elif location == "payload":
        target = message["payload"]
    target[extra] = 1
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("size", [1, 100])
def test_dns_only_batches(message, size):
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("size", [0, 101])
def test_dns_batch_limits(message, size):
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


def ufw_message():
    return {
        "message_id": "22222222-2222-4222-8222-222222222222",
        "message_type": "ufw.event", "payload_version": 1,
        "source_key": "local.ufw", "created_at": "2026-10-23T12:00:00.000000Z",
        "payload": {
            "event_time": "2026-10-23T12:00:00.000000Z", "action": "BLOCK",
            "src_ip": None, "dst_ip": None, "protocol": None,
            "src_port": 0, "dst_port": 0, "raw_line": "original",
            "event_hash": hashlib.sha256(b"original").hexdigest(), "reported_hostname": None,
        },
    }


@pytest.mark.parametrize("dns_first", [False, True])
def test_mixed_ufw_and_dns_batch_preserves_order(message, dns_first):
    messages = [ufw_message(), message]
    if dns_first:
        messages.reverse()
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})
    parsed = EventBatchRequest.model_validate({"protocol_version": 1, "messages": messages})
    dns_index = 0 if dns_first else 1
    assert isinstance(parsed.messages[dns_index], DNSQueryMessage)


@pytest.mark.parametrize("invalid", ["payload", "tag", "missing_tag", "version"])
def test_invalid_dns_in_mixed_batch_cannot_bypass_discriminated_union(message, invalid):
    if invalid == "payload":
        message["payload"]["elapsed_ms"] = 1
    elif invalid == "tag":
        message["message_type"] = "unknown.event"
    elif invalid == "missing_tag":
        del message["message_type"]
    else:
        message["payload_version"] = True
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [ufw_message(), message]})


def test_payload_matches_current_adguard_storage_and_replay_keys():
    from ingestion.dns.adapters.adguard import normalize_event
    from ingestion.dns.collector import replay_keys
    from ingestion.dns.db import event_values

    event = normalize_event({
        "time": "2026-10-23T14:59:59.123456789+03:00", "client": "2001:db8::1",
        "question": {"name": "Example.ORG.", "type": "aaaa"},
        "reason": "NotFilteredNotFound", "status": "noerror",
        "elapsedMs": "0.0007140000000000001", "cached": False,
    }, "adguard")
    # These pure transformations neither open connections nor execute SQL.
    stored = event_values(7, event)
    keys = replay_keys([event, event])
    assert keys[0] != keys[1]
    exported = {}
    for field in DNSQueryPayload.model_fields:
        if field == "dedup_key":
            continue
        exported[field] = getattr(event, field)
    exported["event_time"] = stored[1].replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    exported["elapsed_ms"] = format(stored[10], ".9f")
    for key in keys:
        exported["dedup_key"] = key.hex()
        assert_valid(DNSQueryPayload, exported)
    assert exported["raw_timestamp"] == event.raw_timestamp
    assert exported["elapsed_ms"] == "0.000714000"


@pytest.mark.parametrize("zone,normalized_utc", [
    ("+00:99", "10:21:00"), ("-00:99", "13:39:00"),
    ("+01:60", "10:00:00"), ("-01:60", "14:00:00"),
    ("+12:75", "22:45:00"), ("+24:00", "12:00:00"),
    ("-24:00", "12:00:00"), ("+99:00", "12:00:00"),
])
def test_invalid_offset_is_rejected_even_with_normalized_event_time(payload, zone, normalized_utc):
    payload["raw_timestamp"] = "2026-10-23T12:00:00.123456789" + zone
    day = "2026-10-22" if zone == "+12:75" else "2026-10-23"
    payload["event_time"] = day + "T" + normalized_utc + ".123456Z"
    assert_invalid(DNSQueryPayload, payload)


@pytest.mark.parametrize("raw,utc", [
    ("2026-10-23T12:00:00.123456789+05:45", "2026-10-23T06:15:00.123456Z"),
    ("2026-10-23T12:00:00.999999999+23:59", "2026-10-22T12:01:00.999999Z"),
    ("2026-10-23T12:00:00.999999999-23:59", "2026-10-24T11:59:00.999999Z"),
])
def test_offset_boundary_payload_keeps_raw_timestamp_and_dedup_key(payload, raw, utc):
    payload.update(raw_timestamp=raw, event_time=utc)
    assert_valid(DNSQueryPayload, payload)
    payload["event_time"] = "2026-10-23T00:00:00.000000Z"
    assert_invalid(DNSQueryPayload, payload)
