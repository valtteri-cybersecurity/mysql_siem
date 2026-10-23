"""Security payload and six-type event batches, without database or network I/O."""

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.security import SecurityMetricsMessage, SecurityMetricsPayload


@pytest.fixture
def payload():
    return {"date": "2026-10-23T12:00:00.000000Z", "uptime": "12.50",
            "blocks": "12", "failed_logins": "3", "unique_ips": "5",
            "metric_day": "2026-10-23", "revision": "1"}


@pytest.fixture
def message(payload):
    return {"message_id": "66666666-6666-4666-8666-666666666666",
            "message_type": "security.metrics", "payload_version": 1,
            "source_key": "local.security", "created_at": "2026-10-23T12:00:00.123456Z",
            "payload": payload}


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


def test_valid_payload_and_message(message):
    assert_valid(SecurityMetricsPayload, message["payload"])
    assert_valid(SecurityMetricsMessage, message)


@pytest.mark.parametrize("date,day", [
    ("2026-10-23T00:00:00.000000Z", "2026-10-23"),
    ("2026-10-23T23:59:59.000000Z", "2026-10-23"),
    ("2026-10-24T00:00:00.000000Z", "2026-10-24"),
    ("2024-02-29T23:59:59.000000Z", "2024-02-29"),
    ("2027-01-01T00:00:00.000000Z", "2027-01-01"),
    ("1000-01-01T00:00:00.000000Z", "1000-01-01"),
    ("9999-12-31T23:59:59.000000Z", "9999-12-31"),
])
def test_matching_calendar_and_day_boundaries(payload, date, day):
    payload.update(date=date, metric_day=day)
    assert_valid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("field,value", [
    ("date", "2026-10-23T12:00:00Z"), ("date", "2026-10-23T12:00:00.000001Z"),
    ("date", "2026-10-23T12:00:00.000000+00:00"), ("date", "2026-10-23T12:00:00"),
    ("date", "2026-02-29T12:00:00.000000Z"), ("date", "0999-12-31T12:00:00.000000Z"),
    ("date", "2026-10-23T12:00:00.0000000Z"),
    ("metric_day", "2026-10-22"), ("metric_day", "2026-10-24"),
    ("metric_day", "2026-02-29"), ("metric_day", "2026-1-01"),
    ("metric_day", "2026-10-23T00:00:00Z"),
])
def test_invalid_dates_and_day_mismatch(payload, field, value):
    payload[field] = value
    assert_invalid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("field", SecurityMetricsPayload.model_fields)
@pytest.mark.parametrize("value", [None, True, 1, 1.0, [], {}])
def test_no_fields_are_nullable_or_coerced(payload, field, value):
    payload[field] = value
    assert_invalid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("uptime", ["0.00", "-0.01", "-12.50", "99999999.99", "-99999999.99", "0001.20"])
def test_uptime_accepts_exact_signed_sql_range(payload, uptime):
    payload["uptime"] = uptime
    assert_valid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("uptime", [
    "100000000.00", "-100000000.00", "1", "1.2", "1.234", "1e2", "1.00e0",
    "+1.00", "-0.00", "-000.00", "NaN", "Infinity", " 1.00", "1.00\n", "１.00",
])
def test_uptime_rejects_wrong_range_precision_or_format(payload, uptime):
    payload["uptime"] = uptime
    assert_invalid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("field", ["blocks", "failed_logins", "unique_ips", "revision"])
@pytest.mark.parametrize("value", ["1", "18446744073709551615"])
def test_u64_maximum_and_positive_revision(payload, field, value):
    payload[field] = value
    assert_valid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("field", ["blocks", "failed_logins", "unique_ips", "revision"])
@pytest.mark.parametrize("value", ["-1", "-0", "+1", "01", "", "1.0", "1e2", "18446744073709551616"])
def test_counters_and_revision_reject_invalid_u64(payload, field, value):
    payload[field] = value
    assert_invalid(SecurityMetricsPayload, payload)


def test_zero_counters_are_allowed_but_zero_revision_is_rejected(payload):
    payload.update(blocks="0", failed_logins="0", unique_ips="0")
    assert_valid(SecurityMetricsPayload, payload)
    payload["revision"] = "0"
    assert_invalid(SecurityMetricsPayload, payload)


@pytest.mark.parametrize("model_type,fixture_name", [(SecurityMetricsPayload, "payload"), (SecurityMetricsMessage, "message")])
def test_all_fields_are_required_without_defaults(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("field,value", [
    ("message_id", "invalid"), ("message_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ("message_id", None), ("message_type", "system.metrics"), ("message_type", "SECURITY.METRICS"),
    ("payload_version", True), ("payload_version", False), ("payload_version", 1.0),
    ("payload_version", "1"), ("payload_version", 0), ("payload_version", 2), ("payload_version", None),
    ("source_key", "Local.security"), ("source_key", " invalid "), ("source_key", None),
    ("created_at", "2026-10-23T12:00:00Z"), ("created_at", None),
    ("payload", None), ("payload", {}), ("payload", "invalid"),
])
def test_message_rejects_invalid_fields(message, field, value):
    message[field] = value
    assert_invalid(SecurityMetricsMessage, message)


@pytest.mark.parametrize("location", ["payload", "message", "batch"])
@pytest.mark.parametrize("extra", ["unknown", "host_id", "host_scope", "source_id"])
def test_unknown_fields_and_local_identities_are_rejected(message, location, extra):
    batch = {"protocol_version": 1, "messages": [message]}
    target = batch
    if location == "message":
        target = message
    elif location == "payload":
        target = message["payload"]
    target[extra] = "1"
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("size", [1, 2, 100])
def test_security_only_batches(message, size):
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("size", [0, 101])
def test_batch_size_limits(message, size):
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, None])
def test_batch_protocol_version_remains_strict(message, version):
    assert_invalid(EventBatchRequest, {"protocol_version": version, "messages": [message]})


def other_messages():
    created = "2026-10-23T12:00:00.000000Z"
    examples = [
        ("ufw.event", {"event_time": created, "action": "BLOCK", "src_ip": None, "dst_ip": None,
                       "protocol": None, "src_port": 0, "dst_port": 0, "raw_line": "original",
                       "event_hash": hashlib.sha256(b"original").hexdigest(), "reported_hostname": None}),
        ("ssh.auth_event", {"event_time": created, "hostname": "mint-a", "source_ip": "192.0.2.1",
                            "username": None, "event_type": "SSH_AUTH_FAILURE", "service": "sshd",
                            "raw_message": "original", "event_hash": "a" * 64}),
        ("dns.query", {"event_time": created, "raw_timestamp": "2026-10-23T12:00:00.000000001Z",
                       "client_ip": None, "domain": "example.org", "query_type": "A", "response_code": None,
                       "filtering_result": "allowed", "filtering_reason": None, "upstream": None,
                       "elapsed_ms": None, "cached": None, "dedup_key": "b" * 64}),
        ("system.metrics", {"timestamp": created, "uptime_hours": "12.00", "cpuload1": "0.25",
                            "cpuload5": "0.50", "cpuload15": "0.75", "cpu_usage": "101.50",
                            "cpu_temperature": "-12.50", "ram_free_mb": "2048.00", "disk_used": "1.25",
                            "disk_free": "2.75", "disk_usage": "31.25"}),
        ("filesystem.metrics", {"metric_date": "2026-10-23", "modified_last_day": "12", "total_files": "1234",
                                "observed_at": created, "revision": "1"}),
    ]
    messages = []
    for index, (kind, values) in enumerate(examples, start=1):
        digit = str(index)
        messages.append({"message_id": digit * 8 + "-" + digit * 4 + "-4" + digit * 3 + "-8" + digit * 3 + "-" + digit * 12,
                         "message_type": kind, "payload_version": 1, "source_key": "local.source" + digit,
                         "created_at": created, "payload": values})
    return messages


@pytest.mark.parametrize("other_index", range(5))
def test_security_with_each_existing_type(message, other_index):
    other = other_messages()[other_index]
    for messages in ([message, other], [other, message]):
        assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})


@pytest.mark.parametrize("security_index", range(6))
def test_all_six_message_types_in_one_batch(message, security_index):
    messages = other_messages()
    messages.insert(security_index, message)
    batch = {"protocol_version": 1, "messages": messages}
    assert_valid(EventBatchRequest, batch)
    parsed = EventBatchRequest.model_validate(batch)
    assert isinstance(parsed.messages[security_index], SecurityMetricsMessage)


def test_one_hundred_mixed_messages(message):
    examples = other_messages() + [message]
    messages = []
    for index in range(100):
        messages.append(examples[index % 6])
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})


@pytest.mark.parametrize("field,value", [("metric_day", "2026-10-22"), ("uptime", "100000000.00"), ("blocks", 1), ("revision", "0")])
def test_invalid_security_payload_rejects_mixed_batch(message, field, value):
    message["payload"][field] = value
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": other_messages() + [message]})


@pytest.mark.parametrize("invalid", ["tag", "missing_tag", "payload", "version"])
def test_invalid_security_envelope_rejects_mixed_batch(message, invalid):
    if invalid == "tag":
        message["message_type"] = "unknown.event"
    elif invalid == "missing_tag":
        del message["message_type"]
    elif invalid == "payload":
        message["payload"] = other_messages()[0]["payload"]
    else:
        message["payload_version"] = True
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": other_messages() + [message]})


def test_revision_is_structural_and_targets_exact_measurement_time(message):
    another = copy.deepcopy(message)
    another["message_id"] = "77777777-7777-4777-8777-777777777777"
    another["payload"]["date"] = "2026-10-23T12:00:01.000000Z"
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": [message, another]})
    message["payload"]["revision"] = "15"
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": [message, another]})


def test_payload_matches_current_sql_types_and_nullability():
    schema = (Path(__file__).resolve().parents[2] / "database/schema.sql").read_text()
    table = schema.split("CREATE TABLE `security_metrics` (", 1)[1].split(") ENGINE", 1)[0]
    assert re.search(r"`date`\s+datetime\s+NOT NULL", table, re.IGNORECASE)
    assert re.search(r"`uptime`\s+decimal\(10,2\)\s+NOT NULL", table, re.IGNORECASE)
    for field in ("blocks", "failed_logins", "unique_ips"):
        assert re.search(rf"`{field}`\s+bigint unsigned\s+NOT NULL", table, re.IGNORECASE)
