"""Filesystem contracts validate supplied versions without database or network I/O."""

import copy
import hashlib
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.filesystem import FilesystemMetricsMessage, FilesystemMetricsPayload


@pytest.fixture
def payload():
    return {
        "metric_date": "2026-10-23",
        "modified_last_day": "12",
        "total_files": "3456",
        "observed_at": "2026-10-23T14:30:15.123456Z",
        "revision": "1",
    }


@pytest.fixture
def message(payload):
    return {
        "message_id": "55555555-5555-4555-8555-555555555555",
        "message_type": "filesystem.metrics",
        "payload_version": 1,
        "source_key": "local.filesystem",
        "created_at": "2026-10-23T14:30:16.000000Z",
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


def test_valid_payload_and_message(message):
    assert_valid(FilesystemMetricsPayload, message["payload"])
    assert_valid(FilesystemMetricsMessage, message)


@pytest.mark.parametrize("metric_date,observed_at", [
    ("2026-10-23", "2026-10-23T00:00:00.000000Z"),
    ("2026-10-23", "2026-10-23T23:59:59.999999Z"),
    ("2026-10-24", "2026-10-24T00:00:00.000000Z"),
    ("2024-02-29", "2024-02-29T23:59:59.123456Z"),
    ("2027-01-01", "2027-01-01T00:00:00.000000Z"),
    ("1000-01-01", "1000-01-01T00:00:00.000000Z"),
    ("9999-12-31", "9999-12-31T23:59:59.999999Z"),
])
def test_matching_utc_dates_at_day_and_calendar_boundaries(payload, metric_date, observed_at):
    payload.update(metric_date=metric_date, observed_at=observed_at)
    assert_valid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("metric_date,observed_at", [
    ("2026-10-22", "2026-10-23T00:00:00.000000Z"),
    ("2026-10-24", "2026-10-23T23:59:59.999999Z"),
    ("2026-12-31", "2027-01-01T00:00:00.000000Z"),
    ("2024-02-29", "2024-03-01T00:00:00.000000Z"),
])
def test_mismatching_utc_dates_are_rejected(payload, metric_date, observed_at):
    payload.update(metric_date=metric_date, observed_at=observed_at)
    assert_invalid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("metric_date", [
    "2026-02-29", "2026-13-01", "2026-10-32", "0000-01-01",
    "2026-1-01", "20261023", "2026-10-23T00:00:00Z", "2026-10-23\n", "",
    None, 20261023, True,
])
def test_invalid_metric_dates(payload, metric_date):
    payload["metric_date"] = metric_date
    assert_invalid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("observed_at", [
    "2026-10-23T14:30:15", "2026-10-23T14:30:15.123456", "2026-10-23T14:30:15Z",
    "2026-10-23T14:30:15.123456+00:00", "2026-10-23T17:30:15.123456+03:00",
    "2026-10-23T14:30:15.1234567Z", "2026-10-23T14:30:15.12345Z",
    "2026-02-29T14:30:15.123456Z", "0999-12-31T14:30:15.123456Z",
    "2026-10-23T24:00:00.000000Z", "2026-10-23T14:30:15.123456Z\n", "",
    None, 1, True,
])
def test_observed_at_requires_valid_utc6_without_conversion(payload, observed_at):
    payload["observed_at"] = observed_at
    assert_invalid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("field", ["modified_last_day", "total_files"])
@pytest.mark.parametrize("value", ["0", "1", "123", "18446744073709551615"])
def test_counters_accept_canonical_u64_boundaries(payload, field, value):
    payload[field] = value
    assert_valid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("field", ["modified_last_day", "total_files", "revision"])
@pytest.mark.parametrize("value", [
    "", "-1", "-0", "+1", "01", "00", "1.0", "1e2", " 1", "1\n", "１",
    "18446744073709551616", "9999999999999999999999999999999999999999",
    0, 1, 1.0, True, False, None, [], {},
])
def test_u64_and_revision_reject_invalid_representations(payload, field, value):
    payload[field] = value
    assert_invalid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("revision", ["1", "2", "15", "18446744073709551615"])
def test_positive_revision_is_preserved(payload, revision):
    payload["revision"] = revision
    assert_valid(FilesystemMetricsPayload, payload)


def test_zero_is_allowed_for_counters_but_not_revision(payload):
    payload.update(modified_last_day="0", total_files="0")
    assert_valid(FilesystemMetricsPayload, payload)
    payload["revision"] = "0"
    assert_invalid(FilesystemMetricsPayload, payload)


def test_counter_meanings_do_not_imply_a_shared_total(payload):
    # /etc modifications and /home files measure different directory trees.
    payload.update(modified_last_day="100", total_files="1")
    assert_valid(FilesystemMetricsPayload, payload)


@pytest.mark.parametrize("model_type,fixture_name", [(FilesystemMetricsPayload, "payload"), (FilesystemMetricsMessage, "message")])
def test_every_field_is_required_without_generated_defaults(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("field,value", [
    ("metric_date", date(2026, 10, 23)),
    ("observed_at", datetime(2026, 10, 23, 14, 30, 15, 123456, tzinfo=timezone.utc)),
    ("modified_last_day", b"12"), ("revision", b"1"),
])
def test_python_objects_are_not_automatically_serialized(payload, field, value):
    payload[field] = value
    with pytest.raises(ValidationError):
        FilesystemMetricsPayload.model_validate(payload)


@pytest.mark.parametrize("field,value", [
    ("message_id", "invalid"), ("message_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ("message_id", "11111111-1111-1111-8111-111111111111"), ("message_id", None),
    ("message_type", "system.metrics"), ("message_type", "FILESYSTEM.METRICS"),
    ("payload_version", True), ("payload_version", False), ("payload_version", "1"),
    ("payload_version", 1.0), ("payload_version", 0), ("payload_version", 2), ("payload_version", None),
    ("source_key", "Local.filesystem"), ("source_key", " local.filesystem "), ("source_key", None),
    ("created_at", "2026-10-23T14:30:16Z"), ("created_at", "2026-02-29T14:30:16.000000Z"),
    ("created_at", None), ("payload", None), ("payload", {}), ("payload", "invalid"),
])
def test_message_rejects_invalid_fields(message, field, value):
    message[field] = value
    assert_invalid(FilesystemMetricsMessage, message)


@pytest.mark.parametrize("location", ["payload", "message", "batch"])
@pytest.mark.parametrize("extra", ["unknown", "host_scope", "host_id", "source_id"])
def test_extras_and_local_scope_fields_are_rejected(message, location, extra):
    batch = {"protocol_version": 1, "messages": [message]}
    target = batch
    if location == "message":
        target = message
    elif location == "payload":
        target = message["payload"]
    target[extra] = "1"
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("size", [1, 2, 100])
def test_filesystem_only_batches(message, size):
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("size", [0, 101])
def test_batch_size_limits(message, size):
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, None])
def test_batch_protocol_version_remains_strict(message, version):
    assert_invalid(EventBatchRequest, {"protocol_version": version, "messages": [message]})


def other_messages():
    return [
        {
            "message_id": "11111111-1111-4111-8111-111111111111",
            "message_type": "ufw.event", "payload_version": 1,
            "source_key": "local.ufw", "created_at": "2026-10-23T12:00:00.000000Z",
            "payload": {
                "event_time": "2026-10-23T12:00:00.000000Z", "action": "BLOCK",
                "src_ip": None, "dst_ip": None, "protocol": None,
                "src_port": 0, "dst_port": 0, "raw_line": "original",
                "event_hash": hashlib.sha256(b"original").hexdigest(), "reported_hostname": None,
            },
        },
        {
            "message_id": "22222222-2222-4222-8222-222222222222",
            "message_type": "ssh.auth_event", "payload_version": 1,
            "source_key": "local.ssh", "created_at": "2026-10-23T12:00:00.000000Z",
            "payload": {
                "event_time": "2026-10-23T12:00:00.123456Z", "hostname": "mint-a",
                "source_ip": "192.0.2.1", "username": None, "event_type": "SSH_AUTH_FAILURE",
                "service": "sshd", "raw_message": "original", "event_hash": "a" * 64,
            },
        },
        {
            "message_id": "33333333-3333-4333-8333-333333333333",
            "message_type": "dns.query", "payload_version": 1,
            "source_key": "adguard.dns", "created_at": "2026-10-23T12:00:00.000000Z",
            "payload": {
                "event_time": "2026-10-23T11:59:59.123456Z",
                "raw_timestamp": "2026-10-23T11:59:59.123456789Z", "client_ip": None,
                "domain": "example.org", "query_type": "A", "response_code": None,
                "filtering_result": "allowed", "filtering_reason": None,
                "upstream": None, "elapsed_ms": None, "cached": None, "dedup_key": "b" * 64,
            },
        },
        {
            "message_id": "44444444-4444-4444-8444-444444444444",
            "message_type": "system.metrics", "payload_version": 1,
            "source_key": "local.system", "created_at": "2026-10-23T12:00:00.123456Z",
            "payload": {
                "timestamp": "2026-10-23T12:00:00.000000Z", "uptime_hours": "12.00",
                "cpuload1": "0.25", "cpuload5": "0.50", "cpuload15": "0.75",
                "cpu_usage": "101.50", "cpu_temperature": "-12.50",
                "ram_free_mb": "2048.00", "disk_used": "1.25", "disk_free": "2.75", "disk_usage": "31.25",
            },
        },
    ]


@pytest.mark.parametrize("other_index", range(4))
def test_filesystem_with_each_previous_type_in_both_orders(message, other_index):
    other = other_messages()[other_index]
    for messages in ([message, other], [other, message]):
        assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})


@pytest.mark.parametrize("filesystem_index", range(5))
def test_five_type_batches_preserve_order_and_discriminator(message, filesystem_index):
    messages = other_messages()
    messages.insert(filesystem_index, message)
    batch = {"protocol_version": 1, "messages": messages}
    assert_valid(EventBatchRequest, batch)
    parsed = EventBatchRequest.model_validate(batch)
    assert isinstance(parsed.messages[filesystem_index], FilesystemMetricsMessage)


def test_one_hundred_mixed_messages(message):
    examples = other_messages() + [message]
    messages = []
    for index in range(100):
        messages.append(examples[index % 5])
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})


@pytest.mark.parametrize("field,value", [
    ("metric_date", "2026-10-22"), ("observed_at", "2026-10-24T00:00:00.000000Z"),
    ("modified_last_day", 12), ("total_files", "18446744073709551616"), ("revision", "0"),
])
def test_invalid_filesystem_payload_rejects_mixed_batch(message, field, value):
    message["payload"][field] = value
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": other_messages() + [message]})


@pytest.mark.parametrize("invalid", ["unknown_tag", "missing_tag", "wrong_payload", "version"])
def test_invalid_filesystem_envelope_cannot_bypass_discriminator(message, invalid):
    if invalid == "unknown_tag":
        message["message_type"] = "unknown.event"
    elif invalid == "missing_tag":
        del message["message_type"]
    elif invalid == "wrong_payload":
        message["payload"] = other_messages()[3]["payload"]
    else:
        message["payload_version"] = True
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": other_messages() + [message]})


def test_revision_validation_does_not_increment_or_compare_versions(message):
    newer = copy.deepcopy(message)
    newer["payload"]["revision"] = "15"
    older = copy.deepcopy(message)
    older["payload"]["revision"] = "1"
    older["message_id"] = "66666666-6666-4666-8666-666666666666"
    batch = {"protocol_version": 1, "messages": [newer, older]}
    assert_valid(EventBatchRequest, batch)
    assert_valid(EventBatchRequest, batch)


def test_legacy_row_does_not_generate_observation_time_or_revision(payload):
    del payload["observed_at"]
    del payload["revision"]
    with pytest.raises(ValidationError) as caught:
        FilesystemMetricsPayload.model_validate(payload)
    missing = set()
    for error in caught.value.errors():
        if error["type"] == "missing":
            missing.add(error["loc"])
    assert missing == {("observed_at",), ("revision",)}


def test_counter_types_match_existing_sql_schema():
    schema = (Path(__file__).resolve().parents[2] / "database/schema.sql").read_text()
    table = schema.split("CREATE TABLE `filesystem_metrics` (", 1)[1].split(") ENGINE", 1)[0]
    assert re.search(r"`metric_date`\s+date\s+NOT NULL", table, re.IGNORECASE)
    for field in ("modified_last_day", "total_files"):
        assert re.search(rf"`{field}`\s+bigint unsigned\s+NOT NULL", table, re.IGNORECASE)
