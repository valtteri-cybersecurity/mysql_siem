"""UFW contract validation without a database or network connection."""

import copy
import hashlib
import json
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.ufw import UFWEventMessage, UFWEventPayload

RAW_LINE = (
    "2026-10-23T11:59:59.123456Z mint-a kernel: [UFW BLOCK] "
    "IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 PROTO=TCP SPT=45000 DPT=22"
)


@pytest.fixture
def payload():
    return {
        "event_time": "2026-10-23T11:59:59.123456Z",
        "action": "BLOCK",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "src_port": 45000,
        "dst_port": 22,
        "raw_line": RAW_LINE,
        "event_hash": hashlib.sha256(RAW_LINE.encode()).hexdigest(),
        "reported_hostname": "mint-a",
    }


@pytest.fixture
def message(payload):
    return {
        "message_id": "11111111-1111-4111-8111-111111111111",
        "message_type": "ufw.event",
        "payload_version": 1,
        "source_key": "local.ufw",
        "created_at": "2026-10-23T12:00:00.000000Z",
        "payload": payload,
    }


@pytest.fixture
def batch(message):
    return {"protocol_version": 1, "messages": [message]}


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


def test_valid_payload(payload):
    assert_valid(UFWEventPayload, payload)


@pytest.mark.parametrize("field", UFWEventPayload.model_fields)
def test_all_payload_fields_are_required(payload, field):
    del payload[field]
    assert_invalid(UFWEventPayload, payload)


@pytest.mark.parametrize("field,limit", [
    ("action", 20), ("src_ip", 45), ("dst_ip", 45),
    ("protocol", 10), ("reported_hostname", 255),
])
def test_nullable_strings_preserve_null_empty_whitespace_and_character_boundaries(payload, field, limit):
    for value in (None, "", " ", "ä" * limit):
        payload[field] = value
        assert_valid(UFWEventPayload, payload)
    payload[field] = "a" * (limit + 1)
    assert_invalid(UFWEventPayload, payload)


@pytest.mark.parametrize("field", ["action", "src_ip", "dst_ip", "protocol", "reported_hostname", "raw_line", "event_hash", "event_time"])
@pytest.mark.parametrize("value", [1, True, [], {}])
def test_payload_strings_are_strict(payload, field, value):
    payload[field] = value
    assert_invalid(UFWEventPayload, payload)


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
@pytest.mark.parametrize("value", [-1, 4294967296, True, False, "22", 22.0, None, [], {}])
def test_ports_reject_invalid_values_and_null(payload, field, value):
    payload[field] = value
    assert_invalid(UFWEventPayload, payload)


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
@pytest.mark.parametrize("value", [0, 65535, 65536, 4294967295])
def test_ports_allow_full_sql_unsigned_int_range(payload, field, value):
    payload[field] = value
    assert_valid(UFWEventPayload, payload)


def test_observations_are_not_restricted_to_known_actions_or_valid_ips(payload):
    payload.update(action="CUSTOM", protocol="OTHER", src_ip="not-an-ip", dst_ip="?")
    assert_valid(UFWEventPayload, payload)


@pytest.mark.parametrize("raw_line", [
    "", "  original line\n", "a" * 65535, "ä" * 32767 + "a", "😀" * 16383 + "abc",
])
def test_raw_line_is_preserved_at_utf8_byte_boundaries(payload, raw_line):
    payload["raw_line"] = raw_line
    payload["event_hash"] = hashlib.sha256(raw_line.encode()).hexdigest()
    assert_valid(UFWEventPayload, payload)


@pytest.mark.parametrize("raw_line", ["a" * 65536, "ä" * 32768, "😀" * 16384])
def test_raw_line_over_utf8_byte_limit_is_rejected(payload, raw_line):
    payload["raw_line"] = raw_line
    payload["event_hash"] = hashlib.sha256(raw_line.encode()).hexdigest()
    assert_invalid(UFWEventPayload, payload)


def test_raw_line_rejects_unencodable_unicode(payload):
    payload["raw_line"] = "\ud800"
    assert_invalid(UFWEventPayload, payload)


@pytest.mark.parametrize("field,value", [
    ("event_time", None), ("event_time", "2026-02-29T00:00:00.000000Z"),
    ("event_time", "2026-10-23T12:00:00Z"),
    ("event_time", "2026-10-23T12:00:00.000000+00:00"),
    ("raw_line", None), ("event_hash", None),
    ("event_hash", "PLACEHOLDER_HASH"), ("event_hash", "a" * 63),
    ("event_hash", "A" * 64), ("event_hash", "g" * 64),
    ("event_hash", "0" * 64),
])
def test_payload_rejects_invalid_times_and_hashes(payload, field, value):
    payload[field] = value
    assert_invalid(UFWEventPayload, payload)


def test_hash_cannot_match_a_trimmed_version_of_the_payload(payload):
    payload["raw_line"] = " " + payload["raw_line"] + "\n"
    assert_invalid(UFWEventPayload, payload)


def test_payload_matches_current_collector_storage(payload):
    from database.identity import EventIdentity
    from ingestion.ufw_to_mysql import save_event

    cursor = MagicMock()
    cursor.rowcount = 1
    # Only a fake cursor is used: no database connection is opened.
    assert save_event(cursor, "  " + RAW_LINE + "\n", identity=EventIdentity(1, 2, 3)) == 1
    sql, values = cursor.execute.call_args.args
    fields = sql.split("(", 1)[1].split(")", 1)[0].split(", ")
    stored = dict(zip(fields, values))
    exported = {}
    for field in UFWEventPayload.model_fields:
        exported[field] = stored[field]
    exported["event_time"] = stored["event_time"].isoformat(timespec="microseconds") + "Z"
    assert exported == payload
    assert_valid(UFWEventPayload, exported)


def test_valid_message(message):
    assert_valid(UFWEventMessage, message)


@pytest.mark.parametrize("field", UFWEventMessage.model_fields)
def test_all_message_fields_are_required(message, field):
    del message[field]
    assert_invalid(UFWEventMessage, message)


@pytest.mark.parametrize("field,value", [
    ("message_id", "bad-uuid"), ("message_id", None),
    ("message_type", "ssh.auth_event"), ("message_type", 1),
    ("payload_version", True), ("payload_version", False),
    ("payload_version", 1.0), ("payload_version", "1"),
    ("payload_version", 0), ("payload_version", 2), ("payload_version", None),
    ("source_key", "Local.ufw"), ("source_key", None),
    ("created_at", "2026-10-23T12:00:00Z"), ("created_at", None),
    ("payload", {}), ("payload", None), ("payload", "not-an-object"),
])
def test_message_rejects_invalid_values(message, field, value):
    message[field] = value
    assert_invalid(UFWEventMessage, message)


@pytest.mark.parametrize("size", [1, 2, 100])
def test_batch_accepts_supported_sizes(batch, size):
    batch["messages"] = batch["messages"] * size
    assert_valid(EventBatchRequest, batch)


@pytest.mark.parametrize("size", [0, 101])
def test_batch_rejects_unsupported_sizes(batch, size):
    batch["messages"] = batch["messages"] * size
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, None])
def test_batch_protocol_version_is_strict(batch, version):
    batch["protocol_version"] = version
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("field", ["protocol_version", "messages"])
def test_batch_fields_are_required(batch, field):
    del batch[field]
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("value", [None, {}, "not-a-list", [None], [{}]])
def test_batch_rejects_wrong_message_structure(batch, value):
    batch["messages"] = value
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("location", ["payload", "message", "batch"])
def test_unknown_fields_are_rejected_at_every_level(batch, location):
    message = batch["messages"][0]
    if location == "payload":
        message["payload"]["host_id"] = 1
    elif location == "message":
        message["unknown"] = "value"
    else:
        batch["unknown"] = "value"
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("field,value", [
    ("message_type", "dns.query"), ("payload_version", True),
    ("source_key", " invalid "),
])
def test_invalid_message_inside_batch_is_rejected(batch, field, value):
    invalid = copy.deepcopy(batch["messages"][0])
    invalid[field] = value
    batch["messages"].append(invalid)
    assert_invalid(EventBatchRequest, batch)


def test_invalid_payload_inside_batch_cannot_bypass_validation(batch):
    batch["messages"][0]["payload"]["dst_port"] = True
    assert_invalid(EventBatchRequest, batch)
