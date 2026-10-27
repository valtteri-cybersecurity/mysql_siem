"""SSH contract and mixed event batch validation without MySQL or HTTP."""

import copy
import hashlib
import json
from itertools import permutations
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.dns import DNSQueryMessage
from contracts.v1.ssh import SSHAuthEventMessage, SSHAuthEventPayload
from contracts.v1.ufw import UFWEventMessage


@pytest.fixture
def payload():
    return {
        "event_time": "2026-10-23T11:59:59.123456Z",
        "hostname": "mint-a",
        "source_ip": "192.0.2.10",
        "username": "alice",
        "event_type": "SSH_AUTH_FAILURE",
        "service": "sshd",
        "raw_message": "Original SSH observation",
        "event_hash": "0123456789abcdef" * 4,
    }


@pytest.fixture
def message(payload):
    return {
        "message_id": "11111111-1111-4111-8111-111111111111",
        "message_type": "ssh.auth_event",
        "payload_version": 1,
        "source_key": "local.ssh",
        "created_at": "2026-10-23T12:00:00.000000Z",
        "payload": payload,
    }


def assert_valid(model_type, values):
    original = copy.deepcopy(values)
    assert model_type.model_validate(values).model_dump() == original
    model = model_type.model_validate_json(json.dumps(values))
    assert json.loads(model.model_dump_json()) == original
    assert values == original


def assert_invalid(model_type, values):
    with pytest.raises(ValidationError):
        model_type.model_validate(values)
    with pytest.raises(ValidationError):
        model_type.model_validate_json(json.dumps(values))


def test_valid_ssh_payload_and_message(message):
    assert_valid(SSHAuthEventPayload, message["payload"])
    assert_valid(SSHAuthEventMessage, message)


@pytest.mark.parametrize("source_ip", [
    "0.0.0.0", "192.0.2.10", "255.255.255.255", "::", "::1",
    "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:c000:201",
])
def test_canonical_ipv4_and_ipv6_are_preserved(payload, source_ip):
    payload["source_ip"] = source_ip
    assert_valid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("source_ip", [
    "", "not-an-ip", "256.0.0.1", "192.0.2.001", "127.1", "0xc0000201",
    "192.0.2.1/32", "192.0.2.1:22", " 192.0.2.1", "192.0.2.1\n",
    "[2001:db8::1]", "2001:DB8::1", "2001:0db8::1", "2001:db8:0:0:0:0:0:1",
    "::ffff:192.0.2.1", "::ffff:C000:201", "2001:db8::1/128",
    "fe80::1%eth0", "fe80::1%1", "::1%", "1" * 46,
    None, 1, True, [], {},
])
def test_invalid_noncanonical_and_scoped_addresses_are_rejected(payload, source_ip):
    payload["source_ip"] = source_ip
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("hostname", ["a", "a" * 255, "ä" * 255, "😀" * 255, "  mint-a  "])
def test_hostname_character_boundaries_and_whitespace_are_preserved(payload, hostname):
    payload["hostname"] = hostname
    assert_valid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("hostname", ["", "a" * 256, "ä" * 256])
def test_hostname_requires_one_to_255_characters(payload, hostname):
    payload["hostname"] = hostname
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("username", [None, "", "alice", "ä" * 255, "😀" * 255, "  alice  "])
def test_nullable_username_and_character_boundaries(payload, username):
    payload["username"] = username
    assert_valid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("username", ["a" * 256, "ä" * 256])
def test_username_over_limit_is_rejected(payload, username):
    payload["username"] = username
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("raw_message", [
    "", "  original\r\n", "a" * 60000, "ä" * 30000, "😀" * 15000,
    "a" + "ä" * 29999 + "b",
])
def test_raw_message_preserves_text_up_to_60000_utf8_bytes(payload, raw_message):
    payload["raw_message"] = raw_message
    assert_valid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("raw_message", ["a" * 60001, "ä" * 30000 + "a", "😀" * 15000 + "a", "😀" * 15001, "\ud800"])
def test_raw_message_rejects_oversized_or_unencodable_text(payload, raw_message):
    payload["raw_message"] = raw_message
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("field", SSHAuthEventPayload.model_fields)
@pytest.mark.parametrize("value", [1, True, [], {}])
def test_payload_does_not_coerce_nonstring_values(payload, field, value):
    payload[field] = value
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("field", ["event_time", "hostname", "source_ip", "event_type", "service", "raw_message", "event_hash"])
def test_only_username_allows_null(payload, field):
    payload[field] = None
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("event_time", [
    "2026-10-23T11:59:59Z", "2026-10-23T11:59:59.123456+00:00",
    "2026-10-23T11:59:59.1234567Z", "2026-02-29T11:59:59.123456Z",
    "0999-12-31T23:59:59.123456Z", "invalid",
])
def test_invalid_event_times_are_rejected(payload, event_time):
    payload["event_time"] = event_time
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("field,value", [
    ("event_type", "SSH_AUTH_SUCCESS"), ("event_type", "ssh_auth_failure"),
    ("service", "ssh"), ("service", "sshd-session"), ("service", "SSHD"),
    ("event_hash", ""), ("event_hash", "a" * 63), ("event_hash", "a" * 65),
    ("event_hash", "A" * 64), ("event_hash", "g" * 64),
])
def test_literals_and_hash_format_are_checked(payload, field, value):
    payload[field] = value
    assert_invalid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("event_hash", ["0" * 64, "f" * 64, "0123456789abcdef" * 4])
def test_hash_is_preserved_without_applying_ufw_hash_formula(payload, event_hash):
    payload["event_hash"] = event_hash
    assert event_hash != hashlib.sha256(payload["raw_message"].encode()).hexdigest()
    assert_valid(SSHAuthEventPayload, payload)


@pytest.mark.parametrize("model_type,fixture_name", [(SSHAuthEventPayload, "payload"), (SSHAuthEventMessage, "message")])
def test_all_fields_are_required(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("field,value", [
    ("message_id", "bad"), ("message_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ("message_id", "11111111-1111-1111-8111-111111111111"), ("message_id", None),
    ("message_type", "ufw.event"), ("message_type", "SSH.AUTH_EVENT"), ("message_type", 1),
    ("payload_version", True), ("payload_version", False), ("payload_version", 1.0),
    ("payload_version", "1"), ("payload_version", 0), ("payload_version", 2), ("payload_version", None),
    ("source_key", "Local.ssh"), ("source_key", " invalid "), ("source_key", None),
    ("created_at", "2026-10-23T12:00:00Z"), ("created_at", None),
    ("payload", {}), ("payload", None), ("payload", "not-an-object"),
])
def test_message_rejects_invalid_fields(message, field, value):
    message[field] = value
    assert_invalid(SSHAuthEventMessage, message)


@pytest.mark.parametrize("location", ["payload", "message", "batch"])
@pytest.mark.parametrize("extra", ["unknown", "host_id", "source_id"])
def test_unknown_and_local_identity_fields_are_forbidden(message, location, extra):
    batch = {"protocol_version": 1, "messages": [message]}
    target = batch
    if location == "message":
        target = message
    elif location == "payload":
        target = message["payload"]
    target[extra] = 1
    assert_invalid(EventBatchRequest, batch)


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


def dns_message():
    return {
        "message_id": "33333333-3333-4333-8333-333333333333",
        "message_type": "dns.query", "payload_version": 1,
        "source_key": "adguard.dns", "created_at": "2026-10-23T12:00:00.000000Z",
        "payload": {
            "event_time": "2026-10-23T11:59:59.123456Z",
            "raw_timestamp": "2026-10-23T11:59:59.123456789Z",
            "client_ip": None, "domain": "example.org", "query_type": "A",
            "response_code": None, "filtering_result": "allowed", "filtering_reason": None,
            "upstream": None, "elapsed_ms": None, "cached": None, "dedup_key": "a" * 64,
        },
    }


@pytest.mark.parametrize("types", [
    ("ssh",), ("ufw", "ssh"), ("ssh", "ufw"), ("dns", "ssh"), ("ssh", "dns"),
] + list(permutations(("ufw", "dns", "ssh"))))
def test_batches_accept_all_event_types_and_preserve_order(message, types):
    values = {"ufw": ufw_message(), "dns": dns_message(), "ssh": message}
    model_types = {"ufw": UFWEventMessage, "dns": DNSQueryMessage, "ssh": SSHAuthEventMessage}
    messages = []
    for name in types:
        messages.append(values[name])
    batch = {"protocol_version": 1, "messages": messages}
    assert_valid(EventBatchRequest, batch)
    parsed = EventBatchRequest.model_validate(batch)
    for index, name in enumerate(types):
        assert isinstance(parsed.messages[index], model_types[name])


@pytest.mark.parametrize("size", [1, 100])
def test_ssh_and_mixed_batch_size_limits(message, size):
    messages = []
    examples = [message, ufw_message(), dns_message()]
    for index in range(size):
        messages.append(examples[index % 3])
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("size", [0, 101])
def test_out_of_range_batch_sizes(message, size):
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [message] * size})


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, None])
def test_batch_protocol_version_remains_strict(message, version):
    assert_invalid(EventBatchRequest, {"protocol_version": version, "messages": [message]})


@pytest.mark.parametrize("field,value", [
    ("source_ip", "2001:DB8::1"), ("event_hash", "invalid"), ("service", "sshd-auth"),
    ("raw_message", "ä" * 30001), ("event_time", "2026-10-23T12:00:00Z"),
])
def test_invalid_ssh_payload_is_rejected_inside_three_type_batch(message, field, value):
    message["payload"][field] = value
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [ufw_message(), dns_message(), message]})


@pytest.mark.parametrize("invalid", ["unknown_tag", "missing_tag", "wrong_payload", "version"])
def test_invalid_ssh_envelope_cannot_bypass_discriminator(message, invalid):
    if invalid == "unknown_tag":
        message["message_type"] = "unknown.event"
    elif invalid == "missing_tag":
        del message["message_type"]
    elif invalid == "wrong_payload":
        message["payload"] = ufw_message()["payload"]
    else:
        message["payload_version"] = True
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": [ufw_message(), dns_message(), message]})


@pytest.mark.parametrize("service", ["sshd", "sshd-session", "sshd-auth"])
@pytest.mark.parametrize("source_ip", ["192.0.2.10", "2001:0DB8::1", "::ffff:192.0.2.1"])
def test_payload_matches_current_parser_and_storage_without_database(service, source_ip):
    from ingestion.auth.db import save_event
    from ingestion.auth.parser import parse_auth_line

    line = (
        f"2026-10-23T14:59:59.123456+03:00 mint-a {service}[1234]: "
        f"Failed password for alice from {source_ip} port 2222 ssh2\n"
    )
    event = parse_auth_line(line)
    assert event is not None
    cursor = MagicMock()
    assert save_event(cursor, event) == 1
    sql, values = cursor.execute.call_args.args
    fields = sql.split("(", 1)[1].split(")", 1)[0].split(", ")
    stored = dict(zip(fields, values))
    assert stored["auth_method"] == "password"
    assert stored["source_port"] == 2222
    # API v1 deliberately keeps its established failure-only payload. Storage
    # metadata is additive and is not an automatic API contract expansion.
    exported = {}
    for field in SSHAuthEventPayload.model_fields:
        exported[field] = stored[field]
    exported["event_time"] = event["event_time"].isoformat(timespec="microseconds") + "Z"
    assert exported["event_time"] == "2026-10-23T11:59:59.123456Z"
    assert exported["service"] == "sshd"
    assert exported["raw_message"] == line.rstrip("\r\n")
    assert exported["event_hash"] != hashlib.sha256(exported["raw_message"].encode()).hexdigest()
    assert_valid(SSHAuthEventPayload, exported)


def test_current_ssh_hash_retains_pid_and_utc_identity_semantics():
    from ingestion.auth.parser import parse_auth_line

    first = "2026-10-23T12:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2"
    other_zone = first.replace("12:00:00Z", "15:00:00+03:00")
    other_pid = first.replace("sshd[1]", "sshd[2]")
    assert parse_auth_line(first)["event_hash"] == parse_auth_line(other_zone)["event_hash"]
    assert parse_auth_line(first)["event_hash"] != parse_auth_line(other_pid)["event_hash"]
