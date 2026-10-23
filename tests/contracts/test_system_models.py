"""System metrics contracts and decimal boundaries without MySQL or network I/O."""

import copy
import hashlib
import json
import re
from decimal import Decimal, localcontext
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.decimal_values import validate_decimal_string
from contracts.v1.system import SystemMetricsMessage, SystemMetricsPayload

FIELD_PRECISIONS = {
    "uptime_hours": 12,
    "cpuload1": 10,
    "cpuload5": 10,
    "cpuload15": 10,
    "cpu_usage": 10,
    "cpu_temperature": 10,
    "ram_free_mb": 14,
    "disk_used": 14,
    "disk_free": 14,
    "disk_usage": 10,
}


@pytest.fixture
def payload():
    return {
        "timestamp": "2026-10-23T12:00:00.000000Z",
        "uptime_hours": "12.50",
        "cpuload1": "0.25", "cpuload5": "0.50", "cpuload15": "0.75",
        "cpu_usage": "101.50", "cpu_temperature": "-12.50",
        "ram_free_mb": "2048.00", "disk_used": "1.25", "disk_free": "2.75",
        "disk_usage": "31.25",
    }


@pytest.fixture
def message(payload):
    return {
        "message_id": "44444444-4444-4444-8444-444444444444",
        "message_type": "system.metrics", "payload_version": 1,
        "source_key": "local.system", "created_at": "2026-10-23T12:00:00.123456Z",
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
    assert_valid(SystemMetricsPayload, message["payload"])
    assert_valid(SystemMetricsMessage, message)


def test_all_measurements_can_be_null(payload):
    for field in FIELD_PRECISIONS:
        payload[field] = None
    assert_valid(SystemMetricsPayload, payload)


@pytest.mark.parametrize("field", FIELD_PRECISIONS)
def test_nullable_measurements_and_signed_sql_boundaries(payload, field):
    maximum = "9" * (FIELD_PRECISIONS[field] - 2) + ".99"
    for value in (None, "0.00", "-0.01", "-123.45", "101.50", "0001.20", maximum, "-" + maximum):
        payload[field] = value
        assert_valid(SystemMetricsPayload, payload)


@pytest.mark.parametrize("field", FIELD_PRECISIONS)
def test_each_field_enforces_its_own_sql_precision(payload, field):
    outside = "1" + "0" * (FIELD_PRECISIONS[field] - 2) + ".00"
    for value in (outside, "-" + outside):
        payload[field] = value
        assert_invalid(SystemMetricsPayload, payload)


@pytest.mark.parametrize("field", FIELD_PRECISIONS)
@pytest.mark.parametrize("value", [
    "", "1", "1.", ".50", "1.2", "1.234", "1e2", "1.00e0",
    "+1.00", "-0.00", "-000.00", "NaN", "Infinity", " 1.00", "1.00\n",
    "１.00", "1,00", "--1.00", 1, 1.25, True, [], {},
])
def test_decimal_format_types_and_precision_are_strict(payload, field, value):
    payload[field] = value
    assert_invalid(SystemMetricsPayload, payload)


@pytest.mark.parametrize("value", [Decimal("1.00"), b"1.00"])
def test_python_decimal_and_bytes_are_not_coerced(payload, value):
    payload["cpu_usage"] = value
    with pytest.raises(ValidationError):
        SystemMetricsPayload.model_validate(payload)


@pytest.mark.parametrize("timestamp", [
    "1000-01-01T00:00:00.000000Z", "2024-02-29T23:59:59.000000Z",
    "9999-12-31T23:59:59.000000Z",
])
def test_utcsecond_accepts_whole_seconds(payload, timestamp):
    payload["timestamp"] = timestamp
    assert_valid(SystemMetricsPayload, payload)


@pytest.mark.parametrize("timestamp", [
    None, True, 1, "2026-10-23T12:00:00.000001Z", "2026-10-23T12:00:00.0000000Z",
    "2026-10-23T12:00:00Z", "2026-10-23T12:00:00.000000+00:00",
    "2026-02-29T12:00:00.000000Z", "0999-12-31T12:00:00.000000Z", "invalid",
])
def test_invalid_or_overprecise_timestamp_is_rejected(payload, timestamp):
    payload["timestamp"] = timestamp
    assert_invalid(SystemMetricsPayload, payload)


@pytest.mark.parametrize("model_type,fixture_name", [(SystemMetricsPayload, "payload"), (SystemMetricsMessage, "message")])
def test_all_fields_including_nullable_fields_are_required(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("field,value", [
    ("message_id", "bad"), ("message_id", None),
    ("message_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ("message_type", "filesystem.metrics"), ("message_type", "SYSTEM.METRICS"),
    ("payload_version", True), ("payload_version", False), ("payload_version", 1.0),
    ("payload_version", "1"), ("payload_version", 0), ("payload_version", 2), ("payload_version", None),
    ("source_key", "Local.system"), ("source_key", " invalid "), ("source_key", None),
    ("created_at", "2026-10-23T12:00:00Z"), ("created_at", "2026-02-29T12:00:00.000000Z"),
    ("created_at", None), ("payload", {}), ("payload", None), ("payload", "invalid"),
])
def test_message_rejects_invalid_fields(message, field, value):
    message[field] = value
    assert_invalid(SystemMetricsMessage, message)


@pytest.mark.parametrize("location", ["payload", "message", "batch"])
@pytest.mark.parametrize("extra", ["unknown", "revision", "host_id", "source_id"])
def test_extra_fields_and_revision_are_rejected(message, location, extra):
    batch = {"protocol_version": 1, "messages": [message]}
    target = batch
    if location == "message":
        target = message
    elif location == "payload":
        target = message["payload"]
    target[extra] = "1"
    assert_invalid(EventBatchRequest, batch)


@pytest.mark.parametrize("size", [1, 2, 100])
def test_system_only_batches(message, size):
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
    ]


@pytest.mark.parametrize("other_index", [0, 1, 2])
def test_system_with_each_previous_message_type(message, other_index):
    other = other_messages()[other_index]
    for messages in ([message, other], [other, message]):
        assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})


@pytest.mark.parametrize("system_index", range(4))
def test_all_four_message_types_preserve_order_and_discriminator(message, system_index):
    messages = other_messages()
    messages.insert(system_index, message)
    batch = {"protocol_version": 1, "messages": messages}
    assert_valid(EventBatchRequest, batch)
    parsed = EventBatchRequest.model_validate(batch)
    assert isinstance(parsed.messages[system_index], SystemMetricsMessage)


def test_one_hundred_mixed_messages(message):
    examples = other_messages() + [message]
    messages = []
    for index in range(100):
        messages.append(examples[index % 4])
    assert_valid(EventBatchRequest, {"protocol_version": 1, "messages": messages})


@pytest.mark.parametrize("invalid", ["decimal", "timestamp", "tag", "missing_tag", "payload", "version"])
def test_invalid_system_message_rejects_entire_mixed_batch(message, invalid):
    if invalid == "decimal":
        message["payload"]["cpu_usage"] = 12.5
    elif invalid == "timestamp":
        message["payload"]["timestamp"] = "2026-10-23T12:00:00.000001Z"
    elif invalid == "tag":
        message["message_type"] = "unknown.event"
    elif invalid == "missing_tag":
        del message["message_type"]
    elif invalid == "payload":
        message["payload"] = other_messages()[0]["payload"]
    else:
        message["payload_version"] = True
    assert_invalid(EventBatchRequest, {"protocol_version": 1, "messages": other_messages() + [message]})


@pytest.mark.parametrize("precision,scale,valid,invalid", [
    (3, 0, "-999", "1000"), (3, 3, "-0.999", "1.000"),
    (20, 9, "99999999999.999999999", "100000000000.000000000"),
])
def test_decimal_helper_supports_other_precisions_without_rounding(precision, scale, valid, invalid):
    assert validate_decimal_string(valid, precision=precision, scale=scale) == valid
    with pytest.raises(ValueError):
        validate_decimal_string(invalid, precision=precision, scale=scale)


@pytest.mark.parametrize("precision,scale", [(0, 0), (3, -1), (3, 4)])
def test_decimal_helper_rejects_invalid_configuration(precision, scale):
    with pytest.raises(ValueError):
        validate_decimal_string("1.00", precision=precision, scale=scale)


def test_decimal_range_check_does_not_depend_on_decimal_context(payload):
    with localcontext() as context:
        context.prec = 2
        payload["ram_free_mb"] = "-999999999999.99"
        assert_valid(SystemMetricsPayload, payload)
        payload["ram_free_mb"] = "1000000000000.00"
        assert_invalid(SystemMetricsPayload, payload)


def test_payload_precisions_and_nullability_match_existing_schema():
    schema = (Path(__file__).resolve().parents[2] / "database/schema.sql").read_text()
    table = schema.split("CREATE TABLE `system_metrics` (", 1)[1].split(") ENGINE", 1)[0]
    assert set(SystemMetricsPayload.model_fields) == set(FIELD_PRECISIONS) | {"timestamp"}
    for field, precision in FIELD_PRECISIONS.items():
        pattern = rf"`{field}`\s+decimal\({precision},2\)\s+DEFAULT NULL"
        assert re.search(pattern, table, re.IGNORECASE), field
    assert re.search(r"`timestamp`\s+datetime\s+NOT NULL", table, re.IGNORECASE)


def test_current_collector_field_order_and_insert_match_contract(payload, monkeypatch):
    from metrics.system import db, get

    monkeypatch.setattr(get, "get_uptime", lambda: 12)
    monkeypatch.setattr(get, "get_cpu_load_avg", lambda: (0.25, 0.5, 0.75))
    monkeypatch.setattr(get, "get_cpu_usage", lambda: 101.5)
    monkeypatch.setattr(get, "get_cpu_temp", lambda: -12.5)
    monkeypatch.setattr(get, "get_meminfo", lambda: {"memavailable": 2048.0})
    monkeypatch.setattr(get, "get_disk_usage", lambda: (1.25, 2.75, 31.25))
    monkeypatch.setattr(db, "identity_schema_enabled", lambda connection: False)
    monkeypatch.setattr(db, "configured_identity", lambda cursor, source_type: None)
    connection = MagicMock()
    data = get.get_data()
    # Fake cursor only: no database connection or real INSERT is performed.
    db.save_metrics_db(connection, data)
    sql, values = connection.cursor.return_value.execute.call_args.args
    assert "INSERT INTO system_metrics" in sql
    assert "NOW()" in sql and "ON DUPLICATE KEY" not in sql
    fields = sql.split("(", 1)[1].split(")", 1)[0].replace(" ", "").split()
    fields = "".join(fields).split(",")
    assert fields == list(FIELD_PRECISIONS) + ["timestamp"]
    assert values == (12, 0.25, 0.5, 0.75, 101.5, -12.5, 2048.0, 1.25, 2.75, 31.25)
    for index, field in enumerate(FIELD_PRECISIONS):
        payload[field] = format(Decimal(str(values[index])), ".2f")
    assert_valid(SystemMetricsPayload, payload)
