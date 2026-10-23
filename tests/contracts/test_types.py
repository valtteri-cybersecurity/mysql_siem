"""API value validation requires no database, network or system services."""

import json
from datetime import date, datetime, timezone
from uuid import UUID

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from contracts.v1.types import (
    U64,
    UTC6,
    CanonicalUUIDv4,
    Hex256,
    Revision,
    SourceKey,
    UTCDate,
    UTCSecond,
)

UUID4 = "aabbccdd-1234-4567-89ab-0123456789ab"
TYPES = (CanonicalUUIDv4, UTC6, UTCSecond, UTCDate, SourceKey, Hex256, U64, Revision)


@pytest.mark.parametrize("value_type,value", [
    (CanonicalUUIDv4, UUID4),
    (UTC6, "1000-01-01T00:00:00.000000Z"),
    (UTC6, "9999-12-31T23:59:59.999999Z"),
    (UTC6, "2024-02-29T12:30:15.123456Z"),
    (UTCSecond, "2026-10-23T12:30:15.000000Z"),
    (UTCDate, "2024-02-29"),
    (UTCDate, "0001-01-01"),
    (UTCDate, "9999-12-31"),
    (SourceKey, "local.ufw"),
    (SourceKey, "local.ssh"),
    (SourceKey, "adguard.office"),
    (SourceKey, "0"),
    (SourceKey, "a" * 64),
    (SourceKey, "a.b_c-d"),
    (Hex256, "0123456789abcdef" * 4),
    (U64, "0"),
    (U64, "1"),
    (U64, "18446744073709551615"),
    (Revision, "1"),
    (Revision, "18446744073709551615"),
])
def test_valid_strings_are_preserved_in_python_and_json(value_type, value):
    adapter = TypeAdapter(value_type)
    assert adapter.validate_python(value) == value
    assert adapter.validate_json(json.dumps(value)) == value
    assert adapter.dump_json(adapter.validate_python(value)) == json.dumps(value).encode()


@pytest.mark.parametrize("value_type,value", [
    (CanonicalUUIDv4, UUID4.upper()),
    (CanonicalUUIDv4, UUID4.replace("-", "")),
    (CanonicalUUIDv4, "aabbccdd-1234-1567-89ab-0123456789ab"),
    (CanonicalUUIDv4, "aabbccdd-1234-7567-89ab-0123456789ab"),
    (CanonicalUUIDv4, "aabbccdd-1234-4567-09ab-0123456789ab"),
    (CanonicalUUIDv4, "{" + UUID4 + "}"),
    (CanonicalUUIDv4, "urn:uuid:" + UUID4),
    (CanonicalUUIDv4, "not-a-uuid"),
    (UTC6, "0999-12-31T23:59:59.999999Z"),
    (UTC6, "0000-01-01T00:00:00.000000Z"),
    (UTC6, "10000-01-01T00:00:00.000000Z"),
    (UTC6, "2026-02-29T00:00:00.000000Z"),
    (UTC6, "2026-04-31T00:00:00.000000Z"),
    (UTC6, "2026-10-23T24:00:00.000000Z"),
    (UTC6, "2026-10-23T12:60:00.000000Z"),
    (UTC6, "2026-10-23T12:30:60.000000Z"),
    (UTC6, "2026-10-23T12:30:15Z"),
    (UTC6, "2026-10-23T12:30:15.12345Z"),
    (UTC6, "2026-10-23T12:30:15.1234567Z"),
    (UTC6, "2026-10-23T12:30:15.123456+00:00"),
    (UTC6, "2026-10-23T12:30:15.123456+03:00"),
    (UTC6, "2026-10-23 12:30:15.123456Z"),
    (UTC6, "2026-10-23t12:30:15.123456z"),
    (UTC6, "2026-10-23T12:30:15.123456"),
    (UTC6, "２０２６-10-23T12:30:15.123456Z"),
    (UTCSecond, "2026-10-23T12:30:15.000001Z"),
    (UTCSecond, "2026-10-23T12:30:15Z"),
    (UTCSecond, "2026-10-23T12:30:15.00000Z"),
    (UTCSecond, "2026-02-29T00:00:00.000000Z"),
    (UTCSecond, "0999-01-01T00:00:00.000000Z"),
    (UTCDate, "2026-02-29"),
    (UTCDate, "2026-13-01"),
    (UTCDate, "2026-01-00"),
    (UTCDate, "0000-01-01"),
    (UTCDate, "20261023"),
    (UTCDate, "2026-1-01"),
    (UTCDate, "2026-10-23T00:00:00.000000Z"),
    (SourceKey, "a" * 65),
    (SourceKey, "Local.ufw"),
    (SourceKey, "local ufw"),
    (SourceKey, ".ufw"),
    (SourceKey, "-ufw"),
    (SourceKey, "_ufw"),
    (SourceKey, "local/ufw"),
    (SourceKey, "lоcal.ufw"),
    (SourceKey, "lähde.ufw"),
    (SourceKey, "源"),
    (SourceKey, "１"),
    (Hex256, "a" * 63),
    (Hex256, "a" * 65),
    (Hex256, "A" * 64),
    (Hex256, "g" * 64),
    (Hex256, "０" * 64),
    (U64, "-1"),
    (U64, "-0"),
    (U64, "+1"),
    (U64, "00"),
    (U64, "01"),
    (U64, "1.0"),
    (U64, "1e3"),
    (U64, "18446744073709551616"),
    (U64, "9" * 1000),
    (U64, "١"),
    (Revision, "0"),
    (Revision, "01"),
    (Revision, "-1"),
    (Revision, "+1"),
    (Revision, "1.0"),
    (Revision, "1e3"),
    (Revision, "18446744073709551616"),
])
def test_invalid_strings_fail_in_python_and_json(value_type, value):
    adapter = TypeAdapter(value_type)
    with pytest.raises(ValidationError):
        adapter.validate_python(value)
    with pytest.raises(ValidationError):
        adapter.validate_json(json.dumps(value))


@pytest.mark.parametrize("value_type", TYPES)
@pytest.mark.parametrize("value", ["", " ", "\n", None, True, False, 0, 1, 1.5, [], {}])
def test_empty_values_and_wrong_types_are_rejected(value_type, value):
    adapter = TypeAdapter(value_type)
    with pytest.raises(ValidationError):
        adapter.validate_python(value)
    with pytest.raises(ValidationError):
        adapter.validate_json(json.dumps(value))


@pytest.mark.parametrize("value_type,value", [
    (CanonicalUUIDv4, UUID4),
    (UTC6, "2026-10-23T12:30:15.123456Z"),
    (UTCSecond, "2026-10-23T12:30:15.000000Z"),
    (UTCDate, "2026-10-23"),
    (SourceKey, "local.ufw"),
    (Hex256, "a" * 64),
    (U64, "1"),
    (Revision, "1"),
])
@pytest.mark.parametrize("padding", [" ", "\n", "\t"])
def test_input_is_never_trimmed(value_type, value, padding):
    adapter = TypeAdapter(value_type)
    for padded in (padding + value, value + padding):
        with pytest.raises(ValidationError):
            adapter.validate_python(padded)
        with pytest.raises(ValidationError):
            adapter.validate_json(json.dumps(padded))


@pytest.mark.parametrize("value_type,value", [
    (CanonicalUUIDv4, UUID(UUID4)),
    (UTC6, datetime(2026, 10, 23, tzinfo=timezone.utc)),
    (UTCSecond, datetime(2026, 10, 23, tzinfo=timezone.utc)),
    (UTCDate, date(2026, 10, 23)),
    (SourceKey, b"local.ufw"),
    (Hex256, b"a" * 64),
    (U64, b"1"),
    (Revision, b"1"),
])
def test_native_objects_and_bytes_are_not_coerced(value_type, value):
    with pytest.raises(ValidationError):
        TypeAdapter(value_type).validate_python(value)


class Values(BaseModel):
    identifier: CanonicalUUIDv4
    instant: UTC6
    whole_second: UTCSecond
    day: UTCDate
    source: SourceKey
    digest: Hex256
    counter: U64
    revision: Revision


@pytest.fixture
def values():
    return {
        "identifier": UUID4,
        "instant": "2026-10-23T12:30:15.123456Z",
        "whole_second": "2026-10-23T12:30:15.000000Z",
        "day": "2026-10-23",
        "source": "local.ufw",
        "digest": "a" * 64,
        "counter": "18446744073709551615",
        "revision": "1",
    }


def test_all_types_work_as_model_fields_without_changing_values(values):
    assert Values.model_validate(values).model_dump() == values
    model = Values.model_validate_json(json.dumps(values))
    assert json.loads(model.model_dump_json()) == values


@pytest.mark.parametrize("field", Values.model_fields)
def test_model_fields_remain_strict_in_a_default_lax_model(values, field):
    values[field] = 1
    with pytest.raises(ValidationError):
        Values.model_validate(values)
    with pytest.raises(ValidationError):
        Values.model_validate_json(json.dumps(values))


@pytest.mark.parametrize("field", Values.model_fields)
def test_model_does_not_supply_missing_values(values, field):
    del values[field]
    with pytest.raises(ValidationError):
        Values.model_validate(values)
