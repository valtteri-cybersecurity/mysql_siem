"""Ingress limits and error redaction use only public synthetic test markers."""

import json

import pytest
from pydantic import ValidationError

from contracts.v1 import json_input
from contracts.v1.json_input import (
    ENROLLMENT_MAX_BYTES,
    EVENT_BATCH_MAX_BYTES,
    InputValidationError,
    parse_json_body,
    validate_enrollment_body,
    validate_event_batch_body,
    validation_error_to_safe,
)
from contracts.v1.responses import APIErrorResponse

pytest_plugins = ("test_enrollment", "test_v1_audit")

MARKER = "PUBLIC_SYNTHETIC_PRIVATE_INPUT"


def body(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def assert_safe(error, marker=MARKER):
    for value in (str(error), repr(error), repr(vars(error)), error.error.model_dump_json()):
        assert marker not in value
    envelope = APIErrorResponse(protocol_version=1, request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                error=error.error)
    assert marker not in envelope.model_dump_json()
    assert error.__context__ is None


def test_exact_batch_byte_limit_is_parsed_separately_from_model_validity():
    exact = b'{}' + b' ' * (EVENT_BATCH_MAX_BYTES - 2)
    assert len(exact) == 1048576
    assert parse_json_body(exact) == {}
    with pytest.raises(InputValidationError) as caught:
        validate_event_batch_body(exact)
    assert caught.value.code == "invalid_envelope"


def test_oversize_is_rejected_before_decode_or_json(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("JSON parser called for oversize input")

    monkeypatch.setattr(json_input.json, "loads", forbidden)
    with pytest.raises(InputValidationError) as caught:
        parse_json_body(b'\xff' * 1048577)
    assert caught.value.code == "batch_too_large"
    assert_safe(caught.value)


def test_utf8_bytes_and_whitespace_count_towards_limit():
    encoded = body({"x": "ä😀"})
    assert parse_json_body(encoded, max_bytes=len(encoded)) == {"x": "ä😀"}
    for limit in (len(encoded) - 1, len(encoded.decode("utf-8"))):
        with pytest.raises(InputValidationError) as caught:
            parse_json_body(encoded, max_bytes=limit)
        assert caught.value.code == "batch_too_large"
    with pytest.raises(InputValidationError):
        parse_json_body(b' {} ', max_bytes=3)


@pytest.mark.parametrize("encoded", [
    b'', b' ', b'\xff', b'\xc0\xaf', b'{', b'{"a":}', b'{} trailing',
    b'{"a":1,"a":2}', b'{"payload":{"a":1,"a":2}}', b'{"x":[{"a":1,"a":2}]}',
    b'{"role":1,"\\u0072ole":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    b'{"x":1e999}', b'{"x":-1e999}',
    b'{"x":"\\ud800"}', b'{"x":"\\udfff"}', b'{"\\ud800":1}',
    b'{"x":["\\ud800"]}', b'{"x":"\\uXXXX"}', b'{"x":"\\u12"}',
    b'{"x":"\xed\xa0\x80"}',
])
def test_invalid_json_encodings_constants_duplicates_and_unicode(encoded):
    with pytest.raises(InputValidationError) as caught:
        parse_json_body(encoded)
    assert caught.value.code == "invalid_json"
    assert_safe(caught.value)


@pytest.mark.parametrize("encoded", [b'[]', b'"text"', b'null', b'1', b'true'])
def test_root_must_be_object(encoded):
    with pytest.raises(InputValidationError) as caught:
        parse_json_body(encoded)
    assert caught.value.code == "invalid_envelope"


@pytest.mark.parametrize("value", ['{}', bytearray(b'{}'), None, {}])
def test_only_bytes_are_accepted(value):
    with pytest.raises(InputValidationError) as caught:
        parse_json_body(value)
    assert caught.value.code == "invalid_envelope"


def test_valid_unicode_pairs_and_whitespace_preserve_data():
    assert parse_json_body(b'{"x":"\\ud83d\\ude00"}') == {"x": "😀"}
    value = {"x": "  ä😀  ", "n": 1.5, "values": [None, False, {"a": 1}]}
    assert parse_json_body(b' \n' + body(value) + b'\t ') == value


def test_parser_recursion_error_is_safe(monkeypatch):
    def exhausted_parser(*args, **kwargs):
        raise RecursionError()

    monkeypatch.setattr(json_input.json, "loads", exhausted_parser)
    with pytest.raises(InputValidationError) as caught:
        parse_json_body(b'{}')
    assert caught.value.code == "invalid_json"
    assert_safe(caught.value)


def test_all_six_event_types_pass_ingress_without_changes(six_type_batch):
    assert validate_event_batch_body(body(six_type_batch)).model_dump() == six_type_batch


def test_enrollment_passes_ingress_without_changes(request_values):
    parsed = validate_enrollment_body(body(request_values))
    assert parsed.model_dump() == request_values
    assert request_values["api_key_secret"] not in repr(parsed)


def test_enrollment_has_a_separate_explicit_limit(request_values):
    encoded = body(request_values)
    exact = encoded + b' ' * (ENROLLMENT_MAX_BYTES - len(encoded))
    assert validate_enrollment_body(exact).model_dump() == request_values
    with pytest.raises(InputValidationError) as caught:
        validate_enrollment_body(exact + b' ')
    assert caught.value.code == "invalid_envelope"


def test_enrollment_limit_covers_maximum_escaped_keys_and_hostname(request_values):
    keys = []
    for index in range(64):
        keys.append(str(index).zfill(2) + "a" * 62)
    request_values.update(requested_source_keys=keys, reported_hostname="😀" * 255)
    encoded = json.dumps(request_values, ensure_ascii=True)
    # Escape all source-key ASCII characters too, without changing JSON values.
    for key in keys:
        escaped = ""
        for char in key:
            escaped += "\\u" + format(ord(char), "04x")
        encoded = encoded.replace('"' + key + '"', '"' + escaped + '"')
    assert len(encoded.encode()) < ENROLLMENT_MAX_BYTES
    assert validate_enrollment_body(encoded.encode()).model_dump() == request_values


@pytest.mark.parametrize("field,value", [("message_type", "unknown"), ("payload_version", True),
                                          ("message_id", "invalid"), ("unknown", MARKER)])
def test_bad_message_envelope_is_classified_without_input(six_type_batch, field, value):
    six_type_batch["messages"][0][field] = value
    with pytest.raises(InputValidationError) as caught:
        validate_event_batch_body(body(six_type_batch))
    assert caught.value.code == "invalid_message"
    assert caught.value.error.errors[0].index == 0
    assert_safe(caught.value)


@pytest.mark.parametrize("failure", ["version", "missing", "extra", "messages"])
def test_bad_batch_envelope_is_classified(six_type_batch, failure):
    if failure == "version":
        six_type_batch["protocol_version"] = True
    elif failure == "missing":
        del six_type_batch["protocol_version"]
    elif failure == "extra":
        six_type_batch[MARKER] = MARKER
    else:
        six_type_batch["messages"] = []
    with pytest.raises(InputValidationError) as caught:
        validate_event_batch_body(body(six_type_batch))
    assert caught.value.code == "invalid_envelope"
    assert_safe(caught.value)


@pytest.mark.parametrize("field,value", [("api_key_secret", MARKER), ("key_id", "invalid"),
                                          ("protocol_version", True), (MARKER, MARKER)])
def test_enrollment_failures_are_safe(request_values, field, value):
    request_values[field] = value
    with pytest.raises(InputValidationError) as caught:
        validate_enrollment_body(body(request_values))
    assert caught.value.code == "invalid_envelope"
    assert_safe(caught.value)
    assert_safe(caught.value, request_values["api_key_secret"])


@pytest.mark.parametrize("kind", ["raw_line", "raw_message", "extra_key"])
def test_nested_pydantic_input_and_untrusted_keys_do_not_leak(six_type_batch, kind):
    if kind == "raw_line":
        six_type_batch["messages"][0]["payload"]["raw_line"] = MARKER
    elif kind == "raw_message":
        payload = six_type_batch["messages"][1]["payload"]
        payload.update(raw_message=MARKER, username=True)
    else:
        six_type_batch["messages"][0]["payload"][MARKER] = MARKER
    with pytest.raises(InputValidationError) as caught:
        validate_event_batch_body(body(six_type_batch))
    assert caught.value.code == "invalid_message"
    assert_safe(caught.value)


def test_arbitrary_original_error_messages_and_locations_are_not_copied():
    from pydantic_core import PydanticCustomError

    original = ValidationError.from_exception_data("Untrusted", [
        {"type": PydanticCustomError("custom", MARKER), "loc": (MARKER,), "input": MARKER},
    ])
    safe = validation_error_to_safe(original, event_batch=True)
    assert safe.code == "invalid_envelope"
    assert_safe(safe)


def test_safe_failures_do_not_log_input(capsys, caplog):
    with pytest.raises(InputValidationError):
        parse_json_body(body({MARKER: MARKER})[:-1])
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert not caplog.records
