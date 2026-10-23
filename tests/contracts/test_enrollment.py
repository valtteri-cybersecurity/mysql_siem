"""Enrollment values and redacted errors with deterministic, non-secret test data."""

import base64
import copy
import json
import traceback
from typing import get_args

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.enrollment import (
    EnrollmentRequest,
    EnrollmentResponse,
    EnrollmentSourceBinding,
    MessageType,
)


def encode_test_bytes(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# Deliberately public, deterministic bytes: never a real credential.
TEST_SECRET = encode_test_bytes(bytes(range(32)))


@pytest.fixture
def request_values():
    return {
        "protocol_version": 1,
        "enrollment_request_id": "11111111-1111-4111-8111-111111111111",
        "key_id": "22222222-2222-4222-8222-222222222222",
        "api_key_secret": TEST_SECRET,
        "requested_source_keys": ["local.ufw", "local.ssh", "adguard.office"],
        "reported_hostname": "mint-a",
    }


@pytest.fixture
def binding():
    return {"source_key": "local.ufw", "message_type": "ufw.event", "payload_versions": [1]}


@pytest.fixture
def response(binding):
    return {
        "protocol_version": 1,
        "request_id": "33333333-3333-4333-8333-333333333333",
        "enrollment_request_id": "11111111-1111-4111-8111-111111111111",
        "collector_id": "44444444-4444-4444-8444-444444444444",
        "key_id": "22222222-2222-4222-8222-222222222222",
        "recovery_until": "2026-10-24T12:00:00.123456Z",
        "source_bindings": [binding],
    }


def assert_valid(model_type, values):
    original = copy.deepcopy(values)
    assert model_type.model_validate(values).model_dump() == original
    parsed = model_type.model_validate_json(json.dumps(values))
    assert json.loads(parsed.model_dump_json()) == original
    assert values == original


def assert_no_secret_in_error(error, secret):
    for representation in (str(error), repr(error), repr(error.errors()), error.json(),
                           "".join(traceback.format_exception(error))):
        assert secret not in representation


def assert_invalid(model_type, values):
    with pytest.raises(ValidationError) as caught:
        model_type.model_validate(values)
    assert_no_secret_in_error(caught.value, TEST_SECRET)
    with pytest.raises(ValidationError) as caught:
        model_type.model_validate_json(json.dumps(values))
    assert_no_secret_in_error(caught.value, TEST_SECRET)


def test_valid_request_and_response(request_values, response):
    assert_valid(EnrollmentRequest, request_values)
    assert_valid(EnrollmentResponse, response)


@pytest.mark.parametrize("model_type,fixture_name", [
    (EnrollmentRequest, "request_values"), (EnrollmentResponse, "response"),
    (EnrollmentSourceBinding, "binding"),
])
def test_all_fields_are_required_without_generation(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("model_type,fixture_name", [(EnrollmentRequest, "request_values"), (EnrollmentResponse, "response")])
@pytest.mark.parametrize("version", [True, False, "1", 1.0, 0, 2, None])
def test_protocol_version_is_strictly_integer_one(model_type, fixture_name, version, request):
    values = request.getfixturevalue(fixture_name)
    values["protocol_version"] = version
    assert_invalid(model_type, values)


@pytest.mark.parametrize("model_type,fixture_name,field", [
    (EnrollmentRequest, "request_values", "enrollment_request_id"),
    (EnrollmentRequest, "request_values", "key_id"),
    (EnrollmentResponse, "response", "request_id"),
    (EnrollmentResponse, "response", "enrollment_request_id"),
    (EnrollmentResponse, "response", "collector_id"),
    (EnrollmentResponse, "response", "key_id"),
])
def test_uuid_fields_reuse_canonical_uuid4_rules(model_type, fixture_name, field, request):
    values = request.getfixturevalue(fixture_name)
    for invalid in ("bad", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "11111111-1111-1111-8111-111111111111", 1, None):
        values[field] = invalid
        assert_invalid(model_type, values)


@pytest.mark.parametrize("data", [bytes(32), bytes(range(32)), b"\xff" * 32, b"\xfb\xff" * 16])
def test_secret_accepts_and_preserves_exact_32_byte_base64url(request_values, data):
    value = encode_test_bytes(data)
    request_values["api_key_secret"] = value
    assert_valid(EnrollmentRequest, request_values)
    parsed = EnrollmentRequest.model_validate(request_values)
    assert parsed.api_key_secret == value
    assert value not in repr(parsed)
    assert value not in str(parsed)


@pytest.mark.parametrize("value", [
    "", encode_test_bytes(bytes(31)), encode_test_bytes(bytes(33)), TEST_SECRET + "=",
    TEST_SECRET + "==", " " + TEST_SECRET, TEST_SECRET + " ", TEST_SECRET + "\n",
    TEST_SECRET[:10] + "\t" + TEST_SECRET[11:], "é" + TEST_SECRET[1:],
    "+" + TEST_SECRET[1:], "/" + TEST_SECRET[1:], "=" + TEST_SECRET[1:],
    "!" * 43, "A" * 42, "A" * 44, None, True, 32, [], {},
])
def test_secret_rejects_wrong_alphabet_length_padding_and_types(request_values, value):
    request_values["api_key_secret"] = value
    assert_invalid(EnrollmentRequest, request_values)
    if isinstance(value, str) and value:
        with pytest.raises(ValidationError) as caught:
            EnrollmentRequest.model_validate(request_values)
        assert_no_secret_in_error(caught.value, value)


@pytest.mark.parametrize("pad_bits", [1, 2, 3])
def test_secret_rejects_noncanonical_unused_pad_bits(request_values, pad_bits):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(TEST_SECRET[-1])
    noncanonical = TEST_SECRET[:-1] + alphabet[last + pad_bits]
    assert base64.urlsafe_b64decode(noncanonical + "=") == bytes(range(32))
    request_values["api_key_secret"] = noncanonical
    assert_invalid(EnrollmentRequest, request_values)
    with pytest.raises(ValidationError) as caught:
        EnrollmentRequest.model_validate(request_values)
    assert_no_secret_in_error(caught.value, noncanonical)


def test_standard_base64_alternative_is_not_accepted(request_values):
    value = base64.b64encode(b"\xfb\xff" * 16).decode("ascii").rstrip("=")
    assert "+" in value or "/" in value
    request_values["api_key_secret"] = value
    assert_invalid(EnrollmentRequest, request_values)


def test_secret_bytes_are_not_coerced_to_a_string(request_values):
    request_values["api_key_secret"] = TEST_SECRET.encode()
    with pytest.raises(ValidationError) as caught:
        EnrollmentRequest.model_validate(request_values)
    assert_no_secret_in_error(caught.value, TEST_SECRET)


@pytest.mark.parametrize("size", [1, 64])
def test_requested_sources_keep_order_at_size_boundaries(request_values, size):
    keys = []
    for index in reversed(range(size)):
        keys.append("source." + str(index))
    request_values["requested_source_keys"] = keys
    assert_valid(EnrollmentRequest, request_values)


@pytest.mark.parametrize("value", [[], ["same", "same"], ["a"] * 65, ["Local.ufw"], [" invalid "], [""], [1], [None], None, {}, "local.ufw"])
def test_requested_sources_reject_empty_duplicate_invalid_or_wrong_types(request_values, value):
    request_values["requested_source_keys"] = value
    assert_invalid(EnrollmentRequest, request_values)


def test_65_unique_requested_sources_are_rejected(request_values):
    keys = []
    for index in range(65):
        keys.append("source." + str(index))
    request_values["requested_source_keys"] = keys
    assert_invalid(EnrollmentRequest, request_values)


@pytest.mark.parametrize("value", [None, "", "  mint-a  ", "ä" * 255, "😀" * 255])
def test_hostname_is_preserved_as_nullable_untrusted_metadata(request_values, value):
    request_values["reported_hostname"] = value
    assert_valid(EnrollmentRequest, request_values)


@pytest.mark.parametrize("value", ["a" * 256, "ä" * 256, True, 1, [], {}])
def test_hostname_rejects_overlength_and_coercion(request_values, value):
    request_values["reported_hostname"] = value
    assert_invalid(EnrollmentRequest, request_values)


@pytest.mark.parametrize("message_type", get_args(MessageType))
def test_source_binding_accepts_all_six_types(binding, message_type):
    binding["message_type"] = message_type
    assert_valid(EnrollmentSourceBinding, binding)


def test_binding_message_types_match_current_event_batch_contract():
    mapping = EventBatchRequest.model_json_schema()["properties"]["messages"]["items"]["discriminator"]["mapping"]
    assert set(get_args(MessageType)) == set(mapping)


@pytest.mark.parametrize("field,value", [
    ("source_key", "Local.ufw"), ("source_key", " invalid "), ("source_key", None),
    ("message_type", "unknown.event"), ("message_type", "UFW.EVENT"), ("message_type", None),
    ("payload_versions", []), ("payload_versions", [1, 1]), ("payload_versions", [0]),
    ("payload_versions", [2]), ("payload_versions", [True]), ("payload_versions", [False]),
    ("payload_versions", [1.0]), ("payload_versions", ["1"]), ("payload_versions", [None]),
    ("payload_versions", None), ("payload_versions", {}), ("payload_versions", "1"),
])
def test_binding_rejects_invalid_values(binding, field, value):
    binding[field] = value
    assert_invalid(EnrollmentSourceBinding, binding)


@pytest.mark.parametrize("value", [[], None, {}, "not-a-list", [{}]])
def test_response_requires_at_least_one_valid_binding(response, value):
    response["source_bindings"] = value
    assert_invalid(EnrollmentResponse, response)


def test_response_preserves_local_and_remote_bindings_without_host_id(response):
    response["source_bindings"] = [
        {"source_key": "adguard.office", "message_type": "dns.query", "payload_versions": [1]},
        {"source_key": "local.ufw", "message_type": "ufw.event", "payload_versions": [1]},
    ]
    assert_valid(EnrollmentResponse, response)
    assert "host_id" not in EnrollmentResponse.model_fields


def test_response_rejects_conflicting_bindings_for_one_source(response):
    second = copy.deepcopy(response["source_bindings"][0])
    second["message_type"] = "ssh.auth_event"
    response["source_bindings"].append(second)
    assert_invalid(EnrollmentResponse, response)


def test_response_allows_identical_nonconflicting_bindings_without_deduplicating(response):
    response["source_bindings"].append(copy.deepcopy(response["source_bindings"][0]))
    assert_valid(EnrollmentResponse, response)


@pytest.mark.parametrize("value", [
    "2026-10-24T12:00:00Z", "2026-10-24T12:00:00.000000+00:00", "2026-10-24T12:00:00.0000001Z",
    "2026-02-29T12:00:00.000000Z", "0999-12-31T12:00:00.000000Z", None, 1,
])
def test_recovery_until_reuses_utc6_validation(response, value):
    response["recovery_until"] = value
    assert_invalid(EnrollmentResponse, response)


def test_recovery_time_does_not_apply_a_clock_or_issuance_policy(response):
    response["recovery_until"] = "1000-01-01T00:00:00.000000Z"
    assert_valid(EnrollmentResponse, response)


@pytest.mark.parametrize("model_type,fixture_name", [
    (EnrollmentRequest, "request_values"), (EnrollmentResponse, "response"),
    (EnrollmentSourceBinding, "binding"),
])
@pytest.mark.parametrize("extra", ["unknown", "host_id", "source_id", "enrollment_token"])
def test_unknown_and_server_identity_fields_are_forbidden(model_type, fixture_name, extra, request):
    values = request.getfixturevalue(fixture_name)
    values[extra] = TEST_SECRET
    assert_invalid(model_type, values)


def test_response_never_returns_or_accepts_the_secret(response):
    parsed = EnrollmentResponse.model_validate(response)
    assert "api_key_secret" not in parsed.model_dump()
    assert TEST_SECRET not in parsed.model_dump_json()
    response["api_key_secret"] = TEST_SECRET
    assert_invalid(EnrollmentResponse, response)


@pytest.mark.parametrize("failure", ["protocol", "uuid", "sources", "hostname", "extra", "secret_as_extra_name"])
def test_unrelated_request_errors_do_not_expose_the_valid_secret(request_values, failure):
    if failure == "protocol":
        del request_values["protocol_version"]
    elif failure == "uuid":
        request_values["key_id"] = "invalid"
    elif failure == "sources":
        request_values["requested_source_keys"] = ["same", "same"]
    elif failure == "hostname":
        request_values["reported_hostname"] = "a" * 256
    elif failure == "extra":
        request_values["unexpected"] = {"nested": TEST_SECRET}
    else:
        request_values[TEST_SECRET] = TEST_SECRET
    assert_invalid(EnrollmentRequest, request_values)
    with pytest.raises(ValidationError) as caught:
        EnrollmentRequest(**request_values)
    assert_no_secret_in_error(caught.value, TEST_SECRET)


@pytest.mark.parametrize("model_type", [EnrollmentRequest, EnrollmentResponse, EnrollmentSourceBinding])
def test_malformed_json_errors_are_redacted_without_custom_json_parsing(model_type):
    malformed = '{"api_key_secret":"' + TEST_SECRET + '",'
    for value in (malformed, malformed.encode(), bytearray(malformed.encode())):
        with pytest.raises(ValidationError) as caught:
            model_type.model_validate_json(value)
        assert_no_secret_in_error(caught.value, TEST_SECRET)


def test_root_type_error_does_not_echo_an_entire_request(request_values):
    with pytest.raises(ValidationError) as caught:
        EnrollmentRequest.model_validate(json.dumps(request_values))
    assert_no_secret_in_error(caught.value, TEST_SECRET)


def test_models_do_not_write_logs_or_print_keys(request_values, response, capsys, caplog):
    EnrollmentRequest.model_validate(request_values)
    EnrollmentResponse.model_validate(response)
    request_values["protocol_version"] = False
    assert_invalid(EnrollmentRequest, request_values)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert not caplog.records
