"""Response contract tests require no database, network or HTTP server."""

import copy
import json
from typing import get_args

import pytest
from pydantic import ValidationError

from contracts.v1.responses import (
    APIError,
    APIErrorResponse,
    ErrorCode,
    EventBatchResponse,
    EventResult,
    MessageValidationError,
)

MESSAGE_ID = "11111111-1111-4111-8111-111111111111"
ERROR_CODES = (
    "invalid_json", "invalid_envelope", "invalid_credentials", "source_forbidden",
    "message_id_conflict", "revision_conflict", "event_identity_conflict",
    "batch_too_large", "invalid_message", "unsupported_message_type",
    "unsupported_payload_version", "rate_limited", "internal_error",
    "temporarily_unavailable", "writer_busy", "unsupported_media_type",
    "enrollment_conflict",
)


@pytest.fixture
def result():
    return {"index": 0, "message_id": MESSAGE_ID, "status": "accepted"}


@pytest.fixture
def success(result):
    return {
        "protocol_version": 1,
        "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "collector_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "received_at": "2026-10-23T12:00:00.000000Z",
        "committed": True,
        "results": [result],
    }


@pytest.fixture
def detail():
    return {
        "index": 0, "message_id": MESSAGE_ID,
        "field": "messages[0].source_key", "code": "source_forbidden",
    }


@pytest.fixture
def error(detail):
    return {
        "code": "source_forbidden",
        "message": "Collector is not authorized for this source.",
        "retryable": False,
        "commit_state": "not_committed",
        "errors": [detail],
    }


@pytest.fixture
def failure(error):
    return {
        "protocol_version": 1,
        "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
        "error": error,
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


@pytest.mark.parametrize("status", ["accepted", "duplicate", "stale"])
def test_success_statuses_are_preserved(success, status):
    success["results"][0]["status"] = status
    assert_valid(EventBatchResponse, success)


@pytest.mark.parametrize("size", [1, 2, 100])
def test_success_indices_and_repeated_message_ids(success, size):
    results = []
    for index in range(size):
        results.append({"index": index, "message_id": MESSAGE_ID, "status": "duplicate"})
    success["results"] = results
    assert_valid(EventBatchResponse, success)


@pytest.mark.parametrize("indices", [[], [1], [0, 0], [0, 2], [1, 0], [0, 2, 1], list(range(101))])
def test_success_rejects_empty_oversized_duplicate_missing_or_unordered_indices(success, indices):
    results = []
    for index in indices:
        results.append({"index": index, "message_id": MESSAGE_ID, "status": "accepted"})
    success["results"] = results
    assert_invalid(EventBatchResponse, success)


@pytest.mark.parametrize("field,value", [
    ("protocol_version", True), ("protocol_version", False),
    ("protocol_version", "1"), ("protocol_version", 1.0),
    ("protocol_version", 0), ("protocol_version", 2), ("protocol_version", None),
    ("request_id", "bad"), ("collector_id", "bad"),
    ("received_at", "2026-10-23T12:00:00Z"),
    ("received_at", "2026-02-29T12:00:00.000000Z"),
    ("committed", False), ("committed", 1), ("committed", 1.0),
    ("committed", "true"), ("committed", None),
    ("results", None), ("results", {}), ("results", "not-a-list"),
    ("results", [{}]),
])
def test_success_rejects_invalid_fields(success, field, value):
    success[field] = value
    assert_invalid(EventBatchResponse, success)


@pytest.mark.parametrize("field,value", [
    ("index", -1), ("index", True), ("index", "0"), ("index", 0.0),
    ("index", None), ("message_id", "bad"), ("message_id", None),
    ("status", "failed"), ("status", "ACCEPTED"), ("status", None), ("status", 1),
])
def test_result_rejects_invalid_fields(result, success, field, value):
    result[field] = value
    assert_invalid(EventResult, result)
    assert_invalid(EventBatchResponse, success)


@pytest.mark.parametrize("state", ["not_committed", "unknown"])
@pytest.mark.parametrize("retryable", [False, True])
def test_error_response_accepts_states_without_http_policy(failure, state, retryable):
    failure["error"]["commit_state"] = state
    failure["error"]["retryable"] = retryable
    assert_valid(APIErrorResponse, failure)


def test_error_can_have_no_message_details(failure):
    failure["error"]["errors"] = []
    assert_valid(APIErrorResponse, failure)


def test_error_details_can_be_unidentified(failure):
    failure["error"]["errors"] = [
        {"index": None, "message_id": None, "field": None, "code": "invalid_json"},
    ]
    assert_valid(APIErrorResponse, failure)


@pytest.mark.parametrize("field", ["index", "message_id", "field"])
def test_error_nullable_fields_remain_required_but_accept_null(detail, field):
    detail[field] = None
    assert_valid(MessageValidationError, detail)


@pytest.mark.parametrize("code", ERROR_CODES)
def test_all_agreed_codes_are_supported_in_both_locations(failure, code):
    failure["error"]["code"] = code
    failure["error"]["errors"][0]["code"] = code
    assert_valid(APIErrorResponse, failure)


def test_code_set_matches_v1_contract():
    assert set(get_args(ErrorCode)) == set(ERROR_CODES)


@pytest.mark.parametrize("code", ["", " ", "unknown_code", "INVALID_JSON", 1, True, None])
def test_unknown_empty_or_wrongly_typed_codes_are_rejected(failure, code):
    failure["error"]["code"] = code
    assert_invalid(APIErrorResponse, failure)
    failure["error"]["code"] = "invalid_message"
    failure["error"]["errors"][0]["code"] = code
    assert_invalid(APIErrorResponse, failure)


@pytest.mark.parametrize("field,value", [
    ("message", ""), ("message", None), ("message", 1), ("message", True),
    ("retryable", 0), ("retryable", 1), ("retryable", "false"),
    ("retryable", 0.0), ("retryable", None),
    ("commit_state", "committed"), ("commit_state", "NOT_COMMITTED"),
    ("commit_state", None), ("errors", None), ("errors", {}),
    ("errors", "not-a-list"), ("errors", [{}]),
])
def test_error_rejects_invalid_fields(error, field, value):
    error[field] = value
    assert_invalid(APIError, error)


@pytest.mark.parametrize("field,value", [
    ("index", -1), ("index", True), ("index", "0"), ("index", 0.0),
    ("message_id", "bad"), ("message_id", 1),
    ("field", 1), ("field", True), ("field", []),
])
def test_error_detail_rejects_invalid_fields(detail, field, value):
    detail[field] = value
    assert_invalid(MessageValidationError, detail)


@pytest.mark.parametrize("field,value", [
    ("protocol_version", True), ("protocol_version", False),
    ("protocol_version", 1.0), ("protocol_version", "1"),
    ("protocol_version", 0), ("protocol_version", 2),
    ("request_id", "invalid"), ("request_id", None),
    ("error", None), ("error", {}),
])
def test_error_envelope_rejects_invalid_fields(failure, field, value):
    failure[field] = value
    assert_invalid(APIErrorResponse, failure)


@pytest.mark.parametrize("model_type,fixture_name", [
    (EventResult, "result"), (EventBatchResponse, "success"),
    (MessageValidationError, "detail"), (APIError, "error"),
    (APIErrorResponse, "failure"),
])
def test_every_field_is_required(model_type, fixture_name, request):
    values = request.getfixturevalue(fixture_name)
    for field in model_type.model_fields:
        incomplete = copy.deepcopy(values)
        del incomplete[field]
        assert_invalid(model_type, incomplete)


@pytest.mark.parametrize("model_type,fixture_name", [
    (EventResult, "result"), (EventBatchResponse, "success"),
    (MessageValidationError, "detail"), (APIError, "error"),
    (APIErrorResponse, "failure"),
])
@pytest.mark.parametrize("extra", ["unknown", "raw_message", "input", "api_key"])
def test_unknown_and_sensitive_fields_are_not_passed_through(model_type, fixture_name, extra, request):
    values = request.getfixturevalue(fixture_name)
    values[extra] = "secret-value"
    assert_invalid(model_type, values)


def test_error_validation_text_does_not_echo_sensitive_input(failure):
    failure["error"]["errors"][0]["raw_message"] = "secret-value"
    with pytest.raises(ValidationError) as caught:
        APIErrorResponse.model_validate(failure)
    assert "secret-value" not in str(caught.value)


def test_error_description_is_preserved_without_automatic_rewriting(failure):
    failure["error"]["message"] = "  Safe explanation.  "
    assert_valid(APIErrorResponse, failure)
