"""Bounded JSON decoding and safe validation errors, without HTTP behavior."""

import json
import math

from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.enrollment import EnrollmentRequest, MessageType
from contracts.v1.responses import APIError, MessageValidationError

EVENT_BATCH_MAX_BYTES = 1048576
# Covers 64 maximum-length source keys even when ASCII is Unicode-escaped,
# plus escaped hostname metadata and the request envelope.
ENROLLMENT_MAX_BYTES = 32768
SAFE_MESSAGES = {
    "batch_too_large": "The event batch exceeds the permitted byte limit.",
    "invalid_json": "The request must contain valid UTF-8 JSON without duplicate keys.",
    "invalid_envelope": "The request envelope is invalid.",
    "invalid_message": "An event message is invalid.",
}


class InputValidationError(ValueError):
    def __init__(self, code, *, field=None, index=None):
        message = SAFE_MESSAGES[code]
        details = []
        if field is not None:
            details.append(MessageValidationError(index=index, message_id=None, field=field, code=code))
        self.error = APIError(code=code, message=message, retryable=False,
                              commit_state="not_committed", errors=details)
        self.code = code
        super().__init__(message)


def validation_error_to_safe(error: ValidationError, *, event_batch=False) -> InputValidationError:
    """Use only a bounded, known prefix of the first location; never copy messages."""
    details = error.errors(include_input=False, include_context=False, include_url=False)
    location = details[0]["loc"] if details else ()
    code = "invalid_envelope"
    field = None
    index = None
    if event_batch:
        if location and location[0] in ("protocol_version", "messages"):
            field = location[0]
        if len(location) > 1 and location[0] == "messages" and type(location[1]) is int and 0 <= location[1] < 100:
            code = "invalid_message"
            index = location[1]
            field = f"messages[{index}]"
            offset = 2
            # Pydantic inserts the selected union tag into message error paths.
            if len(location) > offset and location[offset] in MessageType.__args__:
                offset += 1
            if len(location) > offset and location[offset] in (
                "message_id", "message_type", "payload_version", "source_key", "created_at", "payload",
            ):
                field += "." + location[offset]
    elif location and location[0] in EnrollmentRequest.model_fields:
        field = location[0]
    return InputValidationError(code, field=field, index=index)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Non-finite JSON number.")


def check_unicode_and_numbers(value):
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            current.encode("utf-8", errors="strict")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("Non-finite JSON number.")
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def parse_json_body(body: bytes, *, max_bytes=EVENT_BATCH_MAX_BYTES, size_error_code="batch_too_large") -> dict:
    if type(body) is not bytes:
        raise InputValidationError("invalid_envelope")
    if len(body) > max_bytes:
        raise InputValidationError(size_error_code)
    invalid = False
    try:
        text = body.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)
        check_unicode_and_numbers(value)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        invalid = True
    if invalid:
        raise InputValidationError("invalid_json") from None
    if not isinstance(value, dict):
        raise InputValidationError("invalid_envelope")
    return value


def validate_event_batch_body(body: bytes) -> EventBatchRequest:
    value = parse_json_body(body)
    try:
        return EventBatchRequest.model_validate(value)
    except ValidationError as error:
        safe_error = validation_error_to_safe(error, event_batch=True)
    raise safe_error from None


def validate_enrollment_body(body: bytes) -> EnrollmentRequest:
    value = parse_json_body(body, max_bytes=ENROLLMENT_MAX_BYTES, size_error_code="invalid_envelope")
    try:
        return EnrollmentRequest.model_validate(value)
    except ValidationError as error:
        safe_error = validation_error_to_safe(error)
    raise safe_error from None
