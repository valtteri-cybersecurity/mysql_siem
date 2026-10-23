"""Strict string values for API v1; validation never changes the input."""

import re
from datetime import date, datetime
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, StrictStr

U64_MAX = 18446744073709551615


def validate_uuid4(value: str) -> str:
    if len(value) != 36:
        raise ValueError("Expected a canonical lowercase UUIDv4.")
    identifier = UUID(value)
    if identifier.version != 4 or str(identifier) != value:
        raise ValueError("Expected a canonical lowercase UUIDv4.")
    return value


def validate_utc6(value: str) -> str:
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value) is None:
        raise ValueError("Expected YYYY-MM-DDTHH:MM:SS.ffffffZ.")
    instant = datetime.fromisoformat(value[:-1])
    if instant.year < 1000:
        raise ValueError("UTC timestamps require a year within 1000..9999.")
    return value


def validate_whole_second(value: str) -> str:
    if not value.endswith(".000000Z"):
        raise ValueError("Expected zero microseconds.")
    return value


def validate_utc_date(value: str) -> str:
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise ValueError("Expected YYYY-MM-DD.")
    date.fromisoformat(value)
    return value


def validate_source_key(value: str) -> str:
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", value) is None:
        raise ValueError("Expected a lowercase ASCII source key of 1..64 characters.")
    return value


def validate_hex256(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Expected 64 lowercase hexadecimal characters.")
    return value


def validate_u64(value: str) -> str:
    if re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None:
        raise ValueError("Expected a canonical unsigned integer string.")
    if int(value) > U64_MAX:
        raise ValueError("Unsigned integer exceeds the 64-bit limit.")
    return value


def validate_revision(value: str) -> str:
    if value == "0":
        raise ValueError("Revision must be at least 1.")
    return value


CanonicalUUIDv4 = Annotated[StrictStr, AfterValidator(validate_uuid4)]
UTC6 = Annotated[StrictStr, AfterValidator(validate_utc6)]
UTCSecond = Annotated[UTC6, AfterValidator(validate_whole_second)]
UTCDate = Annotated[StrictStr, AfterValidator(validate_utc_date)]
SourceKey = Annotated[StrictStr, AfterValidator(validate_source_key)]
Hex256 = Annotated[StrictStr, AfterValidator(validate_hex256)]
U64 = Annotated[StrictStr, AfterValidator(validate_u64)]
Revision = Annotated[U64, AfterValidator(validate_revision)]
