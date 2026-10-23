"""Strict DNS offset limits without altering timestamp precision or spelling."""

from datetime import datetime, timezone

import pytest

from ingestion.dns import timestamps
from ingestion.dns.adapters.adguard import AdGuardDataError
from ingestion.dns.adapters.adguard import parse_timestamp as parse_adguard_timestamp

INVALID_OFFSETS = (
    "+00:99", "-00:99", "+01:60", "-01:60", "+24:00", "-24:00", "+99:00",
    "+23:60", "-23:60", "+12:75", "-12:75", "+99:99",
)


@pytest.mark.parametrize("zone", INVALID_OFFSETS)
def test_invalid_offsets_raise_existing_validation_errors(zone):
    value = "2026-10-23T12:00:00.123456789" + zone
    for parse in (timestamps.parse_timestamp, timestamps.timestamp_ns):
        with pytest.raises(ValueError, match=r"^Invalid DNS timestamp\.$"):
            parse(value)
    with pytest.raises(AdGuardDataError, match=r"^Invalid query log timestamp\.$"):
        parse_adguard_timestamp(value)


@pytest.mark.parametrize("zone", INVALID_OFFSETS)
def test_invalid_offsets_are_rejected_before_datetime_creation(zone, monkeypatch):
    class ForbiddenDatetime:
        @classmethod
        def fromisoformat(cls, value):
            pytest.fail("Invalid offset reached datetime conversion")

    monkeypatch.setattr(timestamps, "datetime", ForbiddenDatetime)
    with pytest.raises(ValueError, match=r"^Invalid DNS timestamp\.$"):
        timestamps.parse_timestamp("2026-10-23T12:00:00" + zone)


@pytest.mark.parametrize("value,expected", [
    ("2026-10-23T12:00:00Z", "2026-10-23T12:00:00+00:00"),
    ("2026-10-23T12:00:00+00:00", "2026-10-23T12:00:00+00:00"),
    ("2026-10-23T12:00:00-00:00", "2026-10-23T12:00:00+00:00"),
    ("2026-10-23T12:00:00+02:00", "2026-10-23T10:00:00+00:00"),
    ("2026-10-23T12:00:00-05:30", "2026-10-23T17:30:00+00:00"),
    ("2026-10-23T12:00:00+05:45", "2026-10-23T06:15:00+00:00"),
    ("2026-10-23T00:15:00+02:00", "2026-10-22T22:15:00+00:00"),
    ("2026-12-31T23:45:00-00:30", "2027-01-01T00:15:00+00:00"),
    ("2026-01-01T00:15:00+05:45", "2025-12-31T18:30:00+00:00"),
    ("2026-10-23T12:00:00+23:59", "2026-10-22T12:01:00+00:00"),
    ("2026-10-23T12:00:00-23:59", "2026-10-24T11:59:00+00:00"),
])
def test_valid_offsets_preserve_sign_and_calendar_conversion(value, expected):
    parsed = timestamps.parse_timestamp(value)
    assert parsed.isoformat() == expected
    assert parsed.tzinfo is timezone.utc


@pytest.mark.parametrize("digits", range(10))
@pytest.mark.parametrize("zone", ["Z", "+05:45", "-05:30"])
def test_zero_to_nine_fraction_digits_are_truncated_without_rounding(digits, zone):
    fraction = "999999999"[:digits]
    suffix = "." + fraction if fraction else ""
    value = "2026-10-23T12:00:00" + suffix + zone
    expected_microseconds = int(fraction[:6].ljust(6, "0"))
    assert timestamps.parse_timestamp(value).microsecond == expected_microseconds


@pytest.mark.parametrize("value", [
    "1970-01-01T00:00:00.999999999Z",
    "1970-01-01T05:45:00.999999999+05:45",
    "1969-12-31T18:30:00.999999999-05:30",
])
def test_nanosecond_identity_survives_utc_conversion(value):
    assert timestamps.timestamp_ns(value) == 999999999
    assert timestamps.parse_timestamp(value) == datetime(1970, 1, 1, 0, 0, 0, 999999, tzinfo=timezone.utc)


@pytest.mark.parametrize("zone", ["", "+02", "-05", "+0200", "+2:00", "+02:0", "+00:00:00"])
def test_offset_format_is_not_expanded(zone):
    with pytest.raises(ValueError):
        timestamps.parse_timestamp("2026-10-23T12:00:00" + zone)
