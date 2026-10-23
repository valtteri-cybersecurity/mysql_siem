"""UTC conversion boundaries and scheduled analysis independent of host timezone."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from analysis.ufw import main
from ingestion.ufw_to_mysql import convert_timestamp


@pytest.mark.parametrize("value,expected", [
    ("2026-10-22T15:30:00.654321+03:00", datetime(2026, 10, 22, 12, 30, 0, 654321)),
    ("2026-10-22T01:30:00.123456+03:00", datetime(2026, 10, 21, 22, 30, 0, 123456)),
    ("2026-10-22T23:30:00.123456-03:00", datetime(2026, 10, 23, 2, 30, 0, 123456)),
    ("2026-10-22T12:00:00.123456Z", datetime(2026, 10, 22, 12, 0, 0, 123456)),
    ("2026-10-25T03:30:00+03:00", datetime(2026, 10, 25, 0, 30)),
    ("2026-10-25T03:30:00+02:00", datetime(2026, 10, 25, 1, 30)),
])
def test_explicit_offset_converts_to_naive_utc(value, expected):
    actual = convert_timestamp(value)
    assert actual == expected and actual.tzinfo is None


@pytest.mark.parametrize("value", [None, "invalid", "2026-10-22", "2026-10-22T12:00:00",
                                    "0999-12-31T23:00:00Z", "0001-01-01T00:00:00+03:00",
                                    "9999-12-31T23:59:59-03:00"])
def test_invalid_or_ambiguous_timestamp_is_rejected(value):
    with pytest.raises(ValueError):
        convert_timestamp(value)


def test_recent_analysis_uses_utc_clock(monkeypatch):
    instant = datetime(2026, 10, 22, 23, 30, tzinfo=timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant.astimezone(tz) if tz else datetime(2026, 10, 23, 2, 30)

    monkeypatch.setattr(main, "datetime", Clock)
    # Keep type validation on real datetime objects while capturing scheduled bounds.
    periods = Mock(return_value=[(datetime(2026, 10, 22, 23), datetime(2026, 10, 23))])
    monkeypatch.setattr(main, "recent_hour_periods", periods)
    monkeypatch.setattr(main, "get_connection", Mock(return_value=None))
    assert main.main([]) == 1
    assert periods.call_args.args[0] == instant.replace(tzinfo=None)
    assert periods.call_args.args[0] + timedelta(minutes=30) == datetime(2026, 10, 23)
