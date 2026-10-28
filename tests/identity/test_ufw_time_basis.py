"""Time-basis diagnostics must never change events or upgrade safety rules."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from database import ufw_time_basis as basis


@pytest.mark.parametrize('timestamp,stored,precision,expected', [
    ('2026-01-01T14:00:00+02:00', datetime(2026, 1, 1, 12), 6, basis.UTC_VERIFIED),
    ('2026-01-01T14:00:00+02:00', datetime(2026, 1, 1, 14), 6, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T15:00:00+03:00', datetime(2026, 1, 1, 15), 6, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T14:00:00-02:00', datetime(2026, 1, 1, 16), 6, basis.UTC_VERIFIED),
    ('2026-01-01T14:00:00-02:00', datetime(2026, 1, 1, 14), 6, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T12:00:00Z', datetime(2026, 1, 1, 12), 6, basis.UTC_VERIFIED),
    ('2026-01-01T12:00:00+00:00', datetime(2026, 1, 1, 12), 6, basis.UTC_VERIFIED),
    ('2026-01-01T12:00:00-00:00', datetime(2026, 1, 1, 12), 6, basis.UNVERIFIED),
    ('2026-01-01T12:00:00', datetime(2026, 1, 1, 12), 6, basis.UNVERIFIED),
    ('2026-02-31T12:00:00Z', datetime(2026, 1, 1, 12), 6, basis.UNVERIFIED),
    ('2026-01-01T12:00:00+00:60', datetime(2026, 1, 1, 12), 6, basis.UNVERIFIED),
    ('Jan 1 12:00:00', datetime(2026, 1, 1, 12), 6, basis.UNVERIFIED),
    ('2026-01-01T14:00:00+02:00', datetime(2026, 1, 1, 13), 6, basis.UNVERIFIED),
    ('2026-01-01T14:00:00.123456+02:00', datetime(2026, 1, 1, 14), 0, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T14:00:00.800000+02:00', datetime(2026, 1, 1, 14, 0, 1), 0, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T14:00:00.800000+02:00', datetime(2026, 1, 1, 14), 0, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T14:00:00.123456+02:00', datetime(2026, 1, 1, 12), 0, basis.UTC_VERIFIED),
    ('2026-01-01T14:00:00.123456+02:00', datetime(2026, 1, 1, 12), 6, basis.UNVERIFIED),
    ('2026-01-01T14:00:00.123456+02:00', datetime(2026, 1, 1, 14, 0, 1), 0, basis.UNVERIFIED),
    ('2026-01-01T14:00:00.123456+02:00', datetime(2026, 1, 1, 14, 0, 0, 123000), 3, basis.LOCAL_TIME_VERIFIED),
    ('2026-01-01T12:00:00.1234567Z', datetime(2026, 1, 1, 12), 0, basis.UNVERIFIED),
    ('9999-12-31T23:59:59.999999Z', datetime(9999, 12, 31, 23, 59, 59), 0, basis.UTC_VERIFIED),
])
def test_classify_individual_events(timestamp, stored, precision, expected):
    raw_line = timestamp + ' host kernel: [UFW BLOCK] SRC=192.0.2.1'
    assert basis.classify_event_time(raw_line, stored, precision) == expected


@pytest.mark.parametrize('raw,stored,precision', [
    (None, datetime(2026, 1, 1), 6), ('', datetime(2026, 1, 1), 6),
    ('x' * 65537, datetime(2026, 1, 1), 6),
    ('2026-01-01T00:00:00Z', None, 6),
    ('2026-01-01T00:00:00Z', datetime(2026, 1, 1, tzinfo=timezone.utc), 6),
    ('2026-01-01T00:00:00Z', datetime(2026, 1, 1), None),
    ('2026-01-01T00:00:00Z', datetime(2026, 1, 1), True),
    ('2026-01-01T00:00:00Z', datetime(2026, 1, 1), -1),
    ('2026-01-01T00:00:00Z', datetime(2026, 1, 1), 7),
])
def test_invalid_evidence_is_unverified(raw, stored, precision):
    assert basis.classify_event_time(raw, stored, precision) == basis.UNVERIFIED


def fake_history(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (3,)
    cursor.fetchall.return_value = [
        (1, datetime(2026, 1, 1, 12), '2026-01-01T14:00:00+02:00 host [UFW BLOCK]'),
        (2, datetime(2026, 1, 1, 14), '2026-01-01T14:00:00+02:00 host [UFW BLOCK]'),
        (3, datetime(2026, 1, 1, 12), '2026-01-01T12:00:00 host [UFW BLOCK]'),
    ]
    monkeypatch.setattr(basis, 'ufw_timestamp_schema', lambda _: ('datetime', 6, 'YES', None))
    return connection, cursor


def test_mixed_history_summary_only_reads(monkeypatch):
    connection, cursor = fake_history(monkeypatch)
    result = basis.classify_history(connection)
    assert result == {basis.UTC_VERIFIED: 1, basis.LOCAL_TIME_VERIFIED: 1,
                      basis.UNVERIFIED: 1, 'last_id': 3, 'complete': True}
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT')
        assert 'MAX_EXECUTION_TIME(1000)' in call.args[0]
    connection.commit.assert_not_called()
    connection.rollback.assert_not_called()


def test_row_limit_returns_continuation_without_marking_complete(monkeypatch):
    connection, cursor = fake_history(monkeypatch)
    cursor.fetchall.return_value = cursor.fetchall.return_value[:1]
    result = basis.classify_history(connection, max_rows=1)
    assert result['last_id'] == 1
    assert result['complete'] is False
    assert cursor.execute.call_args.args[1] == (0, 3, 1)


def test_time_limit_returns_partial_result(monkeypatch):
    connection, _cursor = fake_history(monkeypatch)
    clock = iter([0, 0, 0, 21])
    monkeypatch.setattr(basis.time, 'monotonic', lambda: next(clock))
    result = basis.classify_history(connection)
    assert result['last_id'] == 1
    assert result['complete'] is False
    assert result[basis.LOCAL_TIME_VERIFIED] == 0


@pytest.mark.parametrize('options', [{'max_rows': 0}, {'max_rows': True}, {'max_rows': 100001},
                                   {'max_seconds': 0}, {'max_seconds': 121},
                                   {'after_id': -1}, {'after_id': True}])
def test_invalid_limits_fail_before_database_access(options):
    connection = MagicMock()
    with pytest.raises(ValueError):
        basis.classify_history(connection, **options)
    connection.cursor.assert_not_called()


def test_history_classification_mysql_is_read_only(empty_mysql):
    connection = empty_mysql
    with connection.cursor() as cursor:
        cursor.execute('CREATE TABLE ufw_log (id BIGINT PRIMARY KEY, event_time DATETIME, raw_line TEXT)')
        cursor.execute('CREATE TABLE ufw_state (id INT PRIMARY KEY, last_position BIGINT)')
        cursor.execute('INSERT INTO ufw_state VALUES (1,12345)')
        rows = [
            (1, datetime(2026, 1, 1, 12), '2026-01-01T14:00:00.123456+02:00 host [UFW BLOCK]'),
            (2, datetime(2026, 1, 1, 14), '2026-01-01T14:00:00.123456+02:00 host [UFW BLOCK]'),
            (3, datetime(2026, 1, 1, 12), '2026-01-01T12:00:00 host [UFW BLOCK]'),
        ]
        cursor.executemany('INSERT INTO ufw_log VALUES (%s,%s,%s)', rows)
    connection.commit()
    before = {}
    with connection.cursor() as cursor:
        for table in ('ufw_log', 'ufw_state'):
            cursor.execute('SELECT * FROM ' + table + ' ORDER BY id')
            before[table] = cursor.fetchall()
        cursor.execute('START TRANSACTION READ ONLY')
    first = basis.classify_history(connection, max_rows=1)
    second = basis.classify_history(connection, after_id=first['last_id'])
    assert first[basis.UTC_VERIFIED] == 1
    assert first['complete'] is False
    assert second[basis.LOCAL_TIME_VERIFIED] == 1
    assert second[basis.UNVERIFIED] == 1
    assert second['complete'] is True
    with connection.cursor() as cursor:
        for table in ('ufw_log', 'ufw_state'):
            cursor.execute('SELECT * FROM ' + table + ' ORDER BY id')
            assert cursor.fetchall() == before[table]
    connection.rollback()


def test_empty_history_is_complete(monkeypatch):
    connection, cursor = fake_history(monkeypatch)
    cursor.fetchone.return_value = (0,)
    result = basis.classify_history(connection)
    assert result['complete'] is True
    assert result['last_id'] == 0
    cursor.fetchall.assert_not_called()


def test_reader_uses_small_batches(monkeypatch):
    connection, cursor = fake_history(monkeypatch)
    cursor.fetchone.return_value = (300,)
    first = []
    second = []
    for event_id in range(1, 301):
        row = (event_id, datetime(2026, 1, 1, 12), '2026-01-01T12:00:00Z host [UFW BLOCK]')
        if event_id <= 256:
            first.append(row)
        else:
            second.append(row)
    cursor.fetchall.side_effect = [first, second]
    result = basis.classify_history(connection)
    assert result[basis.UTC_VERIFIED] == 300
    assert result['complete'] is True
    assert cursor.fetchall.call_count == 2
    assert cursor.execute.call_args.args[1] == (256, 300, 256)
