"""Exact rule boundaries, fail-closed configuration and bounded strict SQL batches."""
import json
from unittest.mock import MagicMock

import pymysql
import pytest

from database.identity import EventIdentity
from ingestion import ufw_filters as filters
from ingestion import ufw_records
from ingestion.ufw_batch import EventBatch
from ingestion.ufw_validation import validate_event

LINE = ('2026-10-29T12:00:00Z host [UFW AUDIT] IN=lo OUT= '
        'SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=12345 DPT=3306\n')


@pytest.mark.parametrize('interfaces,expected', [
    ('IN=lo OUT=', 'MATCH'), ('IN= OUT=lo', 'MATCH'), ('IN=lo OUT=lo', 'MATCH'),
    ('IN=lo', 'AMBIGUOUS_INTERFACE'), ('OUT=lo', 'AMBIGUOUS_INTERFACE'),
    ('', 'AMBIGUOUS_INTERFACE'), ('IN= OUT=', 'AMBIGUOUS_INTERFACE'),
    ('IN=lo OUT=eth0', 'AMBIGUOUS_INTERFACE'), ('IN=eth0 OUT=lo', 'AMBIGUOUS_INTERFACE'),
    ('IN=lo OUT=lo0', 'AMBIGUOUS_INTERFACE'), ('IN=lo IN=lo OUT=', 'AMBIGUOUS_INTERFACE'),
    ('IN=lo OUT= OUT=lo', 'AMBIGUOUS_INTERFACE'), ('IN =lo OUT=', 'AMBIGUOUS_INTERFACE'),
    ('NOTIN=lo NOTOUT=lo', 'AMBIGUOUS_INTERFACE'),
])
def test_exact_interface_fields(interfaces, expected):
    line = LINE.replace('IN=lo OUT=', interfaces)
    assert filters.match(line, validate_event(line)) == expected


@pytest.mark.parametrize('old,new', [
    ('AUDIT', 'BLOCK'), ('AUDIT', 'ALLOW'), ('PROTO=TCP', 'PROTO=UDP'),
    ('SRC=127.0.0.1', 'SRC=192.0.2.1'), ('SRC=127.0.0.1', 'SRC=10.0.0.1'),
    ('DST=127.0.0.1', 'DST=10.0.0.2'), ('DPT=3306', 'DPT=53'),
    ('DPT=3306', 'DPT=445'), ('DPT=3306', 'DPT=5353'),
    ('127.0.0.1', '::1'), ('127.0.0.1', '127.0.0.2'), ('PROTO=TCP', 'PROTO=ICMP'),
])
def test_other_security_events_are_never_filtered(old, new):
    line = LINE.replace(old, new)
    assert filters.match(line, validate_event(line)) == 'NO_MATCH'


def batch_cursor():
    cursor = MagicMock()
    cursor.connection._siem_identity_ready = True
    cursor.fetchall.return_value = []
    return cursor


@pytest.mark.parametrize('enabled,normal,filtered', [(None, 1, 0), (False, 1, 0), (True, 0, 1)])
def test_default_retains_events_and_filtering_requires_explicit_enable(enabled, normal, filtered):
    cursor = batch_cursor()
    stats = {}
    writer = EventBatch(cursor, EventIdentity(1, 2, 3), enabled, stats)
    writer.add(LINE, validate_event(LINE))
    writer.flush()
    assert writer.inserted == normal
    assert stats['filtered'] == filtered
    queries = []
    for call in cursor.executemany.call_args_list:
        queries.append(call.args[0])
    if filtered:
        assert queries[0].startswith('INSERT INTO ufw_filter_seen')
    else:
        assert queries[0].startswith('INSERT INTO ufw_log')


def test_batch_deduplicates_without_hiding_sql_failures():
    cursor = batch_cursor()
    stats = {}
    writer = EventBatch(cursor, None, None, stats)
    for _ in range(100):
        writer.add(LINE, validate_event(LINE))
    writer.flush()
    assert writer.inserted == 1
    assert stats['duplicates'] == 99
    assert cursor.execute.call_count == 1
    assert len(cursor.executemany.call_args.args[1]) == 1
    cursor.executemany.side_effect = pymysql.OperationalError(2013, 'synthetic failure')
    writer.add(LINE, validate_event(LINE))
    with pytest.raises(pymysql.MySQLError):
        writer.flush()


def test_invalid_line_is_quarantined_before_filtering(monkeypatch):
    quarantine = MagicMock(return_value='quarantined')
    monkeypatch.setattr(ufw_records, 'quarantine', quarantine)
    writer = MagicMock()
    stats = {}
    raw = LINE.replace('DPT=3306', 'DPT=bad').encode()
    ufw_records.process_line(MagicMock(), raw, 'synthetic.log', 0, 1, 2, None, stats, writer=writer)
    writer.add.assert_not_called()
    quarantine.assert_called_once()
    assert stats['quarantined'] == 1


@pytest.mark.parametrize('change', ['host', 'version', 'definition', 'audit', 'multiple'])
def test_invalid_configuration_stops_before_any_writes(change):
    cursor = MagicMock()
    row = [1, filters.RULE_KEY, 1, json.dumps(filters.DEFINITION), 1, 99]
    audit = (99, 1, 1, row[3], 1)
    if change == 'host':
        row[0] = 8
    elif change == 'version':
        row[2] = 2
    elif change == 'definition':
        row[3] = json.dumps({'action': 'BLOCK'})
    elif change == 'audit':
        audit = None
    cursor.fetchall.return_value = [tuple(row)]
    if change == 'multiple':
        cursor.fetchall.return_value = [tuple(row), tuple(row)]
    cursor.fetchone.return_value = audit
    with pytest.raises(ValueError):
        filters.load(cursor, EventIdentity(1, 2, 3))
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')


def test_enable_requires_risk_acknowledgement_before_connecting_or_writing():
    connection = MagicMock()
    with pytest.raises(ValueError, match='Explicit risk'):
        filters.change(connection, 2, 1, True, actor='operator', reason='reviewed')
    connection.cursor.assert_not_called()


def test_preview_uses_select_only_and_same_rule():
    from datetime import datetime, timedelta
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [None, (1, 'ufw'), (2,)]
    cursor.fetchall.side_effect = [[(1, LINE), (2, LINE.replace('IN=lo OUT=', 'IN=eth0 OUT=lo'))]]
    start = datetime(2026, 10, 29)
    result = filters.preview(connection, 2, 1, start, start + timedelta(days=1))
    assert result['complete']
    assert result['matching'] == 1
    assert result['ambiguous_interfaces'] == 1
    assert result['percentage'] == 50
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')
    connection.commit.assert_not_called()


def test_batch_memory_is_bounded(monkeypatch):
    cursor = batch_cursor()
    writer = EventBatch(cursor, None, None, {})
    monkeypatch.setattr('ingestion.ufw_batch.MAX_BYTES', len(LINE.encode()) * 2)
    for index in range(20):
        line = LINE.replace('12:00:00', '12:00:' + str(index).zfill(2))
        writer.add(line, validate_event(line))
        assert writer.byte_count < len(LINE.encode()) * 2
        assert len(writer.rows) < 2
