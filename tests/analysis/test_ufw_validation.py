"""Validation never rewrites hash input or turns explicit bad fields into sentinels."""
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_validation import InvalidUFW, convert_port, validate_event

LINE = '2026-10-25T13:35:58.256386+02:00 host kernel: [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=443'


@pytest.mark.parametrize('action', ['BLOCK', 'ALLOW', 'AUDIT'])
@pytest.mark.parametrize('proto', ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'IGMP', '132'])
def test_valid_actions_protocols_and_ipv6(action, proto):
    line = LINE.replace('BLOCK', action).replace('PROTO=TCP', 'PROTO=' + proto).replace('192.0.2.1', '2001:db8::1')
    event = validate_event(line)
    assert event['event_time'] == datetime(2026, 10, 25, 11, 35, 58, 256386)
    assert event['src_ip'] == '2001:db8::1'
    assert event['src_port'] == 0
    assert event['dst_port'] == 443
    assert event['action'] == action


@pytest.mark.parametrize('value', ['', '0', '-1', '65536', 'x', '1.5'])
def test_invalid_ports_are_not_zero(value):
    with pytest.raises(InvalidUFW):
        convert_port(value)


@pytest.mark.parametrize('old,new', [('192.0.2.1', 'bad'), ('SRC=192.0.2.1', ''),
                                    ('+02:00', ''), ('+02:00', '-00:00'),
                                    ('DPT=443', 'DPT=443 DPT=22'), ('BLOCK', 'UNKNOWN')])
def test_invalid_event_fields(old, new):
    with pytest.raises(InvalidUFW):
        validate_event(LINE.replace(old, new))


def test_non_ufw_is_not_a_timestamp_failure():
    assert validate_event('ordinary synthetic log message') is None


def test_failed_database_connection_is_nonzero(monkeypatch):
    monkeypatch.setattr(ufw, 'get_connection', lambda: None)
    assert ufw.main([]) == 1


def test_database_error_is_nonzero_and_safe(monkeypatch, capsys):
    import pymysql
    connection = MagicMock()
    monkeypatch.setattr(ufw, 'get_connection', lambda: connection)
    connection.cursor.side_effect = pymysql.OperationalError(1234, 'secret-payload')
    assert ufw.main([]) == 1
    assert 'secret-payload' not in capsys.readouterr().out


def test_quarantine_rejects_oversized_bytes_before_any_sql():
    from ingestion.ufw_records import quarantine
    cursor = MagicMock()
    with pytest.raises(RuntimeError, match='QUARANTINE_LINE_LIMIT'):
        quarantine(cursor, b'x' * (ufw.MAX_LINE_BYTES + 1), 'INVALID', 'synthetic.log', 0, 1, 2, None, None)
    cursor.execute.assert_not_called()
