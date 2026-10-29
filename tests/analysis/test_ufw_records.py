"""Classification errors are data; storage errors must remain system failures."""
from unittest.mock import MagicMock

import pymysql
import pytest

from ingestion import ufw_records, ufw_to_mysql

GOOD = b'2026-10-25T13:35:58Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=ICMP\n'


def test_closed_archive_partial_last_line_is_preserved(monkeypatch):
    seen = []
    def store(cursor, raw, reason, *args):
        seen.append((raw, reason))
        return 'quarantined'
    monkeypatch.setattr(ufw_records, 'quarantine', store)
    raw = GOOD.rstrip(b'\n')
    stats = {}
    assert ufw_records.process_line(MagicMock(), raw, 'synthetic.gz', 17, 1, 2, None, stats,
                                    archive_sha='a' * 64, partial=True) == 0
    assert seen == [(raw, 'INCOMPLETE_ARCHIVE_LINE')]
    assert stats == {'quarantined': 1}


def test_quarantine_storage_error_does_not_increment_committed_counters(monkeypatch):
    def fail(*args):
        raise pymysql.OperationalError(2013, 'synthetic')
    monkeypatch.setattr(ufw_records, 'quarantine', fail)
    stats = {}
    with pytest.raises(pymysql.OperationalError):
        ufw_records.process_line(MagicMock(), b'\xff[UFW BLOCK]\n', 'synthetic.log', 0, 1, 2, None, stats)
    assert stats == {}


def test_database_failure_for_valid_event_is_not_reclassified_as_bad_data(monkeypatch):
    def fail(*args, **kwargs):
        raise pymysql.OperationalError(2013, 'synthetic')
    quarantine = MagicMock()
    monkeypatch.setattr(ufw_to_mysql, 'save_event', fail)
    monkeypatch.setattr(ufw_records, 'quarantine', quarantine)
    with pytest.raises(pymysql.OperationalError):
        ufw_records.process_line(MagicMock(), GOOD, 'synthetic.log', 0, 1, 2, None, {})
    quarantine.assert_not_called()
