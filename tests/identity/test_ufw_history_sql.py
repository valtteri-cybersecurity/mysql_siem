"""Fixed history SQL rejects identifiers and preserves the original digests."""

import hashlib
import json
from datetime import datetime
from decimal import Decimal
from unittest.mock import Mock

import pytest

from database import ufw_history
from database.migrate import MigrationError


@pytest.mark.parametrize('table,fields', [
    ('auth_events', 'id,event_time,raw_line'),
    ('ufw_log; DROP TABLE ufw_log', 'id,event_time,raw_line'),
    ('ufw_log', 'id,(SELECT SLEEP(10)),raw_line'),
    ('ufw_log', 'id,alert_id,event_type,event_id'),
])
def test_unknown_fingerprint_identifiers_fail_before_database_access(table, fields):
    connection = Mock()
    with pytest.raises(MigrationError, match='Unknown history fingerprint'):
        ufw_history.fingerprint(connection, table, fields)
    connection.cursor.assert_not_called()


@pytest.mark.parametrize('table,fields,rows', [
    ('ufw_log', 'id,event_time,raw_line',
     [(1, datetime(2026, 1, 1, 0, 0, 0, 123456), 'first'),
      (9, datetime(2026, 1, 1, 0, 0, 0, 123456), 'last')]),
    ('detection_alerts', 'id,rule_id,UNIX_TIMESTAMP(detected_at)',
     [(1, 7, Decimal('1767225600.123456')), (9, 8, Decimal('1767225600.123456'))]),
    ('alert_evidence', 'id,alert_id,event_type,event_id',
     [(1, 2, 'AUTH', 3), (9, 4, 'UFW', 5)]),
])
def test_fixed_fingerprint_queries_preserve_hashes_and_bounds_mysql(empty_mysql, table, fields, rows):
    connection = empty_mysql
    with connection.cursor() as cursor:
        cursor.execute('CREATE TABLE ufw_log (id BIGINT PRIMARY KEY,event_time DATETIME(6),raw_line TEXT)')
        cursor.execute('CREATE TABLE detection_alerts (id BIGINT PRIMARY KEY,rule_id BIGINT,detected_at TIMESTAMP(6))')
        cursor.execute('CREATE TABLE alert_evidence (id BIGINT PRIMARY KEY,alert_id BIGINT,event_type VARCHAR(32),event_id BIGINT)')
        cursor.execute("INSERT INTO ufw_log VALUES (1,'2026-01-01 00:00:00.123456','first'),"
                       "(9,'2026-01-01 00:00:00.123456','last')")
        cursor.execute("INSERT INTO detection_alerts VALUES (1,7,'2026-01-01 00:00:00.123456'),"
                       "(9,8,'2026-01-01 00:00:00.123456')")
        cursor.execute("INSERT INTO alert_evidence VALUES (1,2,'AUTH',3),(9,4,'UFW',5)")
    connection.commit()
    with connection.cursor() as cursor:
        cursor.execute('START TRANSACTION READ ONLY')
    for upper, expected_rows, maximum in ((None, rows, 9), (1, rows[:1], 1)):
        digest = hashlib.sha256()
        for row in expected_rows:
            digest.update(json.dumps(row, default=str, ensure_ascii=True).encode('ascii') + b'\n')
        assert ufw_history.fingerprint(connection, table, fields, upper) == {
            'count': len(expected_rows), 'max_id': maximum, 'sha256': digest.hexdigest(),
        }
    connection.rollback()
