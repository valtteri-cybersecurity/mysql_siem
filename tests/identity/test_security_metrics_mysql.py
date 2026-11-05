"""Security metrics isolate mixed UFW time bases on private MySQL only."""

from datetime import datetime, timedelta, timezone

from database.identity import (
    EventIdentity,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from ingestion.ufw_to_mysql import save_event
from metrics.security import get_data


def test_security_metrics_count_only_verified_utc_and_preserve_history(mysql, monkeypatch):
    instant = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
    start = instant.replace(hour=0, tzinfo=None)
    cases = [(None, None)]
    with mysql.cursor() as cursor:
        collector = register_collector(cursor, 'security-utc-test', enabled=True)
        for number in (1, 2):
            host = register_host(cursor, 'security-utc-host-' + str(number))
            cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
            ufw_source = register_source(cursor, host, 'ufw', 'ufw', enabled=True)
            security_source = register_source(cursor, host, 'security', 'security', enabled=True)
            approve_collector_source(cursor, collector, ufw_source)
            approve_collector_source(cursor, collector, security_source)
            cases.append((EventIdentity(host, ufw_source, collector), security_source))
        for identity, _source in cases:
            for number, basis in enumerate(('UTC_VERIFIED', 'LOCAL_TIME_VERIFIED', 'UNVERIFIED')):
                line = ('2026-11-05T12:00:0' + str(number) + 'Z host [UFW BLOCK] '
                        'SRC=192.0.2.' + str(number + 1) + ' DST=198.51.100.1 PROTO=TCP DPT=22')
                assert save_event(cursor, line, identity=identity) == 1
                event_id = cursor.lastrowid
                cursor.execute('UPDATE ufw_log SET time_basis=%s WHERE id=%s', (basis, event_id))
            for timestamp, action in (('2026-11-04T23:59:59.999999Z', 'BLOCK'),
                                      ('2026-11-06T00:00:00Z', 'BLOCK'),
                                      ('2026-11-05T13:00:00Z', 'ALLOW')):
                line = timestamp + ' host [UFW ' + action + '] SRC=192.0.2.9 DST=198.51.100.1 PROTO=TCP DPT=22'
                assert save_event(cursor, line, identity=identity) == 1
        cursor.execute('SELECT * FROM ufw_log ORDER BY id')
        original = cursor.fetchall()
    mysql.commit()
    # Actual read-only transactions reject accidental DML by the metric queries.
    for identity, security_source in cases:
        if identity is None:
            monkeypatch.delenv('SIEM_SECURITY_SOURCE_ID', raising=False)
            monkeypatch.delenv('SIEM_COLLECTOR_ID', raising=False)
            monkeypatch.delenv('SIEM_LOCAL_IDENTITY_REQUIRED', raising=False)
        else:
            monkeypatch.setenv('SIEM_SECURITY_SOURCE_ID', str(security_source))
            monkeypatch.setenv('SIEM_COLLECTOR_ID', str(collector))
        with mysql.cursor() as cursor:
            cursor.execute('SET TRANSACTION READ ONLY')
        mysql.begin()
        try:
            assert get_data.get_blocks_today(mysql, instant) == 1
            assert get_data.get_unique_ips_today(mysql, instant) == 1
            # A UTC day without events remains a genuine zero.
            assert get_data.get_blocks_today(mysql, instant + timedelta(days=2)) == 0
            assert get_data.get_unique_ips_today(mysql, instant + timedelta(days=2)) == 0
        finally:
            mysql.rollback()
    with mysql.cursor() as cursor:
        cursor.execute('SELECT * FROM ufw_log ORDER BY id')
        assert cursor.fetchall() == original
        cursor.execute('SELECT COUNT(*) FROM ufw_log WHERE event_time >= %s AND event_time < %s '
                       "AND action='BLOCK' AND host_id IS NULL", (start, start + timedelta(days=1)))
        assert cursor.fetchone() == (3,)
