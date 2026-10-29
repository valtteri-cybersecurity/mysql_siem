"""Published 022 compatibility and protected 40+6 analysis history."""
from datetime import datetime, timedelta

import pytest

from analysis.ufw import traffic
from config import installation_backup as backup
from config import installation_health as health
from config import reset_installation as reset
from database import migrate, ufw_analysis_history
from database.schema import prepare_schema


@pytest.mark.parametrize('published_022', [False, True])
def test_preserve_40_hourly_6_daily_and_refuse_overwrite(empty_mysql, monkeypatch, tmp_path, published_022):
    connection = empty_mysql
    cutoff = '023'
    if not published_022:
        cutoff = '022'
    versions = []
    for item in migrate.MIGRATIONS:
        if item[0] < cutoff:
            versions.append(item)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(versions))
        migrate.migrate(connection)
    with connection.cursor() as cursor:
        start = datetime(2026, 1, 1)
        for index in range(40):
            begin = start + timedelta(hours=index)
            cursor.execute('INSERT INTO analysis_ufw_traffic '
                           '(period_start,period_end,' + ','.join(traffic.METRICS) + ',period_status) VALUES '
                           '(%s,%s,0,0,0,0,0,0,0,0,0,0,\'CLOSED\')', (begin, begin + timedelta(hours=1)))
        for index in range(6):
            cursor.execute('INSERT INTO analysis_ufw_traffic_daily '
                           '(analysis_date,' + ','.join(traffic.METRICS) + ',period_status) VALUES '
                           '(%s,0,0,0,0,0,0,0,0,0,0,\'CLOSED\')', ((start + timedelta(days=index)).date(),))
    connection.commit()
    original = backup.snapshot_rows(connection, tmp_path)
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts,checksum FROM schema_migrations WHERE version='017'")
        original_017 = cursor.fetchone()
        cursor.execute("SELECT row_counts,checksum FROM schema_migrations WHERE version='022'")
        original_022 = cursor.fetchone()
    reset.check_ufw_before_upgrade(connection)
    migrate.migrate(connection)
    health.verify_schema(connection)
    prepare_schema(connection, "analysis")
    backup.verify_rows(connection, tmp_path, original)
    for table, count in [('analysis_ufw_traffic', 40), ('analysis_ufw_traffic_daily', 6)]:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM ' + table + " WHERE time_basis='HISTORICAL'")
            assert cursor.fetchone() == (count,)
    from database.ufw_analysis_history import snapshot as history_snapshot
    preserved = {}
    for table in ('analysis_ufw_traffic', 'analysis_ufw_traffic_daily'):
        preserved[table] = history_snapshot(connection, table)
    traffic.save_traffic(connection, start, start + timedelta(hours=1), daily=False, now=start)
    traffic.save_traffic(connection, start, start + timedelta(days=1), daily=True, now=start)
    for table, original_history in preserved.items():
        assert history_snapshot(connection, table) == original_history
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM ' + table + " WHERE time_basis='UTC_VERIFIED'")
            assert cursor.fetchone() == (1,)
    future = datetime(2026, 1, 10)
    with connection.cursor() as cursor:
        for event_id, tag in [(1, 'UTC_VERIFIED'), (2, 'UNVERIFIED')]:
            cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash,time_basis) VALUES (%s,%s,%s,%s)",
                           (future, '2026-01-10T00:00:00Z host [UFW BLOCK]', str(event_id).zfill(64), tag))
    connection.commit()
    assert traffic.analyze_traffic(connection, future, future + timedelta(hours=1))['total_events'] == 1
    traffic.save_traffic(connection, future, future + timedelta(hours=1), daily=False, now=future)
    connection.commit()
    assert migrate.migrate(connection) == []
    health.verify_schema(connection)
    backup.verify_rows(connection, tmp_path, original)
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts,checksum FROM schema_migrations WHERE version='017'")
        assert cursor.fetchone() == original_017
        if original_022 is not None:
            cursor.execute("SELECT row_counts,checksum FROM schema_migrations WHERE version='022'")
            assert cursor.fetchone() == original_022
    with connection.cursor() as cursor:
        cursor.execute("UPDATE analysis_ufw_traffic SET coverage_status='CONFLICT' WHERE time_basis='HISTORICAL' LIMIT 1")
    connection.commit()
    with pytest.raises(reset.ResetError, match='Protected analysis history changed'):
        reset.check_ufw_before_upgrade(connection)


def test_interrupted_023_resumes(empty_mysql, monkeypatch):
    connection = empty_mysql
    with monkeypatch.context() as old:
        versions = []
        for item in migrate.MIGRATIONS:
            if item[0] < '023':
                versions.append(item)
        old.setattr(migrate, 'MIGRATIONS', tuple(versions))
        migrate.migrate(connection)
    original = ufw_analysis_history.verify
    calls = [0]
    def interrupt(connection, baseline, **options):
        original(connection, baseline, **options)
        calls[0] += 1
        if calls[0] == 2:
            raise RuntimeError('synthetic interruption after column DDL')
    monkeypatch.setattr(ufw_analysis_history, 'verify', interrupt)
    with pytest.raises(RuntimeError, match='synthetic'):
        migrate.migrate(connection)
    monkeypatch.setattr(ufw_analysis_history, 'verify', original)
    migrate.migrate(connection)
    health.verify_schema(connection)
