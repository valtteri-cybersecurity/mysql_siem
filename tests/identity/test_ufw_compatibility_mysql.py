"""P1 compatibility proofs run only on the private MySQL fixture."""

import json
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from analysis.ufw.ports import analyze_ports
from analysis.ufw.source_ips import analyze_source_ips
from analysis.ufw.traffic import analyze_traffic, run_traffic_analysis
from config import installation_backup as backup
from config import reset_installation as reset
from database import migrate, ufw_history
from detection.port_scan.db import get_db_data, get_new_events


@pytest.fixture
def legacy(empty_mysql, monkeypatch):
    with monkeypatch.context() as older:
        older.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:4])
        migrate.migrate(empty_mysql)
    with empty_mysql.cursor() as cursor:
        rows = [
            (1, '2026-01-01 12:00:00', '2026-01-01T14:00:00+02:00'),
            (4, '2026-01-01 14:00:00', '2026-01-01T14:00:00+02:00'),
            (9, '2026-01-01 15:00:00', '2026-01-01T15:00:00+03:00'),
            (15, '2026-01-01 12:00:00', 'Jan 1 12:00:00'),
        ]
        for event_id, stored, raw in rows:
            cursor.execute("INSERT INTO ufw_log (id,event_time,raw_line,event_hash,action,src_ip,dst_ip,protocol,dst_port) "
                           "VALUES (%s,%s,%s,%s,'BLOCK','192.0.2.1','198.51.100.1','TCP',22)",
                           (event_id, stored, raw + ' host kernel: [UFW BLOCK]', str(event_id).zfill(64)))
        cursor.execute("INSERT INTO ufw_state (logfile,last_position,file_device,file_inode) VALUES ('old.log',12345,1,2)")
    empty_mysql.commit()
    return empty_mysql


def add_ssh(connection, number):
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM detection_rules WHERE rule_key='SSH_BRUTE_FORCE_001'")
        rule = cursor.fetchone()[0]
        cursor.execute("INSERT INTO auth_events (id,event_time,hostname,source_ip,event_type,service,raw_message,event_hash) "
                       "VALUES (%s,'2026-01-01 12:00:00','test','192.0.2.1','SSH_AUTH_FAILURE','sshd','test',%s)",
                       (number, str(number).zfill(64)))
        cursor.execute("INSERT INTO detection_alerts (rule_id,title,description,severity,first_seen,last_seen,alert_fingerprint,details) "
                       "VALUES (%s,'test','test','MEDIUM','2026-01-01','2026-01-01',%s,'{}')",
                       (rule, str(number).zfill(64)))
        alert = cursor.lastrowid
        cursor.execute("INSERT INTO alert_evidence (alert_id,event_type,event_id) VALUES (%s,'AUTH',%s)", (alert, number))
        cursor.execute('INSERT INTO detection_state (rule_id,last_event_id,state_data) VALUES (%s,%s,%s) '
                       'ON DUPLICATE KEY UPDATE last_event_id=VALUES(last_event_id),state_data=VALUES(state_data)',
                       (rule, number, json.dumps({'version': 1, 'events': []})))
    connection.commit()
    return alert


def test_mixed_gapped_history_ssh_growth_and_preservation(legacy, tmp_path):
    connection = legacy
    original_alert = add_ssh(connection, 1)
    before = backup.snapshot_rows(connection, tmp_path)
    reset.check_ufw_before_upgrade(connection)
    migrate.migrate(connection)
    backup.verify_rows(connection, tmp_path, before)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,time_basis FROM ufw_log ORDER BY id')
        assert cursor.fetchall() == ((1, 'UTC_VERIFIED'), (4, 'LOCAL_TIME_VERIFIED'),
                                     (9, 'LOCAL_TIME_VERIFIED'), (15, 'UNVERIFIED'))
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='022'")
        assert json.loads(cursor.fetchone()[0])[ufw_history.KEY]['origin'] == 'CURRENT_BASELINE'
        cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash,action,src_ip,dst_ip,protocol,dst_port) "
                       "VALUES ('2026-01-01 12:00:01.123456',%s,%s,'BLOCK','192.0.2.2','198.51.100.2','TCP',23)",
                       ('2026-01-01T12:00:01.123456Z host kernel: [UFW BLOCK]', 'a' * 64))
    connection.commit()
    start = datetime(2026, 1, 1)
    end = start + timedelta(days=1)
    assert analyze_traffic(connection, start, end)['total_events'] == 2
    assert len(analyze_ports(connection, start, end)) == 2
    assert len(analyze_source_ips(connection, start, end)) == 2
    assert len(get_db_data(connection, start, end)) == 2
    assert len(get_new_events(connection, 0, 100)) == 2
    run_traffic_analysis(connection, start.replace(hour=12), start.replace(hour=13))
    add_ssh(connection, 2)
    with connection.cursor() as cursor:
        cursor.execute("UPDATE detection_alerts SET status='ACKNOWLEDGED' WHERE id=%s", (original_alert,))
    connection.commit()
    reset.check_ufw_before_upgrade(connection)
    migrate.check_ufw_utc_readiness(connection)
    assert migrate.migrate(connection) == []
    backup.verify_rows(connection, tmp_path, {'ufw_log': before['ufw_log'], 'ufw_state': before['ufw_state']})


@pytest.mark.parametrize('fault', ['after_ddl', 'during_rows', 'after_default'])
def test_interrupted_isolation_is_resumable_without_duplicate_events(legacy, monkeypatch, fault):
    connection = legacy
    original = ufw_history.isolate
    if fault == 'after_default':
        def interrupted(connection):
            original(connection)
            raise RuntimeError('synthetic interruption')
        monkeypatch.setattr(ufw_history, 'isolate', interrupted)
    else:
        original_filter = ufw_history.active_filter
        if fault == 'after_ddl':
            def stop(connection):
                present = original_filter(connection)
                if not present:
                    with connection.cursor() as cursor:
                        cursor.execute(migrate.ROOT.joinpath('migrations/022_ufw_history_isolation.sql').read_text())
                    raise RuntimeError('synthetic interruption')
                return present
            monkeypatch.setattr(ufw_history, 'active_filter', stop)
        else:
            from database import ufw_time_basis
            original_classify = ufw_time_basis.classify_event_time
            calls = [0]
            def stop(raw, stored, precision):
                calls[0] += 1
                if calls[0] == 3:
                    raise RuntimeError('synthetic interruption')
                return original_classify(raw, stored, precision)
            def interrupted(connection):
                with monkeypatch.context() as injection:
                    injection.setattr(ufw_time_basis, 'classify_event_time', stop)
                    original(connection)
            monkeypatch.setattr(ufw_history, 'isolate', interrupted)
    with pytest.raises(RuntimeError, match='synthetic'):
        migrate.migrate(connection)
    monkeypatch.undo()
    assert migrate.migration_status(connection)['022'][1] == 'FAILED'
    migrate.migrate(connection)
    reset.check_ufw_before_upgrade(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id FROM ufw_log ORDER BY id')
        assert cursor.fetchall() == ((1,), (4,), (9,), (15,))
        cursor.execute('SELECT last_position FROM ufw_state')
        assert cursor.fetchone() == (12345,)


@pytest.mark.parametrize('lost', [False, True, 'masked'])
def test_count_only_017_does_not_invent_original_ids(legacy, lost):
    connection = legacy
    counts = migrate.history_counts(connection)
    with connection.cursor() as cursor:
        cursor.execute(migrate.UFW_TIME_MIGRATION.read_text())
        cursor.execute("INSERT INTO schema_migrations (version,name,checksum,status,row_counts) "
                       "VALUES ('017','ufw_datetime_precision',%s,'APPLIED',%s)",
                       (migrate.checksum(migrate.UFW_TIME_MIGRATION), json.dumps(counts)))
        if lost:
            cursor.execute('DELETE FROM ufw_log WHERE id=4')
            if lost == 'masked':
                cursor.execute("INSERT INTO ufw_log (id,event_time,raw_line,event_hash,created_at) "
                               "VALUES (99,'2026-01-01','2026-01-01T00:00:00Z',%s,DATE_ADD(CURRENT_TIMESTAMP,INTERVAL 1 DAY))",
                               ('b' * 64,))
    connection.commit()
    if lost:
        with pytest.raises(reset.ResetError, match='counts decreased|may have disappeared'):
            reset.check_ufw_before_upgrade(connection)
    else:
        reset.check_ufw_before_upgrade(connection)
        migrate.migrate(connection)
        migrate.check_ufw_utc_readiness(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='017'")
            assert json.loads(cursor.fetchone()[0]) == counts


@pytest.mark.parametrize('fault', ['unknown_evidence', 'old_port_state', 'old_analysis'])
def test_unsafe_history_stops_before_backup_or_ddl_and_preserves_maintenance(legacy, monkeypatch, tmp_path, fault):
    connection = legacy
    alert = add_ssh(connection, 1)
    with connection.cursor() as cursor:
        if fault == 'unknown_evidence':
            cursor.execute("UPDATE alert_evidence SET event_type='UFW' WHERE alert_id=%s", (alert,))
        elif fault == 'old_port_state':
            cursor.execute("SELECT id FROM detection_rules WHERE rule_key='PORT_SCAN_001'")
            cursor.execute('INSERT INTO detection_state (rule_id,last_event_id,state_data) VALUES (%s,15,%s)',
                           (cursor.fetchone()[0], json.dumps({'version': 1, 'events': []})))
        else:
            cursor.execute("INSERT INTO analysis_source_ips (period_start,period_end,source_ip,total_events,"
                           "blocked_events,allowed_events,audited_events,unique_destination_ports,unique_destination_ips,"
                           "first_seen,last_seen,tcp_events,udp_events) VALUES "
                           "('2026-01-01','2026-01-02','192.0.2.1',1,1,0,0,1,1,'2026-01-01','2026-01-01',1,0)")
    connection.commit()
    gate = tmp_path / 'maintenance'
    gate.write_text('test maintenance')
    monkeypatch.setattr(reset, 'validate_settings', lambda settings: None)
    monkeypatch.setattr(reset, 'check_upgrade_database', reset.check_ufw_before_upgrade)
    create = Mock()
    monkeypatch.setattr(backup, 'create_verified_backup', create)
    before = backup.snapshot_rows(connection, tmp_path)
    with pytest.raises(reset.ResetError):
        reset.upgrade_database(connection, {}, project=tmp_path, state=tmp_path)
    create.assert_not_called()
    assert gate.exists()
    backup.verify_rows(connection, tmp_path, before, exact=True)


def test_process_exit_keeps_running_ledger_and_can_resume(legacy, monkeypatch, tmp_path):
    connection = legacy
    before = backup.snapshot_rows(connection, tmp_path)
    original = ufw_history.isolate

    def process_exit(connection):
        original(connection)
        raise SystemExit('synthetic process exit after committed DDL')

    monkeypatch.setattr(ufw_history, 'isolate', process_exit)
    with pytest.raises(SystemExit, match='synthetic process exit'):
        migrate.migrate(connection)
    assert migrate.migration_status(connection)['022'][1] == 'RUNNING'
    monkeypatch.setattr(ufw_history, 'isolate', original)
    migrate.migrate(connection)
    reset.check_ufw_before_upgrade(connection)
    backup.verify_rows(connection, tmp_path, before)
