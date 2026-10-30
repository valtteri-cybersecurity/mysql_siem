"""P1 compatibility proofs run only on the private MySQL fixture."""

import hashlib
import json
from datetime import datetime, timedelta
from unittest.mock import Mock

import pymysql
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


@pytest.mark.parametrize('history', ['legacy', 'legacy_port'])
@pytest.mark.parametrize('fault', ['after_ddl', 'during_rows', 'after_default'])
def test_interrupted_isolation_is_resumable_without_duplicate_events(request, monkeypatch, tmp_path, history, fault):
    connection = request.getfixturevalue(history)
    if history == 'legacy_port':
        add_port_backlog(connection, 100, mixed=True, gaps=True)
    before = backup.snapshot_rows(connection, tmp_path)
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
        expected = ((1,), (4,), (9,), (15,))
        if history == 'legacy_port':
            expected += ((25000,),)
            for index in range(100):
                expected += ((25001 + 2 * index,),)
        assert cursor.fetchall() == expected
        cursor.execute('SELECT last_position FROM ufw_state')
        assert cursor.fetchone() == (12345,)
    backup.verify_rows(connection, tmp_path, before)


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


@pytest.mark.parametrize('fault', ['unknown_evidence', 'buffered_port_state', 'unrecorded_analysis_isolation'])
def test_unsafe_history_stops_before_backup_or_ddl_and_preserves_maintenance(legacy, monkeypatch, tmp_path, fault):
    connection = legacy
    alert = add_ssh(connection, 1)
    with connection.cursor() as cursor:
        if fault == 'unknown_evidence':
            cursor.execute("UPDATE alert_evidence SET event_type='UFW' WHERE alert_id=%s", (alert,))
        elif fault == 'buffered_port_state':
            cursor.execute("SELECT id FROM detection_rules WHERE rule_key='PORT_SCAN_001'")
            cursor.execute('INSERT INTO detection_state (rule_id,last_event_id,state_data) VALUES (%s,15,%s)',
                           (cursor.fetchone()[0], json.dumps({'version': 1, 'events': [{}]})))
        else:
            # Valid old analysis is preserved by 023; an unrecorded isolation marker is unsafe.
            cursor.execute("ALTER TABLE analysis_source_ips ADD COLUMN time_basis VARCHAR(24) "
                           "NOT NULL DEFAULT 'HISTORICAL'")
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


@pytest.mark.parametrize('history', ['legacy', 'legacy_port'])
def test_process_exit_keeps_running_ledger_and_can_resume(request, monkeypatch, tmp_path, history):
    connection = request.getfixturevalue(history)
    if history == 'legacy_port':
        add_port_backlog(connection, 100, mixed=True, gaps=True)
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


@pytest.fixture
def legacy_port(legacy):
    """Count-only 017 ledger and the drained legacy checkpoint from the upgrade."""
    connection = legacy
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO ufw_log (id,event_time,raw_line,event_hash) "
                       "VALUES (25000,'2026-01-01 12:00:00','Jan 1 12:00:00 host [UFW BLOCK]',%s)",
                       ('f' * 64,))
        for rule, last_id in (('PORT_SCAN_001', 25000), ('SSH_BRUTE_FORCE_001', 7)):
            cursor.execute("INSERT INTO detection_state (rule_id,last_event_id,state_data,updated_at) "
                           "SELECT id,%s,%s,'2026-10-27 17:17:02.420972' FROM detection_rules WHERE rule_key=%s",
                           (last_id, json.dumps({'version': 1, 'events': []}), rule))
        cursor.execute(migrate.UFW_TIME_MIGRATION.read_text())
    counts = migrate.history_counts(connection)
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO schema_migrations (version,name,checksum,status,row_counts) "
                       "VALUES ('017','ufw_datetime_precision',%s,'APPLIED',%s)",
                       (migrate.checksum(migrate.UFW_TIME_MIGRATION), json.dumps(counts)))
    connection.commit()
    return connection


def test_drained_legacy_port_state_preserved_and_new_utc_scan_detected(legacy_port, tmp_path, monkeypatch):
    from detection.port_scan.runner import run_automatic
    from ingestion import ufw_to_mysql as ufw

    connection = legacy_port
    assert migrate.migration_status(connection)['017'][1] == 'APPLIED'
    assert '022' not in migrate.migration_status(connection)
    before = backup.snapshot_rows(connection, tmp_path)
    connection.commit()
    with connection.cursor() as cursor:
        cursor.execute('START TRANSACTION READ ONLY')
    reset.check_ufw_before_upgrade(connection)
    connection.commit()
    backup.verify_rows(connection, tmp_path, before, exact=True)
    applied = migrate.migrate(connection)
    for version in ('022', '023', '024', '025', '026'):
        assert version in applied
        assert migrate.migration_status(connection)[version][1] == 'APPLIED'
    # Includes the full state JSON, checkpoint, updated_at, SSH state, and all old UFW columns.
    backup.verify_rows(connection, tmp_path, before)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,time_basis FROM ufw_log ORDER BY id')
        assert cursor.fetchall() == ((1, 'UTC_VERIFIED'), (4, 'LOCAL_TIME_VERIFIED'),
                                     (9, 'LOCAL_TIME_VERIFIED'), (15, 'UNVERIFIED'), (25000, 'UNVERIFIED'))
        cursor.execute("SELECT last_event_id,state_data,updated_at FROM detection_state s "
                       "JOIN detection_rules r ON r.id=s.rule_id WHERE r.rule_key='PORT_SCAN_001'")
        last_id, raw, updated_at = cursor.fetchone()
        assert last_id == 25000
        assert json.loads(raw) == {'version': 1, 'events': []}
        assert updated_at == datetime(2026, 10, 27, 17, 17, 2, 420972)
    reset.check_ufw_before_upgrade(connection)
    migrate.check_ufw_utc_readiness(connection)

    path = tmp_path / 'ufw.log'
    with path.open('w') as logfile:
        for port in range(2000, 2010):
            logfile.write('2026-10-30T12:00:00.123456+02:00 host [UFW BLOCK] '
                          'SRC=192.0.2.55 DST=198.51.100.1 PROTO=TCP DPT=' + str(port) + '\n')
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    monkeypatch.delenv('SIEM_UFW_SOURCE_ID', raising=False)
    monkeypatch.delenv('SIEM_LOCAL_IDENTITY_REQUIRED', raising=False)
    assert ufw.process_log(connection)['inserted'] == 10
    new_events = get_new_events(connection, 25000, 100)
    assert len(new_events) == 10
    for event in new_events:
        assert event['id'] > 25000
        assert event['event_time'] == datetime(2026, 10, 30, 10, 0, 0, 123456)
    result = run_automatic(connection, {'batch_size': 100, 'max_buffer_events': 100, 'late_seconds': 600},
                           now=datetime(2026, 10, 30, 10, 1))
    assert result['new_events_fetched'] == result['events_analyzed'] == 10
    assert result['scans_detected'] == result['new_alerts_saved'] == 1
    with connection.cursor() as cursor:
        cursor.execute("SELECT event_id FROM alert_evidence WHERE event_type='UFW' ORDER BY event_id")
        evidence = cursor.fetchall()
        assert len(evidence) == 10
        for row in evidence:
            assert row[0] > 25000
        cursor.execute("SELECT last_event_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "WHERE r.rule_key='PORT_SCAN_001'")
        assert cursor.fetchone() == (new_events[-1]['id'],)
    migrate.check_ufw_utc_readiness(connection)
    assert migrate.migrate(connection) == []
    backup.verify_rows(connection, tmp_path, {'ufw_log': before['ufw_log'], 'ufw_state': before['ufw_state']})


@pytest.mark.parametrize('payload', [
    None, [], 'invalid', {}, {'version': 1}, {'events': []},
    {'version': 2, 'events': []}, {'version': True, 'events': []},
    {'version': 1.5, 'events': []}, {'version': '1', 'events': []},
    {'version': 1, 'events': None}, {'version': 1, 'events': {}},
    {'version': 1, 'events': '[]'},
    {'version': 1, 'events': [{'event': {'id': 4, 'event_time': '2026-01-01 14:00:00',
                                     'action': 'BLOCK', 'src_ip': '192.0.2.1', 'dst_ip': '198.51.100.1',
                                     'protocol': 'TCP', 'dst_port': 22},
                              'observed_at': '2026-01-01 14:00:01'}]},
])
def test_invalid_or_buffered_legacy_port_state_blocks_upgrade(legacy_port, tmp_path, payload):
    connection = legacy_port
    with connection.cursor() as cursor:
        cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "SET s.state_data=%s WHERE r.rule_key='PORT_SCAN_001'", (json.dumps(payload),))
    connection.commit()
    before = backup.snapshot_rows(connection, tmp_path)
    with pytest.raises(reset.ResetError, match='legacy port scan|Legacy port scan'):
        reset.check_ufw_before_upgrade(connection)
    with pytest.raises(migrate.MigrationError, match='legacy port scan|Legacy port scan'):
        migrate.migrate(connection)
    assert migrate.migration_status(connection)['022'][1] == 'FAILED'
    assert ufw_history.active_filter(connection) == ''
    backup.verify_rows(connection, tmp_path, before)


def test_malformed_legacy_port_json_blocks_upgrade(legacy_port):
    connection = legacy_port
    with connection.cursor() as cursor:
        # MySQL JSON rejects malformed syntax on write; emulate a damaged legacy text column.
        cursor.execute('ALTER TABLE detection_state MODIFY state_data LONGTEXT NOT NULL')
        cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "SET s.state_data='{broken' WHERE r.rule_key='PORT_SCAN_001'")
    connection.commit()
    with pytest.raises(reset.ResetError, match='Invalid legacy port scan state'):
        reset.check_ufw_before_upgrade(connection)
    with pytest.raises(migrate.MigrationError, match='Invalid legacy port scan state'):
        migrate.migrate(connection)
    assert ufw_history.active_filter(connection) == ''


@pytest.mark.parametrize('checkpoint', [25001, 2**64 - 1])
def test_conflicting_legacy_port_checkpoint_blocks_upgrade(legacy_port, checkpoint):
    connection = legacy_port
    with connection.cursor() as cursor:
        cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "SET s.last_event_id=%s WHERE r.rule_key='PORT_SCAN_001'", (checkpoint,))
    connection.commit()
    with pytest.raises(reset.ResetError, match='checkpoint exceeds'):
        reset.check_ufw_before_upgrade(connection)
    with pytest.raises(migrate.MigrationError, match='checkpoint exceeds'):
        migrate.migrate(connection)
    assert ufw_history.active_filter(connection) == ''


@pytest.mark.parametrize('fault', ['port_alert', 'port_evidence', 'unknown_evidence', 'orphan_evidence',
                                 'unknown_rule', 'wrong_case_rule'])
def test_uncertain_legacy_port_history_still_blocks_upgrade(legacy_port, tmp_path, fault):
    connection = legacy_port
    if fault in ('port_alert', 'port_evidence', 'unknown_evidence'):
        alert = add_ssh(connection, 1)
        with connection.cursor() as cursor:
            if fault in ('port_alert', 'port_evidence'):
                cursor.execute("UPDATE detection_alerts SET rule_id=(SELECT id FROM detection_rules "
                               "WHERE rule_key='PORT_SCAN_001') WHERE id=%s", (alert,))
            if fault == 'port_alert':
                cursor.execute('DELETE FROM alert_evidence WHERE alert_id=%s', (alert,))
            else:
                cursor.execute("UPDATE alert_evidence SET event_type='UFW',event_id=25000 WHERE alert_id=%s", (alert,))
    elif fault == 'orphan_evidence':
        with connection.cursor() as cursor:
            cursor.execute('SET FOREIGN_KEY_CHECKS=0')
            try:
                cursor.execute("INSERT INTO alert_evidence (alert_id,event_type,event_id) VALUES (999,'UFW',25000)")
            finally:
                cursor.execute('SET FOREIGN_KEY_CHECKS=1')
    else:
        key = 'UNKNOWN'
        if fault == 'wrong_case_rule':
            key = 'port_scan_001'
        with connection.cursor() as cursor:
            cursor.execute("UPDATE detection_rules SET rule_key=%s WHERE rule_key='PORT_SCAN_001'", (key,))
    connection.commit()
    before = backup.snapshot_rows(connection, tmp_path)
    with pytest.raises(reset.ResetError):
        reset.check_ufw_before_upgrade(connection)
    with pytest.raises(migrate.MigrationError):
        migrate.migrate(connection)
    assert ufw_history.active_filter(connection) == ''
    backup.verify_rows(connection, tmp_path, before)


@pytest.mark.parametrize('fault', ['buffer', 'checkpoint', 'new_event', 'port_alert'])
def test_022_rechecks_legacy_port_state_under_migration_lock(legacy_port, monkeypatch, fault):
    connection = legacy_port
    reset.check_ufw_before_upgrade(connection)
    isolate = ufw_history.isolate

    def changed_after_preflight(connection):
        assert migrate.migration_status(connection)['022'][1] == 'RUNNING'
        with connection.cursor() as cursor:
            cursor.execute('SELECT IS_USED_LOCK(%s)=CONNECTION_ID()', (migrate.LOCK_NAME,))
            assert cursor.fetchone() == (1,)
            if fault == 'buffer':
                cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                               "SET s.state_data=%s WHERE r.rule_key='PORT_SCAN_001'",
                               (json.dumps({'version': 1, 'events': [{}]}),))
            elif fault == 'checkpoint':
                cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                               "SET s.last_event_id=24999 WHERE r.rule_key='PORT_SCAN_001'")
            elif fault == 'new_event':
                cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash) "
                               "VALUES ('2026-01-01','Jan 1 00:00:00',%s)", ('e' * 64,))
            else:
                cursor.execute("INSERT INTO detection_alerts (rule_id,title,description,severity,first_seen,last_seen,"
                               "alert_fingerprint,details) SELECT id,'test','test','HIGH','2026-01-01','2026-01-01',"
                               "%s,'{}' FROM detection_rules WHERE rule_key='PORT_SCAN_001'", ('e' * 64,))
        connection.commit()
        isolate(connection)

    monkeypatch.setattr(ufw_history, 'isolate', changed_after_preflight)
    with pytest.raises(migrate.MigrationError):
        migrate.migrate(connection)
    assert migrate.migration_status(connection)['022'][1] == 'FAILED'
    assert ufw_history.active_filter(connection) == ''


def add_port_backlog(connection, count, mixed=False, gaps=False):
    rows = []
    eligible = []
    isolated = []
    start = datetime(2026, 1, 2, 12, 0, 0, 123456)
    for index in range(count):
        event_id = 25001 + index
        if gaps:
            event_id += index
        stored = start + timedelta(seconds=index)
        timestamp = stored.isoformat() + 'Z'
        basis = 'UTC_VERIFIED'
        if mixed and index % 3 == 1:
            timestamp = stored.isoformat() + '+02:00'
            basis = 'LOCAL_TIME_VERIFIED'
        elif mixed and index % 3 == 2:
            stored = stored.replace(microsecond=0)
            basis = 'UNVERIFIED'
        protocol = 'ICMP'
        port = 22
        if basis == 'UTC_VERIFIED':
            eligible.append(event_id)
            if len(eligible) <= 10:
                protocol = 'TCP'
                port = 1999 + len(eligible)
        else:
            isolated.append((event_id, basis))
        raw = timestamp + ' host [UFW BLOCK] UID=' + str(index)
        rows.append((event_id, stored, raw, hashlib.sha256(raw.encode()).hexdigest(), protocol, port))
    with connection.cursor() as cursor:
        cursor.executemany("INSERT INTO ufw_log (id,event_time,raw_line,event_hash,action,src_ip,dst_ip,protocol,dst_port) "
                           "VALUES (%s,%s,%s,%s,'BLOCK','192.0.2.55','198.51.100.1',%s,%s)", rows)
    connection.commit()
    return eligible, isolated


@pytest.mark.parametrize('lag,mixed,gaps,proof', [
    (0, False, False, False), (100, False, False, False),
    (800, True, True, False), (10000, True, False, True),
])
def test_lagging_port_upgrade_and_bounded_utc_replay(legacy_port, tmp_path, lag, mixed, gaps, proof):
    from database.identity import (
        approve_collector_source,
        register_collector,
        register_host,
        register_source,
    )
    from detection.port_scan.runner import run_automatic

    connection = legacy_port
    add_ssh(connection, 7)
    with connection.cursor() as cursor:
        host = register_host(cursor, 'legacy-backlog-host')
        collector = register_collector(cursor, 'legacy-backlog-collector', enabled=True)
        source = register_source(cursor, host, 'legacy-backlog-ufw', 'ufw', enabled=True)
        approve_collector_source(cursor, collector, source)
        cursor.execute('UPDATE ufw_log SET host_id=%s,source_id=%s,collector_id=%s,source_scope=%s WHERE id=1',
                       (host, source, collector, source))
    connection.commit()
    if proof:
        original = ufw_history.raw_baseline(connection)
        original['precision'] = 0
        with connection.cursor() as cursor:
            cursor.execute("UPDATE schema_migrations SET row_counts=JSON_SET(row_counts,%s,CAST(%s AS JSON)) "
                           "WHERE version='017'", ('$.' + ufw_history.KEY, json.dumps(original)))
        connection.commit()
    eligible, isolated = add_port_backlog(connection, lag, mixed, gaps)
    before = backup.snapshot_rows(connection, tmp_path)
    connection.commit()
    with connection.cursor() as cursor:
        cursor.execute('START TRANSACTION READ ONLY')
    reset.check_ufw_before_upgrade(connection)
    connection.commit()
    applied = migrate.migrate(connection)
    assert applied[-6:] == ['022', '023', '024', '025', '026', '027']
    backup.verify_rows(connection, tmp_path, before)
    with connection.cursor() as cursor:
        cursor.execute("SELECT last_event_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "WHERE r.rule_key='PORT_SCAN_001'")
        assert cursor.fetchone() == (25000,)
        for event_id, expected_basis in isolated:
            cursor.execute('SELECT time_basis FROM ufw_log WHERE id=%s', (event_id,))
            assert cursor.fetchone() == (expected_basis,)
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='022'")
        saved = json.loads(cursor.fetchone()[0])
        maximum = 25000
        if lag:
            maximum = 25000 + lag
            if gaps:
                maximum += lag - 1
        assert saved[ufw_history.KEY]['max_id'] == maximum
    migrate.check_ufw_utc_readiness(connection)
    assert migrate.migrate(connection) == []
    backup.verify_rows(connection, tmp_path, before)
    config = {'batch_size': 257, 'max_buffer_events': 10000, 'late_seconds': 600}
    fetched = 0
    rounds = 0
    now = datetime(2026, 1, 3)
    while True:
        result = run_automatic(connection, config, now=now)
        assert result['status'] == 'SUCCESS'
        assert result['new_events_fetched'] <= 257
        fetched += result['new_events_fetched']
        rounds += 1
        if result['new_events_fetched'] == 0:
            break
        assert rounds <= lag + 1
    assert fetched == len(eligible)
    with connection.cursor() as cursor:
        cursor.execute("SELECT last_event_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "WHERE r.rule_key='PORT_SCAN_001'")
        expected_checkpoint = 25000
        if eligible:
            expected_checkpoint = eligible[-1]
        assert cursor.fetchone() == (expected_checkpoint,)
        cursor.execute("SELECT e.event_id,u.time_basis FROM alert_evidence e JOIN ufw_log u ON u.id=e.event_id "
                       "WHERE e.event_type='UFW' ORDER BY e.event_id")
        evidence = cursor.fetchall()
        expected_evidence = []
        for event_id in eligible[:10]:
            expected_evidence.append((event_id, 'UTC_VERIFIED'))
        assert evidence == tuple(expected_evidence)
        cursor.execute("SELECT COUNT(*) FROM detection_alerts a JOIN detection_rules r ON r.id=a.rule_id "
                       "WHERE r.rule_key='PORT_SCAN_001'")
        expected_alerts = 0
        if lag:
            expected_alerts = 1
        assert cursor.fetchone() == (expected_alerts,)
    assert run_automatic(connection, config, now=now)['new_alerts_saved'] == 0
    from ingestion.ufw_to_mysql import save_event
    with connection.cursor() as cursor:
        assert save_event(cursor, '2026-01-03T12:00:00Z host [UFW BLOCK] SRC=192.0.2.200 '
                          'DST=198.51.100.1 PROTO=TCP DPT=443') == 1
        new_id = cursor.lastrowid
        assert new_id > maximum
        cursor.execute('SELECT time_basis FROM ufw_log WHERE id=%s', (new_id,))
        assert cursor.fetchone() == ('UTC_VERIFIED',)
    connection.commit()
    assert run_automatic(connection, config, now=now)['new_events_fetched'] == 1
    backup.verify_rows(connection, tmp_path, {'ufw_log': before['ufw_log'], 'auth_events': before['auth_events'],
                                           'hosts': before['hosts'], 'alert_evidence': before['alert_evidence']})


@pytest.mark.parametrize('committed', [False, True])
def test_backlog_connection_loss_retries_without_losing_or_duplicating_events(legacy_port, monkeypatch, committed):
    from detection.port_scan import runner

    connection = legacy_port
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        schema = cursor.fetchone()[0]
    eligible, _isolated = add_port_backlog(connection, 10)
    migrate.migrate(connection)
    save = runner.save_state
    def disconnect(connection, rule_id, last_id, records):
        save(connection, rule_id, last_id, records)
        if committed:
            connection.commit()
        connection.close()
        raise pymysql.OperationalError(2013, 'synthetic lost connection')
    config = {'batch_size': 100, 'max_buffer_events': 100, 'late_seconds': 600}
    with monkeypatch.context() as injected:
        injected.setattr(runner, 'save_state', disconnect)
        with pytest.raises(pymysql.MySQLError):
            runner.run_automatic(connection, config, now=datetime(2026, 1, 3))
    connection.connect()
    connection.select_db(schema)
    with connection.cursor() as cursor:
        cursor.execute("SELECT last_event_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "WHERE r.rule_key='PORT_SCAN_001'")
        expected = 25000
        if committed:
            expected = eligible[-1]
        assert cursor.fetchone() == (expected,)
        cursor.execute('SELECT COUNT(*) FROM alert_evidence')
        expected_evidence = 0
        if committed:
            expected_evidence = 10
        assert cursor.fetchone() == (expected_evidence,)
    result = runner.run_automatic(connection, config, now=datetime(2026, 1, 3))
    assert result['status'] == 'SUCCESS'
    assert runner.run_automatic(connection, config, now=datetime(2026, 1, 3))['new_alerts_saved'] == 0
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM detection_alerts')
        assert cursor.fetchone() == (1,)
        cursor.execute('SELECT COUNT(*) FROM alert_evidence')
        assert cursor.fetchone() == (10,)


@pytest.mark.parametrize('fault', ['new_event', 'checkpoint', 'buffer'])
def test_mutation_during_isolation_blocks_completion(legacy_port, monkeypatch, fault):
    from database import ufw_time_basis

    connection = legacy_port
    add_port_backlog(connection, 100)
    classify = ufw_time_basis.classify_event_time
    mutated = [False]
    def change_during_rows(raw, stored, precision):
        if not mutated[0]:
            mutated[0] = True
            with connection.cursor() as cursor:
                if fault == 'new_event':
                    cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash) "
                                   "VALUES ('2026-01-01','Jan 1 00:00:00',%s)", ('e' * 64,))
                elif fault == 'checkpoint':
                    cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                                   "SET s.last_event_id=25001 WHERE r.rule_key='PORT_SCAN_001'")
                else:
                    cursor.execute("UPDATE detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                                   "SET s.state_data=%s WHERE r.rule_key='PORT_SCAN_001'",
                                   (json.dumps({'version': 1, 'events': [{}]}),))
            connection.commit()
        return classify(raw, stored, precision)
    isolate = ufw_history.isolate
    def inject(connection):
        with monkeypatch.context() as during:
            during.setattr(ufw_time_basis, 'classify_event_time', change_during_rows)
            isolate(connection)
    monkeypatch.setattr(ufw_history, 'isolate', inject)
    with pytest.raises(migrate.MigrationError, match='changed during isolation|buffer must be empty'):
        migrate.migrate(connection)
    assert mutated[0]
    assert migrate.migration_status(connection)['022'][1] == 'FAILED'


def test_concurrent_insert_during_verification_is_seen_before_completion(legacy_port, monkeypatch):
    connection = legacy_port
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        schema = cursor.fetchone()[0]
    add_port_backlog(connection, 100)
    verify = ufw_history.verify_isolation
    inserted = [False]
    def concurrent_insert(connection, *, saved=None):
        verify(connection, saved=saved)
        if saved is not None and not inserted[0]:
            other = pymysql.connect(unix_socket=connection.unix_socket, user='root', database=schema,
                                    autocommit=True, init_command="SET time_zone='+00:00'")
            try:
                with other.cursor() as cursor:
                    cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash) "
                                   "VALUES ('2026-01-01','Jan 1 00:00:00',%s)", ('d' * 64,))
                inserted[0] = True
            finally:
                other.close()
    monkeypatch.setattr(ufw_history, 'verify_isolation', concurrent_insert)
    with pytest.raises(migrate.MigrationError, match='UFW tail changed during isolation'):
        migrate.migrate(connection)
    assert inserted[0]
    assert migrate.migration_status(connection)['022'][1] == 'FAILED'
