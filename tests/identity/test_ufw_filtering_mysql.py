"""Opt-in private MySQL: real config, atomic statistics, replay, analysis and privileges."""
import gzip
import hashlib
import os
import tempfile
from datetime import datetime, timedelta

import pymysql
import pytest

from analysis.ufw.ports import run_port_analysis
from analysis.ufw.source_ips import run_source_ip_analysis
from analysis.ufw.traffic import run_traffic_analysis
from config import installation_backup as backup
from config.reset_installation import RUNTIME_TABLE_PRIVILEGES
from database import migrate
from database.identity import (
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from detection.port_scan.runner import run_automatic
from ingestion import ufw_archives as archives
from ingestion import ufw_filters as filters
from ingestion import ufw_to_mysql as ufw

BASE = ('2026-10-29T12:00:00Z host [UFW AUDIT] IN=lo OUT= SRC=127.0.0.1 '
        'DST=127.0.0.1 PROTO=TCP SPT=12345 DPT=3306')
START = datetime(2026, 10, 29, 12)
END = START + timedelta(hours=1)


def line(index, text=BASE):
    return (text + ' UID=' + str(index) + '\n').encode()


def snapshot(connection, table):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ' + table + ' ORDER BY 1,2')
        return cursor.fetchall()


@pytest.fixture
def collection(mysql, identity_server, tmp_path, monkeypatch):
    with mysql.cursor() as cursor:
        host = register_host(cursor, 'private-filter-host')
        cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
        collector = register_collector(cursor, 'private-filter-collector', enabled=True)
        source = register_source(cursor, host, 'private-ufw', 'ufw', enabled=True)
        approve_collector_source(cursor, collector, source)
        cursor.execute("CREATE USER 'filter_runtime'@'localhost' IDENTIFIED BY 'private-test-password'")
        cursor.execute('SELECT DATABASE()')
        name = cursor.fetchone()[0]
        for table, privileges in RUNTIME_TABLE_PRIVILEGES.items():
            cursor.execute('SELECT 1 FROM information_schema.tables WHERE table_schema=%s AND table_name=%s', (name, table))
            if cursor.fetchone() == (1,):
                cursor.execute('GRANT ' + privileges + ' ON `' + name + '`.`' + table + "` TO 'filter_runtime'@'localhost'")
    mysql.commit()
    runtime = pymysql.connect(unix_socket=identity_server, user='filter_runtime', password='private-test-password',
                              database=name, autocommit=False, charset='utf8mb4',
                              init_command="SET time_zone='+00:00'", read_timeout=30, write_timeout=30)
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'')
    monkeypatch.setenv('SIEM_UFW_SOURCE_ID', str(source))
    monkeypatch.setenv('SIEM_COLLECTOR_ID', str(collector))
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    monkeypatch.setattr(archives, 'CACHE', tmp_path / 'cache')
    archives.cache_directory()
    def prepare(filename, digest):
        record = archives.read_manifest(archives.CACHE / (digest + '.json'))
        if record is None:
            assert archives.worker(filename, archives.CACHE, digest) == 0
        return archives.read_manifest(archives.CACHE / (digest + '.json'))
    monkeypatch.setattr(archives, 'prepare', prepare)
    try:
        yield mysql, runtime, path, host, source
    finally:
        runtime.close()
        with mysql.cursor() as cursor:
            cursor.execute("DROP USER 'filter_runtime'@'localhost'")


def test_filtering_replay_rollback_visibility_and_runtime_privileges(collection, monkeypatch, tmp_path):
    admin, runtime, path, host, source = collection
    path.write_bytes(line(0))
    assert ufw.process_log(runtime)['inserted'] == 1  # no rules: preserve everything
    admin.rollback()
    original = snapshot(admin, 'ufw_log')
    checkpoint = snapshot(admin, 'ufw_file_checkpoints')
    preview = filters.preview(admin, source, host, START, END)
    assert preview['matching'] == 1 and preview['complete']
    assert snapshot(admin, 'ufw_log') == original
    assert snapshot(admin, 'ufw_file_checkpoints') == checkpoint
    assert not snapshot(admin, 'ufw_filter_rules')
    admin.rollback()
    filters.change(admin, source, host, True, actor='private-test', reason='reviewed risk', acknowledge_risk=True)
    with pytest.raises(pymysql.MySQLError):
        filters.change(runtime, source, host, False, actor='runtime', reason='must be denied')
    retained = [BASE.replace('AUDIT', 'BLOCK'), BASE.replace('AUDIT', 'ALLOW'),
                BASE.replace('IN=lo OUT=', 'IN=eth0 OUT=lo'), BASE.replace('IN=lo OUT=', 'IN=lo'),
                BASE.replace('127.0.0.1', '::1'), BASE.replace('SRC=127.0.0.1', 'SRC=10.0.0.1'),
                BASE.replace('SRC=127.0.0.1', 'SRC=192.0.2.1'),
                BASE.replace('DPT=3306', 'DPT=53').replace('PROTO=TCP', 'PROTO=UDP'),
                BASE.replace('DPT=3306', 'DPT=445'),
                BASE.replace('DPT=3306', 'DPT=5353').replace('PROTO=TCP', 'PROTO=UDP')]
    raw = bytearray()
    for index, text in enumerate(retained):
        raw.extend(line(index + 1, text))
    excluded = line(100) + line(101, BASE.replace('IN=lo OUT=', 'IN= OUT=lo')) + line(102, BASE.replace('OUT=', 'OUT=lo'))
    malformed = line(103, BASE.replace('DPT=3306', 'DPT=bad'))
    raw.extend(excluded + malformed)
    with path.open('ab') as output:
        output.write(raw)
    result = ufw.process_log(runtime)
    assert result['inserted'] == len(retained)
    assert result['filtered'] == 3
    assert result['quarantined'] == 1
    admin.rollback()
    assert snapshot(admin, 'ufw_log')[0] == original[0]
    assert filters.statistics(admin, source, START, END)[0][2] == 3
    seen = snapshot(admin, 'ufw_filter_seen')
    assert len(seen) == 3
    # New plaintext and gzip identities replay the same events without incrementing exact counters.
    path.with_name('ufw.log.7').write_bytes(path.read_bytes())
    path.with_name('ufw.log.12.gz').write_bytes(gzip.compress(path.read_bytes()))
    replay = ufw.process_log(runtime)
    assert replay['filtered'] == 0
    admin.rollback()
    assert snapshot(admin, 'ufw_filter_seen') == seen
    assert filters.statistics(admin, source, START, END)[0][2] == 3
    before = snapshot(admin, 'ufw_log')
    admin.rollback()
    filters.change(admin, source, host, False, actor='private-test', reason='restore detailed collection')
    path.with_name('ufw.log.29').write_bytes(excluded)
    with path.open('ab') as output:
        output.write(line(104))
    disabled = ufw.process_log(runtime)
    assert disabled['inserted'] == 1 and disabled['filtered'] == 0
    admin.rollback()
    assert snapshot(admin, 'ufw_log')[:len(before)] == before
    assert snapshot(admin, 'ufw_filter_seen') == seen
    # One failing seen INSERT must roll back the preceding ordinary bulk INSERT too.
    admin.rollback()
    filters.change(admin, source, host, True, actor='private-test', reason='test atomic counters', acknowledge_risk=True)
    before_events = snapshot(admin, 'ufw_log')
    before_state = snapshot(admin, 'ufw_file_checkpoints')
    before_stats = snapshot(admin, 'ufw_filter_stats')
    with admin.cursor() as cursor:
        cursor.execute("CREATE TRIGGER reject_seen BEFORE INSERT ON ufw_filter_seen FOR EACH ROW "
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic seen failure'")
    with path.open('ab') as output:
        output.write(line(105, BASE.replace('AUDIT', 'BLOCK')) + line(106))
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(runtime)
    admin.rollback()
    assert snapshot(admin, 'ufw_log') == before_events
    assert snapshot(admin, 'ufw_file_checkpoints') == before_state
    assert snapshot(admin, 'ufw_filter_stats') == before_stats
    with admin.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_seen')
    resumed = ufw.process_log(runtime)
    assert resumed['inserted'] == resumed['filtered'] == 1
    # Ambiguous configuration fails before consuming another byte.
    admin.rollback()
    before_state = snapshot(admin, 'ufw_file_checkpoints')
    with admin.cursor() as cursor:
        cursor.execute('UPDATE ufw_filter_rules SET rule_version=99 WHERE source_id=%s', (source,))
    admin.commit()
    with path.open('ab') as output:
        output.write(line(107))
    with pytest.raises(ValueError, match='DEFINITION_INVALID'):
        ufw.process_log(runtime)
    admin.rollback()
    assert snapshot(admin, 'ufw_file_checkpoints') == before_state
    filters.change(admin, source, host, True, actor='private-test', reason='repair invalid version', acknowledge_risk=True)
    ufw.process_log(runtime)
    # Retained scans still reference the real, unchanged ufw_log IDs.
    with path.open('ab') as output:
        for index in range(20):
            text = BASE.replace('AUDIT', 'BLOCK').replace('SRC=127.0.0.1', 'SRC=192.0.2.55')
            text = text.replace('DPT=3306', 'DPT=' + str(2000 + index))
            output.write(line(200 + index, text))
    ufw.process_log(runtime)
    admin.rollback()
    source_summary = run_source_ip_analysis(admin, START, END)
    port_summary = run_port_analysis(admin, START, END)
    traffic_summary = run_traffic_analysis(admin, START, END, now=END)
    with admin.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM ufw_log')
        stored = cursor.fetchone()[0]
    assert source_summary['total_events'] == port_summary['total_events'] == stored
    for summary in (source_summary, port_summary, traffic_summary):
        assert summary['intentionally_filtered_events'] == 5
        assert summary['input_scope'] == 'STORED_UFW_EVENTS'
    assert traffic_summary['coverage_status'] == 'UNKNOWN'
    detection = run_automatic(admin, {'batch_size': 1000, 'max_buffer_events': 1000, 'late_seconds': 600}, now=END)
    assert detection['scans_detected'] >= 1
    with admin.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM alert_evidence e LEFT JOIN ufw_log u ON u.id=e.event_id "
                       "WHERE e.event_type='ufw_log' AND u.id IS NULL")
        assert cursor.fetchone() == (0,)
        cursor.execute('SELECT COUNT(*) FROM ufw_filter_audit')
        assert cursor.fetchone()[0] == 4
    # The migration ledger and every pre-existing row survive a repeated upgrade check.
    tables = ('ufw_log', 'ufw_filter_rules', 'ufw_filter_audit', 'ufw_filter_seen', 'ufw_filter_stats',
              'ufw_file_checkpoints', 'detection_state', 'alert_evidence')
    old = {}
    for table in tables:
        old[table] = snapshot(admin, table)
    admin.rollback()
    assert migrate.migrate(admin) == []
    for table in tables:
        assert snapshot(admin, table) == old[table]
    with admin.cursor() as cursor:
        cursor.execute('SELECT event_hash FROM ufw_log WHERE id=%s', (original[0][0],))
        assert cursor.fetchone() == (hashlib.sha256(line(0).strip()).hexdigest(),)
    # Use the existing real restore verifier, with populated binary seen keys and audit/statistics rows.
    folder = tmp_path / 'backup'
    folder.mkdir(mode=0o700)
    admin.rollback()
    tables = backup.snapshot_rows(admin, folder)
    with admin.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
    dump = folder / 'database.sql'
    with dump.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        backup.run([backup.binary('mysqldump'), '--no-defaults', '--protocol=socket',
                    '--socket=' + admin.unix_socket, '--user=root', '--single-transaction', '--quick',
                    '--hex-blob', '--set-gtid-purged=OFF', '--no-tablespaces', '--databases', database], stdout=output)
    monkeypatch.setattr(backup, 'DATABASE', database)
    monkeypatch.setattr(backup, 'trusted_directory', lambda path: None)
    with tempfile.TemporaryDirectory(prefix='siem-p4-restore-') as restore:
        from pathlib import Path
        backup.restore_check(dump, tables, restore_parent=Path(restore))
    backup.verify_rows(admin, folder, tables, exact=True)



def test_migration_026_is_additive_and_preserves_025_state(empty_mysql, monkeypatch):
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:-1])
        migrate.migrate(empty_mysql)
    with empty_mysql.cursor() as cursor:
        cursor.execute("INSERT INTO ufw_state (logfile,last_position,file_device,file_inode,source_scope) "
                       "VALUES ('/synthetic/ufw.log',123456,1,2,0)")
    empty_mysql.commit()
    before = snapshot(empty_mysql, 'ufw_state')
    assert migrate.migrate(empty_mysql) == ['026']
    assert snapshot(empty_mysql, 'ufw_state') == before
    assert not snapshot(empty_mysql, 'ufw_filter_rules')
