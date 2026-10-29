"""Real MySQL proof of parallel time bases, immutable 023 baselines and resumable DDL."""
import json
from datetime import datetime, timedelta

import pymysql
import pytest

from analysis.ufw import ports, source_ips, traffic
from config import installation_health as health
from config import reset_installation as reset
from database import migrate
from database import ufw_analysis_history as history
from database import ufw_analysis_keys as keys
from database.identity import (
    EventIdentity,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from ingestion.ufw_to_mysql import save_event

START = datetime(2026, 10, 27, 12)
END = START + timedelta(hours=1)


def through(connection, monkeypatch, version):
    versions = []
    for item in migrate.MIGRATIONS:
        if item[0] <= version:
            versions.append(item)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(versions))
        return migrate.migrate(connection)


def seed_history(connection, hosts, start=START):
    end = start + timedelta(hours=1)
    with connection.cursor() as cursor:
        for host in hosts:
            scope = 0
            if host is not None:
                scope = host
            cursor.execute('INSERT INTO analysis_source_ips '
                           '(period_start,period_end,source_ip,total_events,blocked_events,allowed_events,audited_events,'
                           'unique_destination_ports,unique_destination_ips,first_seen,last_seen,tcp_events,udp_events,host_id,host_scope) '
                           "VALUES (%s,%s,'192.0.2.1',7,7,0,0,1,1,%s,%s,7,0,%s,%s)",
                           (start, end, start, start, host, scope))
            cursor.execute('INSERT INTO analysis_ufw_ports '
                           '(period_start,period_end,destination_ip,destination_port,protocol,total_events,blocked_events,'
                           'allowed_events,audited_events,unique_source_ips,first_seen,last_seen,host_id,host_scope) '
                           "VALUES (%s,%s,'198.51.100.1',22,'TCP',7,7,0,0,1,%s,%s,%s,%s)",
                           (start, end, start, start, host, scope))
            values = (7, 7, 0, 0, 0, 7, 0, 1, 1, 1)
            for table in ('analysis_ufw_traffic', 'analysis_ufw_traffic_daily'):
                fields = 'period_start,period_end'
                bounds = (start, end)
                if table.endswith('_daily'):
                    fields = 'analysis_date'
                    bounds = (start.date(),)
                fields += ',' + ','.join(traffic.METRICS) + ',period_status,host_id,host_scope'
                row = bounds + values + ('CLOSED', host, scope)
                if not table.endswith('_daily'):
                    fields += ',first_seen,last_seen'
                    row += (start, start)
                cursor.execute('INSERT INTO ' + table + ' (' + fields + ') VALUES (' + ','.join(['%s'] * len(row)) + ')', row)
    connection.commit()


@pytest.fixture
def old_database(empty_mysql, monkeypatch):
    through(empty_mysql, monkeypatch, '022')
    hosts = [None]
    identities = [None]
    with empty_mysql.cursor() as cursor:
        collector = register_collector(cursor, 'parallel-test', enabled=True)
        for index in range(2):
            host = register_host(cursor, 'parallel-host-' + str(index))
            cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
            source = register_source(cursor, host, 'ufw', 'ufw', enabled=True)
            approve_collector_source(cursor, collector, source)
            hosts.append(host)
            identities.append(EventIdentity(host, source, collector))
    empty_mysql.commit()
    seed_history(empty_mysql, hosts)
    seed_history(empty_mysql, hosts, START - timedelta(days=1))
    through(empty_mysql, monkeypatch, '026')
    seed_history(empty_mysql, hosts, START + timedelta(days=10))
    return empty_mysql, hosts, identities


def add_events(connection, identities, index=0):
    with connection.cursor() as cursor:
        for identity in identities:
            line = (START + timedelta(minutes=index)).isoformat() + 'Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=22 UID=' + str(index)
            save_event(cursor, line, identity=identity)
    connection.commit()


def run_all(connection):
    source_ips.run_source_ip_analysis(connection, START, END)
    ports.run_port_analysis(connection, START, END)
    traffic.run_traffic_analysis(connection, START, END, now=END)


def historical(connection):
    result = {}
    for table in history.TABLES:
        result[table] = history.snapshot(connection, table)
    return result


def all_rows(connection, table):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM `' + table + '` ORDER BY 1,2')
        return cursor.fetchall()


def test_parallel_history_full_preservation_recompute_empty_and_rollback(old_database, tmp_path):
    connection, hosts, identities = old_database
    add_events(connection, identities)
    before = historical(connection)
    baseline_023 = all_rows(connection, 'schema_migrations')
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM detection_rules WHERE rule_key='PORT_SCAN_001'")
        rule = cursor.fetchone()[0]
        cursor.execute("INSERT INTO detection_state (rule_id,last_event_id,state_data) VALUES (%s,3,'{\"version\":1,\"events\":[]}')", (rule,))
        cursor.execute("INSERT INTO ufw_state (logfile,last_position,file_device,file_inode,source_scope) VALUES ('synthetic',12345,1,2,0)")
        cursor.execute('INSERT INTO detection_alerts (rule_id,severity,title,description,first_seen,last_seen,alert_fingerprint,details) '
                       "VALUES (%s,'HIGH','Synthetic preserved alert','Preserve this row',%s,%s,%s,'{}')", (rule, START, START, 'a' * 64))
        alert = cursor.lastrowid
        cursor.execute("INSERT INTO alert_evidence (alert_id,event_type,event_id) VALUES (%s,'UFW',1)", (alert,))
        cursor.execute('INSERT INTO ufw_archives (source_scope,archive_sha,filename,file_device,file_inode,logical_position,status) '
                       "VALUES (0,%s,'/synthetic/archive.gz',7,8,123,'READING')", ('b' * 64,))
        cursor.execute('INSERT INTO ufw_file_checkpoints '
                       '(source_scope,file_device,file_inode,filename,byte_position,prefix_sha,observed_size,observed_sha,status,checked_at) '
                       "VALUES (0,7,8,'/synthetic/ufw.log',123,%s,999,%s,'READING',UTC_TIMESTAMP(6))", ('c' * 64, 'd' * 64))
        cursor.execute('INSERT INTO auth_ingestion_state (collector_id,file_device,file_inode,logfile,last_position,position_hash,source_scope) '
                       "VALUES ('synthetic',1,2,'/synthetic/auth.log',456,%s,0)", ('f' * 64,))
        from ingestion import ufw_filters
        from ingestion.ufw_records import quarantine
        quarantine(cursor, b'invalid synthetic line', 'INVALID_SRC_IP', '/synthetic/ufw.log', 100, 7, 8, None, None)
        ufw_filters.record_counts(cursor, identities[1], [('e' * 64, {'event_time': START})])

        cursor.execute("INSERT INTO ufw_log (event_time,raw_line,event_hash,time_basis) VALUES (%s,'local-time stays isolated',%s,'UNVERIFIED')",
                       (START, 'f' * 64))
    connection.commit()
    ufw_filters.change(connection, identities[1].source_id, hosts[1], False, actor='synthetic', reason='preserve disabled setting')
    protected = {}
    for table in migrate.HISTORY_TABLES:
        if table not in history.TABLES:
            protected[table] = all_rows(connection, table)
    assert migrate.migrate(connection) == ['027']
    assert historical(connection) == before
    for table in history.TABLES:
        assert before[table]['count'] == 6
    run_all(connection)
    run_all(connection)
    expected = {'analysis_source_ips': 3, 'analysis_ufw_ports': 3, 'analysis_ufw_traffic': 3, 'analysis_ufw_traffic_daily': 3}
    for table in history.TABLES:
        current = keys.read_results(connection, table, START, END)
        assert len(current) == expected[table]
        for row in current:
            assert row['total_events'] == 1
            assert row['time_basis'] == 'UTC_VERIFIED'
        assert len(keys.read_results(connection, table, START, END, time_basis='HISTORICAL')) == 3
        for host in hosts[1:]:
            rows = keys.read_results(connection, table, START, END, host_id=host)
            assert len(rows) == 1 and rows[0]['host_id'] == host
    add_events(connection, identities[1:2], index=5)
    current_raw = all_rows(connection, 'ufw_log')
    assert current_raw[:len(protected['ufw_log'])] == protected['ufw_log']
    protected['ufw_log'] = current_raw
    run_all(connection)
    for table in history.TABLES:
        assert len(keys.read_results(connection, table, START, END)) == 3
        assert keys.read_results(connection, table, START, END, host_id=hosts[1])[0]['total_events'] == 2
    # Use a future empty interval with preserved legacy rows, then stale UTC groups from that interval.
    empty_start = START - timedelta(days=1)
    empty_end = empty_start + timedelta(hours=1)
    with connection.cursor() as cursor:
        for table in ('analysis_source_ips', 'analysis_ufw_ports'):
            if table == 'analysis_source_ips':
                fields = 'period_start,period_end,source_ip,total_events,blocked_events,allowed_events,audited_events,unique_destination_ports,unique_destination_ips,first_seen,last_seen,tcp_events,udp_events'
                values = (empty_start, empty_end, '192.0.2.9', 1, 1, 0, 0, 1, 1, empty_start, empty_start, 1, 0)
            else:
                fields = 'period_start,period_end,destination_ip,destination_port,protocol,total_events,blocked_events,allowed_events,audited_events,unique_source_ips,first_seen,last_seen'
                values = (empty_start, empty_end, '198.51.100.9', 22, 'TCP', 1, 1, 0, 0, 1, empty_start, empty_start)
            for basis in ('UTC_VERIFIED',):
                cursor.execute('INSERT INTO ' + table + ' (' + fields + ',time_basis) VALUES (' + ','.join(['%s'] * (len(values) + 1)) + ')', values + (basis,))
    connection.commit()
    empty_history = historical(connection)
    source_ips.run_source_ip_analysis(connection, empty_start, empty_end)
    ports.run_port_analysis(connection, empty_start, empty_end)
    traffic.run_traffic_analysis(connection, empty_start, empty_end, now=END)
    for table in ('analysis_source_ips', 'analysis_ufw_ports'):
        assert not keys.read_results(connection, table, empty_start, empty_end)
        assert len(keys.read_results(connection, table, empty_start, empty_end, time_basis='HISTORICAL')) == 3
    assert historical(connection) == empty_history
    # Transaction failures preserve the previous UTC and HISTORICAL rows in all writers.
    for table, writer in ((history.TABLES[0], source_ips.run_source_ip_analysis),
                          (history.TABLES[1], ports.run_port_analysis),
                          (history.TABLES[2], None), (history.TABLES[3], None)):
        saved = all_rows(connection, table)
        with connection.cursor() as cursor:
            cursor.execute('CREATE TRIGGER reject_analysis BEFORE INSERT ON `' + table + "` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic failure'")
        with pytest.raises(pymysql.MySQLError):
            if writer is not None:
                writer(connection, START, END)
            else:
                traffic.save_traffic(connection, START, END, daily=table.endswith('_daily'), now=END)
        assert all_rows(connection, table) == saved
        with connection.cursor() as cursor:
            cursor.execute('DROP TRIGGER reject_analysis')
    assert historical(connection) == before
    health.verify_schema(connection)
    reset.check_ufw_before_upgrade(connection)
    for table, rows in protected.items():
        assert all_rows(connection, table) == rows
    assert all_rows(connection, 'schema_migrations')[:-1] == baseline_023
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='027'")
        proof = json.loads(cursor.fetchone()[0])[keys.KEY]
    assert proof[history.TABLES[0]]['HISTORICAL']['sha256'] == before[history.TABLES[0]]['sha256']
    report = {}
    for table in history.TABLES:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM `' + table + "` WHERE time_basis='UTC_VERIFIED'")
            utc_count = cursor.fetchone()[0]
        after = history.snapshot(connection, table)
        report[table] = {'historical_before': before[table]['count'], 'historical_after': after['count'],
                         'sha256_before': before[table]['sha256'], 'sha256_after': after['sha256'], 'utc_rows': utc_count}
    print('P12_PRESERVATION=' + json.dumps(report, sort_keys=True), flush=True)



@pytest.mark.parametrize('after', [1, 2])
def test_interrupted_ddl_resumes_with_original_snapshots(old_database, monkeypatch, after):
    connection, _, identities = old_database
    add_events(connection, identities)
    before = historical(connection)
    # Interrupt after a committed per-table ALTER, never roll it back or forge APPLIED.
    original_validate = keys.validate_table
    changed = set()
    def validate(connection, table, parallel):
        original_validate(connection, table, parallel)
        if parallel:
            changed.add(table)
            if len(changed) == after:
                raise RuntimeError('synthetic DDL interruption')
    with monkeypatch.context() as interrupted:
        interrupted.setattr(keys, 'validate_table', validate)
        with pytest.raises(RuntimeError, match='synthetic DDL'):
            migrate.migrate(connection)
    assert historical(connection) == before
    assert migrate.migration_status(connection)['027'][1] == 'FAILED'
    assert migrate.migrate(connection) == ['027']
    assert historical(connection) == before
    assert migrate.migrate(connection) == []
    health.verify_schema(connection)


@pytest.mark.parametrize('fault', ['wrong_unique', 'missing_primary', 'invalid_basis', 'bad_baseline', 'ddl_error'])
def test_invalid_schema_or_proof_stops_without_data_changes(old_database, monkeypatch, fault):
    connection, _, identities = old_database
    add_events(connection, identities)
    before = historical(connection)
    with connection.cursor() as cursor:
        if fault == 'wrong_unique':
            cursor.execute('ALTER TABLE analysis_ufw_ports DROP INDEX uq_ufw_ports_period, ADD UNIQUE KEY uq_ufw_ports_period (id,host_scope)')
        elif fault == 'missing_primary':
            cursor.execute('ALTER TABLE analysis_source_ips DROP PRIMARY KEY')
        elif fault == 'invalid_basis':
            cursor.execute("UPDATE analysis_ufw_ports SET time_basis='UNVERIFIED' LIMIT 1")
        elif fault == 'bad_baseline':
            cursor.execute("UPDATE schema_migrations SET row_counts=JSON_SET(row_counts,'$._analysis_baseline.analysis_source_ips.sha256',%s) WHERE version='023'", ('0' * 64,))
    connection.commit()
    if fault == 'ddl_error':
        def fail(*args):
            raise pymysql.OperationalError(1142, 'synthetic DDL permission error')
        monkeypatch.setattr(keys, 'upgrade', fail)
    with pytest.raises((migrate.MigrationError, ValueError, pymysql.MySQLError)):
        migrate.migrate(connection)
    if fault not in ('invalid_basis', 'missing_primary'):
        assert historical(connection) == before
    if fault == 'missing_primary':
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM analysis_source_ips')
            assert cursor.fetchone() == (6,)
    assert migrate.migration_status(connection).get('027', (None, None))[1] != 'APPLIED'


def test_applied_ledger_cannot_hide_old_key(mysql):
    with mysql.cursor() as cursor:
        cursor.execute('ALTER TABLE analysis_ufw_traffic DROP INDEX uq_traffic_period, ADD UNIQUE KEY uq_traffic_period (period_start,period_end,host_scope)')
    with pytest.raises(migrate.MigrationError, match='old analysis key'):
        migrate.check_migration_history(mysql)
    with pytest.raises(migrate.MigrationError):
        traffic.save_traffic(mysql, START, END, daily=False, now=END)


def test_empty_installation_and_runtime_without_ddl(mysql, identity_server):
    health.verify_schema(mysql)
    for table in history.TABLES:
        assert keys.key_state(mysql, table)
        assert not keys.read_results(mysql, table, START, END)
    with mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        name = cursor.fetchone()[0]
        cursor.execute("CREATE USER 'p12_runtime'@'localhost' IDENTIFIED BY 'private-test'")
        for table in history.TABLES:
            cursor.execute('GRANT SELECT,INSERT,UPDATE,DELETE ON `' + name + '`.`' + table + "` TO 'p12_runtime'@'localhost'")
        for table in ('ufw_log', 'schema_migrations', 'hosts', 'log_sources', 'ufw_filter_seen'):
            cursor.execute('GRANT SELECT ON `' + name + '`.`' + table + "` TO 'p12_runtime'@'localhost'")
    runtime = pymysql.connect(unix_socket=identity_server, user='p12_runtime', password='private-test', database=name,
                              charset='utf8mb4', autocommit=False, init_command="SET time_zone='+00:00'")
    try:
        run_all(runtime)
        assert keys.read_results(runtime, 'analysis_ufw_traffic', START, END)[0]['total_events'] == 0
    finally:
        runtime.close()
        with mysql.cursor() as cursor:
            cursor.execute("DROP USER 'p12_runtime'@'localhost'")
    assert migrate.migrate(mysql) == []


def test_unrecorded_partial_key_is_not_accepted_as_original_history(old_database):
    connection, _, _ = old_database
    before = historical(connection)
    with connection.cursor() as cursor:
        cursor.execute('ALTER TABLE analysis_source_ips DROP PRIMARY KEY, '
                       'ADD PRIMARY KEY (period_start,period_end,source_ip,host_scope,time_basis)')
    with pytest.raises(migrate.MigrationError, match='no original migration snapshot'):
        migrate.migrate(connection)
    assert historical(connection) == before
