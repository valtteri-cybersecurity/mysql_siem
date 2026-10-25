"""Use the installer's actual grants on a private socket-only MySQL server."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pymysql
import pytest

from database import migrate
from database.identity import approve_collector_source, register_collector, register_host, register_source
from ingestion.audit import get as audit_get
from ingestion.audit import main as audit_main
from metrics.processes import main as processes_main
from metrics.services import main as services_main


@pytest.fixture(scope='module')
def runtime_database(identity_server):
    name = 'runtime_test_' + uuid4().hex
    user = 'runtime_' + uuid4().hex[:16]
    password = uuid4().hex
    options = {'unix_socket': identity_server, 'charset': 'utf8mb4', 'autocommit': False,
               'read_timeout': 30, 'write_timeout': 30, 'init_command': "SET time_zone = '+00:00'"}
    admin = pymysql.connect(user='root', **options)
    runtime = None
    try:
        with admin.cursor() as cursor:
            cursor.execute(f'CREATE DATABASE `{name}` CHARACTER SET utf8mb4')
            cursor.execute('CREATE USER %s@localhost IDENTIFIED BY %s', (user, password))
        admin.select_db(name)
        migrate.migrate(admin)
        installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
        block = installer.split('# Grant privileges only after the tables have been created.', 1)[1]
        block = block.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        grant_connection = pymysql.connect(user='root', **options)
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv('DB_NAME', name)
            patch.setenv('DB_USER', user)
            patch.setattr(pymysql, 'connect', Mock(return_value=grant_connection))
            exec(compile(block, 'installer-runtime-grants', 'exec'), {})
        runtime = pymysql.connect(user=user, password=password, database=name, **options)
        yield admin, runtime
    finally:
        if runtime is not None:
            runtime.close()
        admin.rollback()
        with admin.cursor() as cursor:
            cursor.execute('DROP USER IF EXISTS %s@localhost', (user,))
            cursor.execute(f'DROP DATABASE IF EXISTS `{name}`')
        admin.close()


def test_three_collectors_work_with_installer_grants_and_history_stays_protected(runtime_database, monkeypatch, tmp_path):
    admin, runtime = runtime_database
    with runtime.cursor() as cursor:
        cursor.execute('SELECT CURRENT_USER()')
        assert cursor.fetchone()[0].startswith('runtime_')
    for kind in ('processes', 'services', 'audit'):
        with admin.cursor() as cursor:
            host = register_host(cursor, 'runtime-' + kind)
            cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
            collector = register_collector(cursor, 'runtime-' + kind, enabled=True)
            source = register_source(cursor, host, 'runtime', kind, enabled=True)
            approve_collector_source(cursor, collector, source)
        admin.commit()
        monkeypatch.setenv('SIEM_COLLECTOR_ID', str(collector))
        monkeypatch.setenv('SIEM_' + kind.upper() + '_SOURCE_ID', str(source))
        if kind == 'processes':
            state = {'process_name': 'worker', 'username': 'synthetic', 'status': 'running',
                     'executable_path': '/synthetic', 'cpu_percent': 75.5}
            observation = {'12:1000.000000': state}
            monkeypatch.setattr(processes_main, 'get_processes', Mock(return_value=observation))
            assert processes_main.collect_processes(runtime) == 0
            state['process_name'] = 'changed'
            assert processes_main.collect_processes(runtime) == 1
            assert processes_main.collect_processes(runtime) == 0
        elif kind == 'services':
            state = {'description': 'Synthetic', 'load_state': 'loaded', 'active_state': 'inactive',
                     'sub_state': 'dead', 'unit_file_state': 'disabled'}
            observation = {'synthetic.service': state}
            monkeypatch.setattr(services_main, 'get_services', Mock(return_value=observation))
            assert services_main.collect_services(runtime) == 0
            state['active_state'] = 'active'
            assert services_main.collect_services(runtime) == 1
            assert services_main.collect_services(runtime) == 0
        else:
            logfile = tmp_path / 'audit.log'
            text = ('type=SYSCALL msg=audit(1792886390.123:12): arch=c000003e syscall=257 '
                    'success=yes exit=3 a0=ffffff9c a2=241 items=1 pid=20 uid=0 '
                    'comm="editor" exe="/synthetic" key="siem_passwd"\n'
                    'type=PATH msg=audit(1792886390.123:12): item=0 name="/etc/passwd" '
                    'inode=200 dev=08:01 nametype=NORMAL\n')
            logfile.write_text(text)
            logfile.chmod(0o600)
            monkeypatch.setattr(audit_get, 'LOG_OWNER', os.getuid())
            monkeypatch.setattr(audit_main, 'runtime_health', Mock(return_value={'boot_id': str(uuid4())}))
            now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
            assert audit_main.collect_to_mysql(runtime, logfile=logfile, now=now)['inserted'] == 1
            with runtime.cursor() as cursor:
                cursor.execute('SELECT position FROM audit_checkpoints WHERE source_id = %s', (source,))
                checkpoint = json.loads(cursor.fetchone()[0])
                checkpoint['offset'] = 0
                import hashlib
                checkpoint['fingerprint'] = hashlib.sha256(b'').hexdigest()
                cursor.execute('UPDATE audit_checkpoints SET position = %s WHERE source_id = %s',
                               (json.dumps(checkpoint), source))
            runtime.commit()
            result = audit_main.collect_to_mysql(runtime, logfile=logfile, now=now)
            assert result['inserted'] == 0 and result['duplicates'] == 1
    statements = ['CREATE TABLE forbidden_runtime_ddl (id INT)',
                  "INSERT INTO hosts (administrative_name) VALUES ('forbidden')",
                  'UPDATE hosts SET administrative_name = administrative_name',
                  'UPDATE audit_targets SET enabled = 0']
    for table in ('process_events', 'service_events', 'audit_events'):
        statements.append(f'UPDATE {table} SET id = id')
        statements.append(f'DELETE FROM {table}')
    for table in ('log_sources', 'collectors', 'collector_sources', 'sender_identities', 'sender_sources', 'schema_migrations'):
        statements.append(f'DELETE FROM {table}')
    for statement in statements:
        with pytest.raises(pymysql.MySQLError) as error:
            with runtime.cursor() as cursor:
                cursor.execute(statement)
        assert error.value.args[0] in (1044, 1142, 1143, 1227)
        runtime.rollback()
