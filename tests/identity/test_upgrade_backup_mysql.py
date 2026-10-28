"""Upgrade a real isolated application database after a tested dump restore."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pymysql
import pytest

from config import installation_backup as backup
from config import installation_state as journal
from config import reset_installation as reset
from config import service_installation as service
from database import local_identity, migrate
from database.identity import (
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)


def test_dump_restore_and_additive_upgrade_preserve_identifiers_and_settings(identity_server, tmp_path, monkeypatch):
    connection = pymysql.connect(unix_socket=identity_server, user='root', autocommit=True,
                                 charset='utf8mb4', read_timeout=30, write_timeout=30,
                                 init_command="SET time_zone = '+00:00'")
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT @@datadir, @@skip_networking, @@server_uuid')
            directory, disabled, server = cursor.fetchone()
            assert disabled and 'siem-mysql' in directory
            cursor.execute('CREATE DATABASE mysql_siem CHARACTER SET utf8mb4')
        connection.select_db('mysql_siem')
        # A real pre-021 installation, without modifying any migration source.
        with monkeypatch.context() as before_upgrade:
            before_upgrade.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:-2])
            migrate.migrate(connection)
        with connection.cursor() as cursor:
            cursor.execute("CREATE USER 'pythonuser'@'localhost' IDENTIFIED BY 'synthetic-private-test'")
            cursor.execute("GRANT SELECT, INSERT ON mysql_siem.auth_events TO 'pythonuser'@'localhost'")
            host = register_host(cursor, 'synthetic-host')
            cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
            collector = register_collector(cursor, 'synthetic-collector', enabled=True)
            source = register_source(cursor, host, 'synthetic-auth', 'auth', enabled=True)
            approve_collector_source(cursor, collector, source)
            cursor.execute("INSERT INTO auth_events (id,event_time,hostname,source_ip,username,event_type,service,raw_message,event_hash) "
                           "VALUES (123,'2026-10-28 12:00:00.123456','synthetic','192.0.2.1','alice',"
                           "'SSH_AUTH_FAILURE','sshd','synthetic event',%s)", ('a' * 64,))
            cursor.execute('INSERT INTO auth_ingestion_state '
                           '(collector_id,file_device,file_inode,logfile,last_position,position_hash,source_scope) '
                           'VALUES (%s,1,2,%s,12345,%s,%s)',
                           ('synthetic-reader', '/synthetic/auth.log', 'b' * 64, source))
            cursor.execute("UPDATE detection_rules SET enabled=FALSE WHERE rule_key='SSH_BRUTE_FORCE_001'")
        project = tmp_path / 'stage'
        (project / 'config').mkdir(parents=True)
        version = project / 'config/installed-version'
        version.write_text('a' * 40 + '\n')
        version.chmod(0o640)
        state = tmp_path / 'state'
        state.mkdir()
        identity = {'SIEM_COLLECTOR_ID': collector, 'SIEM_AUTH_SOURCE_ID': source}
        receipt = {'phase': 'ready', 'database': 'mysql_siem', 'server': server,
                   'identity': identity, 'host_id': host}
        monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
        monkeypatch.setattr(backup, 'trusted_directory', lambda path: None)
        monkeypatch.setattr(journal, 'require_stage', Mock(return_value={
            'stage': str(project), 'target': str(tmp_path / 'installed')}))
        monkeypatch.setattr(local_identity, 'read_receipt', lambda path: receipt)
        monkeypatch.setattr(local_identity, 'read_settings', lambda path: identity)
        real_backup = backup.create_verified_backup
        saved = []
        with tempfile.TemporaryDirectory(prefix='siem-verify-') as restore_parent:
            def create(connection, project, **kwargs):
                result = real_backup(connection, project, state=state, backup_root=tmp_path / 'backups',
                                     restore_parent=Path(restore_parent))
                saved.append(result)
                return result

            monkeypatch.setattr(backup, 'create_verified_backup', create)
            settings = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_NAME': 'mysql_siem',
                        'DB_PASSWORD': 'synthetic-private-test'}
            reset.upgrade_database(connection, settings, project=project, state=state)
            folder, manifest = saved[0]
            assert manifest['phase'] == 'VERIFIED'
            assert manifest['tables']['auth_events']['count'] == 1
            assert json.loads(journal.read_file(state / 'upgrade-backup.json'))['folder'] == str(folder)
            assert migrate.migration_status(connection)['021'][1] == 'APPLIED'
            assert migrate.migrate(connection) == []
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,username,auth_method,source_port FROM auth_events')
                assert cursor.fetchone() == (123, 'alice', None, None)
                cursor.execute("SELECT enabled FROM detection_rules WHERE rule_key='SSH_BRUTE_FORCE_001'")
                assert cursor.fetchone() == (0,)
                cursor.execute('SELECT source_scope,last_position FROM auth_ingestion_state')
                assert cursor.fetchone() == (source, 12345)
                cursor.execute('SELECT host_id FROM log_sources WHERE source_id=%s', (source,))
                assert cursor.fetchone() == (host,)
                cursor.execute("INSERT INTO auth_events (event_time,hostname,source_ip,username,event_type,service,raw_message,event_hash) "
                               "VALUES ('2026-10-28 12:00:01','synthetic','192.0.2.2','bob',"
                               "'SSH_LOGIN_SUCCESS','sshd','approved new row',%s)", ('c' * 64,))
            backup.verify_rows(connection, folder, manifest['tables'])
            published = tmp_path / 'installed'
            project.rename(published)
            record = {'phase': 'activated', 'target': str(published), 'stage': str(project)}
            monkeypatch.setattr(journal, 'require_maintenance', Mock())
            backup.verify_final_backup(connection, published, record, state=state, backup_root=tmp_path / 'backups')
            assert json.loads(journal.read_file(state / 'upgrade-backup.json'))['phase'] == 'FINAL_VERIFIED'
            with connection.cursor() as cursor:
                cursor.execute("UPDATE auth_events SET username='synthetic-corruption' WHERE id=123")
            with pytest.raises(backup.BackupError, match='values changed'):
                backup.verify_rows(connection, folder, manifest['tables'])
            assert (folder / 'database.sql').exists()
            with pytest.raises(backup.BackupError, match='values changed'):
                reset.upgrade_database(connection, settings, project=published, state=state)
            assert len(saved) == 1  # The pre-failure baseline was not overwritten.
    finally:
        connection.close()
