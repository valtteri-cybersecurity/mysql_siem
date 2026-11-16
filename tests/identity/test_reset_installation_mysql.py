"""Reset only the mysql_siem DB inside conftest's private socket-only server."""

import os
import pwd

import pymysql
import pytest

from config import installation_state as journal
from config import reset_installation as reset
from config import service_installation as service
from config.reset_installation import ResetError, reset_database
from database import local_identity as local
from database.identity import IdentityError, resolve_identity
from database.migrate import LOCK_NAME, migration_status
from ingestion import ufw_to_mysql
from ingestion.auth import collector as auth


def test_private_mysql_fresh_and_repeated_reset_preserve_other_database(identity_server):
    connection = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4', autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT @@skip_networking, @@datadir')
            networking_disabled, directory = cursor.fetchone()
            assert networking_disabled and 'siem-mysql' in directory
            cursor.execute('CREATE DATABASE reset_sentinel')
            cursor.execute('CREATE TABLE reset_sentinel.events (id INT PRIMARY KEY)')
            cursor.execute('INSERT INTO reset_sentinel.events VALUES (7)')
        settings = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_NAME': 'mysql_siem', 'DB_PASSWORD': 'synthetic-private-test'}
        reset_database(connection, settings)
        for _ in range(2):
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO ufw_log (raw_line, event_hash) VALUES ('synthetic pre-reset event', %s)", ('a' * 64,))
            reset_database(connection, settings, approved=True)
            assert all(row[1] == 'APPLIED' for row in migration_status(connection).values())
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) FROM ufw_log')
                assert cursor.fetchone() == (0,)
                cursor.execute('SELECT id FROM reset_sentinel.events')
                assert cursor.fetchone() == (7,)
                cursor.execute('SELECT COUNT(*) FROM dns_client_filters')
                assert cursor.fetchone() == (0,)
                cursor.execute('SELECT COUNT(*) FROM dns_domain_filters')
                assert cursor.fetchone() == (0,)
                cursor.execute('SELECT rule_key FROM detection_rules ORDER BY rule_key')
                assert cursor.fetchall() == (
                    ('FIM_CRITICAL_CHANGE_001',), ('FIM_PERMISSION_RISK_001',),
                    ('PORT_SCAN_001',), ('SSH_BRUTE_FORCE_001',),
                )
        app = pymysql.connect(unix_socket=identity_server, user='pythonuser', password=settings['DB_PASSWORD'])
        app.close()  # The stored runtime secret matches the installed account.
    finally:
        connection.close()


def recover_interrupted_reset(connection, socket, tmp_path, monkeypatch):
    state = tmp_path / 'state'
    source = tmp_path / 'source'
    target = tmp_path / 'mysql_siem'
    stable = tmp_path / 'python'
    user = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(reset, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(journal, 'require_install_lock', lambda: None)
    monkeypatch.setattr(local, 'require_administrator', lambda: None)
    monkeypatch.setattr(local, 'require_stopped_legacy_jobs', lambda *args: None)
    monkeypatch.setattr(ufw_to_mysql, 'get_logfiles', list)
    monkeypatch.setattr(auth, 'get_logfiles', lambda *args, **kwargs: [])
    original_chown = os.chown

    def test_chown(path, uid, gid):
        if uid == 0:
            uid = os.getuid()
        original_chown(path, uid, gid)

    monkeypatch.setattr(service.os, 'chown', test_chown)

    def require_maintenance(path):
        assert journal.read_file(path / 'maintenance', public=True) == journal.MAINTENANCE_TEXT

    monkeypatch.setattr(journal, 'require_maintenance', require_maintenance)
    monkeypatch.setattr(journal, 'STATE_DIR', state)
    monkeypatch.setattr(local, 'STATE_DIR', state)
    monkeypatch.setenv('DB_NAME', 'mysql_siem')
    (source / 'config').mkdir(parents=True)
    (source / 'app.py').write_text('original staging code\n')
    credentials = source / 'config/mysql.env'
    credentials.write_text('DB_PASSWORD=synthetic-private-test\n')
    stage = service.prepare_deployment(source, target, user, None, stable, state, reset=True)
    journal.write_file(state / 'maintenance', journal.MAINTENANCE_TEXT, mode=0o644)
    record = journal.read_deployment(state)
    record.update(database_started=True, database_started_current=True, checkpoint_transition=False)
    journal.save_deployment(state, record)
    receipt_path = state / 'receipt.json'
    save_receipt = local.save_receipt

    def interrupt_after_receipt(path, receipt):
        save_receipt(path, receipt)
        if receipt['phase'] == 'database_ready':
            raise InterruptedError('Synthetic interruption after durable receipt')

    with monkeypatch.context() as interrupted:
        interrupted.setattr(local, 'save_receipt', interrupt_after_receipt)
        with pytest.raises(InterruptedError, match='after durable receipt'):
            local.provision(connection, receipt_path, {}, auth_reader='test', ufw_paths=[], auth_paths=[])
    receipt = local.read_receipt(receipt_path)
    identity = receipt['identity']
    assert receipt['phase'] == 'database_ready' and len(identity) == 9
    assert journal.read_deployment(state)['identity'] == {}
    assert not (stage / 'config/identity.env').exists()
    source_id = identity[local.LOCAL_KEYS['ufw']]
    line = '2026-11-05T12:00:00Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=22'
    with connection.cursor() as cursor:
        binding = resolve_identity(cursor, source_id, identity[local.COLLECTOR_KEY], source_type='ufw')
        assert ufw_to_mysql.save_event(cursor, line, identity=binding) == 1
        cursor.execute('INSERT INTO ufw_state (logfile,last_position,file_device,file_inode,source_scope) '
                       "VALUES ('synthetic.log',123,7,8,%s)", (source_id,))

    (source / 'app.py').write_text('replacement staging code\n')
    resumed = service.prepare_deployment(source, target, user, None, stable, state, reset=True)
    assert (resumed / 'app.py').read_text() == 'replacement staging code\n'
    assert stage.exists()
    queries = []
    real_connect = pymysql.connect

    class RecoveryCursor(pymysql.cursors.Cursor):
        def execute(self, query, args=None):
            queries.append(query)
            return super().execute(query, args)

    def connect_private(**kwargs):
        kwargs['unix_socket'] = socket
        reader = real_connect(**kwargs)
        reader.cursorclass = RecoveryCursor
        return reader

    monkeypatch.setattr(pymysql, 'connect', connect_private)
    for key, invalid in ((local.COLLECTOR_KEY, 999999), (local.LOCAL_KEYS['ufw'], identity[local.LOCAL_KEYS['auth']])):
        save_receipt(receipt_path, dict(receipt, identity=dict(identity, **{key: invalid})))
        with pytest.raises(IdentityError):
            reset.prepared_reset_recovery(resumed)
    save_receipt(receipt_path, dict(receipt, token='6bdae41c-43c2-4679-9238-d6f3e0616233'))
    with pytest.raises(IdentityError, match='enrollment marker'):
        reset.prepared_reset_recovery(resumed)
    save_receipt(receipt_path, receipt)
    saved_receipt = receipt_path.read_bytes()
    for _ in range(2):
        before = (state / 'deployment.json').read_bytes()
        assert reset.prepared_reset_recovery(resumed)
        assert (state / 'deployment.json').read_bytes() == before
        assert local.main(['prepare', '--project', str(resumed), '--installed', str(target), '--user', user]) == 0
        assert journal.read_deployment(state)['identity'] == identity
        assert local.read_settings(resumed / 'config/identity.env') == identity
    assert receipt_path.read_bytes() == saved_receipt
    assert (state / 'maintenance').exists()
    assert queries
    for sql in queries:
        assert sql.startswith(('SELECT ', 'SHOW '))
    with connection.cursor() as cursor:
        for table, expected in (('hosts', 1), ('collectors', 1), ('log_sources', 8), ('collector_sources', 8)):
            cursor.execute(f'SELECT COUNT(*) FROM {table}')
            assert cursor.fetchone() == (expected,)
        cursor.execute('SELECT raw_line, source_id FROM ufw_log')
        assert cursor.fetchall() == ((line, source_id),)
        cursor.execute('SELECT last_position, source_scope FROM ufw_state')
        assert cursor.fetchall() == ((123, source_id),)
        cursor.execute('SELECT id FROM resume_sentinel.events')
        assert cursor.fetchone() == (11,)


def test_private_reset_and_migration_share_lock_and_recovery_preserves_data(identity_server, tmp_path, monkeypatch):
    admin = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4', autocommit=True)
    peer = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4', autocommit=True)
    settings = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_NAME': 'mysql_siem', 'DB_PASSWORD': 'synthetic-private-test'}
    try:
        with admin.cursor() as cursor:
            cursor.execute('SELECT @@skip_networking, @@datadir')
            disabled, directory = cursor.fetchone()
            assert disabled and 'siem-mysql' in directory
            cursor.execute('CREATE DATABASE resume_sentinel')
            cursor.execute('CREATE TABLE resume_sentinel.events (id INT PRIMARY KEY)')
            cursor.execute('INSERT INTO resume_sentinel.events VALUES (11)')
        with peer.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s, 0)', (LOCK_NAME,))
            assert cursor.fetchone() == (1,)
        with pytest.raises(ResetError, match='migration is running'):
            reset_database(admin, settings, approved=True)
        with peer.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (LOCK_NAME,))
        reset_database(admin, settings, approved=True)
        assert all(row[1] == 'APPLIED' for row in migration_status(admin).values())
        with peer.cursor() as cursor:
            cursor.execute('SELECT IS_FREE_LOCK(%s)', (LOCK_NAME,))
            assert cursor.fetchone() == (1,)
        recover_interrupted_reset(admin, identity_server, tmp_path, monkeypatch)
    finally:
        admin.close()
        peer.close()
