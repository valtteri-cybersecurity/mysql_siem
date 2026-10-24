"""Reset only the mysql_siem DB inside conftest's private socket-only server."""

import pymysql
import pytest

from config.reset_installation import ResetError, reset_database
from database.migrate import LOCK_NAME, migration_status


def test_private_mysql_fresh_and_repeated_reset_preserve_other_database(identity_server, tmp_path):
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
                assert cursor.fetchall() == (('PORT_SCAN_001',), ('SSH_BRUTE_FORCE_001',))
        from database import local_identity as local
        receipt = tmp_path / 'receipt.json'
        identity = local.provision(connection, receipt, {}, auth_reader='test', ufw_paths=[], auth_paths=[])
        assert len(identity) == 6
        assert local.provision(connection, receipt, identity, auth_reader='test', ufw_paths=[], auth_paths=[]) == identity
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM log_sources')
            assert cursor.fetchone() == (5,)
        app = pymysql.connect(unix_socket=identity_server, user='pythonuser', password=settings['DB_PASSWORD'])
        app.close()  # The stored runtime secret matches the installed account.
    finally:
        connection.close()


def test_private_reset_and_migration_share_and_release_the_same_lock(identity_server):
    admin = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4', autocommit=True)
    peer = pymysql.connect(unix_socket=identity_server, user='root', charset='utf8mb4', autocommit=True)
    settings = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_NAME': 'mysql_siem', 'DB_PASSWORD': 'synthetic-private-test'}
    try:
        with admin.cursor() as cursor:
            cursor.execute('SELECT @@skip_networking, @@datadir')
            disabled, directory = cursor.fetchone()
            assert disabled and 'siem-mysql' in directory
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
    finally:
        admin.close()
        peer.close()
