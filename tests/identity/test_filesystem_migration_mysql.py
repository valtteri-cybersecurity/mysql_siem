"""Filesystem schema tests on the private MySQL instance."""

import hashlib
from datetime import datetime

import pymysql
import pytest

from config import reset_installation
from database import migrate
from database.identity import (
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
    resolve_identity,
)

OBSERVED = datetime(2026, 11, 8, 12, 0, 0, 123456)
PATH = b'/' + (b'a' * 254 + b'/') * 16 + b'\xff' * 14
DIGEST = hashlib.sha256(b'example').hexdigest()
MOUNT = '''INSERT INTO filesystem_mount_metrics
    (host_id, source_id, collector_id, sender_id, measured_at, mount_point,
     filesystem_type, total_bytes, available_bytes, total_inodes, free_inodes, read_only, mount_options)
    VALUES (%s, %s, %s, %s, %s, _binary %s, 'ext4', 100, %s, 10, 3, %s, 'nosuid,nodev')'''
FILE = '''INSERT INTO filesystem_file_state
    (host_id, source_id, file_path, content_sha256, size_bytes, owner_uid, group_gid, mode, observed_at)
    VALUES (%s, %s, _binary %s, UNHEX(%s), 100, 1000, 1000, %s, %s)'''
EVENT = '''INSERT INTO filesystem_file_events
    (host_id, source_id, collector_id, sender_id, file_path, event_type, previous_state, current_state, observed_at)
    VALUES (%s, %s, %s, %s, _binary %s, %s, %s, %s, %s)'''
SCAN = '''INSERT INTO filesystem_scan_state (host_id, source_id, config_sha256, last_successful_scan_at, baseline_complete)
    VALUES (%s, %s, UNHEX(%s), %s, %s)'''


@pytest.fixture
def previous_mysql(empty_mysql, monkeypatch):
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:-2])
        assert migrate.migrate(empty_mysql)[-1] == '033'
    return empty_mysql


def enroll(cursor, name, host=None):
    if host is None:
        host = register_host(cursor, name, reported_hostname='same-hostname')
        cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
    source = register_source(cursor, host, name, 'filesystem', enabled=True)
    collector = register_collector(cursor, name, enabled=True)
    approve_collector_source(cursor, collector, source)
    cursor.execute("INSERT INTO sender_identities (host_id, identity_type, identity_value, enabled) "
                   "VALUES (%s, 'test', %s, TRUE)", (host, name))
    sender = cursor.lastrowid
    cursor.execute('INSERT INTO sender_sources (sender_id, source_id) VALUES (%s, %s)', (sender, source))
    return resolve_identity(cursor, source, collector, source_type='filesystem', sender_id=sender)


def insert_observation(cursor, identity, available):
    scope = (identity.host_id, identity.source_id)
    cursor.execute(MOUNT, identity.values() + (OBSERVED, PATH, available, False))
    cursor.execute(FILE, scope + (PATH, None, 0o640, OBSERVED))
    cursor.execute(EVENT, identity.values() + (PATH, 'CREATED', None, '{"mode":416}', OBSERVED))
    cursor.execute(SCAN, scope + (DIGEST, OBSERVED, True))


def table_rows(connection, table):
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT * FROM `{table}` ORDER BY 1, 2')
        return cursor.fetchall()


def test_upgrade_resume_and_rerun_preserve_rows(previous_mysql, monkeypatch):
    connection = previous_mysql
    with connection.cursor() as cursor:
        identity = enroll(cursor, 'filesystem-upgrade')
        cursor.execute('INSERT INTO filesystem_metrics (metric_date, modified_last_day, total_files) '
                       'VALUES (%s, 3, 17)', (OBSERVED.date(),))
        cursor.execute('INSERT INTO filesystem_metrics '
                       '(metric_date, modified_last_day, total_files, host_id, source_id, collector_id, sender_id, host_scope) '
                       'VALUES (%s, 5, 23, %s, %s, %s, %s, %s)',
                       (OBSERVED.date(),) + identity.values() + (identity.host_id,))
    connection.commit()
    legacy_rows = table_rows(connection, 'filesystem_metrics')

    def interrupt(database, version):
        assert version == '034'
        first_statement = migrate.FILESYSTEM_MIGRATION.read_text().partition(';')[0]
        with database.cursor() as cursor:
            cursor.execute(first_statement)
        raise RuntimeError('synthetic filesystem DDL interruption')

    with monkeypatch.context() as failure:
        failure.setattr(migrate, 'apply_one', interrupt)
        with pytest.raises(RuntimeError, match='synthetic filesystem DDL interruption'):
            migrate.migrate(connection)
    assert migrate.migration_status(connection)['034'][1] == 'FAILED'
    with connection.cursor() as cursor:
        cursor.execute(MOUNT, identity.values() + (OBSERVED, PATH, 75, False))
    connection.commit()
    saved_mounts = table_rows(connection, 'filesystem_mount_metrics')

    assert migrate.migrate(connection) == ['034', '035']
    assert migrate.migration_status(connection)['034'][1] == 'APPLIED'
    assert table_rows(connection, 'filesystem_mount_metrics') == saved_mounts
    with connection.cursor() as cursor:
        insert_observation(cursor, identity, 50)
    connection.commit()
    saved = {}
    for table in migrate.FILESYSTEM_TABLES:
        saved[table] = table_rows(connection, table)
        assert saved[table]

    migrate.apply_one(connection, '034')
    assert migrate.migrate(connection) == []
    for table, rows in saved.items():
        assert table_rows(connection, table) == rows
    assert table_rows(connection, 'filesystem_metrics') == legacy_rows

    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        monkeypatch.setattr(reset_installation, 'DATABASE', cursor.fetchone()[0])
    reset_installation.validate_reset_database(connection)


def test_upgrade_rejects_preexisting_table_without_ledger(previous_mysql):
    with previous_mysql.cursor() as cursor:
        cursor.execute('CREATE TABLE filesystem_scan_state (id INT PRIMARY KEY) ENGINE=InnoDB')
        cursor.execute('INSERT INTO filesystem_scan_state VALUES (42)')
    previous_mysql.commit()
    with pytest.raises(migrate.MigrationError, match='filesystem tables exist without migration history'):
        migrate.migrate(previous_mysql)
    assert '034' not in migrate.migration_status(previous_mysql)
    with previous_mysql.cursor() as cursor:
        cursor.execute('SELECT id FROM filesystem_scan_state')
        assert cursor.fetchall() == ((42,),)


def test_long_binary_paths_and_host_source_isolation(mysql):
    with mysql.cursor() as cursor:
        first = enroll(cursor, 'first')
        second = enroll(cursor, 'second')
        third = enroll(cursor, 'first-secondary', host=first.host_id)
        for identity, available in ((first, 30), (second, 50), (third, 70)):
            insert_observation(cursor, identity, available)
        for table, path_field in (('filesystem_mount_metrics', 'mount_point'),
                                  ('filesystem_file_state', 'file_path'), ('filesystem_file_events', 'file_path')):
            for identity in (first, second, third):
                cursor.execute(f'SELECT `{path_field}`, path_sha256 FROM `{table}` WHERE host_id = %s AND source_id = %s',
                               (identity.host_id, identity.source_id))
                assert cursor.fetchall() == ((PATH, hashlib.sha256(PATH).digest()),)
        cursor.execute('SELECT host_id, source_id, available_bytes, measured_at FROM filesystem_mount_metrics ORDER BY id')
        assert cursor.fetchall() == (
            (first.host_id, first.source_id, 30, OBSERVED),
            (second.host_id, second.source_id, 50, OBSERVED),
            (third.host_id, third.source_id, 70, OBSERVED),
        )
        cursor.execute('SELECT host_id, source_id, last_successful_scan_at FROM filesystem_scan_state ORDER BY source_id')
        assert cursor.fetchall() == (
            (first.host_id, first.source_id, OBSERVED),
            (second.host_id, second.source_id, OBSERVED),
            (third.host_id, third.source_id, OBSERVED),
        )


def rejected(cursor, sql, values, code):
    with pytest.raises(pymysql.MySQLError) as error:
        cursor.execute(sql, values)
    assert error.value.args[0] == code


def test_identity_foreign_keys_and_storage_constraints(mysql):
    with mysql.cursor() as cursor:
        first = enroll(cursor, 'first')
        second = enroll(cursor, 'second')
        third = enroll(cursor, 'first-secondary', host=first.host_id)
        scope = (first.host_id, first.source_id)
        wrong_scope = (second.host_id, first.source_id)
        wrong_host = wrong_scope + (first.collector_id, None)
        wrong_collector = scope + (second.collector_id, None)
        wrong_sender_source = scope + (first.collector_id, third.sender_id)
        cursor.execute('INSERT INTO sender_sources (sender_id, source_id) VALUES (%s, %s)',
                       (second.sender_id, first.source_id))
        wrong_sender_host = scope + (first.collector_id, second.sender_id)
        for identity in (wrong_host, wrong_collector, wrong_sender_source, wrong_sender_host):
            rejected(cursor, MOUNT, identity + (OBSERVED, PATH, 50, False), 1452)
            rejected(cursor, EVENT, identity + (PATH, 'CREATED', None, '{}', OBSERVED), 1452)
        rejected(cursor, FILE, wrong_scope + (PATH, DIGEST, 0o640, OBSERVED), 1452)
        rejected(cursor, SCAN, wrong_scope + (DIGEST, OBSERVED, True), 1452)

        local = scope + (first.collector_id, None)
        cursor.execute(MOUNT, local + (OBSERVED, PATH, 50, False))
        cursor.execute(FILE, scope + (PATH, DIGEST, 0o640, OBSERVED))
        cursor.execute(SCAN, scope + (DIGEST, None, False))
        for kind, before, after in (('CREATED', None, '{}'), ('DELETED', '{}', None),
                                    ('CONTENT_CHANGED', '{}', '{}'), ('PERMISSION_CHANGED', '{}', '{}'),
                                    ('OWNER_CHANGED', '{}', '{}')):
            cursor.execute(EVENT, local + (PATH, kind, before, after, OBSERVED))

        rejected(cursor, MOUNT, local + (OBSERVED, PATH, 101, False), 3819)
        rejected(cursor, MOUNT, local + (OBSERVED, PATH, 50, 2), 3819)
        rejected(cursor, FILE, scope + (PATH, DIGEST, 0o640, OBSERVED), 1062)
        rejected(cursor, FILE, scope + (b'relative', DIGEST, 0o640, OBSERVED), 3819)
        rejected(cursor, FILE, scope + (b'/invalid\x00name', DIGEST, 0o640, OBSERVED), 3819)
        rejected(cursor, FILE, scope + (b'/short-digest', '00', 0o640, OBSERVED), 3819)
        rejected(cursor, FILE, scope + (b'/wrong-mode', DIGEST, 0o10000, OBSERVED), 3819)
        for kind, before, after in (('OTHER', '{}', '{}'), ('CREATED ', None, '{}'), ('CREATED', '{}', '{}'),
                                    ('DELETED', None, None), ('OWNER_CHANGED', '{}', None), ('CREATED', None, 'null')):
            rejected(cursor, EVENT, local + (PATH, kind, before, after, OBSERVED), 3819)
        rejected(cursor, SCAN, scope + (DIGEST, OBSERVED, True), 1062)
        rejected(cursor, SCAN, (third.host_id, third.source_id, DIGEST, None, True), 3819)
        rejected(cursor, SCAN, (third.host_id, third.source_id, '00', OBSERVED, True), 3819)


def test_admin_migration_with_dml_only_runtime(previous_mysql, identity_server):
    with previous_mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        identity = enroll(cursor, 'runtime')
        cursor.execute("CREATE USER 'filesystem_test'@'localhost' IDENTIFIED BY 'private-test'")
    try:
        assert migrate.migrate(previous_mysql) == ['034', '035']
        with previous_mysql.cursor() as cursor:
            for table in migrate.FILESYSTEM_TABLES:
                cursor.execute(f"GRANT SELECT, INSERT ON `{database}`.`{table}` TO 'filesystem_test'@'localhost'")
        runtime = pymysql.connect(unix_socket=identity_server, user='filesystem_test', password='private-test',
                                  database=database, charset='utf8mb4', init_command="SET time_zone = '+00:00'")
        with runtime:
            with runtime.cursor() as cursor:
                insert_observation(cursor, identity, 50)
                rejected(cursor, 'CREATE TABLE filesystem_test_ddl (id INT)', (), 1142)
                rejected(cursor, 'ALTER TABLE filesystem_file_state ADD COLUMN test INT', (), 1142)
            runtime.commit()
        for table in migrate.FILESYSTEM_TABLES:
            assert len(table_rows(previous_mysql, table)) == 1
    finally:
        with previous_mysql.cursor() as cursor:
            cursor.execute("DROP USER 'filesystem_test'@'localhost'")
