import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from database.identity import (
    EventIdentity,
    IdentityError,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from metrics.filesystem import mount_db, mount_main
from metrics.filesystem.mounts import MountCollection, MountFailure, MountMeasurement

STAMP = datetime(2026, 11, 8, 12, 0, 0, 123456, tzinfo=timezone.utc)
TOTAL = 2**64 - 1


def measurement(path=b'/', stamp=STAMP):
    return MountMeasurement(
        mount_point=path, filesystem_type='ext4', mount_source=b'UUID=local',
        mount_options='rw,nosuid', super_options='rw', measured_at=stamp,
        total_bytes=TOTAL, used_bytes=TOTAL - 100, free_bytes=100, available_bytes=75, usage_percent=100.0,
        total_inodes=TOTAL, used_inodes=TOTAL - 25, free_inodes=25, inode_usage_percent=100.0,
        read_only=False, nosuid=True, nodev=False, noexec=False,
    )


@pytest.fixture
def writer(monkeypatch):
    connection = MagicMock()
    connection.open = True
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [('APPLIED',), ('test_schema',), (1,), ('APPLIED',), (1,)]
    cursor.fetchall.return_value = ()
    connect = Mock(return_value=connection)
    resolve = Mock(return_value=EventIdentity(1, 2, 3, 4))
    monkeypatch.setattr(mount_db, 'get_connection', connect)
    monkeypatch.setattr(mount_db, 'identity_schema_enabled', lambda connection: True)
    monkeypatch.setattr(mount_db, 'configured_identity', resolve)
    return SimpleNamespace(connection=connection, cursor=cursor, connect=connect, resolve=resolve)


@pytest.mark.parametrize('count', [1, 2])
def test_save_all_rows_and_commit_once(writer, count):
    observations = (measurement(), measurement(b'/disk\xff'))[:count]
    commit_count = []
    writer.cursor.executemany.side_effect = lambda *_: commit_count.append(writer.connection.commit.call_count)

    assert mount_db.save_mount_metrics(MountCollection(observations, ())) == count

    writer.connect.assert_called_once_with(quiet=True, binary_parameters=True)
    writer.connection.begin.assert_called_once()
    writer.cursor.executemany.assert_called_once()
    sql, rows = writer.cursor.executemany.call_args.args
    assert sql.count('%s') == 13
    assert rows[0] == (1, 2, 3, 4, STAMP.replace(tzinfo=None), b'/', 'ext4', TOTAL, 75, TOTAL, 25, False, 'rw,nosuid')
    assert len(rows) == count and commit_count == [0]
    writer.connection.commit.assert_called_once()
    assert writer.connection.rollback.call_count == 1  # End the identity lookup transaction.
    writer.connection.close.assert_called_once()


def test_insert_failure_rolls_back_before_connection_is_closed(writer):
    writer.cursor.executemany.side_effect = pymysql.IntegrityError(3819, 'private test error')
    with pytest.raises(pymysql.IntegrityError):
        mount_db.save_mount_metrics(MountCollection((measurement(), measurement(b'/other')), ()))
    writer.connection.commit.assert_not_called()
    assert writer.connection.rollback.call_count == 2
    writer.connection.close.assert_called_once()
    assert writer.cursor.execute.call_args.args[0] == 'SELECT RELEASE_LOCK(%s)'


@pytest.mark.parametrize('failure', [None, IdentityError('Invalid registry binding.')])
def test_missing_or_invalid_identity_stops_before_insert(writer, failure):
    writer.resolve.side_effect = failure
    writer.resolve.return_value = None
    with pytest.raises(IdentityError):
        mount_db.save_mount_metrics(MountCollection((measurement(),), ()))
    writer.cursor.executemany.assert_not_called()
    writer.connection.commit.assert_not_called()
    writer.connection.close.assert_called_once()


def test_unapplied_migration_stops_before_insert(writer):
    writer.cursor.fetchone.side_effect = [('FAILED',)]
    with pytest.raises(mount_db.MountStorageError, match='migration 034'):
        mount_db.save_mount_metrics(MountCollection((measurement(),), ()))
    writer.resolve.assert_not_called()
    writer.cursor.executemany.assert_not_called()
    writer.connection.close.assert_called_once()


@pytest.mark.parametrize('collection', [
    MountCollection((), ()),
    MountCollection((), (MountFailure(None, 'Unreadable mountinfo'),)),
    MountCollection((measurement(),), (MountFailure(b'/gone', 'Mount disappeared'),)),
    MountCollection((measurement(), measurement()), ()),
    MountCollection((measurement(b'/bad\0path'),), ()),
    MountCollection((replace(measurement(), available_bytes=-1),), ()),
    MountCollection((replace(measurement(), available_bytes=101),), ()),
    MountCollection((replace(measurement(), total_bytes=2**64),), ()),
    MountCollection((replace(measurement(), free_inodes=26),), ()),
    MountCollection((replace(measurement(), read_only=2),), ()),
    MountCollection((measurement(stamp=STAMP.replace(tzinfo=None)),), ()),
])
def test_invalid_empty_or_incomplete_collection_does_not_connect(writer, collection):
    with pytest.raises(mount_db.MountStorageError):
        mount_db.save_mount_metrics(collection)
    writer.connect.assert_not_called()


def test_connection_failure_and_exit_code(writer, monkeypatch, capsys):
    writer.connect.return_value = None
    monkeypatch.setattr(mount_main, 'collect_mount_metrics', lambda: MountCollection((measurement(),), ()))
    assert mount_main.main() == 1
    output = capsys.readouterr()
    assert output.out == '' and 'storage failed' in output.err


@pytest.mark.parametrize('failure', ['insert', 'disconnect', 'collect'])
def test_failed_run_returns_one_and_redacts_diagnostics(writer, monkeypatch, capsys, failure):
    collect = Mock(return_value=MountCollection((measurement(),), ()))
    if failure == 'insert':
        writer.cursor.executemany.side_effect = pymysql.IntegrityError(3819, 'PRIVATE SQL DETAILS')
    elif failure == 'disconnect':
        writer.connection.commit.side_effect = pymysql.OperationalError(2013, 'PRIVATE CONNECTION DETAILS')
    else:
        collect.side_effect = OSError('PRIVATE MOUNT DETAILS')
    monkeypatch.setattr(mount_main, 'collect_mount_metrics', collect)

    assert mount_main.main() == 1
    output = capsys.readouterr()
    assert output.out == '' and 'PRIVATE' not in output.err
    if failure == 'collect':
        writer.connect.assert_not_called()
    else:
        writer.connection.close.assert_called_once()


@pytest.mark.parametrize('inserted', [0, 2])
def test_success_and_exact_replay_exit_zero(monkeypatch, capsys, inserted):
    collection = MountCollection((measurement(), measurement(b'/disk')), ())
    save = Mock(return_value=inserted)
    monkeypatch.setattr(mount_main, 'collect_mount_metrics', lambda: collection)
    monkeypatch.setattr(mount_main, 'save_mount_metrics', save)
    assert mount_main.main() == 0
    save.assert_called_once_with(collection)
    output = capsys.readouterr()
    assert 'stored' in output.out and output.err == ''


def enroll(cursor, name):
    host = register_host(cursor, name, reported_hostname='same-name')
    cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
    source = register_source(cursor, host, 'filesystem', 'filesystem', enabled=True)
    collector = register_collector(cursor, name, enabled=True)
    approve_collector_source(cursor, collector, source)
    return EventIdentity(host, source, collector)


def configure(monkeypatch, identity):
    monkeypatch.setenv('SIEM_FILESYSTEM_SOURCE_ID', str(identity.source_id))
    monkeypatch.setenv('SIEM_COLLECTOR_ID', str(identity.collector_id))


def history(connection):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute('SELECT host_id,source_id,collector_id,sender_id,measured_at,mount_point,total_bytes,total_inodes '
                       'FROM filesystem_mount_metrics ORDER BY id')
        return cursor.fetchall()


def test_private_mysql_history_atomicity_and_retries(mysql, identity_server, monkeypatch):
    with mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        first = enroll(cursor, 'mount-first')
        second = enroll(cursor, 'mount-second')
        cursor.execute("CREATE USER 'mount_storage_test'@'localhost' IDENTIFIED BY 'private-test'")
        for table in ('schema_migrations', 'hosts', 'log_sources', 'collectors', 'collector_sources'):
            cursor.execute(f"GRANT SELECT ON `{database}`.`{table}` TO 'mount_storage_test'@'localhost'")
        cursor.execute(f"GRANT SELECT, INSERT ON `{database}`.filesystem_mount_metrics TO 'mount_storage_test'@'localhost'")

    def connect(*, quiet, binary_parameters):
        assert quiet and binary_parameters
        return pymysql.connect(unix_socket=identity_server, user='mount_storage_test', password='private-test',
                               database=database, charset='utf8mb4', autocommit=False, binary_prefix=True)

    monkeypatch.setattr(mount_db, 'get_connection', connect)
    configure(monkeypatch, first)
    root = measurement()
    path = b'/disk-\xff'
    collection = MountCollection((root, measurement(path, STAMP + timedelta(microseconds=1))), ())
    assert mount_db.save_mount_metrics(collection) == 2
    saved = history(mysql)
    stamp = STAMP.replace(tzinfo=None)
    assert saved == (
        first.values() + (stamp, b'/', TOTAL, TOTAL),
        first.values() + (stamp + timedelta(microseconds=1), path, TOTAL, TOTAL),
    )
    assert mount_db.save_mount_metrics(collection) == 0
    assert history(mysql) == saved
    conflict = MountCollection((replace(root, available_bytes=50),), ())
    with pytest.raises(mount_db.MountStorageError, match='Conflicting'):
        mount_db.save_mount_metrics(conflict)
    incomplete_replay = MountCollection((root, measurement(b'/new')), ())
    with pytest.raises(mount_db.MountStorageError, match='Only part'):
        mount_db.save_mount_metrics(incomplete_replay)
    assert history(mysql) == saved

    scope = f'{database}:{first.host_id}:{first.source_id}'
    lock = 'siem.fs.mount.' + hashlib.sha256(scope.encode()).hexdigest()[:48]
    with mysql.cursor() as cursor:
        cursor.execute('SELECT GET_LOCK(%s, 0)', (lock,))
        assert cursor.fetchone() == (1,)
        try:
            with pytest.raises(mount_db.MountStorageError, match='Another writer'):
                mount_db.save_mount_metrics(collection)
            configure(monkeypatch, second)
            assert mount_db.save_mount_metrics(MountCollection((root,), ())) == 1
        finally:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (lock,))
    assert history(mysql) == saved + (second.values() + (stamp, b'/', TOTAL, TOTAL),)

    configure(monkeypatch, first)
    later = STAMP + timedelta(minutes=5)
    next_collection = MountCollection((measurement(stamp=later), measurement(b'/reject', later)), ())
    before = history(mysql)
    with mysql.cursor() as cursor:
        cursor.execute('CREATE TRIGGER reject_mount BEFORE INSERT ON filesystem_mount_metrics FOR EACH ROW '
                       "SET NEW.total_bytes = IF(NEW.mount_point = '/reject', 0, NEW.total_bytes)")
    with pytest.raises(pymysql.MySQLError) as error:
        mount_db.save_mount_metrics(next_collection)
    assert error.value.args[0] == 3819
    assert history(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_mount')

    def connect_and_lose_commit_response(*, quiet, binary_parameters):
        connection = connect(quiet=quiet, binary_parameters=binary_parameters)
        commit = connection.commit

        def disconnect_after_commit():
            commit()
            connection._force_close()
            raise pymysql.OperationalError(2013, 'synthetic lost commit response')

        connection.commit = disconnect_after_commit
        return connection

    with monkeypatch.context() as failure:
        failure.setattr(mount_db, 'get_connection', connect_and_lose_commit_response)
        with pytest.raises(pymysql.OperationalError, match='lost commit response'):
            mount_db.save_mount_metrics(next_collection)
    assert mount_db.save_mount_metrics(next_collection) == 0
    later_stamp = later.replace(tzinfo=None)
    assert history(mysql) == before + (
        first.values() + (later_stamp, b'/', TOTAL, TOTAL),
        first.values() + (later_stamp, b'/reject', TOTAL, TOTAL),
    )
