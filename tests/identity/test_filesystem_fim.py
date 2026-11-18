import json
import os
import pwd
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pymysql
import pytest

from config import filesystem_runtime, reset_installation
from database import migrate
from database.identity import (
    IdentityError,
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from detection.filesystem import detector, runner
from metrics.filesystem import fim, fim_db, fim_main
from metrics.filesystem.file_integrity import FileDigest
from metrics.filesystem.inventory import (
    DEFAULT_CONFIG,
    FileMetadata,
    InventoryConfig,
    InventoryEntry,
    InventoryResult,
    collect_inventory,
)
from metrics.filesystem.permissions import PermissionRule
from metrics.snapshot import CollectionBusy

START = datetime(2026, 11, 9, 10, 0, 0, 123456, tzinfo=timezone.utc)
CONFIG = b'c' * 32
ROOT = b'/etc/critical.d'
TRACKED = ROOT + b'/tracked\xff'
REMOVED = ROOT + b'/removed'
ADDED = ROOT + b'/added'
FIRST_HASH = b'a' * 32
SECOND_HASH = b'b' * 32


def found(path, at, *, digest=FIRST_HASH, mode=0o640, uid=1000, gid=1000, mtime=1):
    content = FileDigest('DISABLED')
    if digest is not None:
        content = FileDigest('HASHED', digest)
    return InventoryEntry(path, 'FOUND', at, 'regular', FileMetadata(10, uid, gid, mode, mtime), content)


def scan(at, *files, config=CONFIG):
    return InventoryResult(files + (InventoryEntry(ROOT, 'SCANNED', at, 'directory'),), config, at)


@pytest.mark.parametrize('settings,kinds', [
    ({}, []),
    ({'mtime': 2}, []),
    ({'digest': SECOND_HASH}, ['CONTENT_CHANGED']),
    ({'mode': 0o600}, ['PERMISSION_CHANGED']),
    ({'uid': 1001}, ['OWNER_CHANGED']),
    ({'gid': 1001}, ['OWNER_CHANGED']),
    ({'digest': None}, []),
    ({'digest': SECOND_HASH, 'mode': 0o600, 'uid': 1001, 'gid': 1002},
     ['CONTENT_CHANGED', 'PERMISSION_CHANGED', 'OWNER_CHANGED']),
])
def test_detect_each_kind_without_database(settings, kinds):
    after = START + timedelta(seconds=1)
    previous, _, _, _ = fim.prepare_inventory(scan(START, found(TRACKED, START)))
    current, coverage, _, _ = fim.prepare_inventory(scan(after, found(TRACKED, after, **settings)))
    actual = []
    for path, kind, before, state in fim.detect_changes(previous, current, coverage):
        assert path == TRACKED and before == previous[path] and state == current[path]
        actual.append(kind)
    assert actual == kinds
    if 'digest' in settings and settings['digest'] is None:
        reverse = fim.detect_changes(current, previous, coverage)
        assert reverse == []


def test_created_and_confirmed_deleted_have_correct_null_sides():
    earlier, _, _, _ = fim.prepare_inventory(scan(START, found(REMOVED, START)))
    newer, coverage, _, _ = fim.prepare_inventory(scan(START, found(ADDED, START)))
    assert fim.detect_changes(earlier, newer, coverage) == [
        (ADDED, 'CREATED', None, newer[ADDED]),
        (REMOVED, 'DELETED', earlier[REMOVED], None),
    ]


def test_scanned_directory_mode_change_has_before_and_after_metadata(tmp_path):
    directory = tmp_path / 'monitored'
    directory.mkdir()
    directory.chmod(0o755)
    config = InventoryConfig(files=(), directories=(str(directory),))
    previous, coverage, _, _ = fim.prepare_inventory(collect_inventory(config))
    assert fim.detect_changes({}, previous, coverage) == []

    directory.chmod(0o777)
    current, coverage, _, _ = fim.prepare_inventory(collect_inventory(config))
    path, kind, before, after = fim.detect_changes(previous, current, coverage)[0]
    assert path == os.fsencode(directory) and kind == 'PERMISSION_CHANGED'
    assert before.file_type == after.file_type == 'directory'
    assert (before.mode, after.mode) == (0o755, 0o777)
    assert after.content_sha256 is None


@pytest.mark.parametrize('directory_target', [False, True])
def test_replacing_a_file_with_symlink_keeps_other_changes(tmp_path, directory_target):
    directory = tmp_path / 'monitored'
    directory.mkdir()
    tracked = directory / 'tracked'
    tracked.write_bytes(b'original')
    other = directory / 'other'
    other.write_bytes(b'old')
    if directory_target:
        config = InventoryConfig(files=(), directories=(str(directory),))
    else:
        config = InventoryConfig(files=(str(tracked), str(other)))
    previous, _, _, _ = fim.prepare_inventory(collect_inventory(config))

    tracked.unlink()
    tracked.symlink_to('missing-target')
    other.write_bytes(b'new')
    current, coverage, _, _ = fim.prepare_inventory(collect_inventory(config))
    tracked_path = os.fsencode(tracked)
    other_path = os.fsencode(other)
    assert coverage[tracked_path] == 'SYMLINK'
    assert current[tracked_path].file_type == 'symlink'
    assert current[tracked_path].content_sha256 is None
    assert fim.detect_changes(previous, current, coverage) == [
        (other_path, 'CONTENT_CHANGED', previous[other_path], current[other_path]),
        (tracked_path, 'TYPE_CHANGED', previous[tracked_path], current[tracked_path]),
    ]
    assert fim.detect_changes(current, current, coverage) == []

    tracked.unlink()
    tracked.write_bytes(b'restored')
    restored, coverage, _, _ = fim.prepare_inventory(collect_inventory(config))
    assert fim.detect_changes(current, restored, coverage) == [
        (tracked_path, 'TYPE_CHANGED', current[tracked_path], restored[tracked_path]),
    ]


@pytest.mark.parametrize('coverage', [
    {}, {TRACKED: 'SKIPPED_TYPE', ROOT: 'SCANNED'}, {ROOT: 'SKIPPED_TYPE'}, {ROOT: 'DEPTH_LIMIT'},
])
def test_unproven_absence_is_rejected(coverage):
    previous, _, _, _ = fim.prepare_inventory(scan(START, found(TRACKED, START)))
    with pytest.raises(fim.FimError, match='verified absence'):
        fim.detect_changes(previous, {}, coverage)


def test_missing_directory_proves_absence_of_its_previous_files():
    previous, _, _, _ = fim.prepare_inventory(scan(START, found(TRACKED, START)))
    assert fim.detect_changes(previous, {}, {ROOT: 'MISSING'}) == [
        (TRACKED, 'DELETED', previous[TRACKED], None),
    ]


@pytest.mark.parametrize('entries', [(), (InventoryEntry(ROOT, 'DENIED', START),),
                                     (found(TRACKED, START), InventoryEntry(ROOT, 'CHANGED', START))])
def test_incomplete_inventory_is_rejected(entries):
    with pytest.raises(fim.FimError, match='complete file inventory'):
        fim.prepare_inventory(InventoryResult(entries, CONFIG, START))


def test_cli_reports_configuration_change_without_sql_details(monkeypatch, capsys):
    def fail():
        raise fim.RebaselineRequired('private details')

    monkeypatch.setattr(fim_main, 'collect_fim', fail)
    assert fim_main.main() == 1
    output = capsys.readouterr()
    assert 'rebaseline' in output.err and 'private' not in output.err


def enroll(cursor, name, host=None):
    if host is None:
        host = register_host(cursor, name, reported_hostname='same-name')
        cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
    source = register_source(cursor, host, name, 'filesystem', enabled=True)
    collector = register_collector(cursor, name, enabled=True)
    approve_collector_source(cursor, collector, source)
    return host, source, collector


def configure(monkeypatch, identity):
    _, source, collector = identity
    monkeypatch.setenv('SIEM_FILESYSTEM_SOURCE_ID', str(source))
    monkeypatch.setenv('SIEM_COLLECTOR_ID', str(collector))


def stored_rows(connection):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute('SELECT host_id,source_id,file_path,content_sha256,mode,observed_at '
                       'FROM filesystem_file_state ORDER BY host_id,source_id,file_path')
        current = cursor.fetchall()
        cursor.execute('SELECT host_id,source_id,collector_id,file_path,event_type,previous_state,current_state,observed_at '
                       'FROM filesystem_file_events ORDER BY id')
        events = cursor.fetchall()
        cursor.execute('SELECT host_id,source_id,last_successful_scan_at,config_sha256,baseline_complete '
                       'FROM filesystem_scan_state ORDER BY host_id,source_id')
        return current, events, cursor.fetchall()


def test_private_mysql_fim_is_atomic_scoped_and_retry_safe(mysql, identity_server, monkeypatch):
    with mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        first = enroll(cursor, 'fim-first')
        second = enroll(cursor, 'fim-second')
        third = enroll(cursor, 'fim-third', host=first[0])
        cursor.execute("CREATE USER 'fim_test'@'localhost' IDENTIFIED BY 'private-test'")
        for table in ('schema_migrations', 'hosts', 'log_sources', 'collectors', 'collector_sources'):
            cursor.execute(f"GRANT SELECT ON `{database}`.`{table}` TO 'fim_test'@'localhost'")
        cursor.execute(f"GRANT SELECT, INSERT, DELETE ON `{database}`.filesystem_file_state TO 'fim_test'@'localhost'")
        cursor.execute(f"GRANT INSERT ON `{database}`.filesystem_file_events TO 'fim_test'@'localhost'")
        cursor.execute(f"GRANT SELECT, INSERT, UPDATE ON `{database}`.filesystem_scan_state TO 'fim_test'@'localhost'")

    def connect(*, quiet, binary_parameters):
        assert quiet and binary_parameters
        return pymysql.connect(unix_socket=identity_server, user='fim_test', password='private-test',
                               database=database, charset='utf8mb4', autocommit=False, binary_prefix=True)

    monkeypatch.setattr(fim_db, 'get_connection', connect)
    configure(monkeypatch, first)
    baseline = scan(START, found(TRACKED, START), found(REMOVED, START))

    def observe_under_lock(_config):
        with pytest.raises(CollectionBusy):
            fim_db.save_fim_inventory(baseline)
        return baseline

    monkeypatch.setattr(fim_db, 'collect_inventory', observe_under_lock)
    assert fim_db.collect_fim() == 0
    current, events, checkpoints = stored_rows(mysql)
    initial_at = START.replace(tzinfo=None)
    assert len(current) == 2 and not events
    assert checkpoints == (first[:2] + (initial_at, CONFIG, 1),)

    for identity in (second, third):
        configure(monkeypatch, identity)
        assert fim_db.save_fim_inventory(baseline) == 0
    configure(monkeypatch, first)
    original = stored_rows(mysql)
    next_at = START + timedelta(seconds=1)
    update = scan(next_at, found(TRACKED, next_at, digest=SECOND_HASH, mode=0o600, uid=2000),
                  found(ADDED, next_at, digest=None))

    rule = PermissionRule('critical', directories=(ROOT,), allowed_uids=(1000,), critical=True)
    assessment = fim_db.assess_fim_permissions(update, rules=(rule,))
    finding, = assessment.findings
    assert (finding.host_id, finding.source_id, finding.path, finding.kind) == first[:2] + (TRACKED, 'OWNER_MISMATCH')
    assert finding.previous.mode == 0o640 and finding.current.mode == 0o600
    assert stored_rows(mysql) == original

    with pytest.raises(fim.RebaselineRequired):
        fim_db.save_fim_inventory(replace(update, config_sha256=b'n' * 32))
    partial = InventoryResult((found(TRACKED, next_at), InventoryEntry(ROOT, 'DENIED', next_at)), CONFIG, next_at)
    with pytest.raises(fim.FimError, match='complete file inventory'):
        fim_db.save_fim_inventory(partial)
    overlap = scan(next_at, found(TRACKED, START), found(ADDED, next_at))
    with pytest.raises(fim.FimError, match='stale, overlapping'):
        fim_db.save_fim_inventory(overlap)
    with monkeypatch.context() as wrong:
        wrong.setenv('SIEM_COLLECTOR_ID', str(second[2]))
        with pytest.raises(IdentityError):
            fim_db.save_fim_inventory(update)
    assert stored_rows(mysql) == original

    with mysql.cursor() as cursor:
        cursor.execute('CREATE TRIGGER reject_fim_checkpoint BEFORE UPDATE ON filesystem_scan_state FOR EACH ROW '
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic checkpoint failure'")
    with pytest.raises(pymysql.MySQLError, match='synthetic checkpoint failure'):
        fim_db.save_fim_inventory(update)
    assert stored_rows(mysql) == original
    with mysql.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_fim_checkpoint')

    def connect_with_lost_commit_response(*, quiet, binary_parameters):
        connection = connect(quiet=quiet, binary_parameters=binary_parameters)
        commit = connection.commit

        def disconnect_after_commit():
            commit()
            connection._force_close()
            raise pymysql.OperationalError(2013, 'synthetic lost commit response')

        connection.commit = disconnect_after_commit
        return connection

    with monkeypatch.context() as failure:
        failure.setattr(fim_db, 'get_connection', connect_with_lost_commit_response)
        with pytest.raises(pymysql.OperationalError, match='lost commit response'):
            fim_db.save_fim_inventory(update)
    committed = stored_rows(mysql)
    assert fim_db.save_fim_inventory(update) == 0
    assert stored_rows(mysql) == committed
    current, events, checkpoints = committed
    next_stamp = next_at.replace(tzinfo=None)
    assert checkpoints == (first[:2] + (next_stamp, CONFIG, 1), third[:2] + (initial_at, CONFIG, 1),
                           second[:2] + (initial_at, CONFIG, 1))
    assert current[:2] == (first[:2] + (ADDED, None, 0o640, next_stamp),
                           first[:2] + (TRACKED, SECOND_HASH, 0o600, next_stamp))
    assert current[2:] == original[0][2:]
    expected = [(ADDED, 'CREATED'), (REMOVED, 'DELETED'), (TRACKED, 'CONTENT_CHANGED'),
                (TRACKED, 'PERMISSION_CHANGED'), (TRACKED, 'OWNER_CHANGED')]
    assert len(events) == len(expected)
    for event, (path, kind) in zip(events, expected, strict=True):
        assert event[:5] == first + (path, kind)
        assert event[7] == next_stamp
    assert events[0][5] is None and json.loads(events[0][6])['content_sha256'] is None
    assert events[1][6] is None and json.loads(events[1][5])['content_sha256'] == FIRST_HASH.hex()
    assert json.loads(events[2][6])['content_sha256'] == SECOND_HASH.hex()


def test_private_mysql_upgrade_activates_with_existing_fim_checkpoint(empty_mysql, identity_server, monkeypatch, tmp_path):
    admin = empty_mysql
    with monkeypatch.context() as before:
        before.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:-8])
        assert migrate.migrate(admin)[-1] == '035'
    with admin.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        identity = enroll(cursor, 'deployment-fim')
        cursor.execute("CREATE USER 'pythonuser'@'localhost' IDENTIFIED BY 'private-test'")
    try:
        admin.commit()
        monkeypatch.setattr(reset_installation, 'DATABASE', database)
        configure(monkeypatch, identity)

        def connect(*, quiet=True, binary_parameters=True):
            assert quiet and binary_parameters
            return pymysql.connect(unix_socket=identity_server, user='pythonuser', password='private-test',
                                   database=database, charset='utf8mb4', autocommit=False, binary_prefix=True)

        def grant(cursor, table, privileges):
            cursor.execute(f"GRANT {privileges} ON `{database}`.`{table}` TO 'pythonuser'@'localhost'")

        with admin.cursor() as cursor:
            for table in ('schema_migrations', 'hosts', 'log_sources', 'collectors', 'collector_sources'):
                grant(cursor, table, 'SELECT')
            for table, privileges in reset_installation.FILESYSTEM_RUNTIME_PRIVILEGES.items():
                grant(cursor, table, privileges)
        monkeypatch.setattr(fim_db, 'get_connection', connect)
        digest = filesystem_runtime._digest(DEFAULT_CONFIG)
        file_path = b'/etc/ssh/sshd_config'
        other_path = b'/etc/group'
        with admin.cursor() as cursor:
            for tracked in (file_path, other_path):
                cursor.execute('INSERT INTO filesystem_file_state '
                               '(host_id, source_id, file_path, content_sha256, size_bytes, owner_uid, group_gid, mode, observed_at) '
                               'VALUES (%s,%s,%s,UNHEX(%s),10,0,0,416,%s)',
                               identity[:2] + (tracked, FIRST_HASH.hex(), START.replace(tzinfo=None)))
            cursor.execute('INSERT INTO filesystem_scan_state '
                           '(host_id, source_id, last_successful_scan_at, config_sha256, baseline_complete) '
                           'VALUES (%s,%s,%s,UNHEX(%s),TRUE)', identity[:2] + (START.replace(tzinfo=None), digest.hex()))
        admin.commit()
        original = stored_rows(admin)
        config = tmp_path / 'config'
        config.mkdir()
        settings_path = config / 'identity.env'
        settings_path.write_text(f'SIEM_FILESYSTEM_SOURCE_ID={identity[1]}\nSIEM_COLLECTOR_ID={identity[2]}\n')
        settings_path.chmod(0o600)
        path = tmp_path / filesystem_runtime.CONFIG_PATH
        user = pwd.getpwuid(os.geteuid()).pw_name
        python = tmp_path / 'venv/bin/python'
        monkeypatch.setattr(filesystem_runtime.installation_state, 'require_maintenance', lambda state: None)

        with connect() as runtime, pytest.raises(filesystem_runtime.FilesystemSetupError, match='migrations'):
            filesystem_runtime.prepare(runtime, tmp_path, user, python)
        assert not path.exists()

        assert migrate.migrate(admin) == ['036', '037', '038', '039', '040', '041', '042', '043']
        migrate.apply_one(admin, '036')
        migrate.apply_one(admin, '037')
        migrate.apply_one(admin, '038')
        with admin.cursor() as cursor:
            for table, privileges in filesystem_runtime.REQUIRED_GRANTS.items():
                if table != 'alert_hosts':
                    grant(cursor, table, privileges)
        with connect() as runtime, pytest.raises(filesystem_runtime.FilesystemSetupError, match='grant'):
            filesystem_runtime.prepare(runtime, tmp_path, user, python)
        assert not path.exists()
        with admin.cursor() as cursor:
            grant(cursor, 'alert_hosts', 'INSERT')

        with connect() as runtime:
            lines = filesystem_runtime.prepare(runtime, tmp_path, user, python)
            assert len(lines) == 3
            assert filesystem_runtime.prepare(runtime, tmp_path, user, python) == lines
            assert filesystem_runtime.read_config(path)[1] == DEFAULT_CONFIG
        assert stored_rows(admin) == original
        assert migrate.migrate(admin) == []

        next_at = START + timedelta(seconds=1)
        partial = InventoryResult((found(file_path, next_at), InventoryEntry(ROOT, 'DENIED', next_at)),
                                  digest, next_at)
        monkeypatch.setattr(fim_db, 'collect_inventory', lambda config: partial)
        log = tmp_path / 'cron.log'
        assert fim_main.main(['--config', str(path), '--log-file', str(log)]) == 1
        assert 'PARTIAL duration_seconds=' in log.read_text()
        with connect() as runtime:
            assert runner.run_automatic(runtime) == 0
        assert stored_rows(admin) == original
        modified = found(file_path, next_at, digest=SECOND_HASH, mode=0o666, uid=0, gid=0)
        complete = scan(next_at, modified, found(other_path, next_at, uid=0, gid=0), config=digest)
        monkeypatch.setattr(fim_db, 'collect_inventory', lambda config: complete)
        assert fim_main.main(['--config', str(path), '--log-file', str(log)]) == 0
        assert 'changes=2 risks=' in log.read_text()
        with connect() as runtime:
            assert runner.run_automatic(runtime) == 3
        next_at += timedelta(seconds=1)
        replacement = InventoryEntry(file_path, 'SYMLINK', next_at, 'symlink', FileMetadata(7, 0, 0, 0o777, 1))
        untracked = replace(replacement, path=b'/etc/sudoers')
        other_modified = found(other_path, next_at, digest=SECOND_HASH, uid=0, gid=0)
        link_scan = scan(next_at, replacement, untracked, other_modified, config=digest)
        assert fim_db.save_fim_inventory(link_scan) == 2
        assert fim_db.save_fim_inventory(link_scan) == 0
        _, events, _ = stored_rows(admin)
        with admin.cursor() as cursor:
            cursor.execute('SELECT file_path, file_type, content_sha256 FROM filesystem_file_state ORDER BY file_path')
            assert cursor.fetchall() == ((other_path, 'regular', SECOND_HASH), (file_path, 'symlink', None))
        assert len(events) == 4 and events[-2][3:5] == (other_path, 'CONTENT_CHANGED')
        assert events[-1][3:5] == (file_path, 'TYPE_CHANGED')
        assert json.loads(events[-1][5])['file_type'] == 'regular'
        assert json.loads(events[-1][6])['file_type'] == 'symlink'
        with connect() as runtime:
            assert runner.run_automatic(runtime) == 1
        next_at += timedelta(seconds=1)
        restored = scan(next_at, replace(modified, observed_at=next_at),
                        replace(other_modified, observed_at=next_at), config=digest)
        assert fim_db.save_fim_inventory(restored) == 1
        with connect() as runtime:
            assert runner.run_automatic(runtime) == 2

        oversized = replace(modified, digest=FileDigest('TOO_LARGE'),
                            metadata=replace(modified.metadata, size_bytes=DEFAULT_CONFIG.max_file_bytes + 1))
        for observation in (oversized, oversized, modified, oversized, replace(modified, digest=FileDigest('HASHED', FIRST_HASH))):
            next_at += timedelta(seconds=1)
            inventory = scan(next_at, replace(observation, observed_at=next_at),
                             replace(other_modified, observed_at=next_at), config=digest)
            changes = fim_db.save_fim_inventory(inventory)
            if observation.digest.status == 'TOO_LARGE':
                assert changes == 0
                expected_hashes = (None, SECOND_HASH)
            else:
                expected_hashes = (observation.digest.sha256, None)
                if observation.digest.sha256 == SECOND_HASH:
                    assert changes == 0
                else:
                    assert changes == 1
            assert fim_db.save_fim_inventory(inventory) == 0
            admin.rollback()
            with admin.cursor() as cursor:
                cursor.execute('SELECT content_sha256, retained_sha256 FROM filesystem_file_state WHERE file_path = %s',
                               (file_path,))
                assert cursor.fetchone() == expected_hashes
        _, events, _ = stored_rows(admin)
        assert len(events) == 6 and events[-1][3:5] == (file_path, 'CONTENT_CHANGED')
        previous = json.loads(events[-1][5])
        assert previous['content_sha256'] is None and previous['retained_sha256'] == SECOND_HASH.hex()
        assert json.loads(events[-1][6])['content_sha256'] == FIRST_HASH.hex()
        with connect() as runtime:
            assert runner.run_automatic(runtime) == 1

        directory_path = b'/etc/sudoers.d'
        for mode, expected in ((0o755, 0), (0o777, 1), (0o777, 0)):
            next_at += timedelta(seconds=1)
            directory = InventoryEntry(directory_path, 'SCANNED', next_at, 'directory', FileMetadata(0, 0, 0, mode, 1))
            unchanged = found(file_path, next_at, digest=FIRST_HASH, mode=0o666, uid=0, gid=0)
            inventory = scan(next_at, directory, unchanged, replace(other_modified, observed_at=next_at), config=digest)
            assert fim_db.save_fim_inventory(inventory) == expected
            with connect() as runtime:
                assert runner.run_automatic(runtime) == expected

        admin.rollback()
        with admin.cursor() as cursor:
            cursor.execute('SELECT f.event_type, f.previous_state, f.current_state, a.details '
                           'FROM filesystem_file_events f JOIN alert_evidence e ON e.event_id=f.id '
                           'JOIN detection_alerts a ON a.id=e.alert_id JOIN detection_rules r ON r.id=a.rule_id '
                           'WHERE f.file_path=%s AND e.event_type=%s AND r.rule_key=%s',
                           (directory_path, detector.EVIDENCE_TYPE, detector.PERMISSION_RULE))
            (kind, old, new, details), = cursor.fetchall()
        assert kind == 'PERMISSION_CHANGED'
        assert json.loads(old)['mode'] == 0o755
        assert json.loads(new)['mode'] == 0o777
        assert json.loads(new)['file_type'] == 'directory'
        assert json.loads(details)['risks'][0]['kind'] == 'WORLD_WRITABLE'

        with admin.cursor() as cursor:
            cursor.execute('DROP TABLE filesystem_mount_metrics')
        with connect() as runtime, pytest.raises(filesystem_runtime.FilesystemSetupError, match='transactional'):
            filesystem_runtime.prepare(runtime, tmp_path, user, python)
    finally:
        with admin.cursor() as cursor:
            cursor.execute("DROP USER 'pythonuser'@'localhost'")
