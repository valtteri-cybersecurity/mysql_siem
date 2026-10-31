"""Upgrade safety uses synthetic rows and private files; never production MySQL."""

import copy
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from config import installation_backup as backup
from config import installation_state as journal
from config import reset_installation as reset
from config import service_installation as service
from database import local_identity, migrate


@pytest.fixture
def rows(tmp_path, monkeypatch):
    values = [(1, 'old value'), (3, 'second value')]
    layout = {'events': {'columns': ['id', 'payload'], 'primary': ['id'], 'ddl_sha256': 'test'}}
    monkeypatch.setattr(backup, 'table_layout', lambda connection: copy.deepcopy(layout))

    def select(*args):
        cursor = MagicMock()
        cursor.__enter__.return_value = cursor
        cursor.fetchone.side_effect = list(values) + [None]
        return cursor

    monkeypatch.setattr(backup, 'select_rows', select)
    tables = backup.snapshot_rows(MagicMock(), tmp_path)
    return values, tables, tmp_path


def test_restore_verifies_all_original_rows_and_values(rows):
    values, tables, folder = rows
    backup.verify_rows(MagicMock(), folder, tables, exact=True)
    assert tables['events']['count'] == 2
    assert (folder / tables['events']['file']).stat().st_mode & 0o777 == 0o600
    values.insert(1, (2, 'new migration row'))
    backup.verify_rows(MagicMock(), folder, tables)
    with pytest.raises(backup.BackupError, match='unexpected'):
        backup.verify_rows(MagicMock(), folder, tables, exact=True)


@pytest.mark.parametrize('fault', ['deleted', 'changed', 'identifier'])
def test_missing_or_changed_history_prevents_activation(rows, fault):
    values, tables, folder = rows
    if fault == 'deleted':
        values.pop(0)
    elif fault == 'changed':
        values[0] = (1, 'changed value')
    else:
        values[0] = (2, 'old value')
    with pytest.raises(backup.BackupError):
        backup.verify_rows(MagicMock(), folder, tables)


def test_fingerprint_corruption_is_detected(rows):
    _values, tables, folder = rows
    (folder / tables['events']['file']).write_text('corrupt')
    with pytest.raises(backup.BackupError, match='integrity'):
        backup.verify_rows(MagicMock(), folder, tables)


def test_private_file_rejects_symlink_and_public_permissions(tmp_path):
    path = tmp_path / 'data'
    path.write_bytes(b'private')
    path.chmod(0o644)
    with pytest.raises(backup.BackupError, match='Unsafe'):
        backup.digest_file(path)
    path.chmod(0o600)
    link = tmp_path / 'linked'
    link.symlink_to(path)
    with pytest.raises(OSError):
        backup.digest_file(link)


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(backup, 'trusted_directory', lambda path: None)
    state = tmp_path / 'state'
    state.mkdir()
    project = tmp_path / 'stage'
    (project / 'config').mkdir(parents=True)
    version = project / 'config/installed-version'
    version.write_text('a' * 40 + '\n')
    version.chmod(0o640)
    identity = {'SIEM_COLLECTOR_ID': 7, 'SIEM_AUTH_SOURCE_ID': 2}
    receipt = {'phase': 'ready', 'database': 'mysql_siem', 'server': 'private-server',
               'identity': identity, 'host_id': 4}
    guard = Mock(return_value={'stage': str(project), 'target': str(tmp_path / 'installed')})
    monkeypatch.setattr(journal, 'require_stage', guard)
    monkeypatch.setattr(local_identity, 'read_receipt', lambda path: receipt)
    monkeypatch.setattr(local_identity, 'read_settings', lambda path: identity)
    monkeypatch.setattr(local_identity, 'database_key', lambda connection: ('mysql_siem', 'private-server'))
    monkeypatch.setattr(local_identity, 'validate_bindings', lambda *args, **kwargs: 4)
    monkeypatch.setattr(backup, 'check_prerequisites', Mock(return_value={
        'database': 'mysql_siem', 'server': 'private-server', 'mysql_version': '8.0.46'}))
    monkeypatch.setattr(backup, 'table_layout', lambda connection: {'events': {}})
    monkeypatch.setattr(backup, 'snapshot_rows', Mock(return_value={}))
    restore = Mock()
    monkeypatch.setattr(backup, 'restore_check', restore)
    commands = []

    def dump(arguments, **options):
        commands.append(arguments)
        options['stdout'].write(b'CREATE DATABASE mysql_siem;\n')

    monkeypatch.setattr(backup, 'run', dump)
    return SimpleNamespace(project=project, state=state, root=tmp_path / 'backups',
                           restore=restore, connection=MagicMock(), receipt=receipt,
                           commands=commands, guard=guard)


def create(prepared):
    return backup.create_verified_backup(prepared.connection, prepared.project,
                                         state=prepared.state, backup_root=prepared.root,
                                         restore_parent=prepared.state.parent)


def test_backup_is_verified_before_pointer_publication_and_retained_on_retry(prepared):
    first, manifest = create(prepared)
    assert manifest['phase'] == 'VERIFIED'
    assert manifest['revision'] == 'a' * 40
    prepared.restore.assert_called_once()
    assert first.stat().st_mode & 0o777 == 0o700
    assert (first / 'database.sql').stat().st_mode & 0o777 == 0o600
    pointer = json.loads(journal.read_file(prepared.state / 'upgrade-backup.json'))
    assert pointer['folder'] == str(first)
    prepared.connection.cursor.return_value.__enter__.return_value.fetchone.return_value = ('mysql_siem', 'private-server')
    second, _manifest = create(prepared)
    assert first != second and (first / 'database.sql').exists()
    arguments = prepared.commands[0]
    assert '--single-transaction' in arguments
    assert '--skip-add-drop-table' in arguments
    assert arguments[-2:] == ['--databases', 'mysql_siem']
    for argument in arguments:
        assert 'password' not in argument.lower()
    assert 'MYSQL_PWD' not in backup.private_environment()
    assert backup.private_environment()['MYSQL_TEST_LOGIN_FILE'] == '/dev/null'


@pytest.mark.parametrize('fault', ['dump', 'restore', 'interrupt'])
def test_failed_backup_preserves_evidence_and_never_publishes_ready(prepared, monkeypatch, fault):
    if fault == 'dump':
        monkeypatch.setattr(backup, 'run', Mock(side_effect=backup.BackupError('synthetic dump failure')))
    elif fault == 'restore':
        prepared.restore.side_effect = backup.BackupError('synthetic restore failure')
    else:
        prepared.restore.side_effect = KeyboardInterrupt()
    with pytest.raises((backup.BackupError, KeyboardInterrupt)):
        create(prepared)
    assert not (prepared.state / 'upgrade-backup.json').exists()
    folders = list(prepared.root.iterdir())
    assert len(folders) == 1
    assert json.loads(journal.read_file(folders[0] / 'manifest.json'))['phase'] == 'FAILED'


def test_wrong_database_receipt_prevents_dump(prepared):
    prepared.receipt['server'] = 'another server'
    with pytest.raises(backup.BackupError, match='binding'):
        create(prepared)
    assert prepared.commands == []
    assert not prepared.root.exists()


def test_backup_requires_inherited_maintenance_locks(prepared):
    prepared.guard.side_effect = journal.InstallationStateError('lock unavailable')
    with pytest.raises(journal.InstallationStateError):
        create(prepared)
    assert not prepared.root.exists()


def test_low_disk_space_prevents_backup(monkeypatch, tmp_path):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [('mysql_siem', 'server', '8.0.46'), (100,)]
    monkeypatch.setattr(backup, 'binary', lambda name: name)
    monkeypatch.setattr(backup, 'run', lambda *args, **kwargs: SimpleNamespace(stdout=b'Ver 8.0.46'))
    monkeypatch.setattr(backup, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(backup.shutil, 'disk_usage', lambda path: SimpleNamespace(free=1))
    with pytest.raises(backup.BackupError, match='disk space'):
        backup.check_prerequisites(connection, backup_root=tmp_path, restore_parent=tmp_path)


@pytest.mark.parametrize('fault', ['backup', 'migration', 'preservation', 'lock', None])
def test_upgrade_orders_backup_before_ddl_and_never_runs_reset(monkeypatch, tmp_path, fault):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (1,)
    if fault == 'lock':
        cursor.fetchone.return_value = (0,)
    calls = []

    def step(name):
        calls.append(name)
        if fault == name:
            raise backup.BackupError('synthetic ' + name)

    def make_backup(*args, **kwargs):
        step('backup')
        return tmp_path, {'tables': {}}

    monkeypatch.setattr(reset, 'check_upgrade_database', Mock())
    monkeypatch.setattr(backup, 'create_verified_backup', make_backup)
    monkeypatch.setattr(backup, 'mark_upgrade_phase', Mock())
    monkeypatch.setattr(migrate, 'migrate', lambda connection: step('migration'))
    monkeypatch.setattr(migrate, 'check_ufw_utc_readiness', Mock())
    monkeypatch.setattr(backup, 'verify_rows', lambda *args: step('preservation'))
    settings = {'DB_HOST': 'localhost', 'DB_NAME': 'mysql_siem', 'DB_USER': 'pythonuser', 'DB_PASSWORD': 'synthetic'}
    if fault is not None:
        with pytest.raises((backup.BackupError, reset.ResetError)):
            reset.upgrade_database(connection, settings, project=tmp_path)
    else:
        reset.upgrade_database(connection, settings, project=tmp_path)
    if fault == 'lock':
        assert calls == []
    elif fault == 'backup':
        assert calls == ['backup']
    elif fault == 'migration':
        assert calls == ['backup', 'migration']
    else:
        assert calls == ['backup', 'migration', 'preservation']
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')


def test_new_attempt_checks_original_verified_baseline_first(prepared, monkeypatch):
    first, _manifest = create(prepared)
    prepared.connection.cursor.return_value.__enter__.return_value.fetchone.return_value = ('mysql_siem', 'private-server')
    monkeypatch.setattr(backup, 'verify_rows', Mock(side_effect=backup.BackupError('original history changed')))
    with pytest.raises(backup.BackupError, match='original history changed'):
        create(prepared)
    assert list(prepared.root.iterdir()) == [first]
    assert len(prepared.commands) == 1


def test_completion_requires_successful_migration_and_same_deployment(prepared):
    folder, _manifest = create(prepared)
    record = {'stage': str(prepared.project), 'database_started_current': True}
    with pytest.raises(backup.BackupError, match='incomplete'):
        backup.complete_upgrade_backup(prepared.state, record)
    backup.mark_upgrade_phase(folder, prepared.state, 'FINAL_VERIFIED')
    backup.complete_upgrade_backup(prepared.state, record)
    pointer = json.loads(journal.read_file(prepared.state / 'upgrade-backup.json'))
    assert pointer['phase'] == 'COMPLETE'
    assert (folder / 'database.sql').exists()


def test_sigterm_leaves_upgrade_unfinished_and_restores_handler(monkeypatch, tmp_path, capsys):
    import signal

    previous = signal.getsignal(signal.SIGTERM)
    connection = MagicMock()
    monkeypatch.setattr(journal, 'require_maintenance', Mock())
    monkeypatch.setattr(journal, 'require_stage', Mock())
    monkeypatch.setattr(reset, 'get_installation_role', lambda **kwargs: 'server')
    monkeypatch.setattr(reset, 'validate_settings', Mock())
    monkeypatch.setattr(reset.pymysql, 'connect', Mock(return_value=connection))

    def terminate(*args, **kwargs):
        signal.raise_signal(signal.SIGTERM)

    monkeypatch.setattr(reset, 'upgrade_database', terminate)
    assert reset.main(['upgrade', '--project', str(tmp_path)]) == 1
    assert 'interrupted' in capsys.readouterr().err
    assert signal.getsignal(signal.SIGTERM) == previous
    connection.close.assert_called_once()



def test_failed_mysql_command_reports_phase_and_saves_private_error(
    tmp_path, monkeypatch
):
    def failed_command(arguments, **options):
        options['stderr'].write(
            b'Simulated MySQL permission denied'
        )
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(
        backup.subprocess, 'run', failed_command
    )

    path = tmp_path / 'mysql-initialize.stderr'

    with pytest.raises(
        backup.BackupError,
        match='MYSQL_INITIALIZE failed with exit code 1',
    ):
        backup.run(
            ['mysqld', '--initialize-insecure'],
            phase='MYSQL_INITIALIZE',
            diagnostic=path,
        )

    assert path.stat().st_mode & 0o777 == 0o600
    assert b'permission denied' in path.read_bytes()


def test_successful_mysql_command_leaves_no_diagnostics(
    tmp_path, monkeypatch
):
    def successful_command(arguments, **options):
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        backup.subprocess, 'run', successful_command
    )

    path = tmp_path / 'mysql-restore.stderr'

    backup.run(
        ['mysql'],
        phase='SQL_RESTORE',
        diagnostic=path,
    )

    assert not path.exists()


def test_mysql_restore_path_must_be_private_and_mysql_owned(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace as Namespace
    import os

    parent = tmp_path / 'mysql'
    parent.mkdir(mode=0o700)

    monkeypatch.setattr(
        backup, 'RESTORE_PARENT', parent
    )
    monkeypatch.setattr(
        backup, 'trusted_directory', lambda path: None
    )
    monkeypatch.setattr(
        backup.pwd,
        'getpwnam',
        lambda name: Namespace(
            pw_uid=os.getuid(),
            pw_gid=os.getgid(),
        ),
    )

    backup.trusted_restore_parent(parent)

    parent.chmod(0o777)

    with pytest.raises(
        backup.BackupError,
        match='secure mysql-owned',
    ):
        backup.trusted_restore_parent(parent)


def test_isolated_restore_runs_with_mysql_identity(tmp_path, monkeypatch):
    """Initialization and startup must run as mysql, not root."""
    import os

    user_id = 1234
    group_id = 1234
    calls = []

    monkeypatch.setattr(
        backup, 'trusted_restore_parent', lambda path: None
    )
    monkeypatch.setattr(
        backup.os, 'geteuid', lambda: 0
    )
    monkeypatch.setattr(
        backup.os, 'chown', lambda path, uid, gid: None
    )
    monkeypatch.setattr(
        backup.pwd, 'getpwnam',
        lambda name: SimpleNamespace(
            pw_uid=user_id,
            pw_gid=group_id,
        ),
    )
    monkeypatch.setattr(
        backup, 'binary', lambda name: name
    )

    def fake_run(arguments, **options):
        calls.append((arguments, options))

    def fake_popen(arguments, **options):
        calls.append((arguments, options))
        raise OSError('Synthetic startup failure')

    monkeypatch.setattr(backup, 'run', fake_run)
    monkeypatch.setattr(
        backup.subprocess, 'Popen', fake_popen
    )

    with pytest.raises(OSError, match='Synthetic startup'):
        backup.restore_check(
            tmp_path / 'database.sql',
            {},
            restore_parent=tmp_path,
        )

    assert len(calls) == 2

    for arguments, options in calls:
        assert '--user=mysql' not in arguments
        assert options['user'] == user_id
        assert options['group'] == group_id
        assert options['extra_groups'] == []


from datetime import datetime as _dt_022


@pytest.mark.parametrize(
    "fault",
    [None, "action", "time", "strict", "no_proof"],
)
def test_partial_022_backup_classification(
    tmp_path, monkeypatch, fault
):
    original = (
        1,
        _dt_022(2026, 10, 30, 12, 0, 0),
        "2026-10-30T12:00:00Z host [UFW BLOCK] SRC=192.0.2.1",
        "UNVERIFIED",
        "BLOCK",
    )

    values = [original]

    layout = {
        "ufw_log": {
            "columns": [
                "id", "event_time", "raw_line",
                "time_basis", "action",
            ],
            "primary": ["id"],
            "ddl_sha256": "synthetic",
        }
    }

    monkeypatch.setattr(
        backup,
        "table_layout",
        lambda connection: copy.deepcopy(layout),
    )

    def select_rows(*args):
        cursor = MagicMock()
        cursor.__enter__.return_value = cursor
        cursor.fetchone.side_effect = values + [None]
        return cursor

    monkeypatch.setattr(backup, "select_rows", select_rows)

    tables = backup.snapshot_rows(MagicMock(), tmp_path)

    updated = list(original)
    updated[3] = "UTC_VERIFIED"

    if fault == "action":
        updated[4] = "ALLOW"

    elif fault == "time":
        updated[1] = _dt_022(2026, 10, 30, 12, 0, 1)

    values[0] = tuple(updated)

    def baseline(*args, **kwargs):
        if fault == "no_proof":
            return None

        return {"precision": 6}

    monkeypatch.setattr(
        backup, "_verified_022_baseline", baseline
    )

    if fault is None:
        backup.verify_rows(MagicMock(), tmp_path, tables)

    else:
        with pytest.raises(
            backup.BackupError, match="values changed"
        ):
            backup.verify_rows(
                MagicMock(),
                tmp_path,
                tables,
                exact=fault == "strict",
            )


def test_partial_022_proof_requires_verified_ledger(monkeypatch):
    from database import ufw_history

    cursor = MagicMock()
    cursor.__enter__.return_value = cursor
    cursor.fetchone.return_value = (
        "APPLIED",
        json.dumps({
            "_ufw_compatibility": {"precision": 6}
        }),
    )

    connection = MagicMock()
    connection.cursor.return_value = cursor

    preflight = Mock()
    monkeypatch.setattr(ufw_history, "preflight", preflight)

    tables = {
        "ufw_log": {
            "columns": ["id", "time_basis"]
        }
    }

    result = backup._verified_022_baseline(
        connection, tables, exact=False
    )

    assert result == {"precision": 6}
    preflight.assert_called_once_with(connection)

    preflight.reset_mock()

    assert backup._verified_022_baseline(
        connection, tables, exact=True
    ) is None

    preflight.assert_not_called()
