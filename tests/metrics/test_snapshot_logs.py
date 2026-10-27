"""Real temporary files, with modeled root/service metadata and no host changes."""

import os
import pwd
import stat
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from config import audit_setup
from config import installation_state as journal
from config import service_installation as service


@pytest.fixture
def logs(tmp_path, monkeypatch):
    system = tmp_path / 'system'
    parent = system / 'var/log'
    parent.mkdir(parents=True)
    for path in (system, system / 'var', parent):
        path.chmod(0o755)
    root = parent / 'mysql_siem'
    owners = {}
    ancestors = set(system.parents)
    actual_stat = os.stat
    actual_fstat = os.fstat
    account = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name='mysql_siem')

    def metadata(info, path):
        values = list(info)
        if path in ancestors:
            values[0] = stat.S_IFDIR | 0o755
            values[4], values[5] = 0, 0
        elif path == system or system in path.parents:
            values[4], values[5] = owners.get((info.st_dev, info.st_ino), (0, 0))
        return os.stat_result(values)

    def path_stat(path, *, dir_fd=None, follow_symlinks=True):
        info = actual_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        if isinstance(path, int):
            full = Path(os.readlink('/proc/self/fd/' + str(path)))
        elif dir_fd is not None and not Path(path).is_absolute():
            full = Path(os.readlink('/proc/self/fd/' + str(dir_fd))) / path
        else:
            full = Path(path)
        return metadata(info, full)

    def fd_stat(descriptor):
        path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
        return metadata(actual_fstat(descriptor), path)

    def chown(descriptor, uid, gid):
        info = actual_fstat(descriptor)
        owners[(info.st_dev, info.st_ino)] = (uid, gid)

    def owner(path, uid, gid):
        info = actual_stat(path, follow_symlinks=False)
        owners[(info.st_dev, info.st_ino)] = (uid, gid)

    monkeypatch.setattr(service, 'LOG_PARENT', parent)
    monkeypatch.setattr(service.os, 'stat', path_stat)
    monkeypatch.setattr(service.os, 'fstat', fd_stat)
    monkeypatch.setattr(service.os, 'fchown', Mock(side_effect=chown))
    monkeypatch.setattr(service.os, 'fchmod', Mock(wraps=os.fchmod))
    monkeypatch.setattr(service.pwd, 'getpwnam', Mock(return_value=account))
    group = SimpleNamespace(gr_name='mysql_siem', gr_gid=account.pw_gid, gr_mem=[])
    monkeypatch.setattr(service.grp, 'getgrnam', Mock(side_effect=lambda name: (
        SimpleNamespace(gr_name='syslog', gr_gid=104, gr_mem=[]) if name == 'syslog' else group)))
    monkeypatch.setattr(service.grp, 'getgrall', Mock(return_value=[group]))
    monkeypatch.setattr(service.pwd, 'getpwall', Mock(return_value=[account]))
    monkeypatch.setattr(service.os, 'getgrouplist', lambda name, gid: [gid])
    monkeypatch.setattr(journal, 'require_maintenance', Mock())
    monkeypatch.setattr(service.subprocess, 'run', Mock(return_value=SimpleNamespace(returncode=0)))
    return SimpleNamespace(root=root, parent=parent, owner=owner, account=account)


def prepare(logs, *, check=False):
    service.prepare_snapshot_logs('mysql_siem', logs.root, check_only=check)


@pytest.mark.parametrize('mode,gid,uid,accepted', [
    (0o775, 104, 0, True), (0o755, 0, 0, True),
    (0o777, 104, 0, False), (0o775, 999, 0, False),
    (0o755, 0, 999, False), (0o2775, 104, 0, False),
    (0o700, 0, 0, False), (0o750, 0, 0, False), (0o750, 1001, 0, True),
])
def test_parent_policy_is_checked_without_creating_logs(logs, mode, gid, uid, accepted):
    logs.parent.chmod(mode)
    logs.owner(logs.parent, uid, gid)
    if accepted:
        prepare(logs, check=True)
        assert not logs.root.exists()
        prepare(logs)
        assert logs.root.stat().st_mode & 0o777 == 0o750
    else:
        with pytest.raises(service.InstallationError):
            prepare(logs, check=True)
        with pytest.raises(service.InstallationError):
            prepare(logs)
        assert not logs.root.exists()
    assert logs.parent.stat().st_mode & 0o7777 == mode
    assert (logs.parent.stat().st_uid, logs.parent.stat().st_gid) == (uid, gid)


def test_general_trust_check_still_rejects_writable_parent(logs):
    logs.parent.chmod(0o775)
    logs.owner(logs.parent, 0, 104)
    with pytest.raises(service.InstallationError):
        service.trusted_directory(logs.parent)


@pytest.mark.parametrize('mask', [0o077, 0o022, 0o002])
def test_final_permissions_access_and_repeat_do_not_depend_on_umask(logs, mask):
    previous = os.umask(mask)
    try:
        prepare(logs)
        service.os.fchown.reset_mock()
        service.os.fchmod.reset_mock()
        prepare(logs)
    finally:
        os.umask(previous)
    assert (logs.root.stat().st_uid, logs.root.stat().st_gid, stat.S_IMODE(logs.root.stat().st_mode)) == (0, 1001, 0o750)
    for component in service.LOG_COMPONENTS:
        directory = logs.root / component
        logfile = directory / 'cron.log'
        assert (directory.stat().st_uid, directory.stat().st_gid, stat.S_IMODE(directory.stat().st_mode)) == (1001, 1001, 0o700)
        assert (logfile.stat().st_uid, logfile.stat().st_gid, stat.S_IMODE(logfile.stat().st_mode)) == (1001, 1001, 0o600)
        assert logfile.read_bytes() == b''
    service.os.fchown.assert_not_called()
    service.os.fchmod.assert_not_called()
    assert service.subprocess.run.call_count == 6
    for call in service.subprocess.run.call_args_list:
        assert call.args[0][:8] == ['/usr/sbin/runuser', '-u', 'mysql_siem', '--', '/usr/bin/head', '-c', '0', '--']


@pytest.mark.parametrize('fault', ['root-link', 'directory-link', 'file-link', 'hardlink',
                                    'wrong-root-owner', 'wrong-directory-owner', 'wrong-file-owner',
                                    'writable-directory', 'unexpected-entry'])
def test_unsafe_existing_tree_fails_check_and_preparation(logs, tmp_path, fault):
    prepare(logs)
    untouched = tmp_path / 'unrelated'
    untouched.write_text('preserve\n')
    untouched.chmod(0o600)
    inode = untouched.stat().st_ino
    target = logs.root / 'processes/cron.log'
    if fault == 'root-link':
        logs.root.rename(logs.parent / 'original')
        logs.root.symlink_to(logs.parent / 'original', target_is_directory=True)
    elif fault == 'directory-link':
        target.unlink()
        target.parent.rmdir()
        target.parent.symlink_to(tmp_path, target_is_directory=True)
    elif fault in ('file-link', 'hardlink'):
        target.unlink()
        if fault == 'file-link':
            target.symlink_to(untouched)
        else:
            os.link(untouched, target)
    elif fault == 'wrong-root-owner':
        logs.owner(logs.root, 999, 1001)
    elif fault == 'wrong-directory-owner':
        logs.owner(target.parent, 999, 1001)
    elif fault == 'wrong-file-owner':
        logs.owner(target, 999, 1001)
    elif fault == 'writable-directory':
        target.parent.chmod(0o777)
    else:
        (logs.root / 'other-program').mkdir()
    for check in (True, False):
        with pytest.raises((OSError, service.InstallationError)):
            prepare(logs, check=check)
    assert untouched.read_text() == 'preserve\n'
    assert untouched.stat().st_ino == inode
    assert stat.S_IMODE(untouched.stat().st_mode) == 0o600


def test_check_is_read_only_with_existing_and_missing_logs(logs):
    prepare(logs, check=True)
    prepare(logs)
    logfile = logs.root / 'audit/cron.log'
    logfile.write_text('retained\n')
    (logs.root / 'services/cron.log').unlink()
    before = []
    for path in (logs.root, logs.root / 'audit', logfile):
        info = path.stat()
        before.append((info.st_uid, info.st_gid, info.st_mode, info.st_ino, info.st_size, info.st_mtime))
    service.os.fchown.reset_mock()
    service.os.fchmod.reset_mock()
    service.subprocess.run.reset_mock()
    prepare(logs, check=True)
    assert not (logs.root / 'services/cron.log').exists()
    assert logfile.read_text() == 'retained\n'
    after = []
    for path in (logs.root, logs.root / 'audit', logfile):
        info = path.stat()
        after.append((info.st_uid, info.st_gid, info.st_mode, info.st_ino, info.st_size, info.st_mtime))
    assert before == after
    service.os.fchown.assert_not_called()
    service.os.fchmod.assert_not_called()
    service.subprocess.run.assert_not_called()


def test_group_traversal_is_repaired_on_retry_without_replacing_logs(logs):
    prepare(logs)
    logfile = logs.root / 'audit/cron.log'
    logfile.write_text('keep history\n')
    inode = logfile.stat().st_ino
    logs.root.chmod(0o700)
    prepare(logs, check=True)
    assert stat.S_IMODE(logs.root.stat().st_mode) == 0o700
    prepare(logs)
    assert stat.S_IMODE(logs.root.stat().st_mode) == 0o750
    assert logfile.stat().st_ino == inode
    assert logfile.read_text() == 'keep history\n'


@pytest.mark.parametrize('failure', ['open', 'probe'])
def test_io_or_service_access_failure_is_not_hidden(logs, monkeypatch, failure):
    if failure == 'probe':
        service.subprocess.run.return_value.returncode = 1
    else:
        actual_open = os.open

        def fail_open(path, *args, **kwargs):
            if path == 'cron.log':
                raise OSError('synthetic log creation failure')
            return actual_open(path, *args, **kwargs)

        monkeypatch.setattr(service.os, 'open', fail_open)
    with pytest.raises((OSError, service.InstallationError)):
        prepare(logs)


@pytest.mark.parametrize('replace_at', [1, 2])
def test_replaced_root_is_rejected_before_reporting_success(logs, monkeypatch, replace_at):
    prepare(logs)
    verify = service.verify_snapshot_name
    calls = 0

    def replace_then_verify(parent, name, descriptor):
        nonlocal calls
        if name == 'mysql_siem':
            calls += 1
        if name == 'mysql_siem' and calls == replace_at:
            logs.root.rename(logs.parent / 'old-root')
            logs.root.mkdir(mode=0o750)
        return verify(parent, name, descriptor)

    monkeypatch.setattr(service, 'verify_snapshot_name', replace_then_verify)
    with pytest.raises(service.InstallationError, match='path changed'):
        prepare(logs)


@pytest.mark.parametrize('default', [False, True])
def test_audit_parent_policy_keeps_exception_limited_to_default_directory(monkeypatch, default):
    logfile = Path('/var/log/audit/audit.log') if default else Path('/var/log/custom/audit.log')

    def metadata(path):
        if path == Path('/var/log'):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_gid=104)
        if path == logfile:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=4, st_nlink=1)
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)

    monkeypatch.setattr(service.grp, 'getgrnam', Mock(return_value=SimpleNamespace(gr_gid=104)))
    monkeypatch.setattr(Path, 'lstat', metadata)
    monkeypatch.setattr(Path, 'iterdir', Mock(return_value=iter([logfile])))
    if default:
        assert 'root owned' in audit_setup.inspect_audit_log_directory(logfile)
    else:
        with pytest.raises(service.InstallationError):
            audit_setup.inspect_audit_log_directory(logfile)


def test_failed_installer_precheck_precedes_database_setup_and_preserves_recovery(tmp_path):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    check = installer.index('service_installation snapshot-logs-check "$INSTALL_USER"')
    started = installer.index('\nDATABASE_SETUP_STARTED=1\n')
    assert check < started < installer.index('-m config.reset_installation reset')
    assert check < installer.index('-m config.reset_installation upgrade')
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('retain recovery\n')
    script = '''set -e
INSTALL_USER=mysql_siem
service_installation() { return 17; }
''' + installer[check:started] + '\nprintf "database setup started"\n'
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 17
    assert 'database setup started' not in result.stdout
    assert receipt.read_text() == 'retain recovery\n'



def test_rotating_logs_preserve_history_for_all_collectors(logs):
    from config.run_logging import close_log, open_log

    prepare(logs)
    previous = os.umask(0o077)
    try:
        for component in service.LOG_COMPONENTS:
            path = logs.root / component / 'cron.log'
            logger, handler = open_log('snapshot-test.' + component, path)
            try:
                handler.maxBytes = 100
                for _ in range(20):
                    logger.info('synthetic log entry for rollover')
            finally:
                close_log(logger, handler)
            assert path.with_suffix('.log.1').exists()
            assert len(list(path.parent.glob('cron.log*'))) <= 4
    finally:
        os.umask(previous)
    prepare(logs, check=True)
    prepare(logs)


def test_missing_syslog_group_does_not_relax_writable_parent_policy(logs):
    logs.parent.chmod(0o775)
    logs.owner(logs.parent, 0, 104)
    service.grp.getgrnam.side_effect = KeyError('syslog')
    with pytest.raises(service.InstallationError, match='syslog group'):
        prepare(logs, check=True)
    assert not logs.root.exists()


def test_inaccessible_ancestor_fails_before_logs_are_created(logs):
    logs.parent.parent.chmod(0o700)
    with pytest.raises(service.InstallationError, match='cannot traverse'):
        prepare(logs, check=True)
    assert not logs.root.exists()


def test_cli_dispatches_read_only_check(monkeypatch):
    operation = Mock()
    monkeypatch.setattr(service, 'prepare_snapshot_logs', operation)
    service.main(['snapshot-logs-check', 'mysql_siem'])
    operation.assert_called_once_with('mysql_siem', check_only=True)


@pytest.mark.parametrize('mask', [0o077, 0o022, 0o002])
def test_real_service_user_can_open_isolated_logs(monkeypatch, mask):
    # Explicit opt-in: existing account only, temporary files only, no installation.
    if os.environ.get('SIEM_TEST_LOG_ACCESS') != '1' or os.geteuid() != 0:
        pytest.skip('Needs root and SIEM_TEST_LOG_ACCESS=1; no host settings are changed.')
    try:
        account = pwd.getpwnam('mysql_siem')
    except KeyError:
        pytest.skip('Needs an existing mysql_siem account; this test does not create users.')
    # The test prepares only its temporary tree, without an actual installer.
    monkeypatch.setattr(journal, 'require_maintenance', Mock())
    with tempfile.TemporaryDirectory(prefix='mysql-siem-log-test-', dir='/run') as temporary:
        base = Path(temporary)
        parent = base / 'var/log'
        parent.mkdir(parents=True)
        for directory in (base, base / 'var', parent):
            directory.chmod(0o755)
        monkeypatch.setattr(service, 'LOG_PARENT', parent)
        root = parent / 'mysql_siem'
        previous = os.umask(mask)
        try:
            service.prepare_snapshot_logs('mysql_siem', root)
            service.prepare_snapshot_logs('mysql_siem', root)
        finally:
            os.umask(previous)
        assert (root.stat().st_uid, root.stat().st_gid, stat.S_IMODE(root.stat().st_mode)) == (0, account.pw_gid, 0o750)
        # The preparation above performed real read opens with runuser. Independently
        # verify write opens as the service account, without changing log contents.
        probe = ('import os,sys; '
                 'fd=os.open(sys.argv[1],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW); os.close(fd)')
        for component in service.LOG_COMPONENTS:
            logfile = root / component / 'cron.log'
            assert (logfile.stat().st_uid, stat.S_IMODE(logfile.stat().st_mode)) == (account.pw_uid, 0o600)
            subprocess.run(['/usr/sbin/runuser', '-u', 'mysql_siem', '--', '/usr/bin/python3',
                            '-I', '-B', '-c', probe, str(logfile)],
                           check=True, capture_output=True, timeout=5)
            assert logfile.read_bytes() == b''


@pytest.mark.parametrize('platform,parent_mode,parent_gid', [
    ('Debian 13', 0o755, 0), ('Ubuntu 24.04', 0o775, 104),
])
def test_empty_legacy_root_is_classified_and_migrated_without_replacing_it(logs, platform, parent_mode, parent_gid):
    logs.parent.chmod(parent_mode)
    logs.owner(logs.parent, 0, parent_gid)
    logs.root.mkdir(mode=0o750)
    logs.root.chmod(0o750)
    logs.owner(logs.root, logs.account.pw_uid, logs.account.pw_gid)
    inode = logs.root.stat().st_dev, logs.root.stat().st_ino
    assert service.prepare_snapshot_logs('mysql_siem', logs.root, check_only=True) == 'legacy-empty'
    assert not list(logs.root.iterdir())
    service.os.fchown.assert_not_called()
    journal.require_maintenance.assert_not_called()
    assert service.prepare_snapshot_logs('mysql_siem', logs.root) == 'prepared'
    journal.require_maintenance.assert_called_once_with(journal.STATE_DIR)
    assert (logs.root.stat().st_dev, logs.root.stat().st_ino) == inode
    assert (logs.root.stat().st_uid, logs.root.stat().st_gid, stat.S_IMODE(logs.root.stat().st_mode)) == (0, 1001, 0o750)
    assert sorted(path.name for path in logs.root.iterdir()) == sorted(service.LOG_COMPONENTS)
    for component in service.LOG_COMPONENTS:
        directory = logs.root / component
        logfile = directory / 'cron.log'
        assert (directory.stat().st_uid, directory.stat().st_gid, stat.S_IMODE(directory.stat().st_mode)) == (1001, 1001, 0o700)
        assert (logfile.stat().st_uid, logfile.stat().st_gid, stat.S_IMODE(logfile.stat().st_mode)) == (1001, 1001, 0o600)
    service.os.fchown.reset_mock()
    service.os.fchmod.reset_mock()
    prepare(logs)
    service.os.fchown.assert_not_called()
    service.os.fchmod.assert_not_called()


@pytest.mark.parametrize('fault', ['nonempty', 'known-child', 'wrong-group', 'world-readable',
                                  'group-writable', 'special-mode', 'default-acl', 'group-mismatch',
                                  'shared-group', 'shared-primary', 'group-alias', 'uid-alias'])
def test_legacy_migration_is_narrow_and_rejects_unrecognized_state(logs, fault):
    logs.root.mkdir(mode=0o750)
    logs.root.chmod(0o750)
    logs.owner(logs.root, 1001, 1001)
    if fault == 'nonempty':
        (logs.root / 'unrelated').write_bytes(b'keep')
    elif fault == 'known-child':
        (logs.root / 'processes').mkdir()
    elif fault == 'wrong-group':
        logs.owner(logs.root, 1001, 55)
    elif fault == 'world-readable':
        logs.root.chmod(0o755)
    elif fault == 'group-writable':
        logs.root.chmod(0o770)
    elif fault == 'special-mode':
        logs.root.chmod(0o2750)
    elif fault == 'default-acl':
        from config.audit_permissions import write_acl
        descriptor = os.open(logs.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            write_acl(descriptor, {'user:': 7, 'group:': 5, 'mask:': 5, 'other:': 0}, default=True)
        finally:
            os.close(descriptor)
    elif fault in ('shared-group', 'group-mismatch'):
        group = SimpleNamespace(gr_gid=55 if fault == 'group-mismatch' else 1001,
                                gr_mem=['reader'] if fault == 'shared-group' else [])
        service.grp.getgrnam.side_effect = None
        service.grp.getgrnam.return_value = group
    elif fault == 'shared-primary':
        service.pwd.getpwall.return_value = [logs.account, SimpleNamespace(pw_name='reader', pw_uid=55, pw_gid=1001)]
    elif fault == 'group-alias':
        service.grp.getgrall.return_value = [SimpleNamespace(gr_name='alias', gr_gid=1001)]
    else:
        service.pwd.getpwall.return_value = [logs.account, SimpleNamespace(pw_name='alias', pw_uid=1001, pw_gid=55)]
    for check in (True, False):
        with pytest.raises(service.InstallationError):
            prepare(logs, check=check)
    service.os.fchown.assert_not_called()
    service.os.fchmod.assert_not_called()
    assert logs.root.stat().st_uid == 1001
    if fault == 'nonempty':
        assert (logs.root / 'unrelated').read_bytes() == b'keep'


@pytest.mark.parametrize('point', ['before-change', 'after-change'])
def test_legacy_root_identity_is_verified_on_both_sides_of_migration(logs, monkeypatch, point):
    logs.root.mkdir(mode=0o750)
    logs.root.chmod(0o750)
    logs.owner(logs.root, 1001, 1001)
    original_verify = service.verify_snapshot_name
    original_chown = service.os.fchown
    calls = 0

    def replace():
        logs.root.rename(logs.parent / 'old-root')
        logs.root.mkdir(mode=0o750)

    def verify(parent, name, descriptor):
        nonlocal calls
        if name == 'mysql_siem':
            calls += 1
            if point == 'before-change' and calls == 2:
                replace()
        original_verify(parent, name, descriptor)

    def chown(descriptor, uid, gid):
        original_chown(descriptor, uid, gid)
        if point == 'after-change':
            replace()

    monkeypatch.setattr(service, 'verify_snapshot_name', verify)
    monkeypatch.setattr(service.os, 'fchown', Mock(side_effect=chown))
    with pytest.raises(service.InstallationError, match='path changed'):
        prepare(logs)
    assert not list(logs.root.iterdir())
    assert not list((logs.parent / 'old-root').iterdir())
    if point == 'before-change':
        service.os.fchown.assert_not_called()


def test_snapshot_mutation_requires_both_maintenance_locks_before_creating_paths(logs):
    journal.require_maintenance.side_effect = journal.InstallationStateError('inherited lock missing')
    with pytest.raises(journal.InstallationStateError, match='lock missing'):
        prepare(logs)
    assert not logs.root.exists()
    service.os.fchown.assert_not_called()


def test_partial_legacy_preparation_can_retry_without_losing_recovery_material(logs, tmp_path, monkeypatch):
    logs.root.mkdir(mode=0o750)
    logs.root.chmod(0o750)
    logs.owner(logs.root, 1001, 1001)
    state = tmp_path / 'recovery'
    state.mkdir()
    for name in ('deployment.json', 'receipt.json', 'maintenance', 'mysql.env', 'identity.env'):
        (state / name).write_text('synthetic preserved material\n')
    before = {path.name: (path.stat().st_ino, path.read_bytes()) for path in state.iterdir()}
    original_open = service.open_snapshot_directory

    def interrupt(parent, name, account, **kwargs):
        if name == 'services':
            raise OSError('synthetic interruption after ownership migration')
        return original_open(parent, name, account, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(service, 'open_snapshot_directory', interrupt)
        with pytest.raises(OSError, match='interruption'):
            prepare(logs)
    assert logs.root.stat().st_uid == 0
    assert (logs.root / 'processes/cron.log').exists()
    assert {path.name: (path.stat().st_ino, path.read_bytes()) for path in state.iterdir()} == before
    prepare(logs)
    assert {path.name: (path.stat().st_ino, path.read_bytes()) for path in state.iterdir()} == before


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
def test_failed_snapshot_preparation_preserves_stage_and_stops_before_services_and_database(tmp_path, operation):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    check = installer.index('service_installation snapshot-logs-check "$INSTALL_USER"')
    lock = installer.index('flock -x -w 30 8', installer.index('    local_identity_setup begin --reset'))
    prepare = installer.index('service_installation snapshot-logs "$INSTALL_USER"')
    started = installer.index('\nDATABASE_SETUP_STARTED=1\n')
    assert check < lock < prepare < installer.index('log "Starting services."') < started
    assert installer.count('service_installation snapshot-logs "$INSTALL_USER"') == 1
    cleanup_start = installer.index('cleanup_prepared_installation() {')
    cleanup_end = installer.index('\n}\n', cleanup_start) + 3
    phase_start = installer.index('# Prepare and verify snapshot logs under both inherited locks')
    phase_end = installer.index('# Both schema paths', started)
    receipt = tmp_path / 'receipt.json'
    journal_file = tmp_path / 'deployment.json'
    receipt.write_text('retained receipt\n')
    journal_file.write_text('retained journal\n')
    before = receipt.read_bytes(), journal_file.read_bytes()
    prefix = r'''set -euo pipefail
INSTALL_USER=mysql_siem
INSTALL_OPERATION=$1
LOCAL_DEPLOYMENT_STARTED=1
SERVICE_PUBLISHED=0
warn() { printf '%s\n' "$*" >&2; }
service_installation() {
    [[ "$1" == snapshot-logs ]] || { printf 'UNEXPECTED journal deletion\n'; return 91; }
    return 17
}
systemctl() { printf 'UNEXPECTED service action\n'; return 91; }
log() { printf 'UNEXPECTED service phase\n'; return 91; }
'''
    script = prefix + installer[cleanup_start:cleanup_end] + '\ntrap cleanup_prepared_installation EXIT\n' + installer[phase_start:phase_end]
    result = subprocess.run(['bash', '-c', script, 'snapshot-test', operation],
                            capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 17, result.stdout + result.stderr
    assert 'UNEXPECTED' not in result.stdout
    assert 'recovery journal were retained' in result.stderr
    assert (receipt.read_bytes(), journal_file.read_bytes()) == before



def test_read_only_check_classifies_missing_and_existing_roots(logs):
    assert service.prepare_snapshot_logs('mysql_siem', logs.root, check_only=True) == 'missing'
    prepare(logs)
    assert service.prepare_snapshot_logs('mysql_siem', logs.root, check_only=True) == 'existing'


def test_legacy_exception_does_not_relax_the_shared_root_validator(logs):
    logs.root.mkdir(mode=0o750)
    logs.owner(logs.root, 1001, 1001)
    with pytest.raises(service.InstallationError, match='Unsafe snapshot'):
        service.validate_snapshot_entry(logs.root.stat(), logs.account, shared=True, directory=True)


def test_concurrent_entry_is_not_adopted_during_legacy_migration(logs, monkeypatch):
    logs.root.mkdir(mode=0o750)
    logs.root.chmod(0o750)
    logs.owner(logs.root, 1001, 1001)
    original_chown = service.os.fchown

    def add_entry(descriptor, uid, gid):
        (logs.root / 'unrecognized').write_bytes(b'preserve this content')
        original_chown(descriptor, uid, gid)

    monkeypatch.setattr(service.os, 'fchown', Mock(side_effect=add_entry))
    with pytest.raises(service.InstallationError, match='changed during migration'):
        prepare(logs)
    assert (logs.root / 'unrecognized').read_bytes() == b'preserve this content'
    assert sorted(path.name for path in logs.root.iterdir()) == ['unrecognized']
    service.os.fchown.assert_called_once()
