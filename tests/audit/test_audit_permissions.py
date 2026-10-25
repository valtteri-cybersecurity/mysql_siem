"""Group access checks: synthetic files, modeled ownership, no host changes."""

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from config import audit_setup as setup


@pytest.fixture
def logs(tmp_path, monkeypatch):
    directory = tmp_path / 'audit'
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    active = directory / 'audit.log'
    active.write_text('synthetic active\n')
    active.chmod(0o640)
    rotated = directory / 'audit.log.1'
    rotated.write_text('synthetic rotation\n')
    rotated.chmod(0o440)
    owners = {}
    original_lstat = Path.lstat
    original_fstat = os.fstat
    account = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name='mysql_siem')

    def metadata(info, path):
        if path == directory or directory in path.parents:
            values = list(info)
            values[4], values[5] = owners.get((info.st_dev, info.st_ino), (0, 1001))
            return os.stat_result(values)
        return info

    def lstat(path):
        if path in (Path('/'), Path('/var'), Path('/var/log')):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        return metadata(original_lstat(path), path)

    def fstat(descriptor):
        path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
        return metadata(original_fstat(descriptor), path)

    def owner(path, uid, gid):
        info = original_lstat(path)
        owners[(info.st_dev, info.st_ino)] = (uid, gid)

    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(setup.os, 'fstat', fstat)
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(setup.pwd, 'getpwnam', Mock(return_value=account))
    monkeypatch.setattr(setup.grp, 'getgrnam', Mock(return_value=SimpleNamespace(gr_gid=1001)))
    monkeypatch.setattr(setup, 'command', Mock(return_value=''))
    return SimpleNamespace(directory=directory, active=active, rotated=rotated, account=account, owner=owner)


@pytest.mark.parametrize('value', ['mysql_siem', '1001'])
def test_named_or_numeric_private_group_is_supported(logs, value):
    setup.validate_audit_log_group({'log_group': value}, 'mysql_siem')
    assert setup._preflight_account() == logs.account


@pytest.mark.parametrize('value', [None, 'root', '0', 'adm', '1002'])
def test_old_or_wrong_group_is_rejected_without_rewriting_configuration(logs, value):
    values = {}
    if value is not None:
        values['log_group'] = value
    before = dict(values)
    with pytest.raises(ValueError, match='log_group=mysql_siem'):
        setup.validate_audit_log_group(values, 'mysql_siem')
    assert values == before
    setup.command.assert_not_called()


@pytest.mark.parametrize('fault', ['missing-group', 'root-group', 'wrong-primary', 'missing-user'])
def test_missing_or_unsafe_reader_account_fails(logs, fault):
    if fault == 'missing-group':
        setup.grp.getgrnam.side_effect = KeyError('mysql_siem')
    elif fault == 'root-group':
        setup.grp.getgrnam.return_value.gr_gid = 0
    elif fault == 'wrong-primary':
        logs.account.pw_gid = 4
    else:
        setup.pwd.getpwnam.side_effect = KeyError('mysql_siem')
    with pytest.raises(ValueError):
        setup._preflight_account()


def test_preflight_probes_every_file_after_all_groups_are_removed(logs):
    result = setup.check_audit_log_access(logs.active, logs.account)
    assert '2 Audit logs readable' in result
    paths = []
    for call in setup.command.call_args_list:
        arguments = call.args[0]
        assert arguments[:5] == ['/usr/bin/setpriv', '--reuid=1001', '--regid=1001', '--clear-groups', '--']
        assert arguments[5:10] == ['/usr/bin/python3', '-I', '-B', '-c', setup.READ_PROBE]
        paths.append(arguments[10])
        assert arguments[11:13] == ['1001', '1001']
    assert paths == [str(logs.rotated), str(logs.active)]
    assert 'os.getgroups()' in setup.READ_PROBE
    assert 'os.O_NOFOLLOW' in setup.READ_PROBE


@pytest.mark.parametrize('fault', ['directory-group', 'directory-mode', 'active-group', 'active-owner',
                                    'active-mode', 'old-rotation-group', 'old-rotation-mode',
                                    'active-link', 'rotation-link', 'directory-link', 'hardlink'])
def test_bad_permissions_or_links_fail_before_probe_and_are_not_repaired(logs, tmp_path, fault):
    if fault == 'directory-group':
        logs.owner(logs.directory, 0, 4)
    elif fault == 'directory-mode':
        logs.directory.chmod(0o700)
    elif fault == 'active-group':
        logs.owner(logs.active, 0, 4)
    elif fault == 'active-owner':
        logs.owner(logs.active, 999, 1001)
    elif fault == 'active-mode':
        logs.active.chmod(0o660)
    elif fault == 'old-rotation-group':
        logs.owner(logs.rotated, 0, 4)
    elif fault == 'old-rotation-mode':
        logs.rotated.chmod(0o400)
    elif fault == 'directory-link':
        logs.directory.rename(tmp_path / 'original')
        logs.directory.symlink_to(tmp_path / 'original', target_is_directory=True)
    else:
        target = logs.active if fault == 'active-link' else logs.rotated
        if fault == 'hardlink':
            os.link(target, logs.directory / 'audit.log.2')
        else:
            target.unlink()
            target.symlink_to(tmp_path / 'outside')
    with pytest.raises((ValueError, OSError)):
        setup.check_audit_log_access(logs.active, logs.account)
    setup.command.assert_not_called()


def test_actual_denial_despite_valid_mode_bits_stops_without_repair(logs):
    setup.command.side_effect = RuntimeError('synthetic ACL or mandatory access denial')
    before = logs.active.read_bytes()
    with pytest.raises(ValueError, match='without supplementary groups'):
        setup.check_audit_log_access(logs.active, logs.account)
    assert logs.active.read_bytes() == before
    assert stat.S_IMODE(logs.active.stat().st_mode) == 0o640


def test_rotation_is_rechecked_and_does_not_assume_old_files_changed(logs):
    setup.check_audit_log_access(logs.active, logs.account)
    logs.active.rename(logs.directory / 'audit.log.2')
    logs.active.write_text('new active\n')
    logs.active.chmod(0o640)
    setup.command.reset_mock()
    setup.check_audit_log_access(logs.active, logs.account)
    assert setup.command.call_count == 3
    logs.owner(logs.directory / 'audit.log.2', 0, 4)
    setup.command.reset_mock()
    with pytest.raises(ValueError, match='old rotations separately'):
        setup.check_audit_log_access(logs.active, logs.account)
    setup.command.assert_not_called()


def test_already_dropped_reader_opens_active_and_rotations_read_only(logs, monkeypatch):
    monkeypatch.setattr(setup.os, 'getresuid', Mock(return_value=(1001, 1001, 1001)))
    monkeypatch.setattr(setup.os, 'getresgid', Mock(return_value=(1001, 1001, 1001)))
    monkeypatch.setattr(setup.os, 'getgroups', Mock(return_value=[]))
    files = setup.audit_group_files(logs.active, logs.account, read=True)
    assert len(files) == 2
    setup.command.assert_not_called()
    assert logs.rotated.read_text() == 'synthetic rotation\n'


def test_preflight_does_not_need_setfacl(logs, monkeypatch):
    def executable(path, mode):
        assert 'setfacl' not in path
        return True
    monkeypatch.setattr(setup.os, 'access', executable)
    assert 'no supplementary groups' in setup._preflight_reader_group({'log_group': 'mysql_siem'}, 'mysql_siem')


def test_group_preflight_checks_all_logs_and_reports_old_rotation(logs, monkeypatch):
    monkeypatch.setattr(setup, '_preflight_executables', Mock(return_value='ready'))
    monkeypatch.setattr(setup, '_preflight_auditd_active', Mock(return_value='active'))
    monkeypatch.setattr(setup, '_preflight_kernel_audit_status', Mock(return_value='active'))
    monkeypatch.setattr(setup, 'architectures', Mock(return_value=['b64']))
    monkeypatch.setattr(setup, 'preflight_targets', Mock(return_value=[]))
    monkeypatch.setattr(setup, 'preflight_rules', Mock(return_value='rules verified'))
    monkeypatch.setattr(setup, 'read_root_text', Mock(return_value='log_group=mysql_siem\n'))
    monkeypatch.setattr(setup, 'audit_logfile', Mock(return_value=logs.active))
    monkeypatch.setattr(setup.os, 'access', Mock(return_value=True))
    logs.owner(logs.rotated, 0, 4)
    results = setup.audit_preflight()
    statuses = []
    for status, name, _ in results:
        statuses.append((status, name))
    assert ('FAIL', 'audit log directory') in statuses
    setup.command.assert_not_called()


def test_systemd_input_is_read_only_and_launcher_keeps_privilege_drop():
    root = Path(__file__).resolve().parents[2]
    unit = (root / 'config/systemd/mysql-siem-audit.service').read_text()
    for line in unit.splitlines():
        if line.startswith('ReadWritePaths='):
            assert line == 'ReadWritePaths=/var/log/mysql_siem/audit'
    assert 'ProtectSystem=strict' in unit and 'NoNewPrivileges=true' in unit


@pytest.mark.parametrize('fault', ['root', 'saved-root', 'wrong-gid', 'adm'])
def test_in_process_read_never_accepts_privileged_ids_or_extra_groups(logs, monkeypatch, fault):
    uid = (1001, 1001, 1001)
    gid = (1001, 1001, 1001)
    groups = []
    if fault == 'root':
        uid = (0, 0, 0)
    elif fault == 'saved-root':
        uid = (1001, 1001, 0)
    elif fault == 'wrong-gid':
        gid = (4, 4, 4)
    else:
        groups = [4]
    monkeypatch.setattr(setup.os, 'getresuid', Mock(return_value=uid))
    monkeypatch.setattr(setup.os, 'getresgid', Mock(return_value=gid))
    monkeypatch.setattr(setup.os, 'getgroups', Mock(return_value=groups))
    with pytest.raises(ValueError, match='permanently dropped'):
        setup.audit_group_files(logs.active, logs.account, read=True)


def test_legacy_acls_and_other_readers_are_not_modified(logs, monkeypatch):
    import shutil
    import subprocess

    executable = shutil.which('setfacl')
    if executable is None:
        pytest.skip('Optional setfacl is needed only to create the legacy ACL test fixture.')
    for options in ([executable, '-m', 'u:12345:r--', str(logs.active)],
                    [executable, '-d', '-m', 'u:12345:r-x', str(logs.directory)]):
        result = subprocess.run(options, capture_output=True, check=False)
        if result.returncode != 0:
            pytest.skip('Temporary test filesystem does not support legacy POSIX ACL fixtures.')
    before_access = os.getxattr(logs.active, 'system.posix_acl_access')
    before_default = os.getxattr(logs.directory, 'system.posix_acl_default')
    for name in ('chmod', 'chown', 'fchmod', 'fchown', 'setxattr', 'removexattr'):
        monkeypatch.setattr(setup.os, name, Mock(side_effect=AssertionError('Read checks must not change permissions.')))
    setup.check_audit_log_access(logs.active, logs.account)
    assert os.getxattr(logs.active, 'system.posix_acl_access') == before_access
    assert os.getxattr(logs.directory, 'system.posix_acl_default') == before_default
    assert logs.active.read_text() == 'synthetic active\n'
