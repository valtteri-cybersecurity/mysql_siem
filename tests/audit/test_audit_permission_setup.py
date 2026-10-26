"""Automatic permission migration uses private files, real ACL xattrs and fake auditd."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from config import audit_permissions as permissions


def acl(group=4, mask=4):
    return {'user:': 6, 'group:': group, 'mask:': mask, 'other:': 0}


@pytest.fixture
def account():
    return SimpleNamespace(pw_uid=10001, pw_gid=10002, pw_name='mysql_siem')


@pytest.mark.parametrize('directory', [False, True])
@pytest.mark.parametrize('mask', [0, 4, 5])
def test_effective_reader_policy_is_preserved_without_unmasking_writes(account, directory, mask):
    old = acl(5 if directory else 4, mask)
    rights = 7 if directory else 6
    old.update({'user:55': 0, 'user:56': rights, 'group:8': rights})
    # Masked write permissions must never become effective after normalization.
    if not directory and mask & 1:
        with pytest.raises(ValueError, match='Executable Audit log'):
            permissions.migrated_acl(old, 4, account, directory=directory)
        return
    new = permissions.migrated_acl(old, 4, account, directory=directory)
    for uid in (50, 55, 56):
        for groups in ([], [4], [8], [4, 8]):
            assert permissions.permission_for(old, uid, groups, 0, 4) == permissions.permission_for(
                new, uid, groups, 0, account.pw_gid)
    assert not new['user:56'] & 2
    assert not new['group:8'] & 2
    assert permissions.permission_for(new, account.pw_uid, [account.pw_gid], 0, account.pw_gid) & 4


def test_named_worker_denial_is_replaced_only_for_the_worker(account):
    old = acl()
    old.update({'user:10001': 0, 'user:55': 0})
    new = permissions.migrated_acl(old, 4, account)
    assert new['user:10001'] == 4
    assert new['user:55'] == 0
    assert new['group:4'] == 4


@pytest.mark.parametrize('group', [0, 4])
def test_default_acl_preserves_previous_future_file_policy(account, group):
    old = {'user:': 7, 'group:': 5, 'mask:': 5, 'other:': 0, 'user:55': 5, 'group:8': 7}
    future = permissions.future_acl(old, group, account)
    for uid in (50, 55):
        for groups in ([], [4], [8], [4, 8]):
            before = dict(old, **{'mask:': 4 if group else 0})
            after = dict(future, **{'mask:': 4})
            assert permissions.permission_for(before, uid, groups, 0, group) == permissions.permission_for(
                after, uid, groups, 0, account.pw_gid)


def test_no_default_acl_does_not_extend_named_current_readers_to_future_logs(account):
    future = permissions.future_acl({}, 4, account)
    assert future['group:4'] == 4
    assert 'user:55' not in future
    assert permissions.future_acl({}, account.pw_gid, account) == {}


@pytest.mark.parametrize('text', [
    'log_group = adm\nwrite_logs = yes\n',
    '# untouched\n  LOG_GROUP = adm # reader policy\r\nflush = incremental\r\n',
    'write_logs = yes\n',
])
def test_only_log_group_is_changed_and_updates_are_idempotent(text):
    updated = permissions.configuration_text(text)
    assert permissions.audit.parse_audit_configuration(updated)['log_group'] == 'mysql_siem'
    assert permissions.configuration_text(updated) == updated
    if 'flush = ' in text:
        assert '# reader policy\r\nflush = incremental\r\n' in updated
    assert updated.count('mysql_siem') == 1


@pytest.mark.parametrize('text', ['log_group=adm\nlog_group=root\n', 'log_group adm\n'])
def test_invalid_or_duplicate_configuration_is_rejected(text):
    with pytest.raises(ValueError):
        permissions.configuration_text(text)


@pytest.fixture
def environment(tmp_path, monkeypatch, account):
    directory = tmp_path / 'audit'
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    logfile = directory / 'audit.log'
    for name, mode in (('audit.log', 0o640), ('audit.log.1', 0o440), ('audit.log.2', 0o640)):
        path = directory / name
        path.write_bytes(b'private synthetic event\n')
        path.chmod(mode)
    config = tmp_path / 'auditd.conf'
    config.write_text('# keep comment\nlog_group = adm\nwrite_logs = yes\n')
    config.chmod(0o640)
    state = tmp_path / 'state'
    state.mkdir()
    owners = {}
    original_fstat = os.fstat
    original_chown = os.fchown

    def fstat(descriptor):
        info = original_fstat(descriptor)
        path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
        if path == directory or path.parent == directory:
            values = list(info)
            values[5] = owners.get((info.st_dev, info.st_ino), 4)
            return os.stat_result(values)
        return info

    def chown(descriptor, uid, gid):
        path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
        if path == directory or path.parent == directory:
            info = original_fstat(descriptor)
            owners[(info.st_dev, info.st_ino)] = gid
        else:
            original_chown(descriptor, uid, gid)

    def preflight(**kwargs):
        return [('PASS', 'kernel and rules', 'verified'),
                ('PASS' if 'mysql_siem' in config.read_text() else 'FAIL', 'audit log reader group', 'group'),
                ('PASS' if all(owners.get((path.stat().st_dev, path.stat().st_ino)) == account.pw_gid
                               for path in (directory, *directory.iterdir())) else 'FAIL', 'audit log directory', 'files')]

    monkeypatch.setattr(permissions, 'OWNER', os.geteuid())
    monkeypatch.setattr(permissions, 'check_parents', Mock())
    monkeypatch.setattr(permissions, 'account_and_group', Mock(return_value=account))
    monkeypatch.setattr(permissions, 'probe_readers', Mock(return_value=2))
    monkeypatch.setattr(permissions, 'reload_auditd', Mock())
    monkeypatch.setattr(permissions.os, 'fstat', fstat)
    monkeypatch.setattr(permissions.os, 'fchown', chown)
    monkeypatch.setattr(permissions.audit, 'CONFIG_FILE', config)
    monkeypatch.setattr(permissions.audit, 'audit_logfile', lambda values: logfile)
    monkeypatch.setattr(permissions.audit, 'inspect_audit_log_directory', Mock())
    monkeypatch.setattr(permissions.audit, 'read_root_text', lambda path, **kwargs: path.read_text())
    monkeypatch.setattr(permissions.audit, 'trusted_directory', Mock())
    monkeypatch.setattr(permissions.audit, 'audit_preflight', preflight)
    monkeypatch.setattr(permissions.state, 'STATE_DIR', state)
    monkeypatch.setattr(permissions.state, 'trusted_state', Mock())
    monkeypatch.setattr(permissions.state, 'require_install_lock', Mock())
    monkeypatch.setattr(permissions.state, 'read_deployment', Mock(return_value={
        'phase': 'staged', 'stage': '/synthetic/project', 'user': 'mysql_siem'}))
    return SimpleNamespace(directory=directory, logfile=logfile, config=config, state=state,
                           owners=owners, account=account)


@pytest.mark.parametrize('distribution', ['Ubuntu 24.04', 'Debian 13', 'Linux Mint'])
def test_common_adm_environment_is_migrated_without_changing_log_inodes_or_contents(environment, distribution):
    env = environment
    before = {}
    for path in env.directory.iterdir():
        before[path.name] = path.stat().st_ino, path.read_bytes()
    original = env.config.read_text()
    assert permissions.prepare_permissions(Path('/synthetic/project'), 'reset', confirm=lambda _: 'AUDIT')
    assert env.config.read_text() == original.replace('log_group = adm', 'log_group = mysql_siem')
    assert env.config.stat().st_mode & 0o777 == 0o640
    assert not (env.state / permissions.PENDING).exists()
    backup = json.loads((env.state / permissions.BACKUP).read_text())
    assert backup['phase'] == 'complete'
    assert backup['original'] == original
    for path in env.directory.iterdir():
        assert (path.stat().st_ino, path.read_bytes()) == before[path.name]
        with path.open('rb') as stream:
            entry = permissions.read_acl(stream.fileno())
        assert entry['group:4'] == 4
        assert env.owners[(path.stat().st_dev, path.stat().st_ino)] == env.account.pw_gid
    permissions.reload_auditd.assert_called_once()
    # Repeated installation performs no mutation, approval or reload.
    permissions.reload_auditd.reset_mock()
    assert not permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade',
                                               confirm=Mock(side_effect=AssertionError('Unexpected approval')))
    permissions.reload_auditd.assert_not_called()


def test_declined_audit_approval_changes_nothing(environment):
    env = environment
    before = env.config.read_bytes()
    with pytest.raises(ValueError, match='declined'):
        permissions.prepare_permissions(Path('/synthetic/project'), 'reset', confirm=lambda _: 'no')
    assert env.config.read_bytes() == before
    assert list(env.state.iterdir()) == []
    assert env.owners == {}
    permissions.reload_auditd.assert_not_called()


@pytest.mark.parametrize('fault', ['symlink', 'hardlink', 'unexpected', 'world-readable', 'unsafe-directory'])
def test_unsafe_inventory_stops_before_approval_or_changes(environment, fault):
    env = environment
    if fault == 'symlink':
        env.logfile.unlink()
        env.logfile.symlink_to(env.directory / 'audit.log.1')
    elif fault == 'hardlink':
        os.link(env.logfile, env.directory / 'audit.log.3')
    elif fault == 'unexpected':
        (env.directory / 'unexpected').touch()
    elif fault == 'world-readable':
        env.logfile.chmod(0o644)
    else:
        env.directory.chmod(0o770)
    with pytest.raises((OSError, ValueError)):
        permissions.prepare_permissions(Path('/synthetic/project'), 'reset',
                                        confirm=Mock(side_effect=AssertionError('Unexpected approval')))
    assert list(env.state.iterdir()) == []
    permissions.reload_auditd.assert_not_called()


@pytest.mark.parametrize('fault', ['permissions', 'reload', 'postflight'])
def test_partial_failure_keeps_barrier_and_forward_recovery_preserves_backup(environment, monkeypatch, fault):
    env = environment
    original_acl = permissions.write_acl
    if fault == 'permissions':
        calls = []

        def fail(descriptor, acl, **kwargs):
            calls.append(descriptor)
            if len(calls) == 3:
                raise OSError('synthetic permission failure')
            original_acl(descriptor, acl, **kwargs)

        monkeypatch.setattr(permissions, 'write_acl', fail)
    elif fault == 'reload':
        permissions.reload_auditd.side_effect = ValueError('reload failed')
    else:
        original_preflight = permissions.audit.audit_preflight
        calls = []

        def preflight(**kwargs):
            calls.append(1)
            if len(calls) > 1:
                return [('FAIL', 'kernel Audit status', 'not verified')]
            return original_preflight(**kwargs)

        monkeypatch.setattr(permissions.audit, 'audit_preflight', preflight)
    with pytest.raises((OSError, ValueError)):
        permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade', confirm=lambda _: 'AUDIT')
    assert (env.state / permissions.PENDING).exists()
    before = json.loads((env.state / permissions.BACKUP).read_text())
    assert before['phase'] == 'prepared'
    monkeypatch.setattr(permissions, 'write_acl', original_acl)
    permissions.reload_auditd.side_effect = None
    if fault == 'postflight':
        monkeypatch.setattr(permissions.audit, 'audit_preflight', original_preflight)
    assert permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade',
                                          confirm=Mock(side_effect=AssertionError('Recovery was already approved')))
    after = json.loads((env.state / permissions.BACKUP).read_text())
    assert after['original'] == before['original']
    assert after['entries'] == before['entries']
    assert not (env.state / permissions.PENDING).exists()


def test_rotation_during_migration_blocks_without_touching_unknown_new_inode(environment, monkeypatch):
    env = environment
    original = permissions.reload_auditd

    def rotate(descriptor):
        env.logfile.rename(env.directory / 'audit.log.3')
        env.logfile.write_bytes(b'new inode\n')

    monkeypatch.setattr(permissions, 'reload_auditd', rotate)
    with pytest.raises(ValueError, match='rotation|inventory'):
        permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade', confirm=lambda _: 'AUDIT')
    assert env.logfile.read_bytes() == b'new inode\n'
    assert (env.state / permissions.PENDING).exists()
    monkeypatch.setattr(permissions, 'reload_auditd', original)


@pytest.mark.parametrize('old_gid', [0, 4])
@pytest.mark.parametrize('old_default', [{}, {'user:': 7, 'group:': 0, 'mask:': 5, 'other:': 0, 'user:55': 0}])
def test_transitional_default_acl_neither_expands_nor_removes_other_future_readers(account, old_gid, old_default):
    bridge = permissions.future_bridge(old_default, old_gid, account)
    if not bridge:
        return
    baseline = old_default or {'user:': 7, 'group:': 4, 'mask:': 4, 'other:': 0}
    before = dict(baseline, **{'mask:': baseline['mask:'] & (4 if old_gid else 0), 'other:': 0})
    for uid in (50, 55):
        for groups in ([], [4], [8], [4, 8]):
            expected = permissions.permission_for(before, uid, groups, 0, old_gid)
            for current_gid in (old_gid, account.pw_gid):
                inherited = dict(bridge, **{'mask:': 4 if current_gid else 0})
                assert permissions.permission_for(inherited, uid, groups, 0, current_gid) == expected


def test_real_default_acl_inheritance_and_auditd_chmod_keep_readers(environment):
    env = environment
    permissions.prepare_permissions(Path('/synthetic/project'), 'reset', confirm=lambda _: 'AUDIT')
    path = env.directory / 'audit.log.3'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        os.write(fd, b'new synthetic event\n')
        inherited = permissions.read_acl(fd)
        assert inherited['group:4'] == 4
        os.fchmod(fd, 0o440)  # auditd performs this when retaining a rotation.
        assert permissions.read_acl(fd)['group:4'] & permissions.read_acl(fd)['mask:'] == 4
    finally:
        os.close(fd)


@pytest.mark.parametrize('fault', ['unknown-field', 'acl-plan', 'identity'])
def test_invalid_partial_backup_is_preserved_without_more_mutations(environment, fault):
    env = environment
    permissions.reload_auditd.side_effect = ValueError('synthetic reload failure')
    with pytest.raises(ValueError):
        permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade', confirm=lambda _: 'AUDIT')
    path = env.state / permissions.BACKUP
    record = json.loads(path.read_text())
    if fault == 'unknown-field':
        record['unknown'] = True
    elif fault == 'identity':
        record['gid'] += 1
    else:
        record['entries'][str(env.logfile)]['new']['group:4'] = 6
    permissions.state.write_file(path, json.dumps(record))
    before = path.read_bytes(), env.config.read_bytes()
    with pytest.raises(ValueError):
        permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade', confirm=lambda _: 'AUDIT')
    assert (path.read_bytes(), env.config.read_bytes()) == before
    assert (env.state / permissions.PENDING).exists()


def test_unrelated_preflight_failure_never_asks_for_audit_approval(environment, monkeypatch):
    monkeypatch.setattr(permissions.audit, 'audit_preflight', Mock(return_value=[('FAIL', 'kernel Audit status', 'unsafe')]))
    with pytest.raises(ValueError, match='preflight failed'):
        permissions.prepare_permissions(Path('/synthetic/project'), 'reset',
                                        confirm=Mock(side_effect=AssertionError('Unexpected approval')))
    assert list(environment.state.iterdir()) == []


@pytest.mark.parametrize('fault', ['missing', 'wrong-primary', 'shared'])
def test_missing_or_shared_private_group_stops_before_mutations(environment, monkeypatch, fault):
    error = ValueError('private group is not safe: ' + fault)
    monkeypatch.setattr(permissions, 'account_and_group', Mock(side_effect=error))
    before = environment.config.read_bytes()
    with pytest.raises(ValueError, match='private group'):
        permissions.prepare_permissions(Path('/synthetic/project'), 'reset', confirm=lambda _: 'AUDIT')
    assert environment.config.read_bytes() == before
    assert list(environment.state.iterdir()) == []


@pytest.mark.parametrize('correct_pid', [False, True])
def test_reload_requires_its_own_daemon_acknowledgement_without_real_signals(tmp_path, monkeypatch, correct_pid):
    logfile = tmp_path / 'audit.log'
    logfile.write_bytes(b'private event not printed\n')
    process_file = tmp_path / 'process'
    process_file.touch()
    original_stat = os.stat

    def fake_stat(path, *args, **kwargs):
        if str(path) in ('/proc/12345/exe', '/usr/sbin/auditd'):
            return SimpleNamespace(st_dev=1, st_ino=2)
        return original_stat(path, *args, **kwargs)

    def signal_process(descriptor, number):
        assert number == permissions.signal.SIGHUP
        pid = os.getpid() if correct_pid else os.getpid() + 1
        with logfile.open('ab') as stream:
            stream.write(('type=DAEMON_CONFIG msg=audit(1.0:1): op=reconfigure state=changed '
                          + 'auid=0 pid=' + str(pid) + ' subj=test res=success\n').encode())

    with logfile.open('rb') as stream, monkeypatch.context() as patch:
        patch.setattr(permissions.audit, 'source_status', Mock(return_value={'daemon_pid': 12345}))
        patch.setattr(permissions.os, 'stat', fake_stat)
        patch.setattr(permissions.os, 'pidfd_open', lambda pid: os.open(process_file, os.O_RDONLY))
        patch.setattr(permissions.signal, 'pidfd_send_signal', signal_process)
        ticks = iter([0, 0, 1, 20, 21])
        patch.setattr(permissions.time, 'monotonic', lambda: next(ticks))
        patch.setattr(permissions.time, 'sleep', Mock())
        if correct_pid:
            permissions.reload_auditd(stream.fileno())
        else:
            with pytest.raises(ValueError, match='did not acknowledge'):
                permissions.reload_auditd(stream.fileno())


def test_atomic_config_update_preserves_existing_acl_and_unrelated_settings(environment):
    env = environment
    with env.config.open('rb') as stream:
        original_acl = permissions.read_acl(stream.fileno())
        original_acl['user:7777'] = 4
        permissions.write_acl(stream.fileno(), original_acl)
    before = env.config.read_text()
    permissions.prepare_permissions(Path('/synthetic/project'), 'reset', confirm=lambda _: 'AUDIT')
    with env.config.open('rb') as stream:
        assert permissions.read_acl(stream.fileno()) == original_acl
    assert env.config.read_text() == before.replace('log_group = adm', 'log_group = mysql_siem')


def test_preexisting_identity_maintenance_is_never_removed(environment):
    env = environment
    permissions.state.write_file(env.state / 'maintenance', permissions.state.MAINTENANCE_TEXT, mode=0o644)
    permissions.state.write_file(env.state / 'runtime.lock', '', mode=0o644)
    assert permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade', confirm=lambda _: 'AUDIT')
    assert (env.state / 'maintenance').read_text() == permissions.state.MAINTENANCE_TEXT
    assert not (env.state / permissions.PENDING).exists()
    assert json.loads((env.state / permissions.BACKUP).read_text())['maintenance_owned'] is False


@pytest.mark.parametrize('point', ['before-config', 'after-config', 'after-reload', 'after-complete'])
def test_abrupt_permission_setup_blocks_old_installed_collectors_and_can_resume(environment, monkeypatch, point):
    env = environment
    original_replace = permissions.replace_configuration
    original_write = permissions.state.write_file
    original_reload = permissions.reload_auditd

    def replace(record):
        if point == 'before-config':
            os._exit(77)
        original_replace(record)
        if point == 'after-config':
            os._exit(77)

    def reload(descriptor):
        if point == 'after-reload':
            os._exit(77)

    def write(path, text, **kwargs):
        original_write(path, text, **kwargs)
        if point == 'after-complete' and path == env.state / permissions.BACKUP and json.loads(text)['phase'] == 'complete':
            os._exit(77)

    child = os.fork()
    if child == 0:
        try:
            monkeypatch.setattr(permissions, 'replace_configuration', replace)
            monkeypatch.setattr(permissions, 'reload_auditd', reload)
            monkeypatch.setattr(permissions.state, 'write_file', write)
            permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade', confirm=lambda _: 'AUDIT')
        finally:
            os._exit(99)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    assert (env.state / permissions.PENDING).exists()
    # Existing installed versions already honor this original marker.
    assert (env.state / 'maintenance').read_text() == permissions.state.MAINTENANCE_TEXT
    assert permissions.prepare_permissions(Path('/synthetic/project'), 'upgrade',
                                          confirm=Mock(side_effect=AssertionError('Already approved')))
    assert not (env.state / permissions.PENDING).exists()
    assert not (env.state / 'maintenance').exists()
    assert permissions.reload_auditd is original_reload
