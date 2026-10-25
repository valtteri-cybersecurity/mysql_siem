
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from config import audit_launcher as launcher
from config import audit_setup as setup
from database import local_identity
from ingestion.audit import get
from ingestion.audit.targets import DEFAULT_TARGETS


def manifest():
    return {'version': 1, 'logfile': '/var/log/audit/audit.log', 'rules_sha256': 'a' * 64}


def test_manifest_with_and_without_target_statuses():
    previous = manifest()
    assert launcher.validate_manifest(previous) == previous
    current = manifest()
    current['target_statuses'] = {'/etc/passwd': 'PRESENT', '/etc/sudoers': 'NOT_INSTALLED'}
    assert launcher.validate_manifest(current) == current


@pytest.mark.parametrize('field,value', [
    ('version', 2), ('version', True), ('logfile', '/etc/shadow'),
    ('logfile', '/var/log/audit/../secret'), ('rules_sha256', 'invalid'),
    ('target_statuses', []), ('target_statuses', {'/etc/passwd': 'UNKNOWN'}),
    ('target_statuses', {'passwd': 'PRESENT'}), ('unexpected', 'value'),
])
def test_invalid_manifest_is_rejected(field, value):
    data = manifest()
    data[field] = value
    with pytest.raises(ValueError):
        launcher.validate_manifest(data)


@pytest.mark.parametrize('failure', [None, 'groups-remain', 'read-denied'])
def test_installer_manifest_reaches_unprivileged_worker(monkeypatch, failure):
    """Exercise the writer and launcher with all OS operations mocked."""
    project = Path('/synthetic/mysql_siem')
    account = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name='mysql_siem', pw_dir='/var/lib/mysql_siem')
    targets = []
    statuses = {}
    for definition in DEFAULT_TARGETS:
        target = dict(definition)
        target['audit_key'] = 'siem_' + target['name']
        targets.append(target)
        for kind in ('files', 'directories', 'executables'):
            for path in target[kind]:
                statuses[path] = 'PRESENT'
    expected = setup.rule_lines(targets, ['b64'])
    rules = setup.MARKER + '\n'.join(expected) + '\n'
    configuration = 'log_group = mysql_siem\n'
    written = {}

    def record_write(path, content, **options):
        written[str(path)] = content

    def read_text(path):
        if path == project / 'config/audit-runtime.json':
            return written[str(path)]
        if path == setup.RULES_FILE:
            return rules
        if path == setup.CONFIG_FILE:
            return configuration
        return setup.MARKER

    def command(arguments):
        if arguments == ['/usr/sbin/auditctl', '-l']:
            return '\n'.join(expected)
        if arguments == ['/usr/sbin/auditctl', '-s']:
            return 'enabled 1\n'
        return ''

    health = {'boot_id': '00000000-0000-0000-0000-000000000001', 'lost': 0, 'daemon_pid': 42}
    monkeypatch.setattr(setup.pwd, 'getpwnam', Mock(return_value=account))
    monkeypatch.setattr(setup.grp, 'getgrnam', Mock(return_value=SimpleNamespace(gr_gid=1001)))
    monkeypatch.setattr(setup.os, 'access', Mock(return_value=True))
    monkeypatch.setattr(setup, 'source_status', Mock(return_value=dict(health)))
    monkeypatch.setattr(setup, 'architectures', Mock(return_value=['b64']))
    monkeypatch.setattr(setup, 'inspect_audit_targets', Mock(return_value=(set(statuses), statuses)))
    monkeypatch.setattr(setup, 'command', command)
    monkeypatch.setattr(setup, 'read_root_text', read_text)
    monkeypatch.setattr(setup, 'write_managed', Mock())
    monkeypatch.setattr(setup, 'check_audit_log_access', Mock())
    monkeypatch.setattr(local_identity, 'atomic_write', record_write)
    setup.install_audit(project, targets)
    data = json.loads(written[str(project / 'config/audit-runtime.json')])
    assert data['target_statuses'] == statuses

    calls = []
    current_ids = {'uid': (0, 0, 0), 'gid': (0, 0, 0)}

    def drop_groups(groups):
        assert groups == []
        calls.append('groups')

    def drop_gid(real, effective, saved):
        current_ids['gid'] = (real, effective, saved)
        calls.append('gid')

    def drop_uid(real, effective, saved):
        current_ids['uid'] = (real, effective, saved)
        calls.append('uid')

    def exec_worker(path, arguments, environment):
        assert path == str(project / 'config/run_with_env.sh')
        assert current_ids['uid'] == (1001, 1001, 1001)
        assert current_ids['gid'] == (1001, 1001, 1001)
        assert '--automatic' in arguments
        assert environment['SIEM_AUDIT_LOGFILE'] == data['logfile']
        calls.append('exec')
        raise SystemExit(0)

    def read_logs_as_collector(logfile, reader, *, read=False):
        assert str(logfile) == '/var/log/audit/audit.log'
        assert reader == account and read is True
        assert current_ids['uid'] == (1001, 1001, 1001)
        assert current_ids['gid'] == (1001, 1001, 1001)
        assert launcher.os.getgroups() == []
        calls.append('read-active-and-rotations')
        if failure == 'read-denied':
            raise PermissionError('synthetic denied rotation')
        return []

    monkeypatch.setattr(setup, 'audit_group_files', read_logs_as_collector)
    monkeypatch.setattr(launcher, 'PROJECT', project)
    monkeypatch.setattr(launcher.sys, 'argv', ['audit_launcher.py'])
    monkeypatch.setattr(launcher.sys, 'path', list(launcher.sys.path))
    monkeypatch.setattr(launcher.Path, 'lstat', Mock(return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0)))
    monkeypatch.setattr(launcher.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(get, 'source_status', Mock(return_value=dict(health)))
    monkeypatch.setattr(launcher.os, 'chdir', Mock())
    monkeypatch.setattr(launcher.os, 'umask', Mock())
    monkeypatch.setattr(launcher.os, 'setgroups', drop_groups)
    monkeypatch.setattr(launcher.os, 'setresgid', drop_gid)
    monkeypatch.setattr(launcher.os, 'setresuid', drop_uid)
    monkeypatch.setattr(launcher.os, 'getresgid', lambda: current_ids['gid'])
    monkeypatch.setattr(launcher.os, 'getresuid', lambda: current_ids['uid'])
    monkeypatch.setattr(launcher.os, 'getgroups', Mock(return_value=[4] if failure == 'groups-remain' else []))
    monkeypatch.setattr(launcher.os, 'execve', exec_worker)
    if failure is None:
        with pytest.raises(SystemExit) as result:
            launcher.launch()
        assert result.value.code == 0
        assert calls == ['groups', 'gid', 'uid', 'read-active-and-rotations', 'exec']
    else:
        with pytest.raises((ValueError, PermissionError)):
            launcher.launch()
        assert 'exec' not in calls
        assert calls[:3] == ['groups', 'gid', 'uid']
    setup.check_audit_log_access.assert_called()
