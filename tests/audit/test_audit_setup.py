"""Audit installation failures use temporary files and fake OS commands only."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from config import audit_setup as setup
from database import local_identity
from ingestion.audit import database


@pytest.fixture
def installation(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    units = project / 'config/systemd'
    units.mkdir(parents=True)
    for name in setup.UNIT_NAMES:
        (units / name).write_text(setup.MARKER + '[Unit]\n')
    rules = tmp_path / 'rules.d/50-mysql-siem.rules'
    rules.parent.mkdir()
    unit_dir = tmp_path / 'systemd'
    unit_dir.mkdir()
    config = tmp_path / 'auditd.conf'
    config.write_text('log_group = root\nwrite_logs = yes\n')
    state_dir = tmp_path / 'state'
    state_dir.mkdir()
    state = {'project': project, 'rules': rules, 'config': config, 'directory': state_dir,
             'active': [], 'immutable': False, 'fail': None, 'commands': [], 'writes': []}
    targets = [{'name': 'passwd', 'audit_key': 'siem_passwd', 'files': ['/etc/passwd'],
                'directories': [], 'executables': []}]
    state['targets'] = targets

    def command(arguments):
        state['commands'].append(arguments)
        if arguments == state['fail']:
            raise RuntimeError('synthetic command failure')
        if arguments == ['/usr/sbin/auditctl', '-l']:
            return '\n'.join(state['active'])
        if arguments == ['/usr/sbin/auditctl', '-s']:
            return 'enabled 2\n' if state['immutable'] else 'enabled 1\n'
        if arguments[:2] == ['/usr/sbin/auditctl', '-a']:
            state['active'].append(' '.join(arguments[1:]))
        return ''

    def write(path, content, **options):
        state['writes'].append((path, content, options))
        path.write_text(content)
        path.chmod(options.get('mode', 0o600))

    monkeypatch.setattr(setup, 'RULES_FILE', rules)
    monkeypatch.setattr(setup, 'CONFIG_FILE', config)
    monkeypatch.setattr(setup, 'UNIT_DIR', unit_dir)
    monkeypatch.setattr(setup.installation_state, 'STATE_DIR', state_dir)
    monkeypatch.setattr(setup, 'trusted_directory', Mock())
    monkeypatch.setattr(setup, 'read_root_text', lambda path: path.read_text())
    monkeypatch.setattr(setup, 'command', command)
    monkeypatch.setattr(setup, 'architectures', Mock(return_value=['b64']))
    monkeypatch.setattr(setup, 'inspect_audit_targets', Mock(return_value=({'/etc/passwd'}, {'/etc/passwd': 'PRESENT'})))
    account = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name='mysql_siem')
    monkeypatch.setattr(setup.pwd, 'getpwnam', Mock(return_value=account))
    monkeypatch.setattr(setup.os, 'access', Mock(return_value=True))
    monkeypatch.setattr(setup, 'source_status', Mock(return_value={}))
    monkeypatch.setattr(setup, 'grant_log_read_access', Mock())
    monkeypatch.setattr(local_identity, 'atomic_write', write)
    return state


def prepare(state):
    setup.install_audit(state['project'], state['targets'])


def test_repeated_prepare_preserves_original_backup_and_unrelated_rules(installation):
    state = installation
    unrelated = '-a always,exit -F arch=b64 -F path=/other -F perm=wa -k other_program'
    state['active'].append(unrelated)
    original = state['config'].read_text()
    prepare(state)
    backup = state['config'].with_name('.mysql-siem-auditd.conf.original')
    assert backup.read_text() == original
    first = list(state['active'])
    prepare(state)
    assert state['active'] == first
    assert unrelated in state['active']
    assert backup.read_text() == original
    assert backup.stat().st_mode & 0o777 == 0o600
    assert state['config'].read_text() == 'log_group = mysql_siem\nwrite_logs = yes\n'
    for command in state['commands']:
        assert '-D' not in command
        assert '--load' not in command
    manifest = state['project'] / 'config/audit-runtime.json'
    assert json.loads(manifest.read_text())['target_statuses'] == {'/etc/passwd': 'PRESENT'}


@pytest.mark.parametrize('active', [
    '-a never,task', '-a never,exit -F arch=b64',
    '-a always,exit -F arch=b64 -F path=/other -F perm=wa -k siem_passwd',
])
def test_conflicting_or_suppressing_rule_stops_before_writes(installation, active):
    installation['active'].append(active)
    with pytest.raises(ValueError):
        prepare(installation)
    assert installation['writes'] == []
    setup.grant_log_read_access.assert_not_called()


def test_immutable_missing_rule_only_prepares_persistent_rules(installation):
    installation['immutable'] = True
    original = installation['config'].read_text()
    with pytest.raises(ValueError, match='immutable'):
        prepare(installation)
    assert installation['rules'].read_text().startswith(setup.MARKER)
    assert installation['config'].read_text() == original
    assert installation['active'] == []
    assert not (installation['project'] / 'config/audit-runtime.json').exists()
    setup.grant_log_read_access.assert_not_called()


def test_existing_unmanaged_rule_file_is_preserved(installation):
    installation['rules'].write_text('owned by another program\n')
    with pytest.raises(ValueError, match='another administrator'):
        prepare(installation)
    assert installation['rules'].read_text() == 'owned by another program\n'
    assert installation['writes'] == []


@pytest.mark.parametrize('fault', ['reload', 'permissions', 'rule', 'read-probe'])
def test_partial_preparation_failure_keeps_maintenance_and_does_not_publish_manifest(installation, monkeypatch, fault):
    state = installation
    maintenance = state['directory'] / 'maintenance'
    maintenance.write_text(setup.installation_state.MAINTENANCE_TEXT)
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(setup, 'audit_preflight', Mock(return_value=[('PASS', 'ready', 'ready')]))
    monkeypatch.setattr(setup.installation_state, 'require_maintenance', Mock())
    connection = MagicMock()
    monkeypatch.setattr(pymysql, 'connect', Mock(return_value=connection))
    monkeypatch.setattr(database, 'load_targets', Mock(return_value=state['targets']))
    if fault == 'reload':
        state['fail'] = ['/usr/sbin/auditctl', '--signal', 'reload']
    elif fault == 'permissions':
        setup.grant_log_read_access.side_effect = OSError('synthetic permission error')
    elif fault == 'rule':
        state['fail'] = ['/usr/sbin/auditctl', '-a', 'always,exit', '-F', 'arch=b64',
                         '-F', 'path=/etc/passwd', '-F', 'perm=wa', '-k', 'siem_passwd']
    else:
        state['fail'] = ['/usr/sbin/runuser', '-u', 'mysql_siem', '--', '/usr/bin/head', '-c', '1', '/var/log/audit/audit.log']
    assert setup.main(['prepare', '--project', str(state['project'])]) == 1
    assert maintenance.read_text() == setup.installation_state.MAINTENANCE_TEXT
    assert not (state['project'] / 'config/audit-runtime.json').exists()
    connection.close.assert_called_once()
    assert ['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer'] not in state['commands']


def test_failed_preflight_never_connects_or_writes(installation, monkeypatch):
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(setup, 'audit_preflight', Mock(return_value=[('FAIL', 'missing', 'missing')]))
    connect = Mock()
    monkeypatch.setattr(pymysql, 'connect', connect)
    assert setup.main(['prepare', '--project', str(installation['project'])]) == 1
    connect.assert_not_called()
    assert installation['writes'] == []
    assert installation['commands'] == []


@pytest.mark.parametrize('failure', ['daemon-reload', 'enable', 'manifest', 'maintenance'])
def test_activation_failure_restores_maintenance(installation, monkeypatch, failure):
    state = installation
    prepare(state)
    state['commands'].clear()
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=0))
    if failure == 'daemon-reload':
        state['fail'] = ['/usr/bin/systemctl', 'daemon-reload']
    elif failure == 'enable':
        state['fail'] = ['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer']
    elif failure == 'manifest':
        (state['project'] / 'config/audit-runtime.json').write_text('{invalid')
    else:
        (state['directory'] / 'maintenance').write_text(setup.installation_state.MAINTENANCE_TEXT)
    assert setup.main(['activate', '--project', str(state['project'])]) == 1
    assert (state['directory'] / 'maintenance').read_text() == setup.installation_state.MAINTENANCE_TEXT
    if failure in ('manifest', 'maintenance'):
        assert state['commands'] == []


def test_nonroot_activation_does_not_attempt_privileged_state_write(installation, monkeypatch):
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=1000))
    assert setup.main(['activate', '--project', str(installation['project'])]) == 1
    assert installation['writes'] == []
    assert installation['commands'] == []
