
"""Audit installation failures use temporary files and fake OS commands only."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from config import audit_setup as setup
from config import service_installation
from database import local_identity
from ingestion.audit import database


@pytest.fixture
def installation(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    units = project / 'config/systemd'
    units.mkdir(parents=True)
    shipped_units = Path(__file__).resolve().parents[2] / 'config/systemd'
    for name in setup.UNIT_NAMES:
        (units / name).write_bytes((shipped_units / name).read_bytes())
    rules = tmp_path / 'rules.d/50-mysql-siem.rules'
    rules.parent.mkdir()
    unit_dir = tmp_path / 'systemd'
    unit_dir.mkdir()
    config = tmp_path / 'auditd.conf'
    config.write_text('log_group = mysql_siem\nwrite_logs = yes\n')
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
        if arguments[:2] == ['/usr/bin/systemctl', 'show']:
            return 'LoadState=loaded\nFragmentPath=' + str(unit_dir / arguments[-1]) + '\nDropInPaths=\n'
        if arguments[:2] == ['/usr/bin/systemctl', 'is-enabled']:
            return 'enabled\n'
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
    monkeypatch.setattr(setup.grp, 'getgrnam', Mock(return_value=SimpleNamespace(gr_gid=1001)))
    monkeypatch.setattr(setup.os, 'access', Mock(return_value=True))
    monkeypatch.setattr(setup, 'source_status', Mock(return_value={}))
    monkeypatch.setattr(setup, 'check_audit_log_access', Mock())
    monkeypatch.setattr(local_identity, 'atomic_write', write)
    return state


def prepare(state):
    setup.install_audit(state['project'], state['targets'])


def test_repeated_prepare_preserves_original_configuration_and_unrelated_rules(installation):
    state = installation
    unrelated = '-a always,exit -F arch=b64 -F path=/other -F perm=wa -k other_program'
    state['active'].append(unrelated)
    original = state['config'].read_text()
    prepare(state)
    first = list(state['active'])
    state['writes'].clear()
    prepare(state)
    for name in setup.UNIT_NAMES:
        installed = setup.UNIT_DIR / name
        assert installed.read_bytes() == (state['project'] / 'config/systemd' / name).read_bytes()
        for path, _content, _options in state['writes']:
            assert path != installed
    assert state['active'] == first
    assert unrelated in state['active']
    assert state['config'].read_text() == original
    assert not state['config'].with_name('.mysql-siem-auditd.conf.original').exists()
    for arguments in state['commands']:
        assert '-D' not in arguments
        assert '--load' not in arguments
        assert arguments != ['/usr/sbin/auditctl', '--signal', 'reload']
    manifest = state['project'] / 'config/audit-runtime.json'
    assert json.loads(manifest.read_text())['target_statuses'] == {'/etc/passwd': 'PRESENT'}
    setup.check_audit_log_access.assert_called_with(
        setup.audit_logfile({'log_group': 'mysql_siem'}),
        SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_name='mysql_siem')
    )


@pytest.mark.parametrize('active', [
    '-a never,task', '-a never,exit -F arch=b64',
    '-a always,exit -F arch=b64 -F path=/other -F perm=wa -k siem_passwd',
])
def test_conflicting_or_suppressing_rule_stops_before_writes(installation, active):
    installation['active'].append(active)
    with pytest.raises(ValueError):
        prepare(installation)
    assert installation['writes'] == []
    setup.check_audit_log_access.assert_not_called()


def test_immutable_missing_rule_stops_before_any_writes(installation):
    installation['immutable'] = True
    original = installation['config'].read_text()
    with pytest.raises(ValueError, match='immutable'):
        prepare(installation)
    assert not installation['rules'].exists()
    assert installation['writes'] == []
    assert installation['config'].read_text() == original
    assert installation['active'] == []
    assert not (installation['project'] / 'config/audit-runtime.json').exists()
    setup.check_audit_log_access.assert_not_called()


def test_existing_unmanaged_rule_file_is_preserved(installation):
    installation['rules'].write_text('owned by another program\n')
    with pytest.raises(ValueError, match='another administrator'):
        prepare(installation)
    assert installation['rules'].read_text() == 'owned by another program\n'
    assert installation['writes'] == []


@pytest.mark.parametrize('fault', ['permissions', 'rule', 'read-probe'])
def test_partial_preparation_failure_keeps_maintenance_and_does_not_publish_manifest(
    installation, monkeypatch, fault
):
    state = installation
    maintenance = state['directory'] / 'maintenance'
    maintenance.write_text(setup.installation_state.MAINTENANCE_TEXT)
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(setup, 'audit_preflight', Mock(return_value=[('PASS', 'ready', 'ready')]))
    monkeypatch.setattr(setup.installation_state, 'require_maintenance', Mock())
    connection = MagicMock()
    monkeypatch.setattr(pymysql, 'connect', Mock(return_value=connection))
    monkeypatch.setattr(database, 'load_targets', Mock(return_value=state['targets']))
    if fault == 'permissions':
        setup.check_audit_log_access.side_effect = OSError('synthetic permission error')
    elif fault == 'rule':
        state['fail'] = ['/usr/sbin/auditctl', '-a', 'always,exit', '-F', 'arch=b64',
                         '-F', 'path=/etc/passwd', '-F', 'perm=wa', '-k', 'siem_passwd']
    else:
        setup.check_audit_log_access.side_effect = RuntimeError('synthetic read probe failed')
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


@pytest.fixture
def activation(installation, monkeypatch):
    state = installation
    prepare(state)
    state['commands'].clear()
    state['writes'].clear()
    maintenance = state['directory'] / 'maintenance'
    maintenance.write_text(setup.installation_state.MAINTENANCE_TEXT)
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=0))

    def guard(path):
        if not (path / 'maintenance').exists():
            raise ValueError('Missing maintenance barrier')

    monkeypatch.setattr(setup.installation_state, 'require_maintenance', guard)
    monkeypatch.setattr(setup.installation_state, 'read_deployment', Mock(return_value={'target': str(state['project'])}))
    monkeypatch.setattr(service_installation, 'verify_publication', Mock())
    return state


def test_activation_succeeds_under_maintenance_without_releasing_jobs(activation):
    assert setup.main(['activate', '--project', str(activation['project'])]) == 0
    assert (activation['directory'] / 'maintenance').exists()
    assert activation['writes'] == []
    assert ['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql-siem-audit.timer'] in activation['commands']


@pytest.mark.parametrize('failure', ['daemon-reload', 'enable', 'manifest', 'maintenance', 'is-active'])
def test_activation_failure_keeps_existing_maintenance(activation, failure):
    state = activation
    if failure in ('daemon-reload', 'enable', 'is-active'):
        state['fail'] = {
            'daemon-reload': ['/usr/bin/systemctl', 'daemon-reload'],
            'enable': ['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer'],
            'is-active': ['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql-siem-audit.timer'],
        }[failure]
    elif failure == 'manifest':
        (state['project'] / 'config/audit-runtime.json').write_text('{invalid')
    else:
        (state['directory'] / 'maintenance').unlink()
    assert setup.main(['activate', '--project', str(state['project'])]) == 1
    assert (state['directory'] / 'maintenance').exists() == (failure != 'maintenance')
    assert state['writes'] == []
    if failure in ('manifest', 'maintenance'):
        assert state['commands'] == []


@pytest.mark.parametrize('fault', ['lock', 'publication', 'target', 'unit', 'runtime-only', 'overrides'])
def test_unverified_activation_never_releases_maintenance(activation, monkeypatch, fault):
    state = activation
    if fault == 'lock':
        monkeypatch.setattr(setup.installation_state, 'require_maintenance', Mock(side_effect=ValueError('missing lock')))
    elif fault == 'publication':
        service_installation.verify_publication.side_effect = ValueError('wrong publication')
    elif fault == 'target':
        setup.installation_state.read_deployment.return_value['target'] = '/other'
    elif fault == 'unit':
        (setup.UNIT_DIR / setup.UNIT_NAMES[0]).write_text(setup.MARKER + 'changed unit')
    else:
        original = setup.command

        def command(arguments):
            if fault == 'runtime-only' and 'is-enabled' in arguments:
                return 'enabled-runtime\n'
            output = original(arguments)
            if fault == 'overrides' and 'show' in arguments:
                output = output.replace('DropInPaths=', 'DropInPaths=/unreviewed.conf')
            return output

        monkeypatch.setattr(setup, 'command', command)
    assert setup.main(['activate', '--project', str(state['project'])]) == 1
    assert (state['directory'] / 'maintenance').exists()
    assert state['writes'] == []
    if fault in ('lock', 'publication', 'target', 'unit'):
        assert state['commands'] == []
    if fault in ('lock', 'publication', 'target', 'unit', 'overrides'):
        assert ['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer'] not in state['commands']


def test_nonroot_activation_does_not_attempt_privileged_state_write(installation, monkeypatch):
    monkeypatch.setattr(setup.os, 'geteuid', Mock(return_value=1000))
    assert setup.main(['activate', '--project', str(installation['project'])]) == 1
    assert installation['writes'] == []
    assert installation['commands'] == []


@pytest.mark.parametrize('name', setup.UNIT_NAMES)
def test_shipped_unit_is_managed_and_unchanged_content_is_not_rewritten(installation, name):
    source = installation['project'] / 'config/systemd' / name
    content = source.read_text()
    installed = setup.UNIT_DIR / name
    assert content.startswith(setup.MARKER)
    assert setup.write_managed(installed, content) is True
    assert setup.managed_file_text(installed) == content
    inode = installed.stat().st_ino
    installation['writes'].clear()
    assert setup.write_managed(installed, content) is False
    assert installation['writes'] == []
    assert installed.stat().st_ino == inode
    assert installed.read_bytes() == source.read_bytes()


@pytest.mark.parametrize('name', setup.UNIT_NAMES)
def test_foreign_unit_is_never_replaced(installation, name):
    installed = setup.UNIT_DIR / name
    content = '# Managed by another program.\n[Unit]\n'
    installed.write_text(content)
    inode = installed.stat().st_ino
    with pytest.raises(ValueError, match='another administrator'):
        prepare(installation)
    assert installed.read_text() == content
    assert installed.stat().st_ino == inode
    for path, _content, _options in installation['writes']:
        assert path != installed
    assert not (installation['project'] / 'config/audit-runtime.json').exists()


def test_retry_after_first_unit_write_preserves_it_and_completes_preparation(installation, monkeypatch):
    first = setup.UNIT_DIR / setup.UNIT_NAMES[0]
    second = setup.UNIT_DIR / setup.UNIT_NAMES[1]
    manifest = installation['project'] / 'config/audit-runtime.json'
    write = local_identity.atomic_write

    def interrupt_after_first_unit(path, content, **options):
        write(path, content, **options)
        if path == first:
            raise InterruptedError('synthetic interruption after the first unit was written')

    with monkeypatch.context() as patch:
        patch.setattr(local_identity, 'atomic_write', interrupt_after_first_unit)
        with pytest.raises(InterruptedError, match='first unit'):
            prepare(installation)
    assert first.exists()
    assert not second.exists()
    assert not manifest.exists()
    inode = first.stat().st_ino
    installation['writes'].clear()
    prepare(installation)
    assert first.stat().st_ino == inode
    for path, _content, _options in installation['writes']:
        assert path != first
    for name in setup.UNIT_NAMES:
        source = installation['project'] / 'config/systemd' / name
        assert (setup.UNIT_DIR / name).read_bytes() == source.read_bytes()
    assert manifest.exists()


@pytest.fixture
def unit_preflight(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    source = project / 'config/systemd'
    source.mkdir(parents=True)
    destination = tmp_path / 'systemd'
    destination.mkdir()
    shipped = Path(__file__).resolve().parents[2] / 'config/systemd'
    for name in setup.UNIT_NAMES:
        content = (shipped / name).read_bytes()
        (source / name).write_bytes(content)
        (source / name).chmod(0o640)
        (destination / name).write_bytes(content)
        (destination / name).chmod(0o640)
    state = {'project': project, 'source': source, 'destination': destination, 'wrong_owner': None}
    original_fstat = os.fstat

    def metadata(descriptor):
        info = original_fstat(descriptor)
        values = list(info)
        values[4] = 1001 if info.st_ino == state['wrong_owner'] else 0
        return os.stat_result(values)

    monkeypatch.setattr(setup, 'UNIT_DIR', destination)
    monkeypatch.setattr(setup, 'trusted_directory', Mock())
    monkeypatch.setattr(setup.os, 'fstat', metadata)
    return state


@pytest.mark.parametrize('installed', [False, True])
def test_unit_preflight_reads_real_sources_and_destinations_without_writing(unit_preflight, installed):
    state = unit_preflight
    if not installed:
        for name in setup.UNIT_NAMES:
            (state['destination'] / name).unlink()
    before = {}
    for directory in (state['source'], state['destination']):
        for name in setup.UNIT_NAMES:
            path = directory / name
            if path.exists():
                before[path] = (path.read_bytes(), path.stat().st_ino, path.stat().st_mode)
    assert 'Both Audit units' in setup.preflight_audit_units(state['project'])
    for path, expected in before.items():
        assert (path.read_bytes(), path.stat().st_ino, path.stat().st_mode) == expected
    for name in setup.UNIT_NAMES:
        assert (state['destination'] / name).exists() == installed


@pytest.mark.parametrize('name', setup.UNIT_NAMES)
@pytest.mark.parametrize('fault', ['source-marker', 'destination-marker', 'source-link',
                                  'destination-link', 'destination-hardlink',
                                  'destination-owner', 'destination-write', 'directory'])
def test_unit_preflight_rejects_unsafe_sources_and_destinations(unit_preflight, name, fault, tmp_path):
    state = unit_preflight
    source = state['source'] / name
    destination = state['destination'] / name
    unrelated = tmp_path / 'unrelated'
    unrelated.write_text('preserve this file\n')
    if fault == 'source-marker':
        source.write_text('\n' + source.read_text())
    elif fault == 'destination-marker':
        destination.write_text('# Owned by another program.\n')
    elif fault in ('source-link', 'destination-link'):
        path = source if fault == 'source-link' else destination
        path.unlink()
        path.symlink_to(unrelated)
    elif fault == 'destination-hardlink':
        destination.unlink()
        destination.hardlink_to(unrelated)
    elif fault == 'destination-owner':
        state['wrong_owner'] = destination.stat().st_ino
    elif fault == 'destination-write':
        destination.chmod(0o660)
    else:
        setup.trusted_directory.side_effect = ValueError('unsafe unit directory')
    before = destination.read_bytes()
    with pytest.raises((OSError, ValueError)):
        setup.preflight_audit_units(state['project'])
    assert destination.read_bytes() == before
    assert unrelated.read_text() == 'preserve this file\n'


@pytest.mark.parametrize('rule', [
    '-a never,exclude -F msgtype=SYSCALL',
    '-a exclude,never -F msgtype=1302',
    '-a always,exclude -F msgtype=CWD',
    '-a never,exclude -F msgtype=0001300',
    '-a never,exclude -F uid=1000',
    '-a never,exclude -F msgtype!=AVC',
    '-a never,exclude -F msgtype!=SYSCALL',
])
def test_required_record_exclusions_stop_before_any_installation_writes(installation, rule):
    installation['active'].append(rule)
    with pytest.raises(ValueError, match='exclude rule may suppress'):
        prepare(installation)
    assert installation['writes'] == []
    assert installation['active'] == [rule]


@pytest.mark.parametrize('rule', [
    '-a never,exclude -F msgtype=AVC',
    '-a exclude,never -F msgtype=1400 -F uid=1000',
    '-a never,exclude -F msgtype=PROCTITLE',
    '-a never,exclude -F msgtype=EOE',
    '-a never,exclude -F msgtype!=SYSCALL -F msgtype!=PATH -F msgtype!=CWD',
    '-a never,user -F msgtype=USER_LOGIN',
])
def test_unrelated_record_exclusions_are_accepted_and_preserved(installation, rule):
    installation['active'].append(rule)
    prepare(installation)
    assert rule in installation['active']
    setup.verify_rules(setup.rule_lines(installation['targets'], ['b64']), '\n'.join(installation['active']))


def test_pending_permission_migration_blocks_timer_start(activation):
    marker = activation['directory'] / 'audit-permissions.pending'
    marker.write_text('Permission migration is incomplete.\n')
    assert setup.main(['activate', '--project', str(activation['project'])]) == 1
    assert activation['commands'] == []
    assert (activation['directory'] / 'maintenance').exists()
