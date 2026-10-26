"""Read-only rule planning: no real Audit commands or database connections."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from config import audit_setup as setup


@pytest.fixture
def rules(monkeypatch):
    targets = [{'name': 'passwd', 'audit_key': 'siem_passwd', 'files': ['/etc/passwd'],
                'directories': [], 'executables': []}]
    state = {'active': '', 'status': 'enabled 1\n', 'calls': [], 'targets': targets}

    def command(arguments):
        state['calls'].append(arguments)
        if arguments == ['/usr/sbin/auditctl', '-l']:
            return state['active']
        if arguments == ['/usr/sbin/auditctl', '-s']:
            return state['status']
        pytest.fail('Preflight attempted a mutating/unexpected command: ' + str(arguments))

    monkeypatch.setattr(setup, 'command', command)
    monkeypatch.setattr(setup, 'inspect_audit_targets', Mock(return_value=(
        {'/etc/passwd'}, {'/etc/passwd': 'PRESENT'})))
    return state


@pytest.mark.parametrize('immutable,installed', [(False, False), (False, True), (True, True)])
def test_mutable_missing_and_approved_immutable_rules_are_accepted(rules, immutable, installed):
    expected = setup.rule_lines(rules['targets'], ['b64'])
    rules['status'] = 'enabled 2\n' if immutable else 'enabled 1\n'
    if installed:
        rules['active'] = '\n'.join(expected)
    plan, missing, _ = setup.audit_rule_plan(rules['targets'], ['b64'])
    assert plan == expected
    assert missing == ([] if installed else expected)
    assert rules['calls'] == [['/usr/sbin/auditctl', '-l'], ['/usr/sbin/auditctl', '-s']]


@pytest.mark.parametrize('active,status,message', [
    ('', 'enabled 2\n', 'reboot'),
    ('-a never,task', 'enabled 1\n', 'suppress'),
    ('-a never,exit -F arch=b64', 'enabled 1\n', 'suppress'),
    ('-a always,exit -F arch=b64 -F path=/other -F perm=wa -k siem_passwd', 'enabled 1\n', 'conflicts'),
    ('', 'enabled 0\n', 'enabled Audit'),
    ('', 'invalid status\n', 'enabled Audit'),
])
def test_known_rule_blockers_are_reported_read_only(rules, active, status, message):
    rules['active'], rules['status'] = active, status
    with pytest.raises(ValueError, match=message):
        setup.preflight_rules(rules['targets'], ['b64'])
    for call in rules['calls']:
        assert call in (['/usr/sbin/auditctl', '-l'], ['/usr/sbin/auditctl', '-s'])


def test_optional_paths_and_unrelated_keys_use_the_shared_plan(rules):
    rules['targets'][0]['directories'] = ['/etc/optional']
    setup.inspect_audit_targets.return_value[1]['/etc/optional'] = 'NOT_INSTALLED'
    rules['active'] = '-a always,exit -F arch=b64 -F path=/other -F perm=wa -k other_program'
    detail = setup.preflight_rules(rules['targets'], ['b64'])
    assert '1 expected rules' in detail
    assert 'optional paths not watched: /etc/optional' in detail
    setup.inspect_audit_targets.assert_called_once_with(rules['targets'])


@pytest.fixture
def database(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    connect = Mock(return_value=connection)
    monkeypatch.setattr(pymysql, 'connect', connect)
    return connection, cursor, connect


def stored_target(name='custom', key='siem_custom', enabled=1):
    definition = {'files': ['/etc/group'], 'directories': [], 'executables': []}
    return name, key, json.dumps(definition), enabled


def assert_read_only(database):
    connection, cursor, _ = database
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')
    connection.commit.assert_not_called()
    connection.close.assert_called_once()


def target_names(targets):
    names = []
    for target in targets:
        names.append(target['name'])
    return names


def test_reset_uses_exact_seeded_defaults_without_database_access(database):
    targets = setup.preflight_targets('reset')
    assert target_names(targets) == ['passwd', 'shadow', 'sudoers']
    database[2].assert_not_called()


@pytest.mark.parametrize('tables', [[], [('schema_migrations',)]])
def test_pre_audit_upgrade_predicts_defaults(database, tables):
    _, cursor, _ = database
    cursor.fetchall.return_value = tables
    cursor.fetchone.return_value = None
    targets = setup.preflight_targets('upgrade')
    assert target_names(targets) == ['passwd', 'shadow', 'sudoers']
    assert_read_only(database)


def test_applied_upgrade_preserves_current_custom_scope(database):
    _, cursor, _ = database
    cursor.fetchall.side_effect = [[('schema_migrations',), ('audit_targets',)], [stored_target()]]
    cursor.fetchone.return_value = ('APPLIED',)
    assert setup.preflight_targets('upgrade') == [
        {'name': 'custom', 'audit_key': 'siem_custom', 'files': ['/etc/group'],
         'directories': [], 'executables': []}]
    assert_read_only(database)


@pytest.mark.parametrize('migration', [None, ('RUNNING',), ('FAILED',)])
def test_partial_upgrade_predicts_seeding_without_reenabling_or_overwriting(database, migration):
    _, cursor, _ = database
    cursor.fetchall.side_effect = [[('schema_migrations',), ('audit_targets',)], [
        stored_target(), stored_target('passwd', 'siem_passwd', 0),
        stored_target('renamed', 'siem_shadow', 0)]]
    cursor.fetchone.return_value = migration
    targets = setup.preflight_targets('upgrade')
    assert target_names(targets) == ['custom', 'sudoers']
    assert_read_only(database)


@pytest.mark.parametrize('fault', ['missing-table', 'unknown-state', 'invalid-json', 'disabled', 'bad-enabled'])
def test_unknown_or_invalid_upgrade_scope_fails_closed(database, fault):
    _, cursor, _ = database
    cursor.fetchall.side_effect = [[('schema_migrations',), ('audit_targets',)], [stored_target()]]
    cursor.fetchone.return_value = ('APPLIED',)
    if fault == 'missing-table':
        cursor.fetchall.side_effect = None
        cursor.fetchall.return_value = [('schema_migrations',)]
    elif fault == 'unknown-state':
        cursor.fetchone.return_value = ('UNRECOGNIZED',)
    elif fault == 'invalid-json':
        cursor.fetchall.side_effect = [[('schema_migrations',), ('audit_targets',)], [('custom', 'siem_custom', '{}', 1)]]
    else:
        enabled = 0 if fault == 'disabled' else 2
        cursor.fetchall.side_effect = [[('schema_migrations',), ('audit_targets',)], [stored_target(enabled=enabled)]]
    with pytest.raises(ValueError):
        setup.preflight_targets('upgrade')
    assert_read_only(database)


def test_unavailable_database_never_guesses_upgrade_targets(database):
    database[2].side_effect = pymysql.OperationalError(2002, 'synthetic connection failure')
    with pytest.raises(ValueError, match='Cannot read existing Audit targets'):
        setup.preflight_targets('upgrade')
    database[0].commit.assert_not_called()


@pytest.mark.parametrize('fault', [None, 'targets', 'architectures', 'rules', 'rule-file', 'unit-files'])
def test_only_fully_verified_preflight_reports_ready(monkeypatch, capsys, fault):
    for name in ('_preflight_executables', '_preflight_auditd_active',
                 '_preflight_kernel_audit_status', '_preflight_reader_group', 'check_audit_log_access'):
        monkeypatch.setattr(setup, name, Mock(return_value='ready'))
    account = SimpleNamespace(pw_name='mysql_siem')
    monkeypatch.setattr(setup, '_preflight_account', Mock(return_value=account))
    monkeypatch.setattr(setup, 'managed_file_text', Mock(return_value=None))
    monkeypatch.setattr(setup, 'preflight_audit_units', Mock(return_value='safe units'))
    monkeypatch.setattr(setup, 'architectures', Mock(return_value=['b64']))
    monkeypatch.setattr(setup, 'preflight_targets', Mock(return_value=[]))
    monkeypatch.setattr(setup, 'preflight_rules', Mock(return_value='checked'))
    monkeypatch.setattr(setup, 'read_root_text', Mock(return_value='log_group=mysql_siem\n'))
    if fault is not None:
        function = {'targets': setup.preflight_targets, 'architectures': setup.architectures,
                    'rules': setup.preflight_rules, 'rule-file': setup.managed_file_text,
                    'unit-files': setup.preflight_audit_units}[fault]
        function.side_effect = ValueError('synthetic unavailable prerequisite')
    results = setup.audit_preflight(operation='reset')
    ready = setup.print_audit_preflight(results)
    assert ready == (fault is None)
    assert ('READY FOR PREPARATION' in capsys.readouterr().out) == (fault is None)
    if fault in ('targets', 'architectures'):
        setup.preflight_rules.assert_not_called()


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
def test_rule_conflict_stops_installer_before_database_setup(operation):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('audit_installation check --operation "$INSTALL_OPERATION"')
    database_start = installer.index('\nDATABASE_SETUP_STARTED=1\n')
    assert start < database_start < installer.index('-m config.reset_installation reset')
    assert database_start < installer.index('-m config.reset_installation upgrade')
    script = '''set -e
INSTALL_USER=mysql_siem
audit_installation() { printf '%s\\n' "$*"; return 17; }
service_installation() { printf 'unexpected snapshot check'; }
INSTALL_OPERATION=''' + operation + '\n' + installer[start:database_start] + '\nprintf "database setup started"\n'
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 17
    assert result.stdout.strip() == 'check --operation ' + operation
    assert 'database setup started' not in result.stdout


@pytest.mark.parametrize('existing', [False, True])
def test_read_only_rule_destination_accepts_absent_or_managed_file(tmp_path, monkeypatch, existing):
    path = tmp_path / '50-mysql-siem.rules'
    monkeypatch.setattr(setup, 'trusted_directory', Mock())
    monkeypatch.setattr(setup, 'read_root_text', lambda file: file.read_text())
    if existing:
        path.write_text(setup.MARKER + 'synthetic rules\n')
    before = sorted(tmp_path.iterdir())
    content = setup.managed_file_text(path)
    assert content == (setup.MARKER + 'synthetic rules\n' if existing else None)
    assert sorted(tmp_path.iterdir()) == before
    setup.trusted_directory.assert_called_once_with(path.parent)


def test_read_only_rule_destination_rejects_unmanaged_file_without_overwrite(tmp_path, monkeypatch):
    path = tmp_path / '50-mysql-siem.rules'
    path.write_text('another administrator\n')
    monkeypatch.setattr(setup, 'trusted_directory', Mock())
    monkeypatch.setattr(setup, 'read_root_text', lambda file: file.read_text())
    with pytest.raises(ValueError, match='another administrator'):
        setup.managed_file_text(path)
    assert path.read_text() == 'another administrator\n'
