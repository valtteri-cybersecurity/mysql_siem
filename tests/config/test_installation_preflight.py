"""Preflight checks only temporary state and fake MySQL/systemd endpoints."""

import json
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from config import installation_state as journal
from config import reset_installation as reset
from config import service_installation as service
from database import migrate


@pytest.fixture
def mysql(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [('8.0.46',), ('',), (0,)]
    command = Mock(return_value=SimpleNamespace(returncode=0))
    connect = Mock(return_value=connection)
    monkeypatch.setattr(reset, 'run_command', command)
    monkeypatch.setattr(reset, 'check_system_cron', Mock())
    monkeypatch.setattr(reset.pymysql, 'connect', connect)
    monkeypatch.setattr(reset.Path, 'lstat', Mock(return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o777)))
    return SimpleNamespace(connection=connection, cursor=cursor, command=command, connect=connect)


def test_database_preflight_only_reads_the_fixed_local_server(mysql):
    reset.database_preflight('reset')
    mysql.command.assert_called_once_with(['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql.service'])
    assert mysql.connect.call_args.kwargs['unix_socket'] == reset.SOCKET
    assert mysql.connect.call_args.kwargs['user'] == 'root'
    assert mysql.connect.call_args.kwargs['connect_timeout'] == 5
    for call in mysql.cursor.execute.call_args_list:
        assert call.args[0].startswith(('SELECT ', 'SHOW '))
    mysql.connection.commit.assert_not_called()
    mysql.connection.close.assert_called_once()


@pytest.mark.parametrize('fault', ['stopped', 'missing-socket', 'socket-link', 'socket-file', 'connection', 'version'])
def test_mysql_failure_never_starts_services_or_changes_database(mysql, fault):
    if fault == 'stopped':
        mysql.command.return_value.returncode = 3
    elif fault == 'missing-socket':
        reset.Path.lstat.side_effect = FileNotFoundError('synthetic missing socket')
    elif fault == 'socket-link':
        reset.Path.lstat.return_value.st_mode = stat.S_IFLNK | 0o777
    elif fault == 'socket-file':
        reset.Path.lstat.return_value.st_mode = stat.S_IFREG | 0o600
    elif fault == 'connection':
        mysql.connect.side_effect = pymysql.OperationalError(2002, 'synthetic private connection diagnostic')
    else:
        mysql.cursor.fetchone.side_effect = [('10.11.0-MariaDB',)]
    with pytest.raises((reset.ResetError, FileNotFoundError, pymysql.MySQLError)):
        reset.database_preflight('reset')
    mysql.command.assert_called_once_with(['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql.service'])
    mysql.connection.commit.assert_not_called()
    for call in mysql.cursor.execute.call_args_list:
        assert call.args[0].startswith(('SELECT ', 'SHOW '))
    if fault in ('stopped', 'missing-socket', 'socket-link', 'socket-file'):
        mysql.connect.assert_not_called()
    if fault == 'version':
        mysql.connection.close.assert_called_once()


def test_upgrade_preflight_reuses_history_checks_without_migrating(mysql, monkeypatch):
    mysql.cursor.fetchone.side_effect = [(1,), ('8.0.46',), ('',), (1,), None]
    mysql.cursor.fetchall.return_value = [('GRANT SELECT ON `mysql_siem`.`hosts` TO `pythonuser`@`localhost`',)]
    history = Mock()
    apply = Mock()
    monkeypatch.setattr(reset, 'check_ufw_before_upgrade', history)
    monkeypatch.setattr(migrate, 'migrate', apply)
    reset.database_preflight('upgrade')
    history.assert_called_once_with(mysql.connection)
    apply.assert_not_called()
    mysql.connection.commit.assert_not_called()
    mysql.connection.close.assert_called_once()
    for call in mysql.cursor.execute.call_args_list:
        assert call.args[0].startswith(('SELECT ', 'SHOW '))


def test_upgrade_history_failure_blocks_preflight_and_closes_connection(mysql, monkeypatch):
    mysql.cursor.fetchone.side_effect = [(1,), ('8.0.46',), ('',), (1,), None]
    mysql.cursor.fetchall.return_value = [('GRANT USAGE ON *.* TO `pythonuser`@`localhost`',)]
    monkeypatch.setattr(reset, 'check_ufw_before_upgrade', Mock(side_effect=reset.ResetError('unverified UTC history')))
    with pytest.raises(reset.ResetError, match='UTC history'):
        reset.database_preflight('upgrade')
    mysql.connection.close.assert_called_once()
    mysql.connection.commit.assert_not_called()


@pytest.mark.parametrize('failure', [False, True])
def test_check_cli_never_enters_maintenance_or_reset(mysql, monkeypatch, tmp_path, capsys, failure):
    monkeypatch.setattr(reset.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(reset, 'trusted_directory', Mock())
    monkeypatch.setattr(reset, 'validate_settings', Mock())
    maintenance = Mock(side_effect=AssertionError('Unexpected maintenance'))
    deletion = Mock(side_effect=AssertionError('Unexpected reset'))
    monkeypatch.setattr(reset.journal, 'require_maintenance', maintenance)
    monkeypatch.setattr(reset, 'reset_database', deletion)
    if failure:
        mysql.connect.side_effect = pymysql.OperationalError(2002, 'synthetic private connection diagnostic')
    assert reset.main(['check', '--operation', 'reset', '--project', str(tmp_path)]) == int(failure)
    maintenance.assert_not_called()
    deletion.assert_not_called()
    assert 'private connection diagnostic' not in capsys.readouterr().err


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    project = tmp_path / '.mysql_siem-stage-test'
    project.mkdir()
    state = tmp_path / 'state'
    state.mkdir()
    candidate = tmp_path / 'python-candidate'
    (candidate / 'bin').mkdir(parents=True)
    (candidate / 'bin/python').write_text('synthetic executable\n')
    (candidate / 'pyvenv.cfg').write_text('synthetic environment\n')
    record = {'version': 1, 'stage': str(project), 'target': str(tmp_path / 'mysql_siem'),
              'stable': str(tmp_path / 'python'), 'user': 'mysql_siem', 'candidate': str(candidate),
              'phase': 'staged', 'identity': {}, 'publication': None, 'database_started': True,
              'cron_digest': None, 'checkpoint_transition': None}
    (state / 'deployment.json').write_text(json.dumps(record))
    (state / 'deployment.json').chmod(0o600)
    monkeypatch.setattr(journal, 'require_install_lock', Mock())
    monkeypatch.setattr(service, 'trusted_directory', Mock())
    monkeypatch.setattr(service, 'deployment_paths', Mock())
    monkeypatch.setattr(service, 'validate_virtualenv', Mock())
    gate = Mock()
    monkeypatch.setattr(journal, 'require_maintenance', gate)
    return SimpleNamespace(project=project, state=state, candidate=candidate, record=record, gate=gate)


def check_prepared(prepared):
    service.preflight_deployment(prepared.project, Path(prepared.record['target']),
                                 Path(prepared.record['stable']), 'mysql_siem', prepared.state)


@pytest.mark.parametrize('paused', [False, True])
def test_prepared_state_check_is_read_only_and_preserves_recovery(prepared, paused):
    marker = prepared.state / 'maintenance'
    if paused:
        marker.write_text(journal.MAINTENANCE_TEXT)
    journal_file = prepared.state / 'deployment.json'
    before = journal_file.read_bytes()
    inode = journal_file.stat().st_ino
    check_prepared(prepared)
    assert journal_file.read_bytes() == before
    assert journal_file.stat().st_ino == inode
    assert marker.exists() == paused
    if paused:
        prepared.gate.assert_called_once_with(prepared.state)
        assert marker.read_text() == journal.MAINTENANCE_TEXT
    else:
        prepared.gate.assert_not_called()


@pytest.mark.parametrize('fault', ['missing-journal', 'bad-journal', 'wrong-stage', 'wrong-phase',
                                  'missing-environment', 'incomplete-environment', 'old-gate-lock'])
def test_invalid_recovery_state_is_rejected_without_repair(prepared, fault):
    path = prepared.state / 'deployment.json'
    if fault == 'missing-journal':
        path.unlink()
    elif fault == 'bad-journal':
        path.write_text('{}')
    elif fault == 'wrong-stage':
        prepared.record['stage'] = '/different/stage'
    elif fault == 'wrong-phase':
        prepared.record['phase'] = 'publishing'
        prepared.record['publication'] = {}
    elif fault == 'missing-environment':
        prepared.record['candidate'] = None
    elif fault == 'incomplete-environment':
        (prepared.candidate / 'pyvenv.cfg').unlink()
    else:
        (prepared.state / 'maintenance').write_text(journal.MAINTENANCE_TEXT)
        prepared.gate.side_effect = journal.InstallationStateError('existing maintenance lock is not held')
    if fault in ('wrong-stage', 'wrong-phase', 'missing-environment'):
        path.write_text(json.dumps(prepared.record))
    before = path.read_bytes() if path.exists() else None
    with pytest.raises((service.InstallationError, journal.InstallationStateError, ValueError)):
        check_prepared(prepared)
    assert (path.read_bytes() if path.exists() else None) == before


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
@pytest.mark.parametrize('failure', ['recovery', 'mysql', 'audit', 'snapshot'])
def test_failed_preflight_stops_shell_before_new_maintenance_and_database(operation, failure):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('service_installation preflight "$PROJECT_DIR"')
    begin = installer.index('if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then\n    local_identity_setup begin')
    end = installer.index('# Both schema paths')
    assert start < begin < installer.index('\nDATABASE_SETUP_STARTED=1\n') < end
    prefix = '''set -euo pipefail
PROJECT_DIR=/synthetic/project
SERVICE_DIR=/synthetic/mysql_siem
INSTALL_USER=mysql_siem
APP_PYTHON=preflight_python
STAGING_RECOVERY=0
service_installation() {
    if [[ "$1" == preflight ]]; then
        printf 'recovery\\n'
        [[ "$FAILURE" != recovery ]] || return 17
    elif [[ "$1" == snapshot-logs-check ]]; then
        printf 'snapshot\\n'
        [[ "$FAILURE" != snapshot ]] || return 17
    else
        printf 'UNEXPECTED database journal change\\n'; return 91
    fi
}
preflight_python() {
    if [[ "$*" == *'config.reset_installation recovery-check'* ]]; then printf '0'; return; fi
    [[ "$*" == *'config.reset_installation check'* ]] || { printf 'UNEXPECTED database operation\\n'; return 91; }
    printf 'mysql\\n'
    [[ "$FAILURE" != mysql ]] || return 17
}
audit_installation() { printf 'audit\\n'; [[ "$FAILURE" != audit ]] || return 17; }
local_identity_setup() { printf 'UNEXPECTED maintenance\\n'; return 91; }
systemctl() { printf 'UNEXPECTED service change\\n'; return 91; }
'''
    script = prefix + 'INSTALL_OPERATION=$1\nFAILURE=$2\n' + installer[start:end]
    result = subprocess.run(['bash', '-c', script, 'preflight-test', operation, failure],
                            capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 17, result.stdout + result.stderr
    assert 'UNEXPECTED' not in result.stdout
    assert result.stdout.strip().endswith(failure)


def test_recovery_preflight_requires_the_existing_installer_lock(prepared):
    journal.require_install_lock.side_effect = journal.InstallationStateError('installer lock missing')
    before = (prepared.state / 'deployment.json').read_bytes()
    with pytest.raises(journal.InstallationStateError, match='installer lock missing'):
        check_prepared(prepared)
    assert (prepared.state / 'deployment.json').read_bytes() == before
    service.deployment_paths.assert_not_called()


def test_database_check_cli_rejects_nonroot_before_connection(mysql, monkeypatch, tmp_path):
    monkeypatch.setattr(reset.os, 'geteuid', Mock(return_value=1001))
    assert reset.main(['check', '--project', str(tmp_path)]) == 1
    mysql.connect.assert_not_called()
    mysql.command.assert_not_called()


def test_legacy_system_cron_blocks_reset_preflight_before_maintenance(mysql, monkeypatch, tmp_path):
    monkeypatch.setattr(reset.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(reset, 'trusted_directory', Mock())
    monkeypatch.setattr(reset, 'validate_settings', Mock())
    maintenance = Mock(side_effect=AssertionError('Unexpected maintenance'))
    monkeypatch.setattr(reset.journal, 'require_maintenance', maintenance)
    reset.check_system_cron.side_effect = reset.ResetError('Legacy system cron remains')
    assert reset.main(['check', '--operation', 'reset', '--project', str(tmp_path)]) == 1
    maintenance.assert_not_called()
    mysql.connection.commit.assert_not_called()
    mysql.connection.close.assert_called_once()


@pytest.mark.parametrize('scenario', ['published', 'staged', 'rejected', 'missing-state', 'fresh'])
def test_upgrade_source_gate_keeps_published_checks_and_admits_only_valid_recovery(tmp_path, scenario):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then\n    if [[ -f')
    end = installer.index('trap cleanup_prepared_installation EXIT', start)
    assert installer.index('flock -n 9') < start < installer.index('\nprepare_service_installation\n')
    target = tmp_path / 'service'
    state = tmp_path / 'state'
    if scenario not in ('missing-state', 'fresh'):
        state.mkdir()
    if scenario == 'published':
        (target / 'config').mkdir(parents=True)
        (target / 'config/mysql.env').write_text('synthetic settings\n')
        (target / 'config/identity.env').write_text('synthetic identity\n')
        (state / 'receipt.json').write_text('synthetic receipt\n')
    block = installer[start:end].replace('/usr/local/lib/.mysql_siem-local', '${TEST_STATE}')
    script = '''set -euo pipefail
INSTALL_OPERATION=upgrade
STAGING_RECOVERY=0
INSTALL_USER=mysql_siem
SERVICE_DIR=$1
TEST_STATE=$2
SCENARIO=$3
if [[ "$SCENARIO" == fresh ]]; then INSTALL_OPERATION=reset; fi
log() { :; }
die() { printf '%s\\n' "$*" >&2; exit 19; }
service_installation() {
    [[ "$1" == recovery-check ]] || exit 91
    printf 'recovery-check\\n'
    [[ "$SCENARIO" == staged ]] || return 17
}
''' + block + '\nprintf "continued:%s\\n" "$STAGING_RECOVERY"\n'
    result = subprocess.run(['bash', '-c', script, 'source-test', str(target), str(state), scenario],
                            capture_output=True, text=True, timeout=5, check=False)
    if scenario == 'missing-state':
        assert result.returncode == 19
        assert 'protected local installation state is missing' in result.stderr
        assert 'database was preserved' in result.stderr
        assert 'recovery-check' not in result.stdout
        assert 'continued' not in result.stdout
        assert not state.exists()
    elif scenario == 'rejected':
        assert result.returncode == 17
        assert 'continued' not in result.stdout
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().endswith('continued:' + ('1' if scenario == 'staged' else '0'))
        assert ('recovery-check' in result.stdout) == (scenario == 'staged')
        if scenario == 'fresh':
            assert not state.exists()


def test_receipt_failure_stops_unpublished_upgrade_before_new_maintenance_or_database():
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('service_installation preflight "$PROJECT_DIR"')
    begin = installer.index('if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then\n    local_identity_setup begin')
    end = installer.index('# Both schema paths', begin)
    assert start < installer.index('local_identity_setup check-recovery') < begin
    prefix = '''set -euo pipefail
PROJECT_DIR=/synthetic/project
SERVICE_DIR=/synthetic/service
INSTALL_USER=mysql_siem
INSTALL_OPERATION=upgrade
STAGING_RECOVERY=1
APP_PYTHON=read_only_python
service_installation() { printf 'recovery-metadata\\n'; }
read_only_python() {
    [[ "$*" == *'config.reset_installation check'* ]] || { printf 'UNEXPECTED database change\\n'; return 91; }
    printf 'mysql-check\\n'
}
local_identity_setup() {
    if [[ "$1" == check-recovery ]]; then printf 'receipt-check\\n'; return 17; fi
    printf 'UNEXPECTED maintenance\\n'; return 91
}
audit_installation() { printf 'UNEXPECTED later check\\n'; return 91; }
systemctl() { printf 'UNEXPECTED service change\\n'; return 91; }
'''
    result = subprocess.run(['bash', '-c', prefix + installer[start:end]],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 17, result.stdout + result.stderr
    assert 'UNEXPECTED' not in result.stdout
    assert result.stdout.strip().endswith('receipt-check')


@pytest.mark.parametrize('fault', ['unknown', 'checksum'])
def test_migration_conflicts_stop_read_only_preflight_before_maintenance(mysql, monkeypatch, tmp_path, fault, capsys):
    mysql.cursor.fetchone.side_effect = [(1,), ('8.0.46',), ('',), (1,), ('schema_migrations',)]
    version = '999' if fault == 'unknown' else '017'
    mysql.cursor.fetchall.side_effect = [
        [('GRANT USAGE ON *.* TO `pythonuser`@`localhost`',)],
        [(version, 'incorrect-checksum', 'APPLIED')],
    ]
    monkeypatch.setattr(reset.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(reset, 'trusted_directory', Mock())
    monkeypatch.setattr(reset, 'validate_settings', Mock())
    maintenance = Mock(side_effect=AssertionError('Unexpected maintenance'))
    deletion = Mock(side_effect=AssertionError('Unexpected RESET'))
    migration = Mock(side_effect=AssertionError('Unexpected migration'))
    monkeypatch.setattr(journal, 'require_maintenance', maintenance)
    monkeypatch.setattr(reset, 'reset_database', deletion)
    monkeypatch.setattr(migrate, 'migrate', migration)
    assert reset.main(['check', '--operation', 'upgrade', '--project', str(tmp_path)]) == 1
    maintenance.assert_not_called()
    deletion.assert_not_called()
    migration.assert_not_called()
    mysql.connection.commit.assert_not_called()
    mysql.connection.close.assert_called_once()
    for call in mysql.cursor.execute.call_args_list:
        assert call.args[0].startswith(('SELECT ', 'SHOW '))
    message = capsys.readouterr().err
    assert ('unknown migration versions' if fault == 'unknown' else 'checksum differs') in message


@pytest.mark.parametrize('status', ['APPLIED', 'RUNNING', 'FAILED'])
def test_migration_history_preflight_accepts_original_sources_using_select_only(mysql, status):
    mysql.cursor.fetchone.side_effect = [('schema_migrations',)]
    rows = []
    expected = {}
    for version, _name, path in migrate.MIGRATIONS:
        digest = migrate.checksum(path)
        rows.append((version, digest, status))
        expected[version] = (digest, status)
    mysql.cursor.fetchall.return_value = rows
    assert migrate.check_migration_history(mysql.connection) == expected
    mysql.connection.commit.assert_not_called()
    for call in mysql.cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')


def test_missing_migration_ledger_is_read_only(mysql):
    mysql.cursor.fetchone.side_effect = [None]
    assert migrate.check_migration_history(mysql.connection) == {}
    mysql.cursor.execute.assert_called_once()
    assert mysql.cursor.execute.call_args.args[0].startswith('SELECT ')


@pytest.mark.parametrize('exists,answer,approved', [('1', 'RESET', True), ('1', 'cancel', False), ('0', '', False), ('0', 'RESET', True)])
def test_fresh_install_requires_explicit_reset_confirmation_for_an_existing_database(exists, answer, approved):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('# Final database reset approval')
    end = installer.index('if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then\n    local_identity_setup begin', start)
    block = installer[start:end]
    prefix = r'''set -euo pipefail
INSTALL_OPERATION=reset
SIEM_DATABASE_RESET_APPROVED=0
EXISTING_DATABASE=$1
die() { printf '%s\n' "$*" >&2; exit 19; }
'''
    result = subprocess.run(['bash', '-c', prefix + block + '\nprintf "approved:%s\n" "$SIEM_DATABASE_RESET_APPROVED"\n',
                             'first-install-test', exists], input=answer + '\n',
                            capture_output=True, text=True, timeout=5, check=False)
    if not approved:
        assert result.returncode == 19
        assert 'Reset cancelled' in result.stderr
        assert 'approved:' not in result.stdout
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().endswith('approved:' + ('1' if approved else '0'))
    if exists == '1':
        assert 'Type RESET to confirm' in result.stdout


def test_completed_reset_recovery_skips_new_reset_consent_and_uses_only_resume():
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('# Final database reset approval')
    end = installer.index('if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then\n    local_identity_setup begin', start)
    dispatch = installer.index('if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then\n    PYTHONPATH=', end)
    finish = installer.index('# Both schema paths', dispatch)
    prefix = '''set -euo pipefail
INSTALL_OPERATION=reset
EXISTING_DATABASE=1
RESET_RECOVERY=1
PROJECT_DIR=/synthetic/stage
APP_PYTHON=database_probe
die() { printf 'UNEXPECTED consent\\n'; exit 91; }
database_probe() {
    [[ "$*" == '-m config.reset_installation resume --project /synthetic/stage' ]] || exit 92
    printf 'resumed without database reset\\n'
}
'''
    result = subprocess.run(['bash', '-c', prefix + installer[start:end] + installer[dispatch:finish]],
                            input='', capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'resumed without database reset'


def test_invalid_reset_recovery_stops_before_any_new_maintenance_or_database_action(tmp_path):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('if [[ "$INSTALL_OPERATION" == reset ]]; then\n    RESET_RECOVERY_CHECK_ACTIVE=1')
    end = installer.index('# Both schema paths', start)
    cleanup_start = installer.index('cleanup_prepared_installation() {')
    cleanup_end = installer.index('\n}\n', cleanup_start) + 3
    saved = tmp_path / 'deployment.json'
    saved.write_bytes(b'protected recovery evidence')
    prefix = '''set -euo pipefail
INSTALL_OPERATION=reset
SERVICE_PUBLISHED=0
LOCAL_DEPLOYMENT_STARTED=1
warn() { printf '%s\\n' \"$*\" >&2; }
PROJECT_DIR=/synthetic/stage
APP_PYTHON=database_probe
database_probe() {
    [[ "$*" == *'config.reset_installation recovery-check'* ]] || exit 91
    return 17
}
service_installation() { printf 'UNEXPECTED installation change\\n'; exit 91; }
local_identity_setup() { printf 'UNEXPECTED maintenance change\\n'; exit 91; }
systemctl() { printf 'UNEXPECTED service change\\n'; exit 91; }
'''
    result = subprocess.run(['bash', '-c', prefix + installer[cleanup_start:cleanup_end] + '\ntrap cleanup_prepared_installation EXIT\n' + installer[start:end]],
                            input='', capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 17
    assert 'UNEXPECTED' not in result.stdout
    assert 'recovery journal were retained' in result.stderr
    assert saved.read_bytes() == b'protected recovery evidence'


def test_legacy_grant_transition_is_approved_before_maintenance_and_applied_before_database():
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    check = installer.index('-m config.reset_installation check --operation')
    audit = installer.index('audit_installation check --operation')
    approval = installer.index('-m config.legacy_runtime approve')
    reset_confirmation = installer.index('Type RESET to confirm:')
    maintenance = installer.index('    local_identity_setup begin --reset')
    lock = installer.index('flock -x -w 30 8', maintenance)
    apply = installer.index('-m config.legacy_runtime apply')
    database = installer.index('\\nDATABASE_SETUP_STARTED=1\\n'.replace('\\n', '\n'))
    assert check < audit < approval < reset_confirmation < maintenance < lock < apply < database
    assert '(--allow-legacy-grants)' in installer[check - 200:check]


@pytest.mark.parametrize('action', ['approve', 'apply'])
def test_failed_legacy_grant_transition_never_reaches_database(action):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    marker = 'if [[ "$INSTALL_OPERATION" == reset ]]; then\n    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m config.legacy_runtime ' + action
    start = installer.index(marker)
    end = installer.index('\nfi\n', start) + len('\nfi\n')
    prefix = '''set -euo pipefail
INSTALL_OPERATION=reset
PROJECT_DIR=/synthetic/stage
APP_PYTHON=grant_probe
grant_probe() { return 17; }
'''
    result = subprocess.run(['bash', '-c', prefix + installer[start:end] + '\nprintf "UNEXPECTED database change"\n'],
                            input='', capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 17
    assert 'UNEXPECTED' not in result.stdout
