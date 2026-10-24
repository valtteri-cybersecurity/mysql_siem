"""Installer role integration without real installation commands."""

import os
import pwd
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from config import installation_role_setup as setup
from config.installation_role import RoleConfigurationError

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / 'install.sh').read_text()
FUNCTIONS = INSTALLER.split('# Installation role selection', 1)[1].split('# End installation role selection.', 1)[0]
FUNCTIONS = FUNCTIONS[FUNCTIONS.index('\n'):]


def shell(tmp_path, command, *, input_text='', stored=None, extra=''):
    config = tmp_path / 'config'
    config.mkdir(exist_ok=True)
    if stored is not None:
        (config / 'role.env').write_text(stored)
    script = '''set -euo pipefail
die() { echo "$*" >&2; exit 1; }
''' + FUNCTIONS + '\n' + extra + '\n' + command
    return subprocess.run(['bash', '-c', script], input=input_text, text=True,
                          capture_output=True, timeout=10, check=False,
                          env={**os.environ, 'PROJECT_DIR': str(tmp_path),
                               'INSTALL_USER': pwd.getpwuid(os.getuid()).pw_name})


@pytest.fixture
def target(tmp_path):
    path = tmp_path / 'role.env'
    return path


def test_adapter_initializes_as_current_application_user(target):
    user = pwd.getpwuid(os.getuid()).pw_name
    assert setup.initialize_owned_role(user, 'server', path=target) == 'server'
    assert setup.read_owned_role(user, path=target) == 'server'
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(RoleConfigurationError):
        setup.initialize_owned_role(user, 'collector', path=target)
    assert setup.read_owned_role(user, path=target) == 'server'


@pytest.mark.parametrize('uid', [0, 98765])
def test_wrong_or_root_owner_is_rejected_without_changes(target, monkeypatch, uid):
    target.write_text('SIEM_ROLE=server\n')
    target.chmod(0o600)
    monkeypatch.setattr(setup.pwd, 'getpwnam', lambda user: SimpleNamespace(pw_uid=uid))
    before = target.stat()
    with pytest.raises(RoleConfigurationError):
        setup.read_owned_role('application', path=target)
    with pytest.raises(RoleConfigurationError):
        setup.initialize_owned_role('application', 'collector', path=target)
    assert target.stat() == before
    assert target.read_text() == 'SIEM_ROLE=server\n'


@pytest.mark.parametrize('after_publication', [False, True])
def test_sync_failure_never_deletes_published_role(target, monkeypatch, after_publication):
    import config.installation_role as roles
    original = roles.os.fsync

    def sync(descriptor):
        if not after_publication or target.exists():
            raise OSError('simulated sync failure')
        original(descriptor)

    user = pwd.getpwuid(os.getuid()).pw_name
    with monkeypatch.context() as patch:
        patch.setattr(roles.os, 'fsync', sync)
        with pytest.raises(RoleConfigurationError):
            setup.initialize_owned_role(user, 'server', path=target)
    if after_publication:
        assert setup.read_owned_role(user, path=target) == 'server'
    else:
        assert not target.exists()
    assert list(target.parent.iterdir()) == ([target] if after_publication else [])


@pytest.mark.parametrize('arguments,input_text,accepted', [
    ('--role server', 'yes\n', True), ('', '1\nyes\n', True),
    ('--role server', 'no\n', False), ('--role server', '', False),
])
def test_missing_role_requires_explicit_confirmation(tmp_path, arguments, input_text, accepted):
    result = shell(tmp_path, f'select_installation_role {arguments}; echo "ROLE:$INSTALL_ROLE"', input_text=input_text)
    assert (result.returncode == 0) == accepted
    assert not (tmp_path / 'config/role.env').exists()


@pytest.mark.parametrize('stored,requested,accepted', [
    ('server', '', True), ('server', '--role server', True),
    ('server', '--role collector', False), ('collector', '--role server', False),
])
def test_existing_role_is_used_or_conflict_rejected(tmp_path, stored, requested, accepted):
    result = shell(tmp_path, f'select_installation_role {requested}; echo "ROLE:$INSTALL_ROLE"',
                   stored=stored, extra=f'role_configuration() {{ echo {stored}; }}')
    assert (result.returncode == 0) == accepted
    assert (tmp_path / 'config/role.env').read_text() == stored
    assert 'Confirm Server' not in result.stdout


def test_invalid_existing_configuration_never_prompts_or_initializes(tmp_path):
    result = shell(tmp_path, 'select_installation_role --role server', stored='invalid',
                   extra='role_configuration() { return 1; }', input_text='yes\n')
    assert result.returncode != 0
    assert 'Cannot validate' in result.stderr
    assert 'Confirm Server' not in result.stdout
    assert (tmp_path / 'config/role.env').read_text() == 'invalid'


@pytest.mark.parametrize('publish', [False, True])
def test_installer_stops_after_uncertain_initialization(tmp_path, publish):
    write = 'printf "SIEM_ROLE=server\\n" > "$PROJECT_DIR/config/role.env";' if publish else ''
    result = shell(tmp_path, 'INSTALL_ROLE=server; persist_installation_role; echo UNEXPECTED_CONTINUATION',
                   extra='role_configuration() { ' + write + ' return 1; }')
    assert result.returncode != 0
    assert 'Check config/role.env before retrying' in result.stderr
    assert 'UNEXPECTED_CONTINUATION' not in result.stdout
    assert (tmp_path / 'config/role.env').exists() == publish


def test_initialization_command_runs_as_application_user(tmp_path):
    result = shell(tmp_path, 'INSTALL_ROLE=server; role_configuration initialize', extra='''
runuser() { printf '%s\\n' "$@"; cat >/dev/null; }
''')
    assert result.returncode == 0
    assert result.stdout.splitlines()[:4] == ['-u', pwd.getpwuid(os.getuid()).pw_name, '--', '/usr/bin/python3']


@pytest.mark.parametrize('role', ['server', 'collector'])
def test_role_cron_selection_and_repeatable_managed_block(tmp_path, role):
    cron = tmp_path / 'crontab'
    cron.write_text('MAILTO=keep\n17 * * * * echo external-job\n')
    block = INSTALLER.split("# Update only this installation's marked cron block.", 1)[1].split('log "Installation steps completed.', 1)[0]
    extra = '''
local_identity_setup() { :; }
crontab() {
    if [[ "$*" == *" -l" ]]; then cat "$PROJECT_DIR/crontab"; else cp "${@: -1}" "$PROJECT_DIR/crontab"; fi
}
CRON_BEGIN='# BEGIN mysql_siem managed jobs'
CRON_END='# END mysql_siem managed jobs'
UFW_ANALYSIS_CRON='analysis-job'
PORT_SCAN_CRON='port-detection-job'
SSH_DETECTION_CRON='ssh-detection-job'
SSH_AUTH_CRON='auth-collection-job'
DNS_CRON='dns-collection-job'
APP_PYTHON='/opt/mysql_siem-venv/bin/python'
INSTALL_ROLE=''' + role + '\nselect_role_cron_jobs\n'
    previous = None
    for _attempt in range(2):
        result = shell(tmp_path, block, extra=extra)
        assert result.returncode == 0, result.stderr
        current = cron.read_text()
        if previous is not None:
            assert current == previous
        previous = current
    for job in ('analysis-job', 'port-detection-job', 'ssh-detection-job'):
        assert (job in current) == (role == 'server')
    for job in ('auth-collection-job', 'dns-collection-job', 'ufw_to_mysql.py', 'metrics.security.main', 'external-job', 'MAILTO=keep'):
        assert job in current


def test_role_checks_precede_mutations_and_initialization_precedes_packages():
    assert INSTALLER.index('select_installation_role "$@"') < INSTALLER.index('\nensure_application_user\n')
    assert INSTALLER.index('\npersist_installation_role\n') < INSTALLER.index('\ninstall_dependencies\n')
    assert 'DROP DATABASE' not in INSTALLER
    assert 'DROP TABLE' not in INSTALLER

    assert '-m config.reset_installation reset' in INSTALLER
    assert 'DATABASE_CREATED_THIS_RUN' not in INSTALLER
    assert INSTALLER.index('Type RESET to continue:') < INSTALLER.index('\nensure_application_user\n')



@pytest.mark.parametrize('content,valid', [('SIEM_ROLE=server\n', True), ('SIEM_ROLE=SERVER\n', False)])
def test_real_python_bridge_reads_only_temporary_configuration(tmp_path, content, valid):
    config = tmp_path / 'config'
    config.mkdir()
    for name in ('installation_role.py', 'installation_role_setup.py'):
        (config / name).write_bytes((ROOT / 'config' / name).read_bytes())
    target = config / 'role.env'
    target.write_text(content)
    target.chmod(0o600)
    result = shell(tmp_path, 'select_installation_role; echo "ROLE:$INSTALL_ROLE"')
    assert (result.returncode == 0) == valid
    assert target.read_text() == content
    if valid:
        assert 'ROLE:server' in result.stdout
        assert 'Confirm Server' not in result.stdout


def test_crontab_read_error_does_not_install_replacement(tmp_path):
    block = INSTALLER.split("# Update only this installation's marked cron block.", 1)[1].split('log "Installation steps completed.', 1)[0]
    result = shell(tmp_path, block, extra='''
crontab() { echo "Unexpected cron access error" >&2; return 1; }
''')
    assert result.returncode != 0
    assert 'Cannot read the existing crontab' in result.stderr
    assert not (tmp_path / 'crontab').exists()
