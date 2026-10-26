"""Local enrollment file/maintenance tests never use system cron or MySQL."""

import fcntl
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from database import local_identity as local
from database.identity import IdentityError


def settings():
    result = {local.COLLECTOR_KEY: 7}
    for index, key in enumerate(local.LOCAL_KEYS.values(), start=10):
        result[key] = index
    return result


def test_identity_file_is_atomic_private_and_preserves_approved_dns(tmp_path):
    path = tmp_path / 'identity.env'
    expected = settings()
    expected['SIEM_DNS_SOURCE_ID'] = 20
    local.write_settings(path, expected, os.getgid())
    assert local.read_settings(path) == expected
    assert path.stat().st_mode & 0o777 == 0o640
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize('content', [
    'HOST_ID=1\n', 'SIEM_COLLECTOR_ID=01\n', 'SIEM_COLLECTOR_ID=0\n',
    'SIEM_COLLECTOR_ID=1\nSIEM_COLLECTOR_ID=2\n', 'SIEM_UFW_SOURCE_ID=3\n',
    'SIEM_COLLECTOR_ID=18446744073709551616\n', 'SIEM_COLLECTOR_ID= 1\n',
])
def test_invalid_identity_config_fails_without_overwriting(tmp_path, content):
    path = tmp_path / 'identity.env'
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(IdentityError):
        local.read_settings(path)
    assert path.read_text() == content


def test_file_write_failure_keeps_working_configuration(tmp_path, monkeypatch):
    path = tmp_path / 'identity.env'
    local.write_settings(path, settings(), os.getgid())
    original = path.read_bytes()

    def fail_replace(*args):
        raise OSError('disk failure')

    monkeypatch.setattr(local.os, 'replace', fail_replace)
    with pytest.raises(OSError):
        local.write_settings(path, {local.COLLECTOR_KEY: 99}, os.getgid())
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_links_and_public_settings_are_rejected(tmp_path):
    original = tmp_path / 'original'
    original.write_text('SIEM_COLLECTOR_ID=7\n')
    original.chmod(0o600)
    path = tmp_path / 'identity.env'
    path.symlink_to(original)
    with pytest.raises(OSError):
        local.read_settings(path)
    with pytest.raises(OSError):
        local.write_settings(path, settings(), os.getgid())
    assert original.read_text() == 'SIEM_COLLECTOR_ID=7\n'
    path.unlink()
    original.chmod(0o644)
    with pytest.raises(IdentityError):
        local.read_settings(original)


@pytest.mark.parametrize('kind', ['offset', 'inode', 'digest', 'boundary'])
def test_invalid_checkpoint_never_guesses_a_position(tmp_path, kind):
    path = tmp_path / 'auth.log'
    path.write_bytes(b'first\nsecond\n')
    info = path.stat()
    inode = info.st_ino + 1 if kind == 'inode' else info.st_ino
    offset = 100 if kind == 'offset' else (3 if kind == 'boundary' else 6)
    digest = '0' * 64 if kind == 'digest' else None
    with pytest.raises(IdentityError):
        local.validate_checkpoint(path, info.st_dev, inode, offset, digest)


def test_only_managed_cron_is_paused_and_invalid_markers_fail():
    external = 'MAILTO=local\n17 * * * * echo unrelated\n'
    text = external + local.BEGIN + '\n* * * * * old-job\n' + local.END + '\n'
    assert local.without_managed_jobs(text) == external
    with pytest.raises(IdentityError):
        local.without_managed_jobs(local.BEGIN + '\nold-job\n')


def test_begin_pauses_cron_before_legacy_confirmation(tmp_path, monkeypatch):
    from config import service_installation

    monkeypatch.setattr(service_installation, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(local.installation, 'require_install_lock', lambda: None)
    installed = tmp_path / 'installed'
    installed.mkdir()
    state = tmp_path / 'state'
    text = '17 * * * * echo unrelated\n' + local.BEGIN + '\nold-job\n' + local.END + '\n'
    calls = []

    def fake_crontab(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=text, stderr='')

    def confirm(prompt):
        assert len(calls) == 2
        assert (state / 'maintenance').exists()
        assert 'old-job' not in calls[1][1]['input']
        return 'no'

    monkeypatch.setattr(local.subprocess, 'run', fake_crontab)
    with pytest.raises(IdentityError, match='not confirmed'):
        local.begin_maintenance(state, installed, 'fake-user', confirm=confirm)
    assert (state / 'previous.cron').read_text() == text
    assert (state / 'maintenance').exists()


def wrapper_setup(tmp_path):
    root = Path(__file__).resolve().parents[2]
    (tmp_path / 'config').mkdir()
    (tmp_path / 'config/mysql.env').write_text('DB_HOST=localhost\nDB_USER=synthetic\nDB_PASSWORD=synthetic\nDB_NAME=synthetic\n')
    state = tmp_path / 'state'
    state.mkdir()
    text = (root / 'config/run_with_env.sh').read_text()
    text = text.replace('LOCAL_STATE_DIR=/usr/local/lib/.mysql_siem-local', 'LOCAL_STATE_DIR=' + str(state))
    wrapper = tmp_path / 'config/run_with_env.sh'
    wrapper.write_text(text)
    return wrapper, state


def test_pending_and_locked_installation_cannot_start_any_job(tmp_path):
    wrapper, state = wrapper_setup(tmp_path)
    lock = state / 'runtime.lock'
    lock.touch()
    with lock.open() as descriptor:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        result = subprocess.run(['bash', str(wrapper), '/bin/echo', 'must-not-run'], capture_output=True, text=True, check=False)
    assert result.returncode == 75
    assert 'must-not-run' not in result.stdout
    (state / 'maintenance').touch()
    result = subprocess.run(['bash', str(wrapper), '/bin/echo', 'must-not-run'], capture_output=True, text=True, check=False)
    assert result.returncode == 75
    assert 'must-not-run' not in result.stdout


def test_required_identity_cannot_fall_back_to_inherited_values(tmp_path):
    wrapper, state = wrapper_setup(tmp_path)
    (state / 'required').touch()
    result = subprocess.run(['bash', str(wrapper), '/bin/echo', 'must-not-run'], capture_output=True, text=True,
                            env=dict(os.environ, SIEM_UFW_SOURCE_ID='99'), check=False)
    assert result.returncode != 0
    assert 'must-not-run' not in result.stdout


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
@pytest.mark.parametrize('failure', [None, 'prepare', 'verify', 'published-verify', 'audit-activate'])
def test_installer_verifies_identity_before_publication_and_cron(operation, failure):
    lines = (Path(__file__).resolve().parents[2] / 'install.sh').read_text().splitlines()
    commands = (
        'local_identity_setup begin', 'local_identity_setup begin --reset',
        'local_identity_setup prepare', 'verify_local_identity',
        'audit_installation prepare', 'activate_service_installation',
        'local_identity_setup schedule --cron-file "$CRON_TMP"',
        'crontab -u "$INSTALL_USER" "$CRON_TMP"', 'audit_installation activate', 'local_identity_setup finish',
    )
    positions = {}
    for number, line in enumerate(lines):
        command = line.strip()
        if command in commands:
            positions.setdefault(command, []).append(number)
    for command in commands:
        assert len(positions.get(command, [])) == (2 if command == 'verify_local_identity' else 1)
    begin = positions['local_identity_setup begin'][0]
    reset_begin = positions['local_identity_setup begin --reset'][0]
    prepare = positions['local_identity_setup prepare'][0]
    verify, published_verify = positions['verify_local_identity']
    publish = positions['activate_service_installation'][0]
    schedule = positions['local_identity_setup schedule --cron-file "$CRON_TMP"'][0]
    cron = positions['crontab -u "$INSTALL_USER" "$CRON_TMP"'][0]
    finish = positions['local_identity_setup finish'][0]
    activation = positions['audit_installation activate'][0]
    assert begin < reset_begin < prepare < verify < publish < published_verify < schedule < cron < activation < finish
    condition = 'if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then'
    assert lines[begin - 1].strip() == condition
    assert lines[reset_begin + 1].strip() == 'fi'
    selected = lines[begin - 1:reset_begin + 2] + lines[prepare:published_verify + 1] + lines[schedule:finish + 1]
    # Execute only these allowlisted calls/control statements, all replaced by
    # harmless functions. Never run the installer or any privileged commands.
    for line in selected:
        command = line.strip()
        if command and not command.startswith('#'):
            assert command in commands or command in (condition, 'else', 'fi')
    prefix = r'''set -euo pipefail
INSTALL_OPERATION=$1
FAILURE=$2
INSTALL_USER=mysql_siem
CRON_TMP=/synthetic/cron
VERIFY_COUNT=0
local_identity_setup() {
    printf 'identity:%s\n' "$*"
    if [[ "$1" == prepare && "$FAILURE" == prepare ]]; then return 23; fi
}
verify_local_identity() {
    VERIFY_COUNT=$((VERIFY_COUNT + 1))
    printf 'verify:%s\n' "$VERIFY_COUNT"
    if [[ "$FAILURE" == verify && "$VERIFY_COUNT" == 1 ]]; then return 23; fi
    if [[ "$FAILURE" == published-verify && "$VERIFY_COUNT" == 2 ]]; then return 23; fi
}
activate_service_installation() { printf 'publish\n'; }
audit_installation() {
    printf 'audit:%s\n' "$*"
    if [[ "$1" == activate && "$FAILURE" == audit-activate ]]; then return 23; fi
}
crontab() { printf 'cron\n'; }
'''
    result = subprocess.run(['bash', '-c', prefix + '\n'.join(selected),
                             'identity-order-test', operation, failure or 'none'],
                            capture_output=True, text=True, timeout=5, check=False)
    expected = [
        'identity:begin' + (' --reset' if operation == 'reset' else ''),
        'identity:prepare', 'verify:1', 'audit:prepare', 'publish', 'verify:2',
        'identity:schedule --cron-file /synthetic/cron', 'cron', 'audit:activate', 'identity:finish',
    ]
    if failure == 'prepare':
        expected = expected[:2]
    elif failure == 'verify':
        expected = expected[:3]
    elif failure == 'published-verify':
        expected = expected[:6]
    elif failure == 'audit-activate':
        expected = expected[:9]
    assert result.returncode == (23 if failure else 0), result.stderr
    assert result.stdout.splitlines() == expected


@pytest.mark.parametrize('rows,accepted', [
    ([], True),
    ([(10, 1, 1)], True),
    ([(10, 1, 1), (11, 1, 1)], False),
    ([(10, 1, 1), (11, 0, 1)], False),
    ([(10, 0, 1)], False),
    ([(10, 1, 0)], False),
    ([(10, 1, None)], False),
])
def test_existing_local_source_requires_one_approved_binding(rows, accepted):
    from unittest.mock import MagicMock

    cursor = MagicMock()
    cursor.fetchone.side_effect = [(4,), (4,)]
    cursor.fetchall.return_value = rows
    if accepted:
        expected = 10 if rows else None
        assert local.existing_local_source(cursor, 4, 7, 'auth') == expected
    else:
        with pytest.raises(IdentityError):
            local.existing_local_source(cursor, 4, 7, 'auth')
    # Resolving an existing binding must never approve or update registry rows.
    for call in cursor.execute.call_args_list:
        assert call.args[0].lstrip().startswith('SELECT')
    assert cursor.execute.call_args_list[1].args[1] == (7, 4, 'auth')


@pytest.mark.parametrize('replies', [[None], [(4,), None], [(4,), (9,)]])
def test_existing_source_rejects_inactive_or_conflicting_identity(replies):
    from unittest.mock import MagicMock

    cursor = MagicMock()
    cursor.fetchone.side_effect = replies
    cursor.fetchall.return_value = [(10, 1, 1)]
    with pytest.raises(IdentityError):
        local.existing_local_source(cursor, 4, 7, 'auth')


@pytest.mark.parametrize('fault', ['symlink', 'duplicate', 'missing-rotation', 'wrong-family', 'relative'])
def test_checkpoint_file_inventory_rejects_unsafe_or_incomplete_paths(tmp_path, fault):
    base = tmp_path / 'ufw.log'
    base.write_bytes(b'')
    paths = [base]
    if fault == 'symlink':
        original = tmp_path / 'other.log'
        original.write_bytes(b'')
        base.unlink()
        base.symlink_to(original)
    elif fault == 'duplicate':
        paths = [base, base]
    elif fault == 'missing-rotation':
        (tmp_path / 'ufw.log.1').write_bytes(b'')
    elif fault == 'wrong-family':
        other = tmp_path / 'other.log'
        other.write_bytes(b'')
        paths = [other, base]
    else:
        paths = ['ufw.log']
    with pytest.raises(IdentityError):
        local.checkpoint_files(paths)


@pytest.mark.parametrize('change', ['append', 'rotate', 'new-rotation', 'truncate-regrow'])
def test_file_changes_during_transition_are_rejected(tmp_path, change):
    base = tmp_path / 'ufw.log'
    base.write_bytes(b'old\n')
    root, files = local.checkpoint_files([base])
    if change == 'append':
        with base.open('ab') as output:
            output.write(b'new\n')
    elif change == 'rotate':
        base.rename(tmp_path / 'ufw.log.1')
        base.write_bytes(b'new\n')
    elif change == 'new-rotation':
        (tmp_path / 'ufw.log.1').write_bytes(b'old\n')
    else:
        base.write_bytes(b'new\n')
    with pytest.raises(IdentityError, match='changed|rotation'):
        local.unchanged_checkpoint_files(root, files)


def test_history_scan_is_bounded_before_opening_large_log(tmp_path):
    from unittest.mock import MagicMock

    path = tmp_path / 'ufw.log'
    info = SimpleNamespace(st_size=64 * 1024 * 1024 + 1)
    cursor = MagicMock()
    with pytest.raises(IdentityError, match='64 MiB'):
        local.validate_checkpoint_history(cursor, 'ufw_log', path, info, 0)
    cursor.execute.assert_not_called()


@pytest.mark.parametrize('operation', ['reset', 'upgrade', None])
@pytest.mark.parametrize('error', [IdentityError('synthetic conflict'), OSError('synthetic error')])
def test_recovery_error_preserves_the_selected_operation(tmp_path, monkeypatch, capsys, operation, error):
    from unittest.mock import Mock

    monkeypatch.setattr(local, 'require_administrator', Mock(side_effect=error))
    arguments = ['prepare', '--project', str(tmp_path)]
    if operation is not None:
        arguments += ['--operation', operation]
    assert local.main(arguments) == 1
    message = capsys.readouterr().err
    if operation == 'upgrade':
        assert 'sudo bash install.sh --role server --upgrade' in message
        assert 'server;' not in message and 'server.' not in message
    elif operation == 'reset':
        assert 'sudo bash install.sh --role server' in message
    else:
        assert 'rerun the same installation command' in message
        assert 'sudo bash install.sh --role server' not in message


def test_upgrade_cannot_enter_the_reset_identity_path(tmp_path, monkeypatch):
    from unittest.mock import Mock

    begin = Mock()
    monkeypatch.setattr(local, 'begin_maintenance', begin)
    assert local.main(['begin', '--project', str(tmp_path), '--operation', 'upgrade', '--reset']) == 1
    begin.assert_not_called()


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
def test_installer_passes_operation_to_identity_setup_and_verification(operation):
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index('local_identity_setup() {')
    end = installer.index('# Platform and dependency checks', start)
    script = r'''set -eu
PROJECT_DIR=/synthetic/project
SERVICE_DIR=/synthetic/service
INSTALL_USER=mysql_siem
APP_PYTHON=identity_python
INSTALL_OPERATION=$1
identity_python() { printf '%s\n' "$*"; }
runuser() { printf '%s\n' "$*"; }
''' + installer[start:end] + '\nlocal_identity_setup prepare\nverify_local_identity\n'
    result = subprocess.run(['bash', '-c', script, 'operation-test', operation],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 2
    for line in lines:
        assert '--operation ' + operation in line


@pytest.mark.parametrize('symlink', [False, True])
def test_audit_permission_barrier_blocks_jobs_before_identity_enrollment(tmp_path, symlink):
    wrapper, directory = wrapper_setup(tmp_path)
    (directory / 'runtime.lock').touch(mode=0o644)
    pending = directory / 'audit-permissions.pending'
    if symlink:
        pending.symlink_to(directory / 'missing-marker')
    else:
        pending.write_text('Audit permission setup is incomplete.\n')
    result = subprocess.run(['bash', str(wrapper), '/bin/echo', 'must-not-run'],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 75
    assert 'must-not-run' not in result.stdout
