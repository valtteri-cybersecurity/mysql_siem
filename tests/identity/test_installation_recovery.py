"""Exercise publication failures only in temporary trees, with fake cron/DB."""

import fcntl
import os
import pwd
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from config import installation_state as journal
from config import service_installation as service
from database import local_identity as local
from database.identity import IdentityError


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(service, 'validate_virtualenv', lambda *args, **kwargs: None)
    monkeypatch.setattr(journal, 'require_install_lock', lambda: None)
    monkeypatch.setattr(local, 'require_stopped_legacy_jobs', lambda *args: None)
    monkeypatch.setattr(local, 'require_administrator', lambda: None)
    actual_chown = os.chown
    monkeypatch.setattr(service.os, 'chown', lambda path, uid, gid: actual_chown(path, os.getuid() if uid == 0 else uid, gid))
    state = tmp_path / 'state'
    state.mkdir()
    journal.write_file(state / 'maintenance', journal.MAINTENANCE_TEXT, mode=0o644)

    def guard(path):
        if journal.read_file(path / 'maintenance', public=True) != journal.MAINTENANCE_TEXT:
            raise journal.InstallationStateError('Required maintenance state is missing.')

    monkeypatch.setattr(journal, 'require_maintenance', guard)
    monkeypatch.setattr(local, 'STATE_DIR', state)
    source = tmp_path / 'source'
    (source / 'config').mkdir(parents=True)
    (source / 'app.py').write_text('new program\n')
    target = tmp_path / 'mysql_siem'
    (target / 'config').mkdir(parents=True)
    (target / 'app.py').write_text('working program\n')
    (target / 'config/mysql.env').write_text('DB_PASSWORD=synthetic-preserved-password\n')
    (target / 'collector.log').write_text('preserved log\n')
    old_identity = {local.COLLECTOR_KEY: 7, local.LOCAL_KEYS['ufw']: 10}
    local.write_settings(target / 'config/identity.env', old_identity, os.getgid())
    environments = tmp_path / 'environments'
    environments.mkdir()
    monkeypatch.setattr(service, 'ENVIRONMENTS', environments)
    previous = environments / 'python-previous'
    previous.mkdir()
    stable = tmp_path / 'python'
    stable.symlink_to(previous)
    user = pwd.getpwuid(os.getuid()).pw_name
    stage = service.prepare_deployment(source, target, user, None, stable, state)
    candidate = environments / 'python-candidate'
    (candidate / 'bin').mkdir(parents=True)
    (candidate / 'bin/python').write_text('synthetic interpreter\n')
    (candidate / 'pyvenv.cfg').write_text('synthetic environment\n')
    identity = {local.COLLECTOR_KEY: 7}
    for number, key in enumerate(local.LOCAL_KEYS.values(), 10):
        identity[key] = number
    local.write_settings(stage / 'config/identity.env', identity, os.getgid())
    record = journal.read_deployment(state)
    record.update(candidate=str(candidate), identity=identity, database_started=True, checkpoint_transition=True)
    journal.save_deployment(state, record)
    receipt = {'version': 1, 'token': 'f6077508-f087-40b8-856d-ddc98823a58c', 'database': 'synthetic',
               'server': 'synthetic-server', 'initial': {}, 'identity': identity, 'host_id': 4, 'phase': 'database_ready'}
    local.save_receipt(state / 'receipt.json', receipt)
    monkeypatch.setattr(local, 'database_key', lambda connection: ('synthetic', 'synthetic-server'))
    monkeypatch.setattr(local, 'validate_bindings', lambda *args, **kwargs: 4)
    monkeypatch.setattr(local, 'verify_pending_checkpoints', lambda *args, **kwargs: None)
    return SimpleNamespace(state=state, source=source, target=target, stable=stable, stage=stage,
                           candidate=candidate, user=user, identity=identity, previous=previous)


def activate(layout):
    service.activate_deployment(layout.stage, layout.target, layout.candidate, layout.stable, layout.state)


def finish(layout):
    local.finish_maintenance(layout.state, layout.target / 'config/identity.env', MagicMock(),
                             user=layout.user, installed=layout.target, auth_reader='reader', ufw_paths=[], auth_paths=[])


def prepare_cron(layout, monkeypatch):
    text = (local.BEGIN + '\n* * * * * cd "' + str(layout.target) + '" && "'
            + str(layout.target / 'config/run_with_env.sh') + '" "'
            + str(layout.stable / 'bin/python') + '" -m ingestion.auth.main\n' + local.END + '\n')
    path = layout.state / 'candidate.cron'
    journal.write_file(path, text)
    local.schedule_maintenance(layout.state, layout.target, path, layout.user)
    monkeypatch.setattr(local, 'read_crontab', lambda user: text)
    return text


def test_staged_credentials_and_identity_are_reused_on_retry(deployment):
    layout = deployment
    original = (layout.stage / 'config/mysql.env').read_bytes()
    resumed = service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state)
    assert resumed == layout.stage
    assert (resumed / 'config/mysql.env').read_bytes() == original
    assert local.read_settings(resumed / 'config/identity.env') == layout.identity
    service.discard_deployment(layout.state)
    assert layout.stage.exists()  # Database-started state may never be discarded.
    assert (layout.state / 'maintenance').exists()


def test_finish_before_program_publication_keeps_collection_paused(deployment):
    with pytest.raises(service.InstallationError, match='publication has not completed'):
        finish(deployment)
    assert (deployment.state / 'maintenance').exists()
    assert local.read_receipt(deployment.state / 'receipt.json')['phase'] == 'database_ready'


@pytest.mark.parametrize('fault', ['missing', 'different', 'read-error'])
def test_cron_failure_does_not_unpause_published_program(deployment, monkeypatch, fault):
    activate(deployment)
    if fault != 'missing':
        prepare_cron(deployment, monkeypatch)
    if fault == 'read-error':
        def fail(user):
            raise IdentityError('Cannot read installed crontab')
        monkeypatch.setattr(local, 'read_crontab', fail)
    else:
        monkeypatch.setattr(local, 'read_crontab', lambda user: 'old jobs\n')
    with pytest.raises(IdentityError):
        finish(deployment)
    assert (deployment.state / 'maintenance').exists()
    assert local.read_receipt(deployment.state / 'receipt.json')['phase'] == 'database_ready'
    prepare_cron(deployment, monkeypatch)
    finish(deployment)
    assert not (deployment.state / 'maintenance').exists()
    assert local.read_receipt(deployment.state / 'receipt.json')['phase'] == 'ready'
    assert journal.read_deployment(deployment.state)['phase'] == 'complete'


def test_identity_write_failure_after_commit_is_retryable(deployment, monkeypatch):
    layout = deployment
    before = (layout.stage / 'config/identity.env').read_bytes()
    connection = MagicMock()
    monkeypatch.setattr(local.pymysql, 'connect', lambda **kwargs: connection)
    monkeypatch.setattr(local, 'provision', lambda *args, **kwargs: layout.identity)
    arguments = ['prepare', '--project', str(layout.stage), '--installed', str(layout.target), '--user', layout.user]
    monkeypatch.setenv('DB_NAME', 'synthetic')
    real_write = local.write_settings

    def fail(*args):
        raise OSError('simulated disk error')

    with monkeypatch.context() as patch:
        patch.setattr(local, 'write_settings', fail)
        assert local.main(arguments) == 1
    assert (layout.stage / 'config/identity.env').read_bytes() == before
    assert (layout.state / 'maintenance').exists()
    assert local.read_receipt(layout.state / 'receipt.json')['identity'] == layout.identity
    monkeypatch.setattr(local, 'write_settings', real_write)
    assert local.main(arguments) == 0
    assert local.read_settings(layout.stage / 'config/identity.env') == layout.identity


def test_publish_exception_restores_old_program_and_keeps_prepared_identity(deployment, monkeypatch):
    layout = deployment
    original = service.os.rename

    def fail(old, new):
        if Path(old) == layout.stage and Path(new) == layout.target:
            raise OSError('simulated publication failure')
        return original(old, new)

    with monkeypatch.context() as patch:
        patch.setattr(service.os, 'rename', fail)
        with pytest.raises(OSError, match='publication failure'):
            activate(layout)
    assert (layout.target / 'app.py').read_text() == 'working program\n'
    assert os.readlink(layout.stable) == str(layout.previous)
    assert local.read_settings(layout.target / 'config/identity.env') != layout.identity
    assert local.read_settings(layout.stage / 'config/identity.env') == layout.identity
    assert (layout.state / 'maintenance').exists()
    assert service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state) == layout.stage
    activate(layout)
    assert local.read_settings(layout.target / 'config/identity.env') == layout.identity


@pytest.mark.parametrize('point', ['program-backup', 'settings-move', 'program-published', 'python-published'])
@pytest.mark.parametrize('plain_environment', [False, True])
def test_process_death_during_publication_can_restore_previous_version(deployment, point, plain_environment):
    layout = deployment
    if plain_environment:
        layout.stable.unlink()
        layout.stable.mkdir()
        (layout.stable / 'old-package').write_text('working dependencies\n')
    # This child touches only the temporary fixture. _exit bypasses all cleanup,
    # simulating a killed installer between filesystem operations.
    code = '''
import os, sys
from pathlib import Path
from config import service_installation as service, installation_state as journal
state, point = Path(sys.argv[1]), sys.argv[2]
record = journal.read_deployment(state)
service.trusted_directory = lambda path: None
service.validate_virtualenv = lambda *args, **kwargs: None
journal.require_maintenance = lambda path: None
service.ENVIRONMENTS = Path(record['candidate']).parent
chown = os.chown
os.chown = lambda path, uid, gid: chown(path, os.getuid() if uid == 0 else uid, gid)
rename, replace = os.rename, os.replace
stage, target, stable = Path(record['stage']), Path(record['target']), Path(record['stable'])
def crash_rename(old, new):
    rename(old, new)
    if ((point == 'program-backup' and Path(old) == target)
            or (point == 'program-published' and Path(old) == stage and Path(new) == target)):
        os._exit(86)
def crash_replace(old, new):
    replace(old, new)
    if ((point == 'settings-move' and str(old).endswith('/config/mysql.env'))
            or (point == 'python-published' and Path(new) == stable)):
        os._exit(86)
os.rename, os.replace = crash_rename, crash_replace
service.activate_deployment(stage, target, Path(record['candidate']), stable, state)
raise SystemExit('failpoint was not reached')
'''
    process = subprocess.run([sys.executable, '-B', '-c', code, str(layout.state), point],
                             capture_output=True, text=True, timeout=10, check=False)
    assert process.returncode == 86, process.stderr
    assert journal.read_deployment(layout.state)['phase'] == 'publishing'
    assert (layout.state / 'maintenance').exists()
    resumed = service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state)
    assert resumed == layout.stage
    assert (layout.target / 'app.py').read_text() == 'working program\n'
    assert 'synthetic-preserved-password' in (layout.target / 'config/mysql.env').read_text()
    assert (layout.target / 'collector.log').read_text() == 'preserved log\n'
    if plain_environment:
        assert not layout.stable.is_symlink()
        assert (layout.stable / 'old-package').read_text() == 'working dependencies\n'
    else:
        assert os.readlink(layout.stable) == str(layout.previous)
    assert 'synthetic-preserved-password' in (resumed / 'config/mysql.env').read_text()
    assert local.read_settings(layout.target / 'config/identity.env') != layout.identity
    activate(layout)
    assert (layout.target / 'app.py').read_text() == 'new program\n'
    assert local.read_settings(layout.target / 'config/identity.env') == layout.identity


def test_retry_after_successful_publication_preserves_committed_settings(deployment, monkeypatch):
    activate(deployment)
    resumed = service.prepare_deployment(deployment.source, deployment.target, deployment.user,
                                         None, deployment.stable, deployment.state)
    assert resumed != deployment.stage
    assert local.read_settings(resumed / 'config/identity.env') == deployment.identity
    assert journal.read_deployment(deployment.state)['checkpoint_transition'] is True
    assert (deployment.state / 'maintenance').exists()
    deployment.stage = resumed
    record = journal.read_deployment(deployment.state)
    record.update(candidate=str(deployment.candidate), identity=deployment.identity)
    journal.save_deployment(deployment.state, record)
    activate(deployment)
    prepare_cron(deployment, monkeypatch)
    finish(deployment)
    assert not (deployment.state / 'maintenance').exists()


def test_failure_removing_gate_can_be_retried_without_losing_transition_proof(deployment, monkeypatch):
    activate(deployment)
    prepare_cron(deployment, monkeypatch)
    original = Path.unlink

    def fail(path, *args, **kwargs):
        if path == deployment.state / 'maintenance':
            raise OSError('simulated gate removal failure')
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, 'unlink', fail)
        with pytest.raises(OSError):
            finish(deployment)
    assert (deployment.state / 'maintenance').exists()
    assert journal.read_deployment(deployment.state)['phase'] == 'complete'
    stage = service.prepare_deployment(deployment.source, deployment.target, deployment.user,
                                       None, deployment.stable, deployment.state)
    assert journal.read_deployment(deployment.state)['checkpoint_transition'] is True
    assert local.read_settings(stage / 'config/identity.env') == deployment.identity


@pytest.mark.parametrize('action', ['prepare', 'finish', 'schedule'])
def test_direct_commands_without_locks_cannot_open_database(tmp_path, monkeypatch, action):
    monkeypatch.setattr(local, 'require_administrator', lambda: None)
    monkeypatch.setattr(local, 'STATE_DIR', tmp_path)
    # Keep the real guard: descriptor 9 is not a held installer lock.
    connect = MagicMock(side_effect=AssertionError('unexpected DB access'))
    monkeypatch.setattr(local.pymysql, 'connect', connect)
    assert local.main([action, '--project', str(tmp_path)]) == 1
    connect.assert_not_called()


def test_lock_must_be_owned_by_the_supplied_open_description(tmp_path):
    path = tmp_path / 'lock'
    with path.open('w') as owned, path.open('r') as unrelated:
        path.chmod(0o600)
        with pytest.raises(journal.InstallationStateError, match='not held'):
            journal.require_lock(path, owned.fileno())
        fcntl.flock(owned, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal.require_lock(path, owned.fileno())
        with pytest.raises(journal.InstallationStateError, match='another process'):
            journal.require_lock(path, unrelated.fileno())


def test_parallel_deployment_cannot_take_installer_lock(tmp_path):
    path = tmp_path / 'install.lock'
    with path.open('w') as owner:
        fcntl.flock(owner, fcntl.LOCK_EX)
        code = '''
import fcntl, sys
with open(sys.argv[1]) as lock:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(75)
raise SystemExit('parallel installation acquired the lock')
'''
        result = subprocess.run([sys.executable, '-B', '-c', code, str(path)], check=False,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 75


@pytest.mark.parametrize('root_job', [False, True])
def test_legacy_job_detection_never_kills_running_process(tmp_path, monkeypatch, root_job):
    process = tmp_path / '12345'
    process.mkdir()
    (process / 'cmdline').write_bytes(b'python\0-m\0ingestion.auth.main\0')
    original = Path.iterdir
    original_stat = Path.stat
    if root_job:
        monkeypatch.setattr(Path, 'stat', lambda path, *args, **kwargs: SimpleNamespace(st_uid=0)
                            if path == process else original_stat(path, *args, **kwargs))
    monkeypatch.setattr(Path, 'iterdir', lambda path: iter([process]) if path == Path('/proc') else original(path))
    user = pwd.getpwuid(os.getuid()).pw_name
    with pytest.raises(IdentityError, match='still running.*12345'):
        local.require_stopped_legacy_jobs(tmp_path / 'installed', user)


@pytest.mark.parametrize('missing', [None, 'runtime', 'marker'])
def test_maintenance_requires_both_real_inherited_locks(tmp_path, missing):
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'maintenance').write_text(journal.MAINTENANCE_TEXT)
    (state / 'maintenance').chmod(0o644)
    if missing == 'marker':
        (state / 'maintenance').unlink()
    code = '''
import os
from pathlib import Path
from config import installation_state as journal, service_installation as service
service.trusted_directory = lambda path: None
journal.INSTALL_LOCK = Path(os.environ['TEST_INSTALL_LOCK'])
journal.require_maintenance(Path(os.environ['TEST_STATE']))
'''
    command = 'umask 077; exec 9> "$TEST_INSTALL_LOCK"; flock -x 9; exec 8> "$TEST_STATE/runtime.lock"; flock -x 8; exec "$TEST_PYTHON" -B -c "$TEST_CODE"'
    if missing == 'runtime':
        command = command.replace('flock -x 8;', ':;')
    result = subprocess.run(['bash', '-c', command], capture_output=True, text=True, timeout=10, check=False,
                            env=dict(os.environ, TEST_INSTALL_LOCK=str(tmp_path / 'install.lock'), TEST_STATE=str(state),
                                     TEST_PYTHON=sys.executable, TEST_CODE=code))
    assert (result.returncode == 0) == (missing is None), result.stderr


def test_invalid_cron_plan_cannot_be_marked_ready(deployment):
    activate(deployment)
    path = deployment.state / 'bad.cron'
    journal.write_file(path, local.BEGIN + '\n* * * * * python legacy.py\n' + local.END + '\n')
    with pytest.raises(IdentityError, match='bypasses'):
        local.schedule_maintenance(deployment.state, deployment.target, path, deployment.user)
    assert journal.read_deployment(deployment.state)['cron_digest'] is None
    assert (deployment.state / 'maintenance').exists()


def test_crontab_write_failure_never_calls_finish_or_releases_gate(tmp_path):
    import shlex

    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    block = installer.split("# Update only this installation's marked cron block.", 1)[1]
    block = block.split('log "Installation steps completed.', 1)[0]
    cron = tmp_path / 'crontab'
    cron.write_text('17 * * * * echo unrelated\n')
    gate = tmp_path / 'maintenance'
    gate.write_text('paused\n')
    marker = tmp_path / 'finish-called'
    script = '''set -Eeuo pipefail
local_identity_setup() {
    if [[ "$1" == finish ]]; then touch "$FINISH_MARKER"; fi
}
crontab() {
    if [[ "${@: -1}" == -l ]]; then
        cat "$TEST_CRON"
    else
        printf 'simulated crontab write failure\\n' >&2
        return 42
    fi
}
die() { echo "$*" >&2; exit 1; }
'''
    values = {'INSTALL_USER': 'synthetic', 'PROJECT_DIR': str(tmp_path),
              'APP_PYTHON': '/synthetic/python/bin/python', 'CRON_BEGIN': local.BEGIN, 'CRON_END': local.END,
              'TEST_CRON': str(cron), 'FINISH_MARKER': str(marker), 'PORT_SCAN_CRON': '', 'DNS_CRON': ''}
    for name, value in values.items():
        script += name + '=' + shlex.quote(value) + '\n'
    result = subprocess.run(['bash', '-c', script + block], capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 42, result.stderr
    assert not marker.exists()
    assert gate.exists()
    assert cron.read_text() == '17 * * * * echo unrelated\n'



def test_old_receipt_without_recoverable_credentials_fails_before_staging(deployment):
    layout = deployment
    (layout.state / 'deployment.json').unlink()
    (layout.target / 'config/mysql.env').unlink()
    before = set(layout.target.parent.iterdir())
    with pytest.raises(service.InstallationError, match='original prepared'):
        service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state)
    assert set(layout.target.parent.iterdir()) == before
    assert (layout.state / 'receipt.json').exists()
    assert (layout.state / 'maintenance').exists()



def test_cron_shell_waiting_to_enter_wrapper_is_not_a_legacy_python_job(tmp_path, monkeypatch):
    process = tmp_path / '12345'
    process.mkdir()
    (process / 'cmdline').write_bytes(b'/bin/sh\0-c\0python -m ingestion.auth.main\0')
    original = Path.iterdir
    monkeypatch.setattr(Path, 'iterdir', lambda path: iter([process]) if path == Path('/proc') else original(path))
    local.require_stopped_legacy_jobs(tmp_path / 'installed', pwd.getpwuid(os.getuid()).pw_name)



def test_unmanaged_legacy_job_cannot_be_restored_with_new_cron(deployment):
    activate(deployment)
    path = deployment.state / 'bad.cron'
    text = '* * * * * python -m ingestion.auth.main\n' + local.BEGIN + '\n' + local.END + '\n'
    journal.write_file(path, text)
    with pytest.raises(IdentityError, match='Unmanaged legacy'):
        local.schedule_maintenance(deployment.state, deployment.target, path, deployment.user)
    assert (deployment.state / 'maintenance').exists()
    assert journal.read_deployment(deployment.state)['cron_digest'] is None
