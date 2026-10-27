"""Exercise publication failures only in temporary trees, with fake cron/DB."""

import fcntl
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from config import audit_setup
from config import installation_state as journal
from config import service_installation as service
from config.audit_setup import verify_audit_activation as real_verify_audit_activation
from database import local_identity as local
from database.identity import IdentityError


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(service, 'validate_virtualenv', lambda *args, **kwargs: None)
    monkeypatch.setattr(journal, 'require_install_lock', lambda: None)
    monkeypatch.setattr(local, 'require_stopped_legacy_jobs', lambda *args: None)
    monkeypatch.setattr(local, 'require_administrator', lambda: None)
    monkeypatch.setattr(audit_setup, 'verify_audit_activation', Mock())
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


def rebuild_test_environment(layout):
    # The installer builds a new complete environment after restaging the code.
    record = journal.read_deployment(layout.state)
    assert record['candidate'] is None
    candidate = service.new_environment()
    (candidate / 'bin').mkdir()
    (candidate / 'bin/python').write_text('synthetic interpreter\n')
    (candidate / 'pyvenv.cfg').write_text('synthetic environment\n')
    record['candidate'] = str(candidate)
    journal.save_deployment(layout.state, record)
    layout.candidate = candidate


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
    assert resumed != layout.stage
    assert (resumed / 'config/mysql.env').read_bytes() == original
    assert local.read_settings(resumed / 'config/identity.env') == layout.identity
    service.discard_deployment(layout.state)
    assert layout.stage.exists()  # Database-started state may never be discarded.
    assert resumed.exists()
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
    previous_stage = layout.stage
    layout.stage = service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state)
    assert layout.stage != previous_stage
    rebuild_test_environment(layout)
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
    assert resumed != layout.stage
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
    layout.stage = resumed
    rebuild_test_environment(layout)
    activate(layout)
    assert (layout.target / 'app.py').read_text() == 'new program\n'
    assert local.read_settings(layout.target / 'config/identity.env') == layout.identity


@pytest.mark.parametrize('phase', ['activated', 'complete'])
def test_retry_after_successful_publication_preserves_committed_settings(deployment, monkeypatch, phase):
    activate(deployment)
    record = journal.read_deployment(deployment.state)
    record['phase'] = phase
    journal.save_deployment(deployment.state, record)
    resumed = service.prepare_deployment(deployment.source, deployment.target, deployment.user,
                                         None, deployment.stable, deployment.state)
    assert resumed != deployment.stage
    assert local.read_settings(resumed / 'config/identity.env') == deployment.identity
    record = journal.read_deployment(deployment.state)
    assert record['checkpoint_transition'] is True
    assert record['database_started'] is True
    assert record['database_started_current'] is False
    service.discard_deployment(deployment.state)
    assert resumed.exists()
    assert journal.read_deployment(deployment.state) == record
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


def test_reset_retry_uses_new_code_but_retains_pending_settings(deployment):
    layout = deployment
    (layout.stage / 'app.py').write_text('obsolete staged program\n')
    secret = (layout.stage / 'config/mysql.env').read_bytes()
    fresh = service.prepare_deployment(layout.source, layout.target, layout.user, None,
                                       layout.stable, layout.state, reset=True)
    assert fresh != layout.stage
    assert (fresh / 'app.py').read_text() == 'new program\n'
    assert (fresh / 'config/mysql.env').read_bytes() == secret
    assert (layout.target / 'app.py').read_text() == 'working program\n'
    record = journal.read_deployment(layout.state)
    assert record['stage'] == str(fresh)
    assert record['identity'] == layout.identity
    assert record['database_started'] is True


def test_reset_invalidates_only_old_identity_after_confirmation(deployment):
    from config.reset_installation import clear_old_identity
    layout = deployment
    secret = (layout.stage / 'config/mysql.env').read_bytes()
    clear_old_identity(layout.state, layout.stage)
    assert not (layout.stage / 'config/identity.env').exists()
    assert not (layout.state / 'receipt.json').exists()
    assert (layout.stage / 'config/mysql.env').read_bytes() == secret
    assert (layout.target / 'config/identity.env').exists()
    assert (layout.state / 'maintenance').exists()
    record = journal.read_deployment(layout.state)
    assert record['identity'] == {} and record['checkpoint_transition'] is False


@pytest.fixture(params=['legacy', 'current'])
def unpublished(deployment, request):
    layout = deployment
    path = layout.state / 'deployment.json'
    record = json.loads(path.read_text())
    if request.param == 'legacy':
        record.pop('database_started_current')
    else:
        record['database_started_current'] = True
    journal.write_file(path, json.dumps(record, sort_keys=True) + '\n')
    layout.target.rename(layout.target.with_name('unpublished-fixture-backup'))
    role = layout.stage / 'config/role.env'
    role.write_text('SIEM_ROLE=server\n')
    role.chmod(0o600)
    return layout


def test_unpublished_recovery_uses_protected_journal_and_keeps_settings(unpublished):
    layout = unpublished
    journal_file = layout.state / 'deployment.json'
    receipt = layout.state / 'receipt.json'
    before = journal_file.read_bytes(), receipt.read_bytes(), (layout.stage / 'config/mysql.env').read_bytes()
    recovered = service.check_unpublished_recovery(layout.target, layout.stable, layout.user, layout.state)
    assert recovered == layout.stage
    assert not layout.target.exists()
    assert (journal_file.read_bytes(), receipt.read_bytes(), (layout.stage / 'config/mysql.env').read_bytes()) == before


@pytest.mark.parametrize('fault', ['missing-journal', 'invalid-journal', 'wrong-user', 'wrong-target',
                                  'wrong-stage', 'missing-receipt', 'invalid-receipt', 'prepared-receipt',
                                  'missing-settings', 'unsafe-settings', 'wrong-role', 'no-maintenance'])
def test_invalid_unpublished_recovery_is_rejected_without_repairs(unpublished, fault):
    layout = unpublished
    journal_file = layout.state / 'deployment.json'
    record = journal.read_deployment(layout.state)
    if fault == 'missing-journal':
        journal_file.unlink()
    elif fault == 'invalid-journal':
        journal_file.write_text('{}')
    elif fault in ('wrong-user', 'wrong-target', 'wrong-stage'):
        key = {'wrong-user': 'user', 'wrong-target': 'target', 'wrong-stage': 'stage'}[fault]
        record[key] = 'other-user' if key == 'user' else str(layout.state / 'wrong-location')
        journal.save_deployment(layout.state, record)
    elif fault == 'missing-receipt':
        (layout.state / 'receipt.json').unlink()
    elif fault == 'invalid-receipt':
        (layout.state / 'receipt.json').write_text('{invalid')
    elif fault == 'prepared-receipt':
        receipt = local.read_receipt(layout.state / 'receipt.json')
        receipt['phase'] = 'prepared'
        local.save_receipt(layout.state / 'receipt.json', receipt)
    elif fault == 'missing-settings':
        (layout.stage / 'config/mysql.env').unlink()
    elif fault == 'unsafe-settings':
        (layout.stage / 'config/mysql.env').chmod(0o660)
    elif fault == 'wrong-role':
        (layout.stage / 'config/role.env').write_text('SIEM_ROLE=collector\n')
    else:
        (layout.state / 'maintenance').unlink()
    before = journal_file.read_bytes() if journal_file.exists() else None
    with pytest.raises((service.InstallationError, journal.InstallationStateError, OSError, ValueError)):
        service.check_unpublished_recovery(layout.target, layout.stable, layout.user, layout.state)
    assert (journal_file.read_bytes() if journal_file.exists() else None) == before
    assert not layout.target.exists()
    assert layout.stage.exists()


@pytest.mark.parametrize('mode', ['valid', 'no-installer', 'no-runtime', 'wrong-installer'])
def test_unpublished_recovery_requires_real_inherited_locks(unpublished, mode):
    layout = unpublished
    installer_lock = layout.state / 'install.lock'
    runtime_lock = layout.state / 'runtime.lock'
    installer_lock.touch(mode=0o600)
    runtime_lock.touch(mode=0o644)
    (layout.state / 'other.lock').touch(mode=0o600)
    code = '''import fcntl, os, sys
from pathlib import Path
from config import installation_state as journal, service_installation as service
state, mode = Path(sys.argv[1]), sys.argv[2]
journal.INSTALL_LOCK = state / 'install.lock'
service.trusted_directory = lambda path: None
record = journal.read_deployment(state)
service.ENVIRONMENTS = Path(record['candidate']).parent
for number, name in ((9, 'install.lock'), (8, 'runtime.lock')):
    try:
        os.close(number)
    except OSError:
        pass
    if (number == 9 and mode == 'no-installer') or (number == 8 and mode == 'no-runtime'):
        continue
    path = state / name
    if number == 9 and mode == 'wrong-installer':
        path = state / 'other.lock'
    descriptor = os.open(path, os.O_RDONLY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.dup2(descriptor, number)
    if descriptor != number:
        os.close(descriptor)
try:
    service.check_unpublished_recovery(Path(record['target']), Path(record['stable']), record['user'], state)
except journal.InstallationStateError:
    sys.exit(17)
'''
    result = subprocess.run([sys.executable, '-B', '-c', code, str(layout.state), mode],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == (0 if mode == 'valid' else 17), result.stderr
    assert (layout.state / 'maintenance').exists()


@pytest.mark.parametrize('identity_missing', [False, True])
def test_receipt_check_accepts_ready_bindings_without_reenrollment(unpublished, monkeypatch, identity_missing):
    layout = unpublished
    identity_path = layout.stage / 'config/identity.env'
    if identity_missing:
        identity_path.unlink()
    connection = MagicMock()
    for name in ('register_host', 'register_collector', 'register_source', 'approve_collector_source'):
        monkeypatch.setattr(local, name, Mock(side_effect=AssertionError('Unexpected identity enrollment')))
    before = (layout.state / 'receipt.json').read_bytes(), (layout.state / 'deployment.json').read_bytes()
    local.check_staged_receipt(connection, layout.state, layout.stage, layout.target, layout.user)
    assert ((layout.state / 'receipt.json').read_bytes(), (layout.state / 'deployment.json').read_bytes()) == before
    expected_journal = journal.read_deployment(layout.state)
    monkeypatch.setattr(local, 'identity_schema_enabled', lambda connection: True)
    from ingestion import ufw_to_mysql
    from ingestion.auth import collector

    monkeypatch.setattr(local.pymysql, 'connect', Mock(return_value=connection))
    monkeypatch.setenv('DB_NAME', 'synthetic')
    monkeypatch.setattr(local, 'ssh_settings', lambda *args: ('test', '/synthetic/auth.log'))
    monkeypatch.setattr(collector, 'get_logfiles', Mock(return_value=[]))
    monkeypatch.setattr(ufw_to_mysql, 'get_logfiles', Mock(return_value=[]))
    assert local.main(['prepare', '--project', str(layout.stage), '--installed', str(layout.target),
                       '--user', layout.user]) == 0
    assert local.read_settings(identity_path) == layout.identity
    assert (layout.state / 'receipt.json').read_bytes() == before[0]
    assert journal.read_deployment(layout.state) == expected_journal
    connection.commit.assert_not_called()
    for name in ('register_host', 'register_collector', 'register_source', 'approve_collector_source'):
        getattr(local, name).assert_not_called()


@pytest.mark.parametrize('fault', ['missing', 'invalid', 'prepared', 'database', 'server', 'host', 'identity-file', 'journal-identity'])
def test_bad_receipt_or_bindings_stop_read_only_check(unpublished, fault):
    layout = unpublished
    path = layout.state / 'receipt.json'
    if fault == 'missing':
        path.unlink()
    elif fault == 'invalid':
        path.write_text('{}')
    elif fault in ('prepared', 'database', 'server', 'host'):
        receipt = local.read_receipt(path)
        key = {'prepared': 'phase', 'host': 'host_id'}.get(fault, fault)
        receipt[key] = 'prepared' if fault == 'prepared' else (99 if fault == 'host' else 'other')
        local.save_receipt(path, receipt)
    elif fault == 'identity-file':
        local.write_settings(layout.stage / 'config/identity.env', {local.COLLECTOR_KEY: 99}, os.getgid())
    else:
        record = journal.read_deployment(layout.state)
        record['identity'] = {local.COLLECTOR_KEY: 99}
        journal.save_deployment(layout.state, record)
    connection = MagicMock()
    before = (layout.state / 'deployment.json').read_bytes()
    with pytest.raises((IdentityError, ValueError)):
        local.check_staged_receipt(connection, layout.state, layout.stage, layout.target, layout.user)
    assert (layout.state / 'deployment.json').read_bytes() == before
    for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')
    connection.commit.assert_not_called()


def test_old_code_is_replaced_from_source_and_recovery_evidence_is_kept(unpublished):
    layout = unpublished
    old_stage = layout.stage
    (old_stage / 'app.py').write_text('obsolete staged program\n')
    (old_stage / 'config/installed-version').write_text('a' * 40 + '\n')
    old_record = journal.read_deployment(layout.state)
    old_receipt = (layout.state / 'receipt.json').read_bytes()
    old_settings = (old_stage / 'config/mysql.env').read_bytes()
    layout.stage = service.prepare_deployment(layout.source, layout.target, layout.user, None,
                                              layout.stable, layout.state)
    record = journal.read_deployment(layout.state)
    assert layout.stage != old_stage
    for key in ('identity', 'database_started', 'checkpoint_transition'):
        assert record[key] == old_record[key]
    assert record['candidate'] is None
    assert record['database_started_current'] is False
    assert (layout.stage / 'app.py').read_bytes() == (layout.source / 'app.py').read_bytes()
    assert (layout.stage / 'config/mysql.env').read_bytes() == old_settings
    assert local.read_settings(layout.stage / 'config/identity.env') == layout.identity
    assert (layout.state / 'receipt.json').read_bytes() == old_receipt
    assert (old_stage / 'app.py').read_text() == 'obsolete staged program\n'
    assert (old_stage / 'config/installed-version').read_text().strip() == 'a' * 40
    assert service.check_unpublished_recovery(layout.target, layout.stable, layout.user, layout.state) == layout.stage
    service.discard_deployment(layout.state)
    assert layout.stage.exists()
    assert (layout.state / 'receipt.json').read_bytes() == old_receipt
    assert journal.read_deployment(layout.state) == record
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    start = installer.index("printf '%s\\n' \"$SIEM_BOOTSTRAP_COMMIT\"")
    end = installer.index('# Create or validate the database secrets file', start)
    script = 'set -e\nPROJECT_DIR=$1\nSIEM_BOOTSTRAP_COMMIT=$2\nINSTALL_USER=test\nchown() { :; }\n' + installer[start:end]
    result = subprocess.run(['bash', '-c', script, 'stamp-test', str(layout.stage), 'b' * 40],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    rebuild_test_environment(layout)
    activate(layout)
    assert (layout.target / 'config/installed-version').read_text().strip() == 'b' * 40
    assert (layout.target / 'app.py').read_text() == 'new program\n'
    assert old_stage.exists()


def test_failed_restaging_preserves_the_original_journal_and_directory(unpublished, monkeypatch):
    layout = unpublished
    before = (layout.state / 'deployment.json').read_bytes()
    monkeypatch.setattr(service, 'stage_service', Mock(side_effect=OSError('synthetic copy failure')))
    with pytest.raises(OSError, match='copy failure'):
        service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state)
    assert (layout.state / 'deployment.json').read_bytes() == before
    assert layout.stage.exists()
    assert (layout.state / 'receipt.json').exists()


@pytest.mark.parametrize('fault', [None, 'database', 'missing'])
def test_check_recovery_command_preserves_state(unpublished, monkeypatch, fault):
    layout = unpublished
    receipt_path = layout.state / 'receipt.json'
    if fault == 'database':
        receipt = local.read_receipt(receipt_path)
        receipt['database'] = 'other'
        local.save_receipt(receipt_path, receipt)
    elif fault == 'missing':
        receipt_path.unlink()
    connection = MagicMock()
    monkeypatch.setattr(local.pymysql, 'connect', Mock(return_value=connection))
    monkeypatch.setenv('DB_NAME', 'synthetic')
    prepare = Mock(side_effect=AssertionError('Unexpected identity preparation'))
    begin = Mock(side_effect=AssertionError('Unexpected maintenance'))
    monkeypatch.setattr(local, 'provision', prepare)
    monkeypatch.setattr(local, 'begin_maintenance', begin)
    before = (layout.state / 'deployment.json').read_bytes()
    assert local.main(['check-recovery', '--project', str(layout.stage),
                       '--installed', str(layout.target), '--user', layout.user]) == (0 if fault is None else 1)
    prepare.assert_not_called()
    begin.assert_not_called()
    connection.commit.assert_not_called()
    connection.close.assert_called_once()
    assert (layout.state / 'deployment.json').read_bytes() == before
    assert (layout.state / 'maintenance').exists()


def test_failed_journal_write_preserves_old_staging(unpublished, monkeypatch):
    layout = unpublished
    before = (layout.state / 'deployment.json').read_bytes()
    monkeypatch.setattr(journal, 'save_deployment', Mock(side_effect=OSError('synthetic journal failure')))
    with pytest.raises(OSError, match='journal failure'):
        service.prepare_deployment(layout.source, layout.target, layout.user, None, layout.stable, layout.state)
    assert (layout.state / 'deployment.json').read_bytes() == before
    assert layout.stage.exists()
    assert (layout.stage / 'config/mysql.env').exists()
    assert (layout.state / 'receipt.json').exists()



def test_completed_upgrade_can_discard_only_new_pre_database_preparation(deployment, monkeypatch):
    layout = deployment
    activate(layout)
    prepare_cron(layout, monkeypatch)
    finish(layout)
    receipt = (layout.state / 'receipt.json').read_bytes()
    identity = (layout.target / 'config/identity.env').read_bytes()
    stage = service.prepare_deployment(layout.source, layout.target, layout.user,
                                       None, layout.stable, layout.state)
    record = journal.read_deployment(layout.state)
    assert record['database_started'] is False
    assert record['database_started_current'] is False
    service.discard_deployment(layout.state)
    assert not stage.exists()
    assert (layout.target / 'config/identity.env').read_bytes() == identity
    assert (layout.state / 'receipt.json').read_bytes() == receipt
    assert not (layout.state / 'maintenance').exists()


@pytest.mark.parametrize('point', ['before', 'during', 'after', 'required', 'receipt', 'journal',
                                   'unlink-before', 'unlink-after', 'success'])
def test_abrupt_audit_activation_and_finish_keep_collection_guarded(deployment, monkeypatch, point):
    layout = deployment
    root = Path(__file__).resolve().parents[2]
    units = layout.stage / 'config/systemd'
    units.mkdir()
    installed_units = layout.state / 'units'
    installed_units.mkdir()
    for name in audit_setup.UNIT_NAMES:
        content = (root / 'config/systemd' / name).read_bytes()
        (units / name).write_bytes(content)
        (installed_units / name).write_bytes(content)
    manifest = {'version': 1, 'logfile': '/var/log/audit/audit.log', 'rules_sha256': '0' * 64}
    (layout.stage / 'config/audit-runtime.json').write_text(json.dumps(manifest))
    activate(layout)
    prepare_cron(layout, monkeypatch)
    monkeypatch.setattr(journal, 'STATE_DIR', layout.state)
    monkeypatch.setattr(audit_setup, 'UNIT_DIR', installed_units)
    monkeypatch.setattr(audit_setup, 'read_root_text', lambda path: path.read_text())
    monkeypatch.setattr(audit_setup, 'trusted_directory', Mock())
    monkeypatch.setattr(audit_setup, 'verify_audit_activation', real_verify_audit_activation)
    timer = layout.state / 'enabled-timer'
    verified = layout.state / 'verified-timer'
    error_file = layout.state / 'child-error'
    (layout.state / 'runtime.lock').touch(mode=0o644)
    wrapper = layout.target / 'config/run_with_env.sh'
    wrapper.write_text((root / 'config/run_with_env.sh').read_text().replace(
        'LOCAL_STATE_DIR=/usr/local/lib/.mysql_siem-local', 'LOCAL_STATE_DIR=' + str(layout.state)))

    def command(arguments):
        assert (layout.state / 'maintenance').exists()
        if 'enable' in arguments:
            timer.touch()
            if point == 'during':
                os._exit(77)
        elif 'show' in arguments:
            return 'LoadState=loaded\nFragmentPath=' + str(installed_units / arguments[-1]) + '\nDropInPaths=\n'
        elif 'is-enabled' in arguments:
            return 'enabled\n' if timer.exists() else 'disabled\n'
        elif 'is-active' in arguments:
            assert timer.exists()
            verified.touch()
        else:
            assert arguments == ['/usr/bin/systemctl', 'daemon-reload']
        return ''

    monkeypatch.setattr(audit_setup, 'command', command)
    original_write = local.atomic_write
    original_receipt = local.save_receipt
    original_journal = journal.save_deployment
    original_unlink = Path.unlink

    def write(path, *args, **kwargs):
        original_write(path, *args, **kwargs)
        if point == 'required' and path == layout.state / 'required':
            os._exit(77)

    def save_receipt(path, receipt):
        original_receipt(path, receipt)
        if point == 'receipt':
            os._exit(77)

    def save_journal(state, record):
        original_journal(state, record)
        if point == 'journal' and record['phase'] == 'complete':
            os._exit(77)

    def unlink(path, *args, **kwargs):
        if path == layout.state / 'maintenance' and point == 'unlink-before':
            os._exit(77)
        original_unlink(path, *args, **kwargs)
        if path == layout.state / 'maintenance' and point == 'unlink-after':
            os._exit(77)

    child = os.fork()
    if child == 0:
        try:
            monkeypatch.setattr(local, 'atomic_write', write)
            monkeypatch.setattr(local, 'save_receipt', save_receipt)
            monkeypatch.setattr(journal, 'save_deployment', save_journal)
            monkeypatch.setattr(Path, 'unlink', unlink)
            if point == 'before':
                os._exit(77)
            audit_setup.activate_audit(layout.target)
            if point == 'after':
                os._exit(77)
            finish(layout)
        finally:
            error = sys.exc_info()[1]
            if error is not None:
                error_file.write_text(repr(error))
                os._exit(99)
            os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == (0 if point == 'success' else 77), (
        error_file.read_text() if error_file.exists() else str(status))
    released = point in ('unlink-after', 'success')
    assert (layout.state / 'maintenance').exists() == (not released)
    record = journal.read_deployment(layout.state)
    if released:
        assert record['phase'] == 'complete'
        assert timer.exists() and verified.exists()
        assert local.read_receipt(layout.state / 'receipt.json')['phase'] == 'ready'
    else:
        result = subprocess.run(['bash', str(wrapper), '/bin/echo', 'collector-must-not-run'],
                                capture_output=True, text=True, timeout=5, check=False,
                                env=dict(os.environ, SIEM_INSTALL_MAINTENANCE='0'))
        assert result.returncode == 75
        assert 'collector-must-not-run' not in result.stdout
        if point in ('before', 'during', 'after'):
            assert record['phase'] == 'activated'
    assert (layout.target / 'config/identity.env').exists()
    assert (layout.state / 'receipt.json').exists()


def test_finish_rechecks_audit_and_keeps_all_recovery_state_on_failure(deployment, monkeypatch):
    layout = deployment
    activate(layout)
    prepare_cron(layout, monkeypatch)
    before = (layout.state / 'receipt.json').read_bytes(), (layout.state / 'deployment.json').read_bytes()
    audit_setup.verify_audit_activation.side_effect = RuntimeError('timer is not active')
    with pytest.raises(IdentityError, match='Audit activation is not verified'):
        finish(layout)
    assert ((layout.state / 'receipt.json').read_bytes(), (layout.state / 'deployment.json').read_bytes()) == before
    assert (layout.state / 'maintenance').exists()
    assert not (layout.state / 'required').exists()


@pytest.mark.parametrize('missing', ['state', 'maintenance', 'deployment.json', 'receipt.json'])
def test_missing_upgrade_state_is_diagnosed_without_creating_or_deleting_files(unpublished, missing):
    layout = unpublished
    settings = (layout.stage / 'config/mysql.env').read_bytes()
    if missing == 'state':
        retained = layout.state.with_name('retained-state')
        layout.state.rename(retained)
    else:
        retained = layout.state
        (retained / missing).rename(retained / (missing + '.retained'))
    before = {}
    for path in retained.iterdir():
        if path.is_file():
            before[path.name] = path.read_bytes()
    with pytest.raises(service.InstallationError) as error:
        service.check_unpublished_recovery(layout.target, layout.stable, layout.user, layout.state)
    message = str(error.value)
    if missing == 'state':
        assert 'protected local installation state is missing' in message
    else:
        assert 'missing ' + missing in message
    assert 'Errno 2' not in message
    assert not layout.target.exists()
    assert (layout.stage / 'config/mysql.env').read_bytes() == settings
    after = {}
    for path in retained.iterdir():
        if path.is_file():
            after[path.name] = path.read_bytes()
    assert after == before
    if missing == 'state':
        assert not layout.state.exists()


def test_interrupted_reset_restages_current_code_without_losing_pending_identity(deployment):
    layout = deployment
    (layout.stage / 'config/mysql.env').write_text('DB_PASSWORD=synthetic-pending-reset\n')
    saved = (layout.stage / 'config/mysql.env').read_bytes()
    resumed = service.prepare_deployment(layout.source, layout.target, layout.user, None,
                                        layout.stable, layout.state, reset=True)
    record = journal.read_deployment(layout.state)
    assert record['identity'] == layout.identity
    assert record['database_started'] is True
    assert record['database_started_current'] is False
    assert (resumed / 'config/mysql.env').read_bytes() == saved
    assert local.read_settings(resumed / 'config/identity.env') == layout.identity
    assert (resumed / 'app.py').read_text() == 'new program\n'
    assert layout.stage.exists()


@pytest.mark.parametrize('fault', [None, 'missing-receipt', 'bad-receipt', 'wrong-database',
                                 'wrong-host', 'journal-identity', 'history'])
def test_reset_resume_requires_database_receipt_and_identity_proof(deployment, monkeypatch, fault):
    from config import reset_installation as reset

    layout = deployment
    monkeypatch.setattr(journal, 'STATE_DIR', layout.state)
    connection = MagicMock()
    connect = Mock(return_value=connection)
    monkeypatch.setattr(reset.pymysql, 'connect', connect)
    history = Mock()
    monkeypatch.setattr(reset, 'check_upgrade_database', history)
    receipt = layout.state / 'receipt.json'
    if fault == 'missing-receipt':
        receipt.unlink()
    elif fault == 'bad-receipt':
        receipt.write_text('{invalid')
    elif fault == 'wrong-database':
        monkeypatch.setattr(local, 'database_key', lambda connection: ('other', 'other-server'))
    elif fault == 'wrong-host':
        monkeypatch.setattr(local, 'validate_bindings', lambda *args: 99)
    elif fault == 'journal-identity':
        record = journal.read_deployment(layout.state)
        record['identity'] = dict(layout.identity, SIEM_COLLECTOR_ID=999)
        journal.save_deployment(layout.state, record)
    elif fault == 'history':
        history.side_effect = reset.ResetError('unverified migration history')
    before = {path.name: path.read_bytes() for path in layout.state.iterdir() if path.is_file()}
    if fault is None:
        assert reset.prepared_reset_recovery(layout.stage) is True
        history.assert_called_once_with(connection)
    else:
        with pytest.raises((ValueError, reset.ResetError)):
            reset.prepared_reset_recovery(layout.stage)
    connection.close.assert_called_once()
    assert {path.name: path.read_bytes() for path in layout.state.iterdir() if path.is_file()} == before
    assert not connection.commit.called
    cursor = connection.cursor.return_value.__enter__.return_value
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith(('SELECT ', 'SHOW '))


def test_fresh_reset_does_not_treat_database_started_alone_as_completion(deployment, monkeypatch):
    from config import reset_installation as reset

    layout = deployment
    monkeypatch.setattr(journal, 'STATE_DIR', layout.state)
    record = journal.read_deployment(layout.state)
    record['identity'] = {}
    journal.save_deployment(layout.state, record)
    (layout.state / 'receipt.json').unlink()
    connection = Mock()
    monkeypatch.setattr(reset.pymysql, 'connect', connection)
    assert reset.prepared_reset_recovery(layout.stage) is False
    connection.assert_not_called()


def test_completed_receipt_without_journal_identity_cannot_fall_back_to_reset(deployment, monkeypatch):
    from config import reset_installation as reset

    layout = deployment
    monkeypatch.setattr(journal, 'STATE_DIR', layout.state)
    record = journal.read_deployment(layout.state)
    record['identity'] = {}
    journal.save_deployment(layout.state, record)
    before = (layout.state / 'receipt.json').read_bytes()
    with pytest.raises(reset.ResetError, match='No RESET was attempted'):
        reset.prepared_reset_recovery(layout.stage)
    assert (layout.state / 'receipt.json').read_bytes() == before


@pytest.mark.parametrize('recovered', [True, False])
def test_resume_cli_has_no_destructive_or_identity_recreation_fallback(monkeypatch, tmp_path, recovered):
    from config import reset_installation as reset

    monkeypatch.setattr(reset.os, 'geteuid', Mock(return_value=0))
    monkeypatch.setattr(reset, 'trusted_directory', Mock())
    monkeypatch.setattr(reset, 'validate_settings', Mock())
    monkeypatch.setattr(reset, 'prepared_reset_recovery', Mock(return_value=recovered))
    deletion = Mock(side_effect=AssertionError('Unexpected DROP or ALTER'))
    monkeypatch.setattr(reset, 'reset_database', deletion)
    creation = Mock(side_effect=AssertionError('Unexpected identity recreation'))
    monkeypatch.setattr(local, 'provision', creation)
    assert reset.main(['resume', '--project', str(tmp_path)]) == int(not recovered)
    deletion.assert_not_called()
    creation.assert_not_called()
