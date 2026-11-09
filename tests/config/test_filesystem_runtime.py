import fcntl
import os
import pwd
import signal
from pathlib import Path
from unittest.mock import Mock

import pymysql
import pytest

from config import filesystem_runtime as setup
from database.local_identity import BEGIN, END, without_managed_jobs
from metrics.filesystem import mount_main
from metrics.filesystem.inventory import DEFAULT_CONFIG, InventoryConfig
from metrics.filesystem.mounts import MountCollection, MountFailure
from metrics.filesystem.runtime import run_job


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    (tmp_path / 'config').mkdir()
    monkeypatch.setattr(setup.installation_state, 'require_maintenance', Mock())
    monkeypatch.setattr(setup, 'read_settings', Mock(return_value={}))
    monkeypatch.setattr(setup, '_checkpoint_config', Mock(return_value=None))
    user = pwd.getpwuid(os.geteuid()).pw_name
    return tmp_path, user, tmp_path / 'venv/bin/python'


def test_fresh_activation_replaces_only_the_managed_cron_block(deployment):
    project, _, _ = deployment
    lines = setup.prepare(None, *deployment)
    path = project / setup.CONFIG_PATH
    _, config = setup.read_config(path)
    assert config.metadata_only == ['/etc/sudoers']
    assert path.stat().st_mode & 0o777 == 0o640
    schedules = []
    for line in lines:
        schedules.append(line.split()[0])
        assert '/usr/bin/timeout --signal=TERM --kill-after=5s 270s' in line
        assert 'config/run_with_env.sh' in line
    assert schedules == ['*/5', '*/30', '*/5']
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    cron_template = installer.split('<<CRON\n', 1)[1].split('\nCRON\n', 1)[0]
    assert cron_template.count('$FILESYSTEM_CRON') == 1
    assert 'metrics/filesystem/main.py' not in cron_template
    assert 'metrics/system/main.py' in cron_template
    assert 'metrics.services.main' in cron_template
    unrelated = '0 0 * * * /usr/bin/true'
    cron = f'{unrelated}\n{BEGIN}\n*/5 * * * * /example/metrics/filesystem/main.py\n{END}\n'
    for _ in range(2):
        jobs = '\n'.join(setup.prepare(None, *deployment))
        cron = f'{without_managed_jobs(cron)}{BEGIN}\n{jobs}\n{END}\n'
        setup.verify(None, *deployment, {}, cron)
        assert cron.count(unrelated) == 1
        assert 'metrics/filesystem/main.py' not in cron
    with pytest.raises(setup.FilesystemSetupError, match='duplicated'):
        setup.verify(None, *deployment, {}, cron + lines[0] + '\n')


def test_upgrade_preserves_fim_policy_and_uses_custom_intervals(deployment):
    project, _, _ = deployment
    setup._checkpoint_config.return_value = setup._digest(DEFAULT_CONFIG)
    setup.prepare(None, *deployment)
    path = project / setup.CONFIG_PATH
    assert setup.read_config(path)[1] == DEFAULT_CONFIG
    custom = ('FIM_INVENTORY={}\nFILESYSTEM_MOUNT_MINUTES=1\n'
              'FILESYSTEM_FIM_MINUTES=60\nFILESYSTEM_DETECTION_MINUTES=15\n')
    path.write_text(custom)
    mount, fim, detection = setup.prepare(None, *deployment)
    assert mount.startswith('*/1 ') and '--kill-after=5s 50s' in mount
    assert fim.startswith('0 ') and '--config ' in fim
    assert detection.startswith('*/15 ')
    assert path.read_text() == custom
    setup._checkpoint_config.return_value = setup._digest(InventoryConfig(files=('/etc/group',)))
    with pytest.raises(setup.FilesystemSetupError, match='saved baseline'):
        setup.prepare(None, *deployment)
    assert path.read_text() == custom


@pytest.mark.parametrize('setting', [
    'FILESYSTEM_MOUNT_MINUTES=7',
    'FILESYSTEM_FIM_MINUTES=true',
    'FILESYSTEM_DETECTION_MINUTES=0',
    'FIM_INVENTORY={"metadata_only":["/etc/shadow"]}',
    'FIM_INVENTORY={}\nFIM_INVENTORY={}',
    'UNRECOGNIZED=1',
])
def test_invalid_config_cannot_activate(deployment, setting):
    project, _, _ = deployment
    path = project / setup.CONFIG_PATH
    path.write_text(setting + '\n')
    path.chmod(0o600)
    with pytest.raises((setup.FilesystemSetupError, ValueError)):
        setup.prepare(None, *deployment)


def test_metadata_only_observes_a_file_without_opening_its_contents(tmp_path, monkeypatch):
    from metrics.filesystem import inventory

    path = tmp_path / 'sudoers'
    path.write_text('private')
    hash_file = Mock(side_effect=PermissionError)
    monkeypatch.setattr(inventory, 'hash_regular_file', hash_file)
    config = InventoryConfig(files=(str(path),), metadata_only=(str(path),))
    result = inventory.collect_inventory(config)
    assert result.status == 'SUCCESS'
    entry, = result.entries
    assert entry.digest.status == 'DISABLED'
    assert entry.digest.sha256 is None
    assert entry.metadata.size_bytes == 7
    hash_file.assert_not_called()


def test_job_lock_refuses_overlap_and_failure_log_is_redacted(tmp_path, capsys):
    path = tmp_path / 'cron.log'
    action = Mock(side_effect=pymysql.OperationalError(2013, 'private-credentials'))
    lock = os.open(tmp_path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert run_job('Filesystem', path, action) == 75
    finally:
        os.close(lock)
    assert 'SKIPPED' in capsys.readouterr().err
    assert not path.exists()
    action.assert_not_called()
    assert run_job('Filesystem', path, action) == 1
    log = path.read_text()
    assert 'FAILED duration_seconds=' in log
    assert 'private-credentials' not in log


def test_mount_partial_logs_coverage_and_skips_storage(tmp_path, monkeypatch):
    path = tmp_path / 'cron.log'
    result = MountCollection((object(),), (MountFailure(b'/sensitive', 'secret details'),))
    monkeypatch.setattr(mount_main, 'collect_mount_metrics', Mock(return_value=result))
    save = Mock()
    monkeypatch.setattr(mount_main, 'save_mount_metrics', save)
    assert mount_main.main(['--log-file', str(path)]) == 1
    log = path.read_text()
    assert 'PARTIAL duration_seconds=' in log and 'mounts=1 failures=1' in log
    assert 'secret details' not in log and '/sensitive' not in log
    save.assert_not_called()


def test_job_termination_is_logged_and_releases_lock(tmp_path):
    path = tmp_path / 'cron.log'
    previous = signal.getsignal(signal.SIGTERM)

    def terminate():
        signal.raise_signal(signal.SIGTERM)

    assert run_job('Filesystem', path, terminate) == 1
    assert 'Collection interrupted.' in path.read_text()
    assert signal.getsignal(signal.SIGTERM) == previous
    assert run_job('Filesystem', path, lambda: ('SUCCESS', 'mounts=1')) == 0
