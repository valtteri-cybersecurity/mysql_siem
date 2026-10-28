"""Read-only health checks against synthetic deployment metadata."""

import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from config import installation_health as health
from database import migrate


@pytest.fixture
def installed(tmp_path, monkeypatch):
    project = tmp_path / 'installed'
    (project / 'config').mkdir(parents=True)
    version = project / 'config/installed-version'
    version.write_text('a' * 40 + '\n')
    version.chmod(0o640)
    state = tmp_path / 'state'
    state.mkdir()
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    stable = tmp_path / 'python'
    stable.symlink_to(candidate)
    identity = {'SIEM_COLLECTOR_ID': 1, 'SIEM_AUTH_SOURCE_ID': 2}
    cron = 'synthetic managed jobs\n'
    record = {'target': str(project), 'phase': 'complete', 'stable': str(stable),
              'candidate': str(candidate), 'user': 'mysql_siem', 'identity': identity,
              'cron_digest': hashlib.sha256(cron.encode()).hexdigest()}
    receipt = {'phase': 'ready', 'identity': identity, 'host_id': 3,
               'database': 'mysql_siem', 'server': 'server'}
    monkeypatch.setattr(health, 'trusted_directory', Mock())
    monkeypatch.setattr(health.journal, 'read_deployment', lambda state: record)
    monkeypatch.setattr(health.journal, 'require_maintenance', Mock())
    monkeypatch.setattr(health, 'validate_virtualenv', Mock())
    monkeypatch.setattr(health, 'read_owned_role', Mock(return_value='server'))
    monkeypatch.setattr(health, 'read_settings', lambda path: identity)
    monkeypatch.setattr(health, 'read_receipt', lambda path: receipt)
    monkeypatch.setattr(health, 'database_key', lambda connection: ('mysql_siem', 'server'))
    monkeypatch.setattr(health, 'validate_bindings', Mock(return_value=3))
    monkeypatch.setattr(health, 'verify_schema', Mock())
    monkeypatch.setattr(health, 'read_crontab', Mock(return_value=cron))
    return SimpleNamespace(project=project, state=state, record=record, receipt=receipt,
                           stable=stable, version=version)


def verify(installed, **kwargs):
    return health.verify_health(MagicMock(), installed.project, state=installed.state, **kwargs)


def test_completed_installation_health_is_read_only(installed):
    before = installed.version.read_bytes()
    assert verify(installed, revision='a' * 40) == 'a' * 40
    assert installed.version.read_bytes() == before
    health.journal.require_maintenance.assert_not_called()


@pytest.mark.parametrize('fault', ['maintenance', 'unfinished', 'revision', 'python', 'receipt', 'host', 'cron', 'role'])
def test_bad_health_never_releases_maintenance(installed, monkeypatch, fault):
    if fault == 'maintenance':
        (installed.state / 'maintenance').write_text('paused\n')
    elif fault == 'unfinished':
        installed.record['phase'] = 'staged'
    elif fault == 'revision':
        installed.version.write_text('b' * 40 + '\n')
    elif fault == 'python':
        installed.stable.unlink()
        installed.stable.mkdir()
    elif fault == 'receipt':
        installed.receipt['server'] = 'other'
    elif fault == 'host':
        health.validate_bindings.return_value = 999
    elif fault == 'cron':
        health.read_crontab.return_value = 'different jobs\n'
    else:
        health.read_owned_role.return_value = 'collector'
    with pytest.raises(health.HealthError):
        verify(installed, revision='a' * 40)
    if fault == 'maintenance':
        assert (installed.state / 'maintenance').exists()


def test_activated_version_can_be_checked_only_under_both_locks(installed):
    installed.record['phase'] = 'activated'
    (installed.state / 'maintenance').write_text('paused\n')
    assert verify(installed, during_maintenance=True) == 'a' * 40
    health.journal.require_maintenance.assert_called_once_with(installed.state)
    assert (installed.state / 'maintenance').exists()


@pytest.mark.parametrize('content', ['', 'main\n', 'a' * 40, 'a' * 41 + '\n'])
def test_invalid_version_file_is_rejected(tmp_path, content):
    (tmp_path / 'config').mkdir()
    version = tmp_path / 'config/installed-version'
    version.write_text(content)
    version.chmod(0o640)
    with pytest.raises(health.InstallationError):
        health.read_revision(tmp_path)


@pytest.mark.parametrize('state', [None, 'RUNNING', 'FAILED'])
def test_schema_health_requires_every_migration_applied(monkeypatch, state):
    records = {}
    for version, _name, _path in migrate.MIGRATIONS:
        records[version] = ('verified', 'APPLIED')
    if state is None:
        records.pop('021')
    else:
        records['021'] = ('verified', state)
    monkeypatch.setattr(migrate, 'check_migration_history', lambda connection: records)
    connection = MagicMock()
    with pytest.raises(health.HealthError, match='incomplete'):
        health.verify_schema(connection)
