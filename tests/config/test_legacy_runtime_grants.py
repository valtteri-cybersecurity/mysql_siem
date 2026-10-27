"""Replay the reported Mint grants using an in-memory MySQL simulation only."""

import json
import re
from types import SimpleNamespace
from unittest.mock import Mock

import pymysql
import pytest

from config import legacy_runtime as legacy
from config import reset_installation as reset

# Observed rights, including old summaries and the retired ufw_monitor database.
REPORTED_GRANTS = '''GRANT USAGE ON *.* TO `pythonuser`@`localhost`
GRANT SELECT, INSERT ON `mysql_siem`.`alert_evidence` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, DELETE ON `mysql_siem`.`analysis_source_ips` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, DELETE ON `mysql_siem`.`analysis_ufw_ports` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`analysis_ufw_traffic_daily` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`analysis_ufw_traffic` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT ON `mysql_siem`.`auth_events` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`auth_ingestion_state` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`detection_alerts` TO `pythonuser`@`localhost`
GRANT SELECT ON `mysql_siem`.`detection_rules` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`detection_state` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE, DELETE ON `mysql_siem`.`dns_client_filters` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`dns_collection_state` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE, DELETE ON `mysql_siem`.`dns_domain_filters` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, DELETE ON `mysql_siem`.`dns_events` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`dns_sources` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`filesystem_metrics` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`security_metrics` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT ON `mysql_siem`.`system_metrics` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`top_attacking_ips` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`top_targeted_ports` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`ufw_daily_actions_counts` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `mysql_siem`.`ufw_state` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `ufw_monitor`.`filesystem_metrics` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `ufw_monitor`.`security_metrics` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT ON `ufw_monitor`.`system_metrics` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `ufw_monitor`.`top_attacking_ips` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `ufw_monitor`.`top_targeted_ports` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `ufw_monitor`.`ufw_daily_actions_counts` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT ON `ufw_monitor`.`ufw_log` TO `pythonuser`@`localhost`
GRANT SELECT, INSERT, UPDATE ON `ufw_monitor`.`ufw_state` TO `pythonuser`@`localhost`'''


class FakeConnection:
    def __init__(self):
        self.grants = []
        for line in REPORTED_GRANTS.splitlines():
            self.grants.append((line,))
        self.statements = []
        self.data = {'mysql_siem': [1, 2], 'ufw_monitor': [3, 4], 'other_account': [5]}
        self.server = 'e7d7c166-aa32-4e17-b7c8-eef74ea0972b'
        self.version = '8.0.46'
        self.revokes = 0
        self.failure_after = None
        self.lock_available = True
        self.closed = False

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, parameters=None):
        assert statement.startswith(('SELECT ', 'SHOW ', 'REVOKE ')), 'Unexpected data/account mutation'
        self.statements.append(statement)
        if statement.startswith('REVOKE '):
            self.revokes += 1
            if self.revokes == self.failure_after:
                raise pymysql.OperationalError(1142, 'synthetic private diagnostic')
            match = re.fullmatch(r"REVOKE [A-Z, ]+ ON `([a-z_]+)`\.`([a-z_]+)` FROM 'pythonuser'@'localhost'", statement)
            assert match is not None
            retained = []
            for row in self.grants:
                schema, table, _privileges = reset.parse_runtime_grant(row)
                if (schema, table) != match.groups():
                    retained.append(row)
            self.grants = retained

    def fetchone(self):
        statement = self.statements[-1]
        if statement == 'SELECT @@GLOBAL.mandatory_roles':
            return ('',)
        if statement == 'SELECT @@server_uuid':
            return (self.server,)
        if statement == 'SELECT VERSION()':
            return (self.version,)
        if 'GET_LOCK' in statement:
            return (int(self.lock_available),)
        return (1,)

    def fetchall(self):
        return list(self.grants)

    def close(self):
        self.closed = True


@pytest.fixture
def environment(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir()
    project = tmp_path / 'stage'
    project.mkdir()
    for name in ('deployment.json', 'receipt.json', 'maintenance'):
        (state / name).write_text('retained recovery data\n')
    connection = FakeConnection()
    monkeypatch.setattr(legacy, 'OWNER', legacy.os.geteuid())
    monkeypatch.setattr(legacy, 'trusted_directory', Mock())
    monkeypatch.setattr(legacy.journal, 'trusted_state', Mock())
    monkeypatch.setattr(legacy.journal, 'STATE_DIR', state)
    monkeypatch.setattr(legacy.journal, 'require_install_lock', Mock())
    monkeypatch.setattr(legacy.journal, 'require_maintenance', Mock())
    monkeypatch.setattr(legacy.journal, 'require_stage', Mock())
    monkeypatch.setattr(legacy.journal, 'read_deployment', Mock(return_value={
        'phase': 'staged', 'stage': str(project), 'user': 'mysql_siem', 'target': '/usr/local/lib/mysql_siem'}))
    monkeypatch.setattr(reset, 'get_installation_role', Mock(return_value='server'))
    monkeypatch.setattr(reset, 'validate_settings', Mock())
    monkeypatch.setattr(legacy.pymysql, 'connect', Mock(return_value=connection))
    for name in ('pause_cron', 'pause_systemd', 'wait_for_legacy_jobs'):
        monkeypatch.setattr(reset, name, Mock())
    return SimpleNamespace(state=state, project=project, connection=connection)


def test_reported_mint_rights_are_strictly_rejected_but_exact_legacy_plan_is_read_only():
    connection = FakeConnection()
    with pytest.raises(reset.ResetError, match='mysql_siem.top_attacking_ips'):
        reset.validate_account(connection)
    plan = reset.validate_account(connection, allow_legacy=True)
    assert len(plan) == 11
    assert sum(entry['schema'] == 'ufw_monitor' for entry in plan) == 8
    assert all(statement.startswith(('SELECT ', 'SHOW ')) for statement in connection.statements)


@pytest.mark.parametrize('answer', ['y', 'yes', 'YES', ' Y '])
def test_simple_approval_saves_private_original_grants_without_changing_mysql(environment, answer):
    env = environment
    before = list(env.connection.grants)
    legacy.prepare_grants(env.connection, env.state, confirm=lambda _: answer)
    path = env.state / legacy.BACKUP
    record = json.loads(path.read_text())
    assert path.stat().st_mode & 0o777 == 0o600
    assert record['phase'] == 'approved'
    assert record['original_grants'] == REPORTED_GRANTS.splitlines()
    assert env.connection.grants == before
    assert env.connection.revokes == 0


@pytest.mark.parametrize('answer', ['', 'n', 'no', 'RESET'])
def test_declining_legacy_cleanup_does_not_change_rights_or_recovery(environment, answer):
    env = environment
    before = dict.fromkeys(env.state.iterdir())
    with pytest.raises(reset.ResetError, match='declined'):
        legacy.prepare_grants(env.connection, env.state, confirm=lambda _: answer)
    assert dict.fromkeys(env.state.iterdir()) == before
    assert env.connection.revokes == 0


@pytest.mark.parametrize('version', ['8.0.46', '8.4.13'])
def test_approved_cleanup_removes_only_eleven_legacy_grants_and_preserves_data(environment, version):
    env = environment
    env.connection.version = version
    reset.check_server_version(env.connection)
    before = {}
    for path in env.state.iterdir():
        before[path.name] = path.read_bytes()
    legacy.prepare_grants(env.connection, env.state, confirm=lambda _: 'yes')
    legacy.apply_grants(env.connection, env.state)
    assert env.connection.revokes == 11
    reset.validate_account(env.connection)
    assert env.connection.data == {'mysql_siem': [1, 2], 'ufw_monitor': [3, 4], 'other_account': [5]}
    for name, content in before.items():
        assert (env.state / name).read_bytes() == content
    assert json.loads((env.state / legacy.BACKUP).read_text())['phase'] == 'complete'
    legacy.journal.require_maintenance.assert_called_once_with(env.state)
    before_revokes = env.connection.revokes
    legacy.apply_grants(env.connection, env.state)
    assert env.connection.revokes == before_revokes


def test_partial_revoke_failure_keeps_original_backup_and_can_finish_forward(environment):
    env = environment
    legacy.prepare_grants(env.connection, env.state, confirm=lambda _: 'yes')
    env.connection.failure_after = 2
    with pytest.raises(pymysql.MySQLError):
        legacy.apply_grants(env.connection, env.state)
    record = json.loads((env.state / legacy.BACKUP).read_text())
    assert record['phase'] == 'approved'
    assert record['original_grants'] == REPORTED_GRANTS.splitlines()
    assert (env.state / 'maintenance').exists()
    env.connection.failure_after = None
    legacy.prepare_grants(env.connection, env.state, confirm=lambda _: 'yes')
    legacy.apply_grants(env.connection, env.state)
    reset.validate_account(env.connection)
    assert json.loads((env.state / legacy.BACKUP).read_text())['original_grants'] == record['original_grants']


@pytest.mark.parametrize('fault', ['server', 'unknown-field', 'unsafe-mode', 'new-grant', 'lock'])
def test_conflicting_cleanup_state_fails_before_any_revoke(environment, fault):
    env = environment
    legacy.prepare_grants(env.connection, env.state, confirm=lambda _: 'yes')
    path = env.state / legacy.BACKUP
    if fault == 'server':
        env.connection.server = '1b73f599-5a48-4d67-93b7-572e8d387d2a'
    elif fault == 'unknown-field':
        record = json.loads(path.read_text())
        record['unknown'] = True
        path.write_text(json.dumps(record))
    elif fault == 'unsafe-mode':
        path.chmod(0o666)
    elif fault == 'new-grant':
        env.connection.grants.append(('GRANT SELECT ON `other`.`ufw_log` TO `pythonuser`@`localhost`',))
    else:
        env.connection.lock_available = False
    before = path.read_bytes()
    with pytest.raises((reset.ResetError, legacy.journal.InstallationStateError)):
        legacy.apply_grants(env.connection, env.state)
    assert env.connection.revokes == 0
    assert path.read_bytes() == before
    assert (env.state / 'maintenance').exists()


def test_apply_cli_requires_maintenance_before_connecting(environment):
    env = environment
    legacy.journal.require_stage.side_effect = legacy.journal.InstallationStateError('lock missing')
    assert legacy.main(['apply', '--project', str(env.project)]) == 1
    legacy.pymysql.connect.assert_not_called()


def test_no_legacy_rights_require_no_approval_or_backup(environment):
    env = environment
    env.connection.grants = [('GRANT USAGE ON *.* TO `pythonuser`@`localhost`',)]
    legacy.prepare_grants(env.connection, env.state, confirm=Mock(side_effect=AssertionError('Unexpected approval')))
    legacy.apply_grants(env.connection, env.state)
    assert not (env.state / legacy.BACKUP).exists()
    assert env.connection.revokes == 0


@pytest.mark.parametrize('grant', [
    'GRANT ALL PRIVILEGES ON `mysql_siem`.* TO `pythonuser`@`localhost`',
    'GRANT SELECT ON *.* TO `pythonuser`@`localhost`',
    'GRANT SELECT ON `ufw_monitor`.`ufw_log` TO `pythonuser`@`localhost` WITH GRANT OPTION',
    'GRANT DELETE ON `ufw_monitor`.`ufw_log` TO `pythonuser`@`localhost`',
    'GRANT INSERT ON `mysql_siem`.`hosts` TO `pythonuser`@`localhost`',
    'GRANT `shared_role`@`%` TO `pythonuser`@`localhost`',
])
def test_legacy_preparation_does_not_accept_unrelated_or_dangerous_rights(environment, grant):
    env = environment
    env.connection.grants.append((grant,))
    with pytest.raises(reset.ResetError):
        legacy.prepare_grants(env.connection, env.state, confirm=Mock(side_effect=AssertionError('Unexpected approval')))
    assert not (env.state / legacy.BACKUP).exists()
    assert env.connection.revokes == 0
