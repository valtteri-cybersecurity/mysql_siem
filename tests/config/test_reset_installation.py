"""All reset/cron/systemd effects are fake or confined to tmp_path."""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from config import reset_installation as reset
from database import migrate as migrations

ROOT = Path(__file__).resolve().parents[2]


class FakeConnection:
    def __init__(self, exists=False):
        self.exists = exists
        self.events = [1, 2] if exists else []
        self.other_database = [77]
        self.statements = []
        self.version = '8.4.13'
        self.grants = ['GRANT SELECT, INSERT ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost`']
        self.failure = None
        self.selected = None
        self.closed = False
        self.lock_available = True

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        if self.failure and sql.startswith(self.failure):
            raise OSError('synthetic sensitive SQL error')
        if sql.startswith('DROP DATABASE'):
            assert sql == 'DROP DATABASE `mysql_siem`'
            self.exists = False
            self.events = []
        elif sql.startswith('CREATE DATABASE'):
            self.exists = True

    def fetchone(self):
        sql = self.statements[-1][0]
        if 'GET_LOCK' in sql:
            return (int(self.lock_available),)
        if sql == 'SELECT VERSION()':
            return (self.version,)
        if sql == 'SELECT @@GLOBAL.mandatory_roles':
            return ('',)
        if 'mysql.user' in sql:
            return (1,)
        return (int(self.exists),)

    def fetchall(self):
        return [(grant,) for grant in self.grants]

    def select_db(self, name):
        self.selected = name

    def close(self):
        self.closed = True


@pytest.fixture
def settings():
    return {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_PASSWORD': 'synthetic-test-value', 'DB_NAME': 'mysql_siem'}


@pytest.fixture
def initialized(monkeypatch):
    calls = []
    monkeypatch.setattr(migrations, 'migrate', lambda connection: calls.append('migrate'))
    monkeypatch.setattr(migrations, 'check_ufw_utc_readiness', lambda connection: calls.append('check'))
    return calls


def test_fresh_install_initializes_once(settings, initialized):
    connection = FakeConnection()
    prepared = []
    reset.reset_database(connection, settings, prepare=lambda: prepared.append(True))
    assert prepared == [True]
    assert initialized == ['migrate', 'check']
    assert connection.selected == 'mysql_siem'
    assert not any(sql.startswith('DROP') for sql, _ in connection.statements)
    assert connection.other_database == [77]


def test_existing_database_needs_explicit_reset(settings, initialized):
    connection = FakeConnection(True)
    with pytest.raises(reset.ResetError, match='explicit RESET'):
        reset.reset_database(connection, settings)
    assert connection.events == [1, 2]
    assert not initialized
    assert len(connection.statements) == 1


def test_approved_repeated_reinstallation_only_resets_fixed_database(settings, initialized):
    connection = FakeConnection(True)
    for _ in range(2):
        reset.reset_database(connection, settings, approved=True)
        assert connection.events == []
        assert connection.other_database == [77]
        connection.events.append(5)
    assert initialized == ['migrate', 'check', 'migrate', 'check']
    assert sum(sql == 'DROP DATABASE `mysql_siem`' for sql, _ in connection.statements) == 2
    passwords = [params for sql, params in connection.statements if sql.startswith('ALTER USER')]
    assert passwords == [(settings['DB_PASSWORD'],), (settings['DB_PASSWORD'],)]


@pytest.mark.parametrize('key,value', [('DB_NAME', 'other'), ('DB_NAME', 'mysql_siem; DROP DATABASE other'),
                                     ('DB_HOST', 'remote'), ('DB_USER', 'root'), ('DB_PORT', '3307'),
                                     ('DB_PASSWORD', '')])
def test_invalid_target_fails_before_any_sql(settings, initialized, key, value):
    settings[key] = value
    connection = FakeConnection(True)
    with pytest.raises(reset.ResetError):
        reset.reset_database(connection, settings, approved=True)
    assert not connection.statements


@pytest.mark.parametrize('grant', ['GRANT SELECT ON `other`.* TO `pythonuser`@`localhost`',
                                   'GRANT ALL PRIVILEGES ON *.* TO `pythonuser`@`localhost`',
                                   'GRANT `shared_role` TO `pythonuser`@`localhost`'])
def test_shared_account_is_not_changed(settings, initialized, grant):
    connection = FakeConnection(True)
    connection.grants = [grant]
    with pytest.raises(reset.ResetError, match='Unsafe runtime privileges'):
        reset.reset_database(connection, settings, approved=True)
    assert connection.events == [1, 2]
    assert not any(sql.startswith(('DROP', 'ALTER USER')) for sql, _ in connection.statements)


@pytest.mark.parametrize('version', ['10.11.0-MariaDB', '8.1.0', '5.7.0'])
def test_wrong_server_is_not_reset(settings, initialized, version):
    connection = FakeConnection(True)
    connection.version = version
    with pytest.raises(reset.ResetError, match='Oracle MySQL'):
        reset.reset_database(connection, settings, approved=True)
    assert connection.events == [1, 2]


def test_creation_failure_is_specific_and_does_not_expose_raw_error(settings, initialized):
    connection = FakeConnection(True)
    connection.failure = 'CREATE DATABASE'
    with pytest.raises(reset.ResetError, match='database creation failed') as error:
        reset.reset_database(connection, settings, approved=True)
    assert 'sensitive' not in str(error.value)
    assert settings['DB_PASSWORD'] not in str(error.value)
    assert not initialized
    assert connection.other_database == [77]


@pytest.mark.parametrize('answer', ['', 'yes', 'reset', ' RESET '])
def test_confirmation_rejects_everything_except_exact_reset(answer):
    with pytest.raises(reset.ResetError, match='cancelled'):
        reset.confirm_reset(True, confirm=lambda _: answer)


def test_first_install_does_not_prompt():
    reset.confirm_reset(False, confirm=lambda _: pytest.fail('Unexpected prompt'))
    reset.confirm_reset(True, confirm=lambda _: 'RESET')


def test_shell_cancellation_precedes_persistent_changes(tmp_path):
    installer = (ROOT / 'install.sh').read_text()
    block = installer.split('# Cancelled reset', 1)[1].split('# Recheck persistent roles', 1)[0]
    block = block[block.index('\n') + 1:]
    fake = tmp_path / 'mysql'
    fake.write_text('#!/bin/bash\nprintf "1\n"\n')
    fake.chmod(0o755)
    script = 'set -eu\nSIEM_DATABASE_RESET_APPROVED=0\ndie() { echo "$*" >&2; exit 1; }\n'
    script += block.replace('/usr/bin/mysql', str(fake))
    script += '\nprintf "APPROVED=%s\n" "$SIEM_DATABASE_RESET_APPROVED"'
    before = fake.read_bytes()
    cancelled = subprocess.run(['/bin/bash', '-c', script], input='no\n', capture_output=True, text=True, check=False)
    assert cancelled.returncode == 1
    assert 'cancelled' in cancelled.stderr
    assert 'APPROVED=' not in cancelled.stdout
    approved = subprocess.run(['/bin/bash', '-c', script], input='RESET\n', capture_output=True, text=True, check=False)
    assert approved.returncode == 0, approved.stderr
    assert 'APPROVED=1' in approved.stdout
    assert fake.read_bytes() == before
    assert list(tmp_path.iterdir()) == [fake]


def test_cron_pauses_only_legacy_mysql_siem_jobs(tmp_path, monkeypatch):
    monkeypatch.setattr(reset.pwd, 'getpwall', lambda: [SimpleNamespace(pw_name='nordman'), SimpleNamespace(pw_name='root')])
    writes = []
    old = '* * * * * cd /home/nordman/mysql_siem && python3 ingestion/ufw_to_mysql.py\n'
    unrelated = '0 1 * * * /usr/bin/backup-other-db\n'

    def fake(arguments, **kwargs):
        if arguments[-1] == '-l':
            text = unrelated + old if arguments[2] == 'nordman' else unrelated
            return SimpleNamespace(returncode=0, stdout=text, stderr='')
        writes.append((arguments[2], kwargs['input']))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(reset, 'run_command', fake)
    monkeypatch.setattr(reset.journal, 'write_file', lambda path, text: path.write_text(text))
    reset.pause_cron(tmp_path)
    assert writes == [('nordman', unrelated)]
    assert (tmp_path / 'reset-cron.json').exists()


def test_cron_read_error_never_replaces_any_crontab(tmp_path, monkeypatch):
    monkeypatch.setattr(reset.pwd, 'getpwall', lambda: [SimpleNamespace(pw_name='root')])
    calls = []

    def fake(arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(returncode=1, stdout='', stderr='permission denied')

    monkeypatch.setattr(reset, 'run_command', fake)
    with pytest.raises(reset.ResetError, match='Cannot inspect crontab'):
        reset.pause_cron(tmp_path)
    assert len(calls) == 1 and calls[0][-1] == '-l'
    assert not list(tmp_path.iterdir())


def test_only_mysql_siem_systemd_units_are_stopped(monkeypatch):
    calls = []

    def fake(arguments, **kwargs):
        calls.append(arguments)
        output = ''
        if 'list-unit-files' in arguments:
            output = 'siem.service enabled\nother.service enabled\nsiem.timer enabled\n'
        elif 'show' in arguments:
            if arguments[2] == 'siem.timer':
                output = 'siem.service\n'
            elif arguments[2] == 'siem.service':
                output = '/opt/mysql_siem/.venv/bin/python /opt/mysql_siem/ingestion/ufw_to_mysql.py'
            else:
                output = '/usr/bin/other-service'
        return SimpleNamespace(returncode=0, stdout=output, stderr='')

    monkeypatch.setattr(reset, 'run_command', fake)
    reset.pause_systemd()
    changed = [call for call in calls if call[1] in ('stop', 'disable')]
    assert changed == [['systemctl', 'stop', 'siem.timer'], ['systemctl', 'disable', 'siem.timer'],
                       ['systemctl', 'stop', 'siem.service'], ['systemctl', 'disable', 'siem.service']]


def test_legacy_system_cron_stops_reset_without_modifying_file(tmp_path):
    path = tmp_path / 'crontab'
    text = '* * * * * root python3 /opt/mysql_siem/metrics/system/main.py\n'
    path.write_text(text)
    with pytest.raises(reset.ResetError, match='system cron'):
        reset.check_system_cron(tmp_path)
    assert path.read_text() == text


@pytest.mark.parametrize('command', ['/usr/bin/python3 /opt/mysql_siem/ingestion/ufw_to_mysql.py',
                                     '/usr/bin/python3 -m ingestion.auth.main'])
def test_running_legacy_process_prevents_reset(tmp_path, command):
    process = tmp_path / str(os.getpid() + 100000)
    process.mkdir()
    (process / 'cmdline').write_bytes(command.encode().replace(b' ', b'\0'))
    with pytest.raises(reset.ResetError, match='still running'):
        reset.wait_for_legacy_jobs(tmp_path, timeout=0)


def test_reset_cli_requires_maintenance_before_opening_db(tmp_path, monkeypatch):
    def missing():
        raise reset.journal.InstallationStateError('missing lock')
    monkeypatch.setattr(reset.journal, 'require_maintenance', lambda _: missing())
    monkeypatch.setattr(reset, 'run_command', lambda *args, **kwargs: pytest.fail('Unexpected scheduler action'))
    import pymysql
    monkeypatch.setattr(pymysql, 'connect', lambda **kwargs: pytest.fail('Unexpected connection'))
    assert reset.main(['reset', '--project', str(tmp_path)]) == 1


def test_failure_after_reset_keeps_maintenance_and_closes_connection(tmp_path, monkeypatch, settings, initialized, capsys):
    state = tmp_path / 'state'
    state.mkdir()
    gate = state / 'maintenance'
    gate.write_text('paused\n')
    connection = FakeConnection(True)
    connection.failure = 'CREATE DATABASE'
    monkeypatch.setattr(reset, 'get_installation_role', lambda **kwargs: 'server')
    monkeypatch.setattr(reset.journal, 'STATE_DIR', state)
    monkeypatch.setattr(reset.journal, 'require_maintenance', lambda _: None)
    monkeypatch.setattr(reset.journal, 'require_stage', lambda *args: {})
    monkeypatch.setattr(reset.pymysql, 'connect', lambda **kwargs: connection)
    monkeypatch.setattr(reset, 'check_system_cron', lambda: None)
    monkeypatch.setattr(reset, 'pause_cron', lambda _: None)
    monkeypatch.setattr(reset, 'pause_systemd', lambda: None)
    monkeypatch.setattr(reset, 'wait_for_legacy_jobs', lambda: None)
    monkeypatch.setattr(reset, 'clear_old_identity', lambda *args: None)
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv('SIEM_DATABASE_RESET_APPROVED', '1')
    assert reset.main(['reset', '--project', str(tmp_path)]) == 1
    assert gate.read_text() == 'paused\n'
    assert connection.closed
    assert not initialized
    assert connection.other_database == [77]
    assert settings['DB_PASSWORD'] not in capsys.readouterr().err


def test_custom_checkout_directory_is_recognized(monkeypatch):
    monkeypatch.setenv('SIEM_BOOTSTRAP_SETTINGS', '/home/student/private security project')
    assert reset.collection_command('cd "/home/student/private security project" && python3 ingestion/ufw_to_mysql.py')
    assert not reset.collection_command('python3 /home/student/other/ingestion/main.py')


def test_parallel_migration_prevents_reset_before_identity_changes(settings, initialized):
    connection = FakeConnection(True)
    connection.lock_available = False
    with pytest.raises(reset.ResetError, match='migration is running'):
        reset.reset_database(connection, settings, approved=True, prepare=lambda: pytest.fail('Unexpected identity reset'))
    assert connection.events == [1, 2]
    assert not any(sql.startswith('DROP') for sql, _ in connection.statements)


def test_relative_legacy_command_is_detected_from_working_directory(tmp_path):
    process = tmp_path / str(os.getpid() + 100000)
    process.mkdir()
    (process / 'cmdline').write_bytes(b'python3\0ingestion/ufw_to_mysql.py\0')
    (process / 'cwd').symlink_to('/home/student/mysql_siem')
    with pytest.raises(reset.ResetError, match='still running'):
        reset.wait_for_legacy_jobs(tmp_path, timeout=0)


def test_related_pytest_path_is_not_a_collector():
    assert not reset.collection_command('/home/student/mysql_siem/.venv/bin/python -m pytest tests/analysis/test_ufw_install.py')


def test_reset_cli_rejects_collector_before_database_connection(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reset.journal, 'require_maintenance', lambda _: None)
    monkeypatch.setattr(reset.journal, 'require_stage', lambda *args: {})
    monkeypatch.setattr(reset, 'get_installation_role', lambda **kwargs: 'collector')
    monkeypatch.setattr(reset.pymysql, 'connect', lambda **kwargs: pytest.fail('Collector must not connect'))
    assert reset.main(['reset', '--project', str(tmp_path)]) == 1
    assert 'only for the Server' in capsys.readouterr().err
