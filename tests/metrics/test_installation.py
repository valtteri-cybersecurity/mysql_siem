"""Integration of protected files, settings, grants and schedules; no real install."""

import ast
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from config import reset_installation as setup
from database import migrate
from database.snapshot_migrations import source_clause

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('escaped', [False, True])
def test_mysql_check_clause_normalization(escaped):
    text = "(`source_type` in (_utf8mb4'ufw',_ascii'services'))"
    if escaped:
        text = text.replace("'", "\\'")
    assert source_clause(text) == "(source_type in ('ufw','services'))"


def test_cron_grants_and_required_sources_cover_both_collectors():
    installer = (ROOT / 'install.sh').read_text()
    tree = ast.parse('grants = ' + installer.split('grants = ', 1)[1].split('\nconn =', 1)[0])
    grants = ast.literal_eval(tree.body[0].value)
    for kind, table in [('processes', 'process'), ('services', 'service')]:
        assert grants[table + '_events'] == 'SELECT, INSERT'
        assert grants[table + '_state'] == 'SELECT, INSERT, DELETE'
        assert f'metrics/{kind}/main.py' in installer
        cron = next(line for line in installer.splitlines() if f'-m metrics.{kind}.main --log-file' in line)
        assert cron.startswith('* * * * * ')
        assert 'config/run_with_env.sh' in cron and '"$APP_PYTHON"' in cron
        assert f'/var/log/mysql_siem/{kind}/cron.log' in cron
    assert grants['collector_snapshots'] == 'SELECT, INSERT, UPDATE'
    assert 'service_installation snapshot-logs "$INSTALL_USER"' in installer



def upgrade_connection(grants=None):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(1,), ('8.0.46',), ('',), (1,)]
    cursor.fetchall.return_value = [(grant,) for grant in (grants or [
        'GRANT SELECT ON `mysql_siem`.`hosts` TO `pythonuser`@`localhost`',
        'GRANT SELECT, INSERT ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost`',
    ])]
    return connection


def test_upgrade_never_resets_database_registry_passwords_or_checkpoints(monkeypatch):
    connection = upgrade_connection()
    calls = []
    monkeypatch.setattr(migrate, 'migration_status', lambda _: {'017': (migrate.checksum(migrate.UFW_TIME_MIGRATION), 'APPLIED')})
    monkeypatch.setattr(migrate, 'migrate', lambda _: calls.append('migrate'))
    monkeypatch.setattr(migrate, 'check_ufw_utc_readiness', lambda _: calls.append('utc'))
    settings = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_PASSWORD': 'synthetic', 'DB_NAME': 'mysql_siem'}
    setup.upgrade_database(connection, settings)
    assert calls == ['utc', 'migrate', 'utc']
    connection.select_db.assert_called_once_with('mysql_siem')
    cursor = connection.cursor.return_value.__enter__.return_value
    assert all(call.args[0].startswith(('SELECT', 'SHOW')) for call in cursor.execute.call_args_list)


@pytest.mark.parametrize('grant', [
    'GRANT ALL PRIVILEGES ON *.* TO `pythonuser`@`localhost`',
    'GRANT SELECT, INSERT ON `mysql_siem`.* TO `pythonuser`@`localhost`',
    'GRANT SELECT, UPDATE ON `mysql_siem`.`hosts` TO `pythonuser`@`localhost`',
    'GRANT CREATE ON `mysql_siem`.`service_events` TO `pythonuser`@`localhost`',
])
def test_upgrade_rejects_administrative_runtime_grants(monkeypatch, grant):
    connection = upgrade_connection([grant])
    apply = MagicMock()
    monkeypatch.setattr(migrate, 'migrate', apply)
    settings = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser', 'DB_PASSWORD': 'synthetic', 'DB_NAME': 'mysql_siem'}
    with pytest.raises(setup.ResetError):
        setup.upgrade_database(connection, settings)
    apply.assert_not_called()


def test_upgrade_option_is_kept_in_role_selection_and_bootstrap(tmp_path):
    installer = (ROOT / 'install.sh').read_text()
    functions = installer.split('# Installation role selection', 1)[1].split('# End installation role selection.', 1)[0]
    functions = functions[functions.index('\n'):]
    script = 'set -eu\n' + functions + '''
PROJECT_DIR=/synthetic
SOURCE_DIR=/synthetic
SETTINGS_SOURCE_DIR=/synthetic
SERVICE_DIR=/synthetic
SIEM_BOOTSTRAP_CONFIRMED=/synthetic
die() { echo "$*" >&2; exit 1; }
select_installation_role --upgrade --role server
printf '%s:%s' "$INSTALL_ROLE" "$INSTALL_OPERATION"
'''
    result = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'server:upgrade'
    bootstrap = (ROOT / 'config/install_bootstrap.sh').read_text()
    assert 'operation_arguments=(--upgrade)' in bootstrap
    assert '"${operation_arguments[@]}"' in bootstrap
