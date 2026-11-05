"""Metric collectors expose failures to cron without leaking driver messages."""

import importlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pymysql
import pytest


@pytest.fixture(params=['system', 'security', 'filesystem'])
def collector(request, monkeypatch):
    name = request.param
    main = importlib.import_module('metrics.' + name + '.main')
    writer_name = 'db'
    if name == 'security':
        writer_name = 'database'
    writer = importlib.import_module('metrics.' + name + '.' + writer_name)
    connection = MagicMock()
    monkeypatch.setattr(writer, 'identity_schema_enabled', lambda connection: False)
    monkeypatch.setattr(writer, 'configured_identity', lambda cursor, source: None)
    data = tuple(range(10))
    if name == 'security':
        data = {'uptime': 1, 'blocks': 2, 'failed_logins': 3, 'unique_ips': 4,
                'date': datetime(2026, 11, 5, tzinfo=timezone.utc)}
    if name == 'filesystem':
        monkeypatch.setattr(writer, 'get_connection', lambda: connection)
        monkeypatch.setattr(main, 'get_all_files', lambda: 17)
        monkeypatch.setattr(main, 'get_modified_files', lambda: 3)
    else:
        monkeypatch.setattr(main, 'get_connection', lambda: connection)
        monkeypatch.setattr(main, 'get_data', lambda *args: data)
    def save():
        if name == 'filesystem':
            return writer.save_metrics(3, 17)
        return writer.save_metrics_db(connection, data)
    return SimpleNamespace(name=name, main=main, writer=writer, connection=connection, save=save)


def test_success_returns_zero_and_commits(collector):
    assert collector.main.main() == 0
    collector.connection.commit.assert_called_once()
    collector.connection.rollback.assert_not_called()
    collector.connection.cursor.return_value.close.assert_called_once()
    collector.connection.close.assert_called_once()


@pytest.mark.parametrize('stage', ['execute', 'commit', 'identity'])
def test_failure_returns_one_rolls_back_and_redacts_details(collector, monkeypatch, capsys, stage):
    failure = pymysql.OperationalError(2013, 'PRIVATE DRIVER DETAILS')
    if stage == 'identity':
        def invalid_identity(connection):
            raise ValueError('PRIVATE DRIVER DETAILS')
        monkeypatch.setattr(collector.writer, 'identity_schema_enabled', invalid_identity)
    elif stage == 'execute':
        collector.connection.cursor.return_value.execute.side_effect = failure
    else:
        collector.connection.commit.side_effect = failure
    assert collector.main.main() == 1
    collector.connection.rollback.assert_called_once()
    collector.connection.close.assert_called_once()
    assert 'PRIVATE DRIVER DETAILS' not in capsys.readouterr().out


def test_writer_does_not_swallow_sql_error(collector):
    collector.connection.cursor.return_value.execute.side_effect = pymysql.OperationalError(2013, 'synthetic')
    with pytest.raises(pymysql.OperationalError):
        collector.save()
    collector.connection.rollback.assert_called_once()
    collector.connection.commit.assert_not_called()


def test_missing_connection_returns_one(collector, monkeypatch):
    target = collector.main
    if collector.name == 'filesystem':
        target = collector.writer
    monkeypatch.setattr(target, 'get_connection', lambda: None)
    assert collector.main.main() == 1
    collector.connection.commit.assert_not_called()


def test_collection_failure_prevents_writes(collector, monkeypatch):
    def fail(*args):
        raise OSError('PRIVATE SOURCE DETAILS')
    field = 'get_data'
    if collector.name == 'filesystem':
        field = 'get_all_files'
    monkeypatch.setattr(collector.main, field, fail)
    assert collector.main.main() == 1
    collector.connection.commit.assert_not_called()


@pytest.mark.parametrize('function_name', ['get_all_files', 'get_modified_files'])
def test_find_error_is_not_a_partial_measurement(function_name, monkeypatch):
    from metrics.filesystem import get
    run = MagicMock(side_effect=subprocess.CalledProcessError(1, ['find']))
    monkeypatch.setattr(get.subprocess, 'run', run)
    with pytest.raises(subprocess.CalledProcessError):
        getattr(get, function_name)()
    assert run.call_args.kwargs['check'] is True


def test_filesystem_reports_find_failure(monkeypatch):
    from metrics.filesystem import main
    def fail():
        raise subprocess.CalledProcessError(1, ['find'])
    save = MagicMock()
    monkeypatch.setattr(main, 'get_all_files', fail)
    monkeypatch.setattr(main, 'save_metrics', save)
    assert main.main() == 1
    save.assert_not_called()


def test_system_missing_measurement_is_failure(monkeypatch):
    from metrics.system import main
    connection = MagicMock()
    monkeypatch.setattr(main, 'get_connection', lambda: connection)
    monkeypatch.setattr(main, 'get_data', lambda: None)
    assert main.main() == 1
    connection.commit.assert_not_called()
    connection.close.assert_called_once()


@pytest.mark.parametrize('name', ['system', 'security', 'filesystem'])
@pytest.mark.parametrize('fails', [False, True])
def test_actual_process_exit_status(name, fails):
    script = '''
import importlib
import runpy
from unittest.mock import MagicMock
from datetime import datetime, timezone
import database.connection
connection = MagicMock()
database.connection.get_connection = lambda: connection
name = NAME
if FAILS:
    database.connection.get_connection = lambda: None
if name == 'filesystem':
    get = importlib.import_module('metrics.filesystem.get')
    get.get_all_files = lambda: 17
    get.get_modified_files = lambda: 3
elif name == 'system':
    get = importlib.import_module('metrics.system.get')
    get.get_data = lambda: tuple(range(10))
else:
    get = importlib.import_module('metrics.security.get_data')
    get.get_data = lambda connection: {'date': datetime(2026, 11, 5, tzinfo=timezone.utc),
                                     'uptime': 1, 'blocks': 2, 'failed_logins': 3, 'unique_ips': 4}
identity = importlib.import_module('database.identity')
identity.identity_schema_enabled = lambda connection: False
identity.configured_identity = lambda cursor, source: None
runpy.run_module('metrics.' + name + '.main', run_name='__main__')
'''
    script = script.replace('NAME', repr(name)).replace('FAILS', repr(fails))
    result = subprocess.run([sys.executable, '-B', '-c', script], cwd=Path(__file__).resolve().parents[2],
                            capture_output=True, text=True, timeout=10, check=False)
    expected = 0
    if fails:
        expected = 1
    assert result.returncode == expected, result.stderr
