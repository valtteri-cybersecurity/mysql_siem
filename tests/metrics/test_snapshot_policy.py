import os
import subprocess
import sys
from unittest.mock import Mock

import pymysql
import pytest

from config.snapshot_policy import (
    SnapshotSettingError,
    collection_seconds,
    inventory_limit,
    retention_policy,
)
from metrics import snapshot_retention
from metrics.bounded_output import OutputLimitError, bounded_output


def test_retention_defaults_and_separate_overrides(monkeypatch):
    defaults = retention_policy()
    assert not defaults.enabled
    assert defaults.event_days == 180
    assert defaults.window_days == defaults.detail_days == defaults.health_days == 30
    monkeypatch.setenv('SIEM_SNAPSHOT_EVENT_DAYS', '200')
    monkeypatch.setenv('SIEM_SNAPSHOT_WINDOW_DAYS', '25')
    monkeypatch.setenv('SIEM_SNAPSHOT_DETAIL_DAYS', '7')
    monkeypatch.setenv('SIEM_SNAPSHOT_HEALTH_DAYS', '5')
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
    policy = retention_policy()
    assert policy.enabled
    assert (policy.event_days, policy.window_days, policy.detail_days, policy.health_days) == (200, 25, 7, 5)


@pytest.mark.parametrize(('name', 'value'), [
    ('SIEM_SNAPSHOT_EVENT_DAYS', '0'),
    ('SIEM_SNAPSHOT_EVENT_DAYS', '-5'),
    ('SIEM_SNAPSHOT_RETENTION_ENABLED', 'yes'),
    ('SIEM_SNAPSHOT_WINDOW_DAYS', '1.5'),
    ('SIEM_SNAPSHOT_DETAIL_DAYS', '31'),
    ('SIEM_SNAPSHOT_RETENTION_BATCH_ROWS', '1001'),
    ('SIEM_SNAPSHOT_WARNING_MIB', ''),
])
def test_invalid_retention_settings_are_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(SnapshotSettingError):
        retention_policy()


def test_runtime_limits_can_only_shrink_existing_ceilings(monkeypatch):
    assert collection_seconds() == 40
    monkeypatch.setenv('SIEM_SNAPSHOT_MAX_SECONDS', '20')
    monkeypatch.setenv('SIEM_SNAPSHOT_MAX_PROCESSES', '200')
    monkeypatch.setenv('SIEM_SNAPSHOT_MAX_SERVICES', '12')
    assert collection_seconds() == 20
    assert inventory_limit('processes') == 200 and inventory_limit('services') == 12
    monkeypatch.setenv('SIEM_SNAPSHOT_MAX_SECONDS', '41')
    with pytest.raises(SnapshotSettingError, match='SIEM_SNAPSHOT_MAX_SECONDS'):
        collection_seconds()


SCOPE = ['--kind', 'services', '--host-id', '1', '--source-id', '2']


def test_cli_defaults_to_preview_even_when_apply_is_enabled(monkeypatch, capsys):
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
    monkeypatch.setenv('SIEM_SNAPSHOT_WARNING_MIB', '5')
    connection = Mock()
    monkeypatch.setattr(snapshot_retention, 'get_connection', Mock(return_value=connection))
    monkeypatch.setattr(snapshot_retention, 'capacity_bytes', Mock(return_value=6 * 1024 * 1024))
    cleanup = Mock(return_value=(7, 3, 1, 4))
    monkeypatch.setattr(snapshot_retention, 'cleanup', cleanup)
    assert snapshot_retention.main(SCOPE) == 0
    assert cleanup.call_args.kwargs == {'apply': False}
    output = capsys.readouterr()
    assert 'security events (protected) 7' in output.out
    assert 'retention' not in output.err.lower()
    assert 'size warning level' in output.err
    connection.close.assert_called_once()


def test_cli_apply_requires_opt_in_and_does_not_expose_database_errors(monkeypatch, capsys):
    connection = Mock()
    connect = Mock(return_value=connection)
    monkeypatch.setattr(snapshot_retention, 'get_connection', connect)
    assert snapshot_retention.main([*SCOPE, '--apply']) == 1
    connect.assert_not_called()
    assert 'SIEM_SNAPSHOT_RETENTION_ENABLED=1' in capsys.readouterr().err
    monkeypatch.setenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '1')
    monkeypatch.setattr(snapshot_retention, 'capacity_bytes', Mock(side_effect=pymysql.OperationalError(
        1045, 'secret username and password arbitrary SQL payload',
    )))
    assert snapshot_retention.main([*SCOPE, '--apply']) == 1
    assert 'secret' not in capsys.readouterr().err
    connection.close.assert_called_once()


def test_bounded_reader_discards_stderr_and_keeps_exact_byte_limit():
    command = [sys.executable, '-c', 'import sys; sys.stdout.write("sample"); sys.stderr.write("private")']
    result = bounded_output(command, env=os.environ.copy(), timeout=5, max_bytes=6)
    assert result.stdout == 'sample' and result.returncode == 0 and result.stderr is None


def test_bounded_reader_rejects_oversized_output_and_times_out():
    command = [sys.executable, '-c', 'import sys; sys.stdout.write("x" * 65536)']
    with pytest.raises(OutputLimitError):
        bounded_output(command, env=os.environ.copy(), timeout=5, max_bytes=128)
    command = [sys.executable, '-c', 'import time; time.sleep(3)']
    with pytest.raises(subprocess.TimeoutExpired):
        bounded_output(command, env=os.environ.copy(), timeout=0.1, max_bytes=128)
