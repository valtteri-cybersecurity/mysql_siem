"""Read-only migration/key guards and the immutable 023 snapshot key order."""
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from database import ufw_analysis_history as history
from database import ufw_analysis_keys as keys
from database.migrate import MigrationError


@pytest.mark.parametrize('columns,expected', [
    (('period_start', 'period_end', 'source_ip', 'host_scope'), False),
    (('period_start', 'period_end', 'source_ip', 'host_scope', 'time_basis'), True),
])
def test_actual_keys_determine_partial_migration_state(columns, expected):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    rows = []
    for name in columns:
        rows.append((name, 0, None, 'YES', 'BTREE'))
    cursor.fetchall.return_value = rows
    assert keys.key_state(connection, 'analysis_source_ips') is expected
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')


@pytest.mark.parametrize('rows', [[], [('id', 0, None, 'YES', 'BTREE')],
    [('period_start', 1, None, 'YES', 'BTREE')], [('period_start', 0, 5, 'YES', 'BTREE')]])
def test_unknown_or_nonunique_keys_are_rejected(rows):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = rows
    with pytest.raises(MigrationError):
        keys.key_state(connection, 'analysis_source_ips')


def test_original_snapshot_order_survives_primary_key_expansion(monkeypatch):
    monkeypatch.setattr(history, 'marked', lambda connection, table: True)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    fields = [('period_start', 'datetime'), ('period_end', 'datetime'), ('source_ip', 'varchar'), ('host_scope', 'bigint'), ('time_basis', 'varchar')]
    primary = [('period_start',), ('period_end',), ('source_ip',), ('host_scope',), ('time_basis',)]
    start = datetime(2026, 10, 27)
    row = (start, start + timedelta(hours=1), '192.0.2.1', 0)
    cursor.fetchall.side_effect = [fields, primary, [row], []]
    saved = history.snapshot(connection, 'analysis_source_ips')
    assert saved['primary'] == ['period_start', 'period_end', 'source_ip', 'host_scope']
    cursor.fetchall.side_effect = [[row], []]
    assert history.snapshot(connection, 'analysis_source_ips', saved) == saved
    assert saved['count'] == 1


def test_read_results_defaults_to_utc_and_can_explicitly_select_history(monkeypatch):
    monkeypatch.setattr(keys, 'require_ready', lambda connection, table: None)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = [{'time_basis': 'UTC_VERIFIED', 'host_id': 3}]
    start = datetime(2026, 10, 27)
    keys.read_results(connection, 'analysis_source_ips', start, start + timedelta(hours=1), host_id=3)
    query, parameters = cursor.execute.call_args.args
    assert 'time_basis=%s' in query and 'host_id=%s' in query
    assert parameters[0] == 'UTC_VERIFIED'
    keys.read_results(connection, 'analysis_source_ips', start, start + timedelta(hours=1), time_basis='HISTORICAL')
    assert cursor.execute.call_args.args[1][0] == 'HISTORICAL'
    connection.commit.assert_not_called()


def test_missing_027_never_allows_an_empty_interval_write(monkeypatch):
    monkeypatch.setattr(keys, 'applied', lambda connection: False)
    with pytest.raises(MigrationError, match='027'):
        history.protect_interval(MagicMock(), 'analysis_source_ips', datetime(2026, 1, 1), datetime(2026, 1, 2))


def test_027_checksum_mismatch_stops_before_schema_checks(monkeypatch):
    from database import migrate
    connection = MagicMock()
    monkeypatch.setattr(migrate, 'migration_status', lambda connection: {'027': ('0' * 64, 'APPLIED')})
    with pytest.raises(MigrationError, match='027 checksum differs'):
        migrate.check_migration_history(connection)
    connection.cursor.assert_not_called()


@pytest.mark.parametrize('column', [None, ('int', 'NO', None, None), ('varchar(24)', 'YES', 'ascii_bin', 'UTC_VERIFIED')])
def test_raw_isolation_mismatch_cannot_authorize_utc_writes(monkeypatch, column):
    from database import migrate
    monkeypatch.setattr(keys, 'applied', lambda connection: True)
    monkeypatch.setattr(migrate, 'ufw_timestamp_schema', lambda connection: ('datetime', 6, 'YES', None))
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = (('022', 'APPLIED'), ('023', 'APPLIED'))
    cursor.fetchone.return_value = column
    with pytest.raises(MigrationError, match='raw UTC isolation'):
        keys.require_ready(connection, 'analysis_source_ips')
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')
