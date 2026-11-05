"""A rotation I/O error is isolated; database and integrity errors remain fatal."""
from unittest.mock import Mock

import pymysql
import pytest

from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_batch import OccurrenceConflict
from tests.analysis.test_ufw_collector import connection_for_files, line


@pytest.mark.parametrize('error', [FileNotFoundError(), PermissionError(), OSError('SOURCE_CHANGED')])
def test_failed_rotation_restores_counters_and_continues_to_next_source(tmp_path, monkeypatch, error, capsys):
    active = tmp_path / 'ufw.log'
    bad = tmp_path / 'ufw.log.2'
    good = tmp_path / 'ufw.log.1'
    active.write_bytes(line(0))
    good.write_bytes(line(1))
    monkeypatch.setattr(ufw, 'LOGFILE', str(active))
    monkeypatch.setattr(ufw, 'get_logfiles', lambda: [str(bad), str(good), str(active)])
    original = ufw.process_file
    def read(cursor, filename, **options):
        if filename == str(bad):
            options['stats']['lines_read'] += 10
            options['stats']['quarantined'] = 7
            options['stats']['duplicates'] = 8
            options['stats']['source_failure'] = (123, filename)
            raise error
        return original(cursor, filename, **options)
    monkeypatch.setattr(ufw, 'process_file', read)
    connection = connection_for_files()
    result = ufw.process_log(connection)
    assert result['inserted'] == result['lines_read'] == 2
    assert result.get('quarantined', 0) == result.get('duplicates', 0) == 0
    assert result['source_errors'] == 1
    assert result['status'] == 'FAILED'
    assert result['stop_reason'] == 'source_file_error'
    assert result['active_state'] == 'HEALTHY'
    connection.rollback.assert_not_called()
    calls = connection.cursor.return_value.execute.call_args_list
    gap = None
    for index, call in enumerate(calls):
        if call.args[0].startswith('INSERT INTO ufw_collection_gaps'):
            gap = call.args[1]
            assert calls[index - 1].args[0] == 'ROLLBACK TO SAVEPOINT ufw_file'
    assert gap[2:4] == (123, 'SOURCE_UNAVAILABLE')
    assert 'UFW source: FAILED' in capsys.readouterr().out


@pytest.mark.parametrize('error', [pymysql.OperationalError(2013, 'database error'),
                                 RuntimeError('unexpected failure'),
                                 OccurrenceConflict('UFW_AMBIGUOUS_OCCURRENCE_SOURCE')])
def test_rotation_database_or_integrity_error_still_aborts_the_transaction(tmp_path, monkeypatch, error):
    active = tmp_path / 'ufw.log'
    bad = tmp_path / 'ufw.log.1'
    active.write_bytes(line(0))
    bad.write_bytes(line(1))
    monkeypatch.setattr(ufw, 'LOGFILE', str(active))
    original = ufw.process_file
    def read(cursor, filename, **options):
        if filename == str(bad):
            raise error
        return original(cursor, filename, **options)
    monkeypatch.setattr(ufw, 'process_file', read)
    connection = connection_for_files()
    with pytest.raises(type(error)):
        ufw.process_log(connection)
    connection.rollback.assert_called_once()
    for call in connection.cursor.return_value.execute.call_args_list:
        assert call.args[0] != 'ROLLBACK TO SAVEPOINT ufw_file'


def test_gap_write_database_failure_is_not_swallowed(tmp_path, monkeypatch):
    active = tmp_path / 'ufw.log'
    active.write_bytes(line(0))
    monkeypatch.setattr(ufw, 'LOGFILE', str(active))
    monkeypatch.setattr(ufw, 'get_logfiles', lambda: [str(active), str(active) + '.1'])
    connection = connection_for_files()
    cursor = connection.cursor.return_value
    original = cursor.execute.side_effect
    def execute(query, values=()):
        if query.startswith('INSERT INTO ufw_collection_gaps'):
            raise pymysql.OperationalError(2013, 'diagnostic write failed')
        return original(query, values)
    cursor.execute.side_effect = execute
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(connection)
    assert connection.rollback.called


def test_partial_collection_returns_nonzero_exit_status(monkeypatch):
    connection = Mock()
    monkeypatch.setattr(ufw, 'get_connection', lambda: connection)
    monkeypatch.setattr(ufw, 'process_log', lambda *args, **kwargs: {'status': 'FAILED', 'inserted': 1})
    assert ufw.main([]) == 1
    connection.close.assert_called_once()
