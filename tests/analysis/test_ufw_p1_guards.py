"""Fail closed on unstable final reads and historical content-only recoveries."""
from unittest.mock import MagicMock

import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw
from tests.analysis.test_ufw_collector import line
from tests.analysis.test_ufw_continuity import cursor_for_files


@pytest.mark.parametrize('rewrite', [False, True])
def test_growth_during_last_check_cannot_publish_a_checkpoint(tmp_path, monkeypatch, rewrite):
    path = tmp_path / 'ufw.log'
    path.write_bytes(line(0))
    cursor = cursor_for_files()
    original = continuity.digest_prefixes
    calls = [0]
    def change(source, sizes, deadline):
        result = original(source, sizes, deadline)
        calls[0] += 1
        if calls[0] >= 2:
            if rewrite and calls[0] == 3:
                with path.open('r+b') as output:
                    output.write(b'X')
            with path.open('ab') as output:
                output.write(line(calls[0]))
        return result
    monkeypatch.setattr(continuity, 'digest_prefixes', change)
    with pytest.raises(TimeoutError, match='SOURCE_UNSTABLE_DURING_VERIFICATION'):
        ufw.process_file(cursor, str(path))
    assert calls[0] == 3
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith(('INSERT INTO ufw_file_checkpoints', 'UPDATE ufw_file_checkpoints'))


@pytest.mark.parametrize('health', [None, (None, None, None, 'HEALTHY', 0, 'snapshot_end', 0, 0, False)])
def test_recovered_history_is_visible_even_without_unresolved_gaps(health):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [health, (2,)]
    cursor.fetchall.return_value = []
    result = continuity.read_health(connection, 7)
    assert result['state'] == 'GAP_DETECTED'
    assert result['unverified_recoveries'] == 2
    connection.commit.assert_not_called()
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')
        assert call.args[1] == (7,)


@pytest.mark.parametrize('audit', [None, (-1,), ('2',), (1, 2)])
def test_invalid_recovery_audit_never_returns_healthy(audit):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(None, None, None, 'HEALTHY', 0, 'snapshot_end', 0, 0, False), audit]
    cursor.fetchall.return_value = []
    with pytest.raises(RuntimeError, match='UFW_RECOVERY_AUDIT_UNVERIFIED'):
        continuity.read_health(connection, 7)
    connection.commit.assert_not_called()


def test_recovery_audit_has_a_database_execution_limit():
    import pymysql
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (None, None, None, 'HEALTHY', 0, 'snapshot_end', 0, 0, False)
    cursor.fetchall.return_value = []
    def execute(query, values):
        if "status='RECOVERED'" in query:
            assert 'MAX_EXECUTION_TIME(1000)' in query
            assert values == (7,)
            raise pymysql.OperationalError(3024, 'synthetic audit time limit')
    cursor.execute.side_effect = execute
    with pytest.raises(pymysql.MySQLError):
        continuity.read_health(connection, 7)
    connection.commit.assert_not_called()
