"""Content proofs, read-only diagnosis, bounded verification and safe generations."""
import hashlib
import io
from unittest.mock import MagicMock

import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw


def cursor_for_files():
    """Minimal SQL replay model; real transactions are covered by private MySQL tests."""
    cursor = MagicMock()
    cursor.__enter__.return_value = cursor
    cursor.connection._siem_identity_ready = False
    cursor.rowcount = 1
    rows = {}
    def execute(query, values=()):
        cursor.fetchone.return_value = None
        cursor.fetchall.return_value = []
        if 'GET_LOCK' in query or 'information_schema.tables' in query:
            cursor.fetchone.return_value = (1,)
        elif query.startswith('SELECT id,byte_position'):
            cursor.fetchone.return_value = rows.get(tuple(values))
        elif query.startswith('INSERT INTO ufw_file_checkpoints'):
            _filename, position, prefix, size, digest, status, scope, device, inode = values
            rows[(scope, device, inode)] = (len(rows) + 1, position, prefix, size, digest, status)
        elif query.startswith('UPDATE ufw_file_checkpoints SET filename'):
            _filename, position, prefix, size, digest, status, checkpoint, scope = values
            for key, row in rows.items():
                if row[0] == checkpoint:
                    rows[key] = (checkpoint, position, prefix, size, digest, status)
                    break
    cursor.execute.side_effect = execute
    def executemany(query, rows):
        for row in rows:
            cursor.execute(query, row)
        cursor.rowcount = len(rows)
    cursor.executemany.side_effect = executemany
    return cursor


@pytest.mark.parametrize('change', ['copytruncate', 'regrowth', 'same_size', 'unread_tail', 'inode_reuse'])
def test_content_change_creates_generation_and_preserves_old_offset(tmp_path, change):
    path = tmp_path / 'ufw.log'
    old = b'one\ntwo\n'
    path.write_bytes(old)
    cursor = cursor_for_files()
    ufw.process_file(cursor, str(path), max_lines=1)
    cursor.reset_mock()
    content = b'new\n'
    if change in ('regrowth', 'inode_reuse'):
        content = b'new\nextra\nlong\n'
    elif change == 'same_size':
        content = b'new\nend\n'
    elif change == 'unread_tail':
        content = b'one\nNEW\n'
    path.write_bytes(content)
    ufw.process_file(cursor, str(path))
    queries = []
    for call in cursor.execute.call_args_list:
        queries.append(call.args[0])
    gap_written = False
    checkpoint_written = False
    for query in queries:
        if 'INSERT INTO ufw_collection_gaps' in query:
            gap_written = True
        if 'INSERT INTO ufw_file_checkpoints' in query:
            checkpoint_written = True
        assert 'UPDATE ufw_state' not in query
    assert gap_written
    assert checkpoint_written
    inserts = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('INSERT INTO ufw_file_checkpoints'):
            inserts.append(call.args[1])
    assert inserts[-1][1] == len(content)


def test_verification_is_streaming_and_bounded(monkeypatch):
    source = io.BytesIO(b'x' * 200000)
    assert continuity.digest_prefix(source, 200000, None).hexdigest() == hashlib.sha256(source.getvalue()).hexdigest()
    monkeypatch.setattr(continuity.time, 'monotonic', lambda: 2)
    with pytest.raises(TimeoutError):
        continuity.digest_prefix(source, 200000, 1)


@pytest.mark.parametrize('active,error,gaps,expected', [
    ('HEALTHY', None, [], 'HEALTHY'), ('BACKLOG', None, [], 'BACKLOG'),
    ('HEALTHY', 'OperationalError', [], 'DEGRADED'), ('UNKNOWN', None, [], 'UNKNOWN'),
    ('HEALTHY', None, [('MISSING_SOURCE', 1)], 'GAP_DETECTED'),
    ('HEALTHY', None, [('LEGACY_UNVERIFIED', 1)], 'UNKNOWN'),
])
def test_diagnostic_states_are_read_only(active, error, gaps, expected):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (None, None, error, active, 0, 'snapshot_end', 1, 0, False)
    cursor.fetchall.return_value = gaps
    assert continuity.read_health(connection, 7)['state'] == expected
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT ')
    connection.commit.assert_not_called()


def test_file_replacement_during_read_never_publishes_checkpoint(tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'one\n')
    cursor = cursor_for_files()
    def replace(*args, **kwargs):
        path.rename(tmp_path / 'ufw.log.1')
        path.write_bytes(b'new\n')
        return 0
    monkeypatch.setattr('ingestion.ufw_records.process_line', replace)
    with pytest.raises(OSError, match='SOURCE_REPLACED'):
        ufw.process_file(cursor, str(path))
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith('INSERT INTO ufw_file_checkpoints')


def test_missing_source_records_gap(tmp_path):
    cursor = MagicMock()
    cursor.fetchall.return_value = [(12, 1, 2, str(tmp_path / 'gone'), 100, 'a' * 64, 'READING')]
    cursor.fetchone.return_value = None
    assert continuity.reconcile(cursor, 7, [], float('inf'))
    writes = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('INSERT INTO ufw_collection_gaps'):
            writes.append(call.args[1])
    assert writes[0][0] == 7
    assert writes[0][2:4] == (12, 'MISSING_SOURCE')


def test_source_scope_has_an_independent_checkpoint(tmp_path):
    from database.identity import EventIdentity
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'ordinary line\n')
    cursor = cursor_for_files()
    ufw.process_file(cursor, str(path), identity=EventIdentity(1, 2, 3))
    ufw.process_file(cursor, str(path), identity=EventIdentity(1, 4, 3))
    scopes = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('INSERT INTO ufw_file_checkpoints'):
            scopes.append(call.args[1][6])
    assert scopes == [2, 4]


def test_slow_active_verification_does_not_starve_archives(tmp_path, monkeypatch):
    from tests.analysis.test_ufw_collector import connection_for_files
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'ordinary line\n')
    path.with_name('ufw.log.8.gz').touch()
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    def timeout(*args):
        raise TimeoutError('CHECKPOINT_VERIFY_TIME_LIMIT')
    monkeypatch.setattr(continuity, 'start', timeout)
    def archives(connection, logfile, *, max_lines, deadline, totals):
        assert max_lines > 0
        totals.update({'inserted': 2, 'lines_read': 2, 'archives_pending': 3, 'archive_errors': 0, 'quarantined': 0})
    monkeypatch.setattr('ingestion.ufw_archives.process_archives', archives)
    result = ufw.process_log(connection_for_files())
    assert result['archive_lines'] == 2
    assert result['status'] == 'FAILED'
    assert result['stop_reason'] == 'verification_time_limit'


def test_rename_during_read_follows_the_same_verified_descriptor(tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    rotated = tmp_path / 'ufw.log.9'
    path.write_bytes(b'one\n')
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    def rotate(*args, **kwargs):
        path.rename(rotated)
        path.write_bytes(b'new\n')
        return 0
    monkeypatch.setattr('ingestion.ufw_records.process_line', rotate)
    cursor = cursor_for_files()
    ufw.process_file(cursor, str(path))
    writes = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('INSERT INTO ufw_file_checkpoints'):
            writes.append(call.args[1])
    assert writes[0][0] == str(rotated)
    assert writes[0][1] == len(b'one\n')


@pytest.mark.parametrize('turn,active_lines,archive_lines', [(1, 1, 0), (2, 0, 0), (3, 0, 1)])
def test_single_line_budget_rotates_between_active_plain_and_gzip(tmp_path, monkeypatch, turn, active_lines, archive_lines):
    from tests.analysis.test_ufw_collector import connection_for_files
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'live\n')
    path.with_name('ufw.log.9').write_bytes(b'rotated\n')
    path.with_name('ufw.log.8.gz').touch()
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    connection = connection_for_files()
    cursor = connection.cursor.return_value
    execute = cursor.execute.side_effect
    def read_turn(query, values=()):
        execute(query, values)
        if query.startswith('SELECT pass_number'):
            cursor.fetchone.return_value = (turn,)
    cursor.execute.side_effect = read_turn
    def archives(connection, logfile, *, max_lines, deadline, totals):
        totals.update({'inserted': max_lines, 'lines_read': max_lines, 'archives_pending': 1, 'archive_errors': 0, 'quarantined': 0})
    monkeypatch.setattr('ingestion.ufw_archives.process_archives', archives)
    result = ufw.process_log(connection, max_lines=1)
    assert result.get('active_lines', 0) == active_lines
    assert result['archive_lines'] == archive_lines
    assert result['lines_read'] == 1
