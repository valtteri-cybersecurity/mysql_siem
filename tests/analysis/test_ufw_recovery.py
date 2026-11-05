"""Equal content never proves that a missing source generation was recovered."""
from unittest.mock import MagicMock

import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw
from tests.analysis.test_ufw_continuity import cursor_for_files


@pytest.mark.parametrize('proof', [None, (1,)])
def test_missing_checkpoints_cannot_prove_each_other_or_use_content_only_archives(proof):
    cursor = MagicMock()
    cursor.fetchall.return_value = [
        (1, 10, 11, '/missing/ufw.log.1', 100, 'same-hash', 'READING'),
        (2, 10, 12, '/missing/ufw.log.2', 100, 'same-hash', 'READING'),
    ]
    def execute(query, values=()):
        cursor.fetchone.return_value = proof
        if 'FROM ufw_file_checkpoints f' in query:
            cursor.fetchone.return_value = None  # No producer-recorded lineage exists.
    cursor.execute.side_effect = execute
    assert continuity.reconcile(cursor, 7, [], float('inf'))
    gaps = []
    for call in cursor.execute.call_args_list:
        query = call.args[0]
        assert not query.startswith('UPDATE ')
        assert 'ufw_archive_proofs' not in query
        if query.startswith('INSERT INTO ufw_collection_gaps'):
            gaps.append(call.args[1][2])
    assert gaps == [1, 2]
    assert cursor.fetchone.call_count == 2


@pytest.mark.parametrize('max_lines,cleared', [(1, False), (2, True)])
def test_only_fully_verified_source_clears_its_own_missing_gap(tmp_path, max_lines, cleared):
    path = tmp_path / 'ufw.log'
    path.write_bytes(b'ordinary one\nordinary two\n')
    cursor = cursor_for_files()
    ufw.process_file(cursor, str(path), max_lines=max_lines)
    if cleared:
        cursor.reset_mock()
        ufw.process_file(cursor, str(path), max_lines=max_lines)
    resolved = []
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('UPDATE ufw_collection_gaps SET resolved=TRUE'):
            assert "reason='MISSING_SOURCE'" in call.args[0]
            assert 'CONTENT_CHANGED' not in call.args[0]
            resolved.append(call.args[1])
    if cleared:
        assert resolved == [(0, 1)]
    else:
        assert not resolved
