"""An occurrence needs a source generation and position, independently of content."""
import hashlib
import os
from unittest.mock import MagicMock

import pytest

from ingestion import ufw_to_mysql as ufw
from ingestion.ufw_batch import EventBatch, OccurrenceConflict
from ingestion.ufw_validation import validate_event
from tests.analysis.test_ufw_continuity import cursor_for_files

LINE = '2026-10-29T12:00:00Z host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=22\n'
GENERATION = b'g' * 32


def cursor_for_batch():
    cursor = MagicMock()
    cursor.fetchall.return_value = []
    return cursor


def test_equal_content_at_different_positions_is_not_deduplicated():
    cursor = cursor_for_batch()
    writer = EventBatch(cursor, None, None, {}, generation=GENERATION)
    writer.add(LINE, validate_event(LINE), position=0)
    writer.add(LINE, validate_event(LINE), position=len(LINE))
    writer.flush()
    assert writer.inserted == 2
    values = cursor.executemany.call_args.args[1]
    assert values[0][:-1] == values[1][:-1]
    assert values[0][-1] == 0
    assert values[1][-1] == len(LINE)


def test_same_position_cannot_change_its_content_inside_a_batch():
    cursor = cursor_for_batch()
    writer = EventBatch(cursor, None, None, {}, generation=GENERATION)
    writer.add(LINE, validate_event(LINE), position=0)
    changed = LINE.replace('DPT=22', 'DPT=443')
    writer.add(changed, validate_event(changed), position=0)
    with pytest.raises(OccurrenceConflict, match='UFW_OCCURRENCE_CONTENT_CHANGED'):
        writer.flush()
    cursor.executemany.assert_not_called()


@pytest.mark.parametrize('position', [None, -1, True, '0'])
def test_missing_or_invalid_position_never_writes(position):
    cursor = cursor_for_batch()
    writer = EventBatch(cursor, None, None, {}, generation=GENERATION)
    with pytest.raises(ValueError):
        writer.add(LINE, validate_event(LINE), position=position)
    cursor.execute.assert_not_called()
    cursor.executemany.assert_not_called()


def test_foreign_or_legacy_content_is_an_explicit_conflict():
    cursor = cursor_for_batch()
    digest = hashlib.sha256(LINE.strip().encode()).hexdigest()
    def execute(query, values):
        cursor.fetchall.return_value = []
        if 'file_generation IS NULL OR file_generation<>%s' in query:
            cursor.fetchall.return_value = [(digest,)]
    cursor.execute.side_effect = execute
    writer = EventBatch(cursor, None, None, {}, generation=GENERATION)
    writer.add(LINE, validate_event(LINE), position=0)
    with pytest.raises(OccurrenceConflict, match='UFW_AMBIGUOUS_OCCURRENCE_SOURCE'):
        writer.flush()
    cursor.executemany.assert_not_called()


def test_identical_same_inode_rewrite_is_not_assumed_to_be_replay(tmp_path):
    path = tmp_path / 'ufw.log'
    path.write_text(LINE)
    cursor = cursor_for_files()
    assert ufw.process_file(cursor, str(path)) == 1
    original = path.stat()
    path.write_text(LINE)
    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns + 1000000))
    cursor.reset_mock()
    with pytest.raises(OccurrenceConflict, match='UFW_AMBIGUOUS_FILE_GENERATION'):
        ufw.process_file(cursor, str(path))
    cursor.executemany.assert_not_called()
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith('UPDATE ufw_file_checkpoints')


def test_rename_between_passes_retains_the_occurrence_generation(tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    path.write_text(LINE)
    cursor = cursor_for_files()
    assert ufw.process_file(cursor, str(path)) == 1
    first = cursor.executemany.call_args.args[1][0][-2]
    rotated = path.with_name('ufw.log.1')
    path.rename(rotated)
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    assert ufw.process_file(cursor, str(rotated)) == 0
    generation = None
    for call in cursor.execute.call_args_list:
        if call.args[0].startswith('UPDATE ufw_file_checkpoints SET generation_key'):
            generation = call.args[1][0]
    assert first == generation
