"""Auth occurrence keys, verified file generations and conservative legacy handling."""
import hashlib
import io
import os
from unittest.mock import MagicMock

import pymysql
import pytest

from database.identity import EventIdentity
from ingestion.auth import identity as origin
from ingestion.auth.collector import process_file
from ingestion.auth.db import save_event
from ingestion.auth.parser import parse_auth_line
from tests.ssh_brute_force.test_auth_collector import (
    LINE,
    prepare_cursor,
    verified_state,
)

GENERATION = b'g' * 32


def stored(event):
    result = []
    for name in ('event_time', 'hostname', 'source_ip', 'username', 'event_type', 'service',
                 'raw_message', 'event_hash', 'auth_method', 'source_port'):
        result.append(event.get(name))
    return tuple(result)


def test_occurrence_insert_keeps_original_hash_and_uses_trusted_scope():
    event = parse_auth_line(LINE.decode())
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    assert save_event(cursor, event, identity=EventIdentity(1, 7, 3), generation=GENERATION, position=94) == 1
    sql, values = cursor.execute.call_args.args
    assert 'file_generation,file_position' in sql
    assert event['event_hash'] in values
    assert values[-7:] == (GENERATION, 94, 1, 7, 3, None, 7)
    content_lookup = cursor.execute.call_args_list[1]
    assert content_lookup.args[1] == (7, event['event_hash'], GENERATION)


def test_known_occurrence_replay_does_not_insert_or_use_content_as_identity():
    event = parse_auth_line(LINE.decode())
    cursor = MagicMock()
    cursor.fetchone.return_value = stored(event)
    assert save_event(cursor, event, generation=GENERATION, position=0) == 0
    assert cursor.execute.call_count == 1
    assert cursor.execute.call_args.args[1] == (0, GENERATION, 0)


def test_same_position_with_changed_content_is_never_suppressed():
    event = parse_auth_line(LINE.decode())
    cursor = MagicMock()
    cursor.fetchone.return_value = ('different content',)
    with pytest.raises(origin.AuthCollectionError, match='content changed'):
        save_event(cursor, event, generation=GENERATION, position=0)


def test_unbound_matching_content_is_blocked_before_insert():
    cursor = MagicMock()
    cursor.fetchone.side_effect = [None, (1,)]
    with pytest.raises(origin.AuthCollectionError, match='Ambiguous'):
        save_event(cursor, parse_auth_line(LINE.decode()), generation=GENERATION, position=0)
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith('INSERT')


@pytest.mark.parametrize('number', [1062, 1048])
def test_unrelated_constraint_error_is_propagated(number):
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    def execute(sql, values):
        if sql.startswith('INSERT'):
            raise pymysql.IntegrityError(number, 'synthetic constraint failure')
    cursor.execute.side_effect = execute
    with pytest.raises(pymysql.IntegrityError):
        save_event(cursor, parse_auth_line(LINE.decode()), generation=GENERATION, position=0)


@pytest.mark.parametrize('generation,position', [(bytes(32), 0), (b'g', 0), (GENERATION, -1), (GENERATION, True)])
def test_invalid_occurrence_cannot_touch_database(generation, position):
    cursor = MagicMock()
    with pytest.raises(origin.AuthCollectionError):
        save_event(cursor, parse_auth_line(LINE.decode()), generation=generation, position=position)
    cursor.execute.assert_not_called()


def test_identical_lines_keep_distinct_offsets_in_one_generation(tmp_path, monkeypatch):
    path = tmp_path / 'auth.log'
    path.write_bytes(LINE * 5)
    cursor = MagicMock()
    prepare_cursor(cursor)
    occurrences = []
    def save(cursor, event, *, generation, position, identity=None):
        occurrences.append((generation, position, event['event_hash']))
        return 1
    monkeypatch.setattr('ingestion.auth.collector.save_event', save)
    assert process_file(cursor, str(path), 'reader') == (5, 0)
    positions = []
    for generation, position, digest in occurrences:
        assert generation == occurrences[0][0]
        assert digest == occurrences[0][2]
        positions.append(position)
    assert positions == [0, len(LINE), 2 * len(LINE), 3 * len(LINE), 4 * len(LINE)]


def test_rename_preserves_generation_and_offsets(tmp_path, monkeypatch):
    path = tmp_path / 'auth.log'
    path.write_bytes(LINE * 3)
    state = verified_state(path, len(LINE))
    rotation = tmp_path / 'auth.log.1'
    path.rename(rotation)
    cursor = MagicMock()
    prepare_cursor(cursor, state)
    occurrences = []
    def save(cursor, event, *, generation, position, identity=None):
        occurrences.append((generation, position))
        return 1
    monkeypatch.setattr('ingestion.auth.collector.save_event', save)
    assert process_file(cursor, str(rotation), 'reader') == (2, 0)
    assert occurrences == [(GENERATION, len(LINE)), (GENERATION, 2 * len(LINE))]


def test_legacy_checkpoint_is_preserved_without_inventing_origin(tmp_path):
    path = tmp_path / 'auth.log'
    path.write_bytes(LINE)
    cursor = MagicMock()
    prepare_cursor(cursor, (len(LINE), hashlib.sha256(LINE).hexdigest(), None, None, None, None, None))
    with pytest.raises(origin.AuthCollectionError, match='Legacy Auth checkpoint'):
        process_file(cursor, str(path), 'reader')
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith(('INSERT', 'UPDATE'))


def test_changes_outside_old_256_byte_anchor_are_detected(tmp_path):
    path = tmp_path / 'auth.log'
    path.write_bytes(LINE * 20)
    state = verified_state(path, len(LINE) * 15)
    with path.open('r+b') as target:
        target.write(b'X')
    stats = {'source_resets': 0, 'coverage_gaps': 0}
    with path.open('rb') as source:
        generation, prefix, _snapshot = origin.start(source, os.fstat(source.fileno()), state, stats, None)
        assert generation != GENERATION
        assert source.tell() == 0
        assert prefix.hexdigest() == hashlib.sha256(b'').hexdigest()
    assert stats == {'source_resets': 1, 'coverage_gaps': 1}


def test_same_size_rewrite_with_equal_bytes_does_not_prove_generation(tmp_path):
    path = tmp_path / 'auth.log'
    path.write_bytes(LINE)
    state = verified_state(path, len(LINE))
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000))
    with path.open('rb') as source, pytest.raises(origin.AuthCollectionError, match='Ambiguous'):
        origin.start(source, os.fstat(source.fileno()), state, {}, None)


def test_full_prefix_verification_is_streaming_and_obeys_deadline():
    content = LINE * 3000
    class BoundedReader(io.BytesIO):
        def read(self, size):
            assert 0 < size <= origin.CHUNK
            return super().read(size)
    source = BoundedReader(content)
    result = origin.hashes(source, (0, 13, len(content)), None)
    assert result[13].hexdigest() == hashlib.sha256(content[:13]).hexdigest()
    assert result[len(content)].hexdigest() == hashlib.sha256(content).hexdigest()
    with pytest.raises(origin.AuthCollectionError, match='time budget'):
        origin.hashes(source, (len(content),), 0)
