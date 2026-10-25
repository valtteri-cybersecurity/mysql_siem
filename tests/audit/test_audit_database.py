import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from database.identity import EventIdentity, IdentityError
from ingestion.audit import database, main
from ingestion.audit.parser import parse_events
from ingestion.audit.targets import DEFAULT_TARGETS


@pytest.fixture
def identity():
    return EventIdentity(1, 7, 3)


@pytest.fixture
def checkpoint():
    return {'version': 2, 'source_id': '7', 'device': 1, 'inode': 2, 'offset': 100,
            'fingerprint': 'a' * 64, 'reader_boot_id': '00000000-0000-0000-0000-000000000001',
            'initial_started_at': '2026-10-25T00:00:00+00:00', 'history_policy': 'retained_uncompressed'}


@pytest.fixture
def event(event_text):
    return parse_events(event_text(), source_id='7')['events'][0]


def test_event_and_checkpoint_are_written_without_committing(identity, event, checkpoint):
    cursor = Mock()
    assert database.save_batch(cursor, identity, [event], checkpoint) == 1
    assert len(cursor.execute.call_args_list) == 2
    first, last = cursor.execute.call_args_list
    assert first.args[0].startswith('INSERT INTO audit_events')
    assert last.args[0].startswith('INSERT INTO audit_checkpoints')
    assert first.args[1][:4] == identity.values()
    assert last.args[1][:4] == identity.values()
    assert json.loads(last.args[1][4]) == checkpoint
    assert first.args[1][7].tzinfo is None
    cursor.commit.assert_not_called()


def test_duplicate_preserves_history_and_updates_checkpoint(identity, event, checkpoint):
    cursor = Mock()
    cursor.execute.side_effect = [pymysql.IntegrityError(1062, 'duplicate'), None, None]
    values = database.event_values(event, identity)
    cursor.fetchone.return_value = (identity.host_id, values[-1])
    assert database.save_batch(cursor, identity, [event], checkpoint) == 0
    assert cursor.execute.call_args.args[0].startswith('INSERT INTO audit_checkpoints')
    for call in cursor.execute.call_args_list:
        assert not call.args[0].startswith('UPDATE audit_events')


def test_insert_failure_never_writes_checkpoint(identity, event, checkpoint):
    cursor = Mock()
    cursor.execute.side_effect = pymysql.OperationalError(2013, 'synthetic')
    with pytest.raises(pymysql.OperationalError):
        database.save_batch(cursor, identity, [event], checkpoint)
    assert cursor.execute.call_count == 1


def test_conflicting_duplicate_never_writes_checkpoint(identity, event, checkpoint):
    cursor = Mock()
    cursor.execute.side_effect = [pymysql.IntegrityError(1062, 'duplicate'), None]
    cursor.fetchone.return_value = (identity.host_id + 1, '{}')
    with pytest.raises(ValueError, match='Conflicting'):
        database.save_batch(cursor, identity, [event], checkpoint)
    assert cursor.execute.call_count == 2


def test_foreign_source_and_unexpected_fields_prevent_writes(identity, event, checkpoint):
    cursor = Mock()
    event['source_id'] = '99'
    with pytest.raises(IdentityError):
        database.save_batch(cursor, identity, [event], checkpoint)
    event['source_id'] = '7'
    event['raw_message'] = 'must not be stored'
    with pytest.raises(ValueError):
        database.save_batch(cursor, identity, [event], checkpoint)
    cursor.execute.assert_not_called()


@pytest.fixture
def collection(monkeypatch, identity, checkpoint, event_text):
    connection = MagicMock()
    monkeypatch.setattr(database, 'begin_collection', Mock(return_value=(identity, 'audit-lock')))
    monkeypatch.setattr(database, 'load_targets', Mock(return_value=DEFAULT_TARGETS))
    monkeypatch.setattr(database, 'load_checkpoint', Mock(return_value=None))
    monkeypatch.setattr(database, 'release_lock', Mock())
    monkeypatch.setattr(main, 'runtime_health', Mock(return_value={}))
    batch = {'output': event_text(), 'checkpoint': checkpoint, 'pending': False,
             'limited': False, 'bytes_read': 100, 'initial': True}
    monkeypatch.setattr(main, 'read_log_batch', Mock(return_value=batch))
    return connection


def test_collection_commits_only_after_event_and_checkpoint_writes(collection):
    calls = []
    cursor = collection.cursor.return_value.__enter__.return_value

    def execute(sql, values):
        if sql.startswith('INSERT INTO audit_events'):
            calls.append('event')
        elif sql.startswith('INSERT INTO audit_checkpoints'):
            calls.append('checkpoint')

    def commit():
        calls.append('commit')

    cursor.execute.side_effect = execute
    collection.commit.side_effect = commit
    result = main.collect_to_mysql(collection)
    assert result['inserted'] == 1
    assert calls == ['event', 'checkpoint', 'commit']
    collection.rollback.assert_not_called()
    database.release_lock.assert_called_once_with(collection, 'audit-lock')


@pytest.mark.parametrize('failure', ['event', 'checkpoint', 'commit', 'interrupt'])
def test_collection_rolls_back_and_releases_lock(collection, failure):
    cursor = collection.cursor.return_value.__enter__.return_value

    def execute(sql, values):
        if failure == 'event' and sql.startswith('INSERT INTO audit_events'):
            raise pymysql.OperationalError(2013, 'synthetic event failure')
        if failure == 'checkpoint' and sql.startswith('INSERT INTO audit_checkpoints'):
            raise pymysql.OperationalError(2013, 'synthetic checkpoint failure')
        if failure == 'interrupt':
            raise KeyboardInterrupt

    cursor.execute.side_effect = execute
    if failure == 'commit':
        collection.commit.side_effect = pymysql.OperationalError(2013, 'synthetic commit failure')
    with pytest.raises((pymysql.OperationalError, KeyboardInterrupt)):
        main.collect_to_mysql(collection)
    collection.rollback.assert_called_once()
    if failure != 'commit':
        collection.commit.assert_not_called()
    database.release_lock.assert_called_once_with(collection, 'audit-lock')


def test_busy_writer_never_reads_or_writes(collection):
    database.begin_collection.return_value = (None, None)
    assert main.collect_to_mysql(collection)['status'] == 'busy'
    main.read_log_batch.assert_not_called()
    database.load_checkpoint.assert_not_called()
    collection.commit.assert_not_called()


def test_invalid_identity_blocks_reading(collection):
    database.begin_collection.side_effect = IdentityError('disabled source')
    with pytest.raises(IdentityError):
        main.collect_to_mysql(collection)
    main.read_log_batch.assert_not_called()
    collection.commit.assert_not_called()
    collection.rollback.assert_called_once()


def test_missing_optional_event_metadata_is_storable(identity, event):
    event['auid'] = None
    event['success'] = None
    values = database.event_values(event, identity)
    assert values[11] is None
    assert values[18] is None
    assert values[7] == event['event_time'].astimezone(timezone.utc).replace(tzinfo=None)
    assert isinstance(values[7], datetime)
