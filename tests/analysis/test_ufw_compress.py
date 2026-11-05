"""Compression preserves input and publishes lineage only after a complete output."""
import gzip
import hashlib
import os
from unittest.mock import MagicMock

import pytest

from ingestion import ufw_compress as compressor
from ingestion import ufw_to_mysql as ufw


@pytest.fixture
def compression(tmp_path, monkeypatch):
    active = tmp_path / 'ufw.log'
    source = tmp_path / 'ufw.log.1'
    output = tmp_path / 'ufw.log.1.gz'
    source.write_bytes(b'private source data\n' * 30)
    source.chmod(0o600)
    monkeypatch.setattr(ufw, 'LOGFILE', str(active))
    monkeypatch.setattr(compressor, 'TRUSTED_OWNER', os.geteuid())
    monkeypatch.setattr(compressor, 'configured_identity', lambda cursor, kind: None)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.lastrowid = 99
    def execute(query, values=()):
        cursor.fetchone.return_value = None
        if 'GET_LOCK' in query:
            cursor.fetchone.return_value = (1,)
        elif query.startswith('SELECT generation_key'):
            cursor.fetchone.return_value = (b'g' * 32,)
    cursor.execute.side_effect = execute
    original = source.read_bytes()
    def start(*args):
        return 1, hashlib.sha256(b''), hashlib.sha256(original).hexdigest(), b'g' * 32
    monkeypatch.setattr(compressor.continuity, 'start', start)
    return connection, source, output, original


def run(compression):
    connection, source, output, _original = compression
    with source.open('rb') as input_file, output.open('wb') as output_file:
        output.chmod(0o600)
        return compressor.compress_stream(connection, input_file, output_file, str(source))


def test_complete_output_is_bound_without_inserting_events_or_advancing_checkpoint(compression):
    connection, source, output, original = compression
    digest = run(compression)
    assert source.read_bytes() == original
    assert gzip.decompress(output.read_bytes()) == original
    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    queries = []
    for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list:
        queries.append(call.args[0])
        assert 'INSERT INTO ufw_log' not in call.args[0]
        assert 'UPDATE ufw_file_checkpoints' not in call.args[0]
    lineage_inserted = False
    for query in queries:
        if query.startswith('INSERT INTO ufw_archive_lineage'):
            lineage_inserted = True
    assert lineage_inserted
    assert connection.commit.call_count == 2


@pytest.mark.parametrize('change', ['append', 'rewrite', 'replace'])
def test_source_mutation_does_not_publish_lineage_or_leave_output(compression, monkeypatch, change):
    connection, source, output, original = compression
    write = compressor.CompressedOutput.write
    calls = [0]
    def mutate(writer, block):
        result = write(writer, block)
        calls[0] += 1
        if calls[0] == 1:
            if change == 'append':
                with source.open('ab') as target:
                    target.write(b'more data\n')
            elif change == 'rewrite':
                source.write_bytes(b'X' + original[1:])
            else:
                source.rename(source.with_name('retained-old-source'))
                source.write_bytes(b'replacement data')
        return result
    monkeypatch.setattr(compressor.CompressedOutput, 'write', mutate)
    with pytest.raises(OSError):
        run(compression)
    assert output.read_bytes() == b''
    assert source.exists()
    for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list:
        assert not call.args[0].startswith('INSERT INTO ufw_archive_lineage')


def test_output_limit_keeps_source_and_marks_failure(compression, monkeypatch):
    connection, source, output, original = compression
    monkeypatch.setattr(compressor.archives, 'MAX_COMPRESSED', 1)
    with pytest.raises(OSError, match='ARCHIVE_COMPRESSED_LIMIT'):
        run(compression)
    assert output.read_bytes() == b''
    assert source.read_bytes() == original
    assert connection.rollback.called


def test_lock_contention_does_not_start_compression(compression):
    connection, source, output, original = compression
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.execute.side_effect = None
    cursor.fetchone.return_value = (0,)
    with pytest.raises(RuntimeError, match='LOCK_UNAVAILABLE'):
        run(compression)
    assert source.read_bytes() == original
    assert output.read_bytes() == b''
    assert not connection.commit.called


def test_existing_output_is_never_truncated(compression):
    connection, source, output, original = compression
    output.write_bytes(b'existing archive')
    output.chmod(0o600)
    with source.open('rb') as input_file, output.open('r+b') as output_file, pytest.raises(OSError, match='OUTPUT_NOT_EMPTY'):
        compressor.compress_stream(connection, input_file, output_file, str(source))
    assert output.read_bytes() == b'existing archive'
    assert source.read_bytes() == original
    connection.cursor.assert_not_called()


def test_group_writable_input_is_rejected_before_database_access(compression):
    connection, source, _output, original = compression
    source.chmod(0o660)
    with pytest.raises(OSError, match='UNTRUSTED_COMPRESSION_DESCRIPTOR'):
        run(compression)
    assert source.read_bytes() == original
    connection.cursor.assert_not_called()
