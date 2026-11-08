"""Read-only verification of real log files with synthetic checkpoint rows."""

import hashlib
import json
import os
import time
from unittest.mock import Mock

import pytest

from config import auth_checkpoint_upgrade as auth
from ingestion.auth.identity import AuthCollectionError


@pytest.fixture
def source(tmp_path, monkeypatch):
    path = tmp_path / 'auth.log'
    path.write_bytes(b'original\n' + b'x' * 300 + b'\n')
    info = path.stat()
    key = ('reader', info.st_dev, info.st_ino, 8)
    with path.open('rb') as infile:
        digest = auth.position_hash(infile, info.st_size)
    position = info.st_size
    state = (position, digest, None, None, None, None, None)
    monkeypatch.setattr(auth.journal, 'trusted_state', Mock())
    monkeypatch.setattr(auth, 'database_key', Mock(return_value=('mysql_siem', 'server-id')))
    return path, key, state


def verify(path, key, checkpoint, approved=False):
    return auth.verify_file(Mock(), path.parent, str(path), key, checkpoint, time.monotonic() + 5, approved)


def approve(path, key, checkpoint):
    info = path.stat()
    proof = [key[3], *key[:3], *checkpoint[:2], info.st_size, info.st_mtime_ns,
             hashlib.sha256(path.read_bytes()).hexdigest()]
    approval = path.parent / auth.APPROVAL
    approval.write_text(json.dumps({'database': 'mysql_siem', 'server': 'server-id',
                                    'approve': auth.ACKNOWLEDGEMENT, 'checkpoints': [proof]}))
    approval.chmod(0o600)


def test_legacy_zero_needs_no_approval(source):
    path, key, _checkpoint = source
    assert verify(path, key, (0, '', None, None, None, None, None)) is None


def test_legacy_offset_requires_independent_approval(source):
    path, key, checkpoint = source
    with pytest.raises(AuthCollectionError, match='independently verified backup'):
        verify(path, key, checkpoint, approved=True)
    with pytest.raises(AuthCollectionError, match='has not been migrated'):
        verify(path, key, checkpoint)


def test_approved_rotated_file_and_modern_checkpoint_keep_their_offset(source):
    path, key, checkpoint = source
    approve(path, key, checkpoint)
    rotated = path.rename(path.with_suffix('.log.1'))
    path.write_bytes(b'new file\n')
    with rotated.open('ab') as infile:
        infile.write(b'appended\n')
    snapshot = verify(rotated, key, checkpoint, approved=True)
    assert snapshot[1] == rotated.stat().st_size
    origin = (b'g' * 32, *snapshot)
    assert verify(rotated, key, checkpoint[:2] + origin) is None
    with pytest.raises(AuthCollectionError, match='rotated during verification'):
        verify(path, key, checkpoint, approved=True)


def test_matching_short_fingerprint_cannot_prove_changed_prefix(source):
    path, key, checkpoint = source
    approve(path, key, checkpoint)
    info = path.stat()
    with path.open('r+b') as infile:
        infile.write(b'changed!')
        assert auth.position_hash(infile, checkpoint[0]) == checkpoint[1]
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    with pytest.raises(AuthCollectionError, match='content differs from the independently approved'):
        verify(path, key, checkpoint, approved=True)


def test_rejects_approval_for_another_server(source, monkeypatch):
    path, key, checkpoint = source
    approve(path, key, checkpoint)
    monkeypatch.setattr(auth, 'database_key', Mock(return_value=('mysql_siem', 'another-server')))
    with pytest.raises(AuthCollectionError, match='unmatched Auth recovery approval'):
        verify(path, key, checkpoint, approved=True)


def test_rejects_approval_with_unsafe_permissions(source):
    path, key, checkpoint = source
    approve(path, key, checkpoint)
    (path.parent / auth.APPROVAL).chmod(0o640)
    with pytest.raises(auth.journal.InstallationStateError, match='Unsafe deployment state'):
        verify(path, key, checkpoint, approved=True)


def test_unchanged_bytes_with_unproven_generation_are_rejected(source):
    path, key, checkpoint = source
    approve(path, key, checkpoint)
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
    with pytest.raises(AuthCollectionError, match='metadata differs from the independently approved'):
        verify(path, key, checkpoint, approved=True)
