"""Managed rotation configuration is reversible and preserves custom settings."""
import os
import stat

import pytest

from config import ufw_rotation as rotation


@pytest.fixture
def setup(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    path = tmp_path / 'ufw'
    path.write_text(rotation.STOCK)
    path.chmod(0o640)
    def trusted(directory):
        info = directory.lstat()
        assert stat.S_ISDIR(info.st_mode)
        assert info.st_uid == os.geteuid() and not info.st_mode & 0o022
    monkeypatch.setattr(rotation, 'trusted_directory', trusted)
    monkeypatch.setattr(rotation.journal, 'trusted_state', trusted)
    monkeypatch.setattr(rotation, 'CONFIG', path)
    return state, path


def test_apply_commit_and_repeated_apply_preserve_original_receipt(setup):
    state, path = setup
    original = path.read_bytes()
    assert rotation.apply(state, path)
    assert path.read_text() == rotation.MANAGED
    assert 'compresscmd' in path.read_text()
    assert 'delaycompress' in path.read_text()
    assert 'copytruncate' not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o644
    rotation.commit(state)
    before = (state / rotation.RECEIPT).read_bytes()
    assert not rotation.apply(state, path)
    assert (state / rotation.RECEIPT).read_bytes() == before
    rotation.rollback(state, path)
    assert path.read_bytes() == original
    assert path.stat().st_mode & 0o777 == 0o640
    assert path.stat().st_gid == os.getegid()


def test_pending_apply_can_resume_or_restore(setup):
    state, path = setup
    assert rotation.apply(state, path)
    assert rotation.apply(state, path)
    rotation.rollback(state, path)
    assert path.read_text() == rotation.STOCK
    assert rotation.receipt(state)['phase'] == 'restored'


def test_new_configuration_can_be_removed_on_rollback(setup):
    state, path = setup
    path.unlink()
    assert rotation.apply(state, path)
    rotation.rollback(state, path)
    assert not path.exists()


def test_custom_configuration_is_not_overwritten(setup):
    state, path = setup
    path.write_text(rotation.STOCK.replace('rotate 4', 'rotate 12'))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match='Custom UFW'):
        rotation.apply(state, path)
    assert path.read_bytes() == before
    assert not (state / rotation.RECEIPT).exists()


def test_modified_configuration_is_not_overwritten_by_rollback(setup):
    state, path = setup
    rotation.apply(state, path)
    path.write_text('administrator changed this configuration\n')
    with pytest.raises(RuntimeError, match='automatic restore was refused'):
        rotation.rollback(state, path)
    assert path.read_text() == 'administrator changed this configuration\n'
    assert rotation.receipt(state)['phase'] == 'pending'


def test_failure_after_replacement_restores_original(setup, monkeypatch):
    state, path = setup
    original = rotation.write_config
    calls = [0]
    def fail_after_replace(*args):
        original(*args)
        calls[0] += 1
        if calls[0] == 1:
            raise OSError('synthetic interrupted configuration publication')
    monkeypatch.setattr(rotation, 'write_config', fail_after_replace)
    with pytest.raises(OSError):
        rotation.apply(state, path)
    assert path.read_text() == rotation.STOCK
    assert rotation.receipt(state)['phase'] == 'restored'


@pytest.mark.parametrize('unsafe', ['symlink', 'hardlink', 'writable'])
def test_unsafe_configuration_is_rejected(setup, unsafe):
    state, path = setup
    target = path.with_name('target')
    if unsafe == 'symlink':
        path.rename(target)
        path.symlink_to(target)
    elif unsafe == 'hardlink':
        os.link(path, target)
    else:
        path.chmod(0o666)
    with pytest.raises((OSError, RuntimeError)):
        rotation.apply(state, path)
    assert not (state / rotation.RECEIPT).exists()
