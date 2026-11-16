"""Managed rotation configuration is reversible and preserves custom settings."""
import gzip
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from config import ufw_external_rotation as external
from config import ufw_rotation as rotation

LABOR88 = Path(__file__).parent / 'fixtures/ufw_rotation/ubuntu-custom-uncompressed.conf'


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
    assert path.stat().st_mode & 0o777 == 0o640
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


def test_labor88_keeps_external_rotation_byte_for_byte(setup, monkeypatch):
    state, path = setup
    original = LABOR88.read_bytes()
    path.write_bytes(original)
    # Host-side source verification is exercised independently with temporary inputs.
    monkeypatch.setattr(rotation, 'check_external_source', lambda *args: ())
    for _ in range(2):
        expected = rotation.check(path, state=state)
        assert not rotation.apply(state, path, expected=expected)
        rotation.commit(state)
        assert rotation.verify_active(state) == rotation.EXTERNAL_PLAIN
        assert path.read_bytes() == original
        assert not (state / rotation.RECEIPT).exists()


@pytest.fixture
def external_installation(setup, monkeypatch):
    state, old = setup
    base = old.parent
    includes = base / 'logrotate.d'
    includes.mkdir(mode=0o755)
    path = includes / 'ufw'
    path.write_bytes(LABOR88.read_bytes())
    path.chmod(0o644)
    defaults = base / 'logrotate.conf'
    defaults.write_text(f'weekly\nsu root adm\nrotate 4\ncreate\ninclude {includes}\n')
    defaults.chmod(0o644)
    logdir = base / 'logs'
    logdir.mkdir(mode=0o755)
    logdir.chmod(0o775)
    logfile = logdir / 'ufw.log'
    logfile.write_bytes(b'2026-11-16T10:00:00+00:00 host kernel: [UFW BLOCK] SRC=192.0.2.1\n')
    logfile.chmod(0o640)
    rule = base / '20-ufw.conf'
    rule.write_text(external.RSYSLOG_RULE + '\n& stop\n')
    rule.chmod(0o644)
    helper = base / 'rsyslog-rotate'
    helper.write_text('#!/bin/sh\nexit 0\n')
    helper.chmod(0o755)
    sibling = includes / 'rsyslog'
    sibling.write_text('/var/log/syslog\n{\n    daily\n    compress\n}\n')
    sibling.chmod(0o644)
    monkeypatch.setattr(external, 'LOGROTATE_DEFAULTS', defaults)
    monkeypatch.setattr(external, 'UFW_RULE', rule)
    monkeypatch.setattr(external, 'POSTROTATE', helper)
    monkeypatch.setattr(external, 'LOG', logfile)
    monkeypatch.setattr(external, 'trusted_directory', rotation.trusted_directory)
    monkeypatch.setattr(external.grp, 'getgrnam', lambda name: SimpleNamespace(gr_gid=os.getegid()))
    monkeypatch.setattr(external.pwd, 'getpwnam',
                        lambda name: SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid()))
    monkeypatch.setattr(external.subprocess, 'run', lambda *args, **kwargs: None)
    monkeypatch.setattr(rotation, 'CONFIG', path)
    return state, path, defaults, sibling, rule, logfile


def test_external_source_and_preflight_fingerprint(external_installation):
    state, path, _defaults, sibling, _rule, _logfile = external_installation
    expected = rotation.check(path, state=state)
    assert not rotation.apply(state, path, expected=expected)
    sibling.write_text('# verified but changed since preflight\n' + sibling.read_text())
    with pytest.raises(RuntimeError, match='changed after preflight'):
        rotation.apply(state, path, expected=expected)
    assert path.read_bytes() == LABOR88.read_bytes()
    assert not (state / rotation.RECEIPT).exists()


def test_external_mode_preserves_preexisting_committed_gzip_receipt(external_installation):
    state, path, *_ = external_installation
    path.write_text(rotation.STOCK)
    rotation.apply(state, path)
    assert rotation.verify_active(state, during_maintenance=True) == rotation.MANAGED_GZIP
    rotation.commit(state)
    assert rotation.verify_active(state) == rotation.MANAGED_GZIP
    saved = state / rotation.RECEIPT
    before = saved.read_bytes()
    path.write_bytes(LABOR88.read_bytes())
    assert not rotation.apply(state, path, expected=rotation.check(path, state=state))
    rotation.commit(state)
    assert rotation.verify_active(state) == rotation.EXTERNAL_PLAIN
    assert saved.read_bytes() == before


@pytest.mark.parametrize('frequency,retention', [('hourly', 7), ('weekly', 90), ('monthly', 2), ('daily', 255)])
def test_safe_external_schedule_and_retention_are_user_settings(external_installation, frequency, retention):
    state, path, defaults, *_ = external_installation
    original = LABOR88.read_text().replace('rotate 30', f'rotate {retention}').replace('daily', frequency)
    original = original.replace('    nocompress\n', '    create 0640 syslog adm\n    nocompress\n')
    defaults.write_text(defaults.read_text().replace('rotate 4', 'rotate 8\ncompress'))
    path.write_text(original)
    assert not rotation.apply(state, path, expected=rotation.check(path, state=state))
    assert rotation.verify_active(state) == rotation.EXTERNAL_PLAIN
    assert path.read_text() == original
    assert not (state / rotation.RECEIPT).exists()


def test_external_policy_rotates_without_compression(tmp_path):
    executable = shutil.which('logrotate')
    if executable is None:
        pytest.skip('Private rotation test requires logrotate.')
    source = tmp_path / 'ufw.log'
    source.write_bytes(b'original private UFW log\n')
    config = tmp_path / 'rotation.conf'
    hook = tmp_path / 'postrotate'
    text = LABOR88.read_text().replace('/var/log/ufw.log', str(source))
    text = text.replace('[ -x /usr/lib/rsyslog/rsyslog-rotate ] && /usr/lib/rsyslog/rsyslog-rotate || true',
                        f'printf reopened > "{hook}"')
    config.write_text('create\ncompress\n' + text)
    command = [executable, '--state', str(tmp_path / 'state'), '--force']
    debug = subprocess.run([*command, '--debug', str(config)], check=False, capture_output=True, text=True, timeout=10)
    assert debug.returncode == 0, debug.stderr
    assert not hook.exists()
    for _ in range(2):
        result = subprocess.run([*command, str(config)], check=False, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        source.write_bytes(b'next private UFW log\n')
    assert hook.read_text() == 'reopened'
    assert source.with_suffix('.log.2').read_bytes() == b'original private UFW log\n'
    assert not list(tmp_path.glob('*.gz'))


@pytest.mark.parametrize('line', ['copytruncate', 'create 0666 root root', 'su nobody nogroup', 'dateext',
                                  'olddir /tmp', 'compress', 'compresscmd /usr/bin/gzip', 'start 0', 'rotate 1', 'weekly'])
def test_external_stanza_refuses_conflicting_options(setup, line):
    state, path = setup
    changed = LABOR88.read_text().replace('    nocompress\n', '    nocompress\n    ' + line + '\n')
    path.write_text(changed)
    with pytest.raises(RuntimeError, match='Custom UFW'):
        rotation.check(path, state=state)
    assert path.read_text() == changed
    assert not (state / rotation.RECEIPT).exists()


@pytest.mark.parametrize('fault', ['global', 'inherited', 'conflicting', 'rule', 'unreadable', 'symlink',
                                  'timestamp', 'hardlink', 'missing', 'pending', 'archive-naming', 'archive-conflict'])
def test_external_policy_refuses_unverified_inputs(external_installation, monkeypatch, fault):
    state, path, defaults, sibling, rule, logfile = external_installation
    if fault == 'global':
        defaults.write_text('dateext\n' + defaults.read_text())
    elif fault == 'inherited':
        sibling.write_text('copytruncate\n' + sibling.read_text())
    elif fault == 'conflicting':
        sibling.write_text(str(logfile) + ' {\n copytruncate\n}\n')
    elif fault == 'rule':
        rule.write_text(':msg,contains,"[UFW " /var/log/syslog\n')
    elif fault == 'unreadable':
        def unreadable(*args, **kwargs):
            raise subprocess.CalledProcessError(1, 'synthetic')
        monkeypatch.setattr(external.subprocess, 'run', unreadable)
    elif fault == 'symlink':
        logfile.symlink_to(logfile.rename(logfile.with_suffix('.original')))
    elif fault == 'timestamp':
        logfile.write_text('Nov 16 10:00:00 host kernel: [UFW BLOCK] SRC=192.0.2.1\n')
    elif fault == 'hardlink':
        os.link(logfile, logfile.with_suffix('.backup'))
    elif fault == 'missing':
        logfile.unlink()
    elif fault == 'archive-naming':
        logfile.with_suffix('.log.03').write_bytes(b'')
    elif fault == 'archive-conflict':
        sibling.write_text(str(logfile) + '.30 {\n daily\n}\n')
    else:
        original = path.read_bytes()
        path.write_text(rotation.STOCK)
        rotation.apply(state, path)
        path.write_bytes(original)
    saved = state / rotation.RECEIPT
    before = None
    if saved.exists():
        before = saved.read_bytes()
    with pytest.raises((OSError, RuntimeError)):
        rotation.check(path, state=state)
    assert path.read_bytes() == LABOR88.read_bytes()
    if before is not None:
        assert saved.read_bytes() == before
    else:
        assert not saved.exists()


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


@pytest.fixture(params=['ubuntu-noble', 'mint-zena', 'debian-trixie'])
def packaged_config(request):
    # Noble and Mint's APT candidate: ufw 0.36.2-6. Trixie: ufw 0.36.2-9.
    # The installed Mint package independently lists the same conffile checksum.
    path = Path(__file__).parent / 'fixtures/ufw_rotation' / (request.param + '.conf')
    return path.read_text()


def test_packaged_installation_resume_and_restore(setup, packaged_config):
    state, path = setup
    path.write_text(packaged_config)
    expected = rotation.check(path, state=state)
    assert path.read_text() == packaged_config
    assert not (state / rotation.RECEIPT).exists()
    assert rotation.apply(state, path, expected=expected)
    managed = path.read_text()
    assert rotation.configuration_lines(managed)[0].count(rotation.COMPRESSOR_OPTIONS[0]) == 1
    preserved = []
    for line in managed.splitlines(keepends=True):
        if line.strip() not in rotation.COMPRESSOR_OPTIONS:
            preserved.append(line)
    assert ''.join(preserved) == packaged_config
    assert rotation.apply(state, path, expected=rotation.check(path, state=state))
    rotation.commit(state)
    assert not rotation.apply(state, path, expected=rotation.check(path, state=state))
    rotation.rollback(state, path)
    assert path.read_text() == packaged_config


def test_packaged_managed_config_rotates_numbered_archives(setup, packaged_config):
    executable = shutil.which('logrotate')
    if executable is None:
        pytest.skip('Private rotation test requires logrotate.')
    state, path = setup
    path.write_text(packaged_config)
    rotation.apply(state, path)
    source = path.with_name('ufw.log')
    source.write_bytes(b'first private UFW log\n')
    configuration = path.read_text().replace('/var/log/ufw.log', str(source))
    # Match the packaged global create behavior without changing system files.
    path.write_text('create\n' + configuration)
    command = [executable, '--state', str(state / 'logrotate.status')]
    debug = subprocess.run([*command, '--debug', '--force', str(path)],
                           check=False, capture_output=True, text=True, timeout=10)
    assert debug.returncode == 0, debug.stderr
    assert not (state / 'logrotate.status').exists()

    # Use the same stanza with private stand-ins for the production scripts.
    hook = state / 'postrotate'
    configuration = configuration.replace(rotation.COMPRESSOR_OPTIONS[0], 'compresscmd /usr/bin/gzip')
    configuration = configuration.replace(
        '[ -x /usr/lib/rsyslog/rsyslog-rotate ] && /usr/lib/rsyslog/rsyslog-rotate || true',
        f'printf reopened > "{hook}"',
    )
    path.write_text('create\n' + configuration)
    for _ in range(2):
        result = subprocess.run([*command, '--force', str(path)], check=False,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        source.write_bytes(b'next private UFW log\n')
    assert hook.read_text() == 'reopened'
    assert source.with_suffix('.log.1').read_bytes() == b'next private UFW log\n'
    assert gzip.decompress(source.with_suffix('.log.2.gz').read_bytes()) == b'first private UFW log\n'


def test_comments_and_indentation_are_preserved(setup):
    state, path = setup
    original = '# Packaged defaults\n' + rotation.STOCK.replace('/var/log/ufw.log\n{', '/var/log/ufw.log  {')
    original = original.replace('    compress\n', '\t# Keep delayed compression\n\tcompress\n')
    path.write_text(original)
    assert original.split() != rotation.STOCK.split()
    assert rotation.apply(state, path, expected=rotation.check(path, state=state))
    assert '\t# Keep delayed compression\n\tcompress\n\tcompresscmd ' in path.read_text()
    rotation.rollback(state, path)
    assert path.read_text() == original


@pytest.mark.parametrize('before,after', [
    ('rotate 4', 'rotate\n    4'),
    ('compress\n', 'compress\n    compresscmd /usr/bin/gzip\n'),
    ('delaycompress', 'delaycompress\n    nocompress'),
    ('delaycompress', 'delaycompress\n    dateext'),
    ('delaycompress', 'delaycompress\n    olddir /tmp'),
    ('delaycompress', 'delaycompress\n    copytruncate'),
    ('delaycompress', 'delaycompress\n    su nobody nogroup'),
    ('delaycompress', 'delaycompress\n    create 0666 root root'),
    ('[ -x /usr/lib/rsyslog/rsyslog-rotate ]', '/bin/true'),
    (' && ', '\n        && '),
])
def test_unverified_stanza_is_preserved(setup, before, after):
    state, path = setup
    original = rotation.STOCK.replace(before, after)
    path.write_text(original)
    with pytest.raises(RuntimeError, match='Custom UFW'):
        rotation.check(path, state=state)
    with pytest.raises(RuntimeError, match='Custom UFW'):
        rotation.apply(state, path)
    assert path.read_text() == original
    assert not (state / rotation.RECEIPT).exists()


def test_preflight_detects_changes_even_if_still_compatible(setup):
    state, path = setup
    expected = rotation.check(path, state=state)
    updated = '# administrator annotation\n' + path.read_text()
    path.write_text(updated)
    with pytest.raises(RuntimeError, match='changed after preflight'):
        rotation.apply(state, path, expected=expected)
    assert path.read_text() == updated
    assert not (state / rotation.RECEIPT).exists()


def test_publisher_rechecks_after_receipt_is_written(setup, monkeypatch):
    state, path = setup
    original_write = rotation.journal.write_file
    updated = '# changed just before publication\n' + path.read_text()

    def change_after_receipt(*args):
        original_write(*args)
        path.write_text(updated)

    monkeypatch.setattr(rotation.journal, 'write_file', change_after_receipt)
    with pytest.raises(RuntimeError, match='changed before publication'):
        rotation.apply(state, path)
    assert path.read_text() == updated
    assert rotation.receipt(state)['phase'] == 'pending'


@pytest.mark.parametrize('published', [False, True])
def test_legacy_pending_receipt_resumes_without_replacing_evidence(setup, published):
    state, path = setup
    record = {'original': path.read_text(), 'mode': 0o640, 'gid': os.getegid(), 'phase': 'pending',
              'managed_sha': '526f5b69351a9db656f4d4ffdcb173db1a156bed4c6c09d2f2fe96cde71a6c15'}
    saved_path = state / rotation.RECEIPT
    rotation.journal.write_file(saved_path, json.dumps(record))
    if published:
        path.write_text(rotation.MANAGED)
        path.chmod(0o644)
    assert rotation.apply(state, path, expected=rotation.check(path, state=state))
    assert json.loads(saved_path.read_bytes()) == record
    assert path.stat().st_mode & 0o777 == 0o644
    rotation.commit(state)
    assert not rotation.apply(state, path)
    rotation.rollback(state, path)
    assert path.read_text() == record['original']


@pytest.mark.parametrize('fault', ['missing', 'corrupt', 'digest', 'permissions'])
def test_unverified_recovery_retains_files(setup, fault):
    state, path = setup
    rotation.apply(state, path)
    saved_path = state / rotation.RECEIPT
    if fault == 'missing':
        saved_path.unlink()
    elif fault == 'corrupt':
        rotation.journal.write_file(saved_path, '{')
    elif fault == 'digest':
        record = rotation.receipt(state)
        record['managed_sha'] = '0' * 64
        rotation.journal.write_file(saved_path, json.dumps(record))
    else:
        path.chmod(0o600)
    before = path.read_bytes()
    with pytest.raises((RuntimeError, ValueError)):
        rotation.check(path, state=state)
    with pytest.raises((RuntimeError, ValueError)):
        rotation.apply(state, path)
    assert path.read_bytes() == before
