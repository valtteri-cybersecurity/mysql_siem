import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from ingestion.audit import get
from ingestion.audit.parser import parse_events

NOW = datetime.fromtimestamp(1792886500, timezone.utc)
HEALTH = {'boot_id': '00000000-0000-0000-0000-000000000001'}


def raw(text):
    lines = []
    for line in text.splitlines():
        if line.startswith(('type=', 'node=')):
            lines.append(line)
    return '\n'.join(lines) + '\n'


def write_log(path, text):
    path.write_text(text)
    path.chmod(0o600)


@pytest.fixture
def source(tmp_path, monkeypatch, event_text):
    monkeypatch.setattr(get, 'LOG_OWNER', os.getuid())
    logfile = tmp_path / 'audit.log'
    write_log(logfile, raw(event_text()))
    return logfile


def read(logfile, checkpoint=None, **kwargs):
    return get.read_log_batch(logfile=logfile, checkpoint=checkpoint, source_id='7', health=HEALTH, now=NOW, **kwargs)


def test_position_resume_and_delayed_old_timestamp(source, event_text):
    first = read(source)
    assert len(parse_events(first['output'])['events']) == 1
    assert first['checkpoint']['offset'] == source.stat().st_size
    assert first['checkpoint']['fingerprint'] == hashlib.sha256(source.read_bytes()[-256:]).hexdigest()
    assert read(source, first['checkpoint'])['output'] == ''
    with source.open('a') as output:
        output.write(raw(event_text('/etc/shadow', serial=13, seconds=1792886000)))
    second = read(source, first['checkpoint'])
    assert parse_events(second['output'])['events'][0]['targets'] == ['shadow']


def test_rotation_and_disappeared_history(source, event_text):
    first = read(source)['checkpoint']
    rotated = source.with_name('audit.log.1')
    source.rename(rotated)
    write_log(source, raw(event_text('/etc/sudoers.d/new', serial=13)))
    assert parse_events(read(source, first)['output'])['events'][0]['targets'] == ['sudoers']
    rotated.unlink()
    with pytest.raises(RuntimeError, match='disappeared'):
        read(source, first)


@pytest.mark.parametrize('kind', ['truncate', 'regrow', 'gap', 'link'])
def test_corrupt_or_unsafe_history_rejected(source, kind):
    checkpoint = read(source)['checkpoint']
    if kind == 'truncate':
        source.write_text('')
    elif kind == 'regrow':
        source.write_bytes(b'x' * (checkpoint['offset'] + 10))
    elif kind == 'gap':
        source.rename(source.with_name('audit.log.3'))
        write_log(source.with_name('audit.log.1'), '')
        write_log(source, '')
    else:
        original = source.with_name('original')
        source.rename(original)
        source.symlink_to(original)
    with pytest.raises((ValueError, RuntimeError)):
        read(source, checkpoint)


def test_event_spanning_rotations(source, event_text):
    lines = raw(event_text()).splitlines(True)
    write_log(source.with_name('audit.log.1'), ''.join(lines[:2]))
    source.write_text(''.join(lines[2:]))
    batch = read(source)
    assert len(parse_events(batch['output'])['events']) == 1


def test_recent_incomplete_group_is_replayed(source, event_text):
    text = raw(event_text(seconds=int(NOW.timestamp()) - 2))
    lines = text.splitlines(True)
    partial_lines = []
    path_line = None
    for line in lines:
        if 'type=PATH' in line:
            path_line = line
        else:
            partial_lines.append(line)
    write_log(source, ''.join(partial_lines))
    batch = read(source)
    assert batch['pending'] and batch['output'] == '' and batch['checkpoint']['offset'] == 0
    assert path_line is not None
    with source.open('a') as output:
        output.write(path_line)
    complete = get.read_log_batch(logfile=source, checkpoint=batch['checkpoint'], source_id='7', health=HEALTH,
                                  now=NOW + timedelta(seconds=20))
    assert len(parse_events(complete['output'])['events']) == 1


def test_old_incomplete_and_malformed_records_fail(source):
    source.write_text('type=PATH msg=audit(1792886390.123:12): item=0 name="/etc/passwd"\n')
    with pytest.raises(ValueError, match='incomplete historical'):
        read(source)
    source.write_text('SECRET malformed record\n')
    with pytest.raises(ValueError) as error:
        read(source)
    assert 'SECRET' not in str(error.value)


def test_interleaved_recent_group_keeps_earlier_group_before_cursor(source, event_text):
    old = raw(event_text()).splitlines(True)
    recent = raw(event_text(serial=13, seconds=int(NOW.timestamp()) - 2)).splitlines(True)
    source.write_text(old[0] + recent[0] + ''.join(old[1:] + recent[1:]))
    batch = read(source)
    assert batch['pending'] and batch['checkpoint']['offset'] == 0 and batch['output'] == ''


def test_output_budget_and_empty_source(source, event_text):
    source.write_text('')
    assert read(source)['checkpoint']['offset'] == 0
    filler = 'type=PROCTITLE msg=audit(1792886390.123:12): proctitle=' + 'ab' * 20000 + '\n'
    source.write_text(raw(event_text()) + filler * 5)
    batch = read(source, max_bytes=65536)
    assert batch['limited'] and batch['bytes_read'] <= 65536
    assert batch['checkpoint']['offset'] < source.stat().st_size


@pytest.mark.parametrize('mask', [0o000, 0o002, 0o077])
def test_safe_fixture_permissions_do_not_depend_on_umask(source, event_text, mask):
    previous_mask = os.umask(mask)
    try:
        source.unlink()
        write_log(source, raw(event_text()))
        first = read(source)['checkpoint']
        rotated = source.with_name('audit.log.1')
        source.rename(rotated)
        write_log(source, raw(event_text(serial=13)))
        batch = read(source, first)
    finally:
        os.umask(previous_mask)
    assert source.stat().st_mode & 0o777 == 0o600
    assert rotated.stat().st_mode & 0o777 == 0o600
    assert len(parse_events(batch['output'])['events']) == 1


@pytest.mark.parametrize('mode', [0o620, 0o602])
def test_writable_audit_logs_are_still_rejected(source, mode):
    source.chmod(mode)
    with pytest.raises(ValueError, match='Unsafe Audit log'):
        read(source)


@pytest.mark.parametrize('resumed', [False, True])
@pytest.mark.parametrize('larger', [False, True])
def test_log_rewritten_during_parsing_is_rejected(source, event_text, monkeypatch, resumed, larger):
    original = source.read_text()
    checkpoint = None
    replacement = raw(event_text(serial=14))
    if resumed:
        checkpoint = read(source)['checkpoint']
        source.write_text(original + raw(event_text(serial=13)))
        replacement = original + replacement
    if larger:
        replacement += raw(event_text(serial=15))
    inode = source.stat().st_ino
    parse = get.parse_events
    rewritten = False

    def rewrite_then_parse(*args, **kwargs):
        nonlocal rewritten
        if not rewritten:
            source.write_text(replacement)
            rewritten = True
        return parse(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(get, 'parse_events', rewrite_then_parse)
        with pytest.raises(RuntimeError, match='Audit log bytes changed'):
            read(source, checkpoint)
    assert source.stat().st_ino == inode
    events = parse_events(read(source, checkpoint)['output'])['events']
    serials = []
    for event in events:
        serials.append(event['serial'])
    expected = [14]
    if larger:
        expected.append(15)
    assert serials == expected


def test_rewritten_earlier_bytes_are_rejected_even_with_unchanged_tail(source, event_text, monkeypatch):
    original = raw(event_text(serial=12)) + raw(event_text(serial=13))
    replacement = raw(event_text(serial=14)) + raw(event_text(serial=13))
    source.write_text(original)
    assert original[-256:] == replacement[-256:]
    parse = get.parse_events

    def rewrite_then_parse(*args, **kwargs):
        source.write_text(replacement)
        return parse(*args, **kwargs)

    monkeypatch.setattr(get, 'parse_events', rewrite_then_parse)
    with pytest.raises(RuntimeError, match='Audit log bytes changed'):
        read(source)


def test_rotated_file_rewrite_is_rejected_when_checkpoint_is_in_active_file(source, event_text, monkeypatch):
    rotated = source.with_name('audit.log.1')
    source.rename(rotated)
    write_log(source, raw(event_text(serial=13)))
    parse = get.parse_events

    def rewrite_then_parse(*args, **kwargs):
        rotated.write_text(raw(event_text(serial=14)))
        return parse(*args, **kwargs)

    monkeypatch.setattr(get, 'parse_events', rewrite_then_parse)
    with pytest.raises(RuntimeError, match='Audit log bytes changed'):
        read(source)


@pytest.mark.parametrize('change', ['append', 'rotate'])
def test_append_and_rename_rotation_during_parsing_remain_safe(source, event_text, monkeypatch, change):
    parse = get.parse_events
    changed = False

    def change_then_parse(*args, **kwargs):
        nonlocal changed
        if not changed:
            if change == 'rotate':
                source.rename(source.with_name('audit.log.1'))
                write_log(source, raw(event_text(serial=13)))
            else:
                with source.open('a') as output:
                    output.write(raw(event_text(serial=13)))
            changed = True
        return parse(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(get, 'parse_events', change_then_parse)
        first = read(source)
    assert parse_events(first['output'])['events'][0]['serial'] == 12
    second = read(source, first['checkpoint'])
    assert parse_events(second['output'])['events'][0]['serial'] == 13


def test_late_rewrite_cannot_replace_original_checkpoint_fingerprint(source, event_text, monkeypatch):
    fingerprint = hashlib.sha256(source.read_bytes()[-256:]).hexdigest()
    verify = get.verify_log_reads

    def verify_then_rewrite(*args):
        verify(*args)
        source.write_text(raw(event_text(serial=13)))

    with monkeypatch.context() as patch:
        patch.setattr(get, 'verify_log_reads', verify_then_rewrite)
        batch = read(source)
    assert batch['checkpoint']['fingerprint'] == fingerprint
    assert batch['checkpoint']['fingerprint'] != hashlib.sha256(source.read_bytes()[-256:]).hexdigest()
    with pytest.raises(RuntimeError, match='checkpoint bytes changed'):
        read(source, batch['checkpoint'])


@pytest.mark.parametrize('boundary', ['recent', 'event-limit'])
def test_checkpoint_fingerprint_matches_actual_safe_boundary(source, event_text, boundary):
    first = raw(event_text(serial=12))
    second_time = int(NOW.timestamp()) - 2
    limits = {}
    if boundary == 'event-limit':
        second_time = 1792886390
        limits['max_events'] = 1
    source.write_text(first + raw(event_text(serial=13, seconds=second_time)))
    batch = read(source, **limits)
    assert batch['checkpoint']['offset'] == len(first.encode('utf-8'))
    assert batch['checkpoint']['fingerprint'] == hashlib.sha256(first.encode('utf-8')[-256:]).hexdigest()
    assert parse_events(batch['output'])['events'][0]['serial'] == 12
