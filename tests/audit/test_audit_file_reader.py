import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from ingestion.audit import get
from ingestion.audit.parser import parse_events

NOW = datetime.fromtimestamp(1792886500, timezone.utc)
HEALTH = {'boot_id': '00000000-0000-0000-0000-000000000001'}


def raw(text):
    return '\n'.join(line for line in text.splitlines() if line.startswith(('type=', 'node='))) + '\n'


@pytest.fixture
def source(tmp_path, monkeypatch, event_text):
    monkeypatch.setattr(get, 'LOG_OWNER', os.getuid())
    logfile = tmp_path / 'audit.log'
    logfile.write_text(raw(event_text()))
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
    source.write_text(raw(event_text('/etc/sudoers.d/new', serial=13)))
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
        source.with_name('audit.log.1').write_text('')
        source.write_text('')
    else:
        original = source.with_name('original')
        source.rename(original)
        source.symlink_to(original)
    with pytest.raises((ValueError, RuntimeError)):
        read(source, checkpoint)


def test_event_spanning_rotations(source, event_text):
    lines = raw(event_text()).splitlines(True)
    source.with_name('audit.log.1').write_text(''.join(lines[:2]))
    source.write_text(''.join(lines[2:]))
    batch = read(source)
    assert len(parse_events(batch['output'])['events']) == 1


def test_recent_incomplete_group_is_replayed(source, event_text):
    text = raw(event_text(seconds=int(NOW.timestamp()) - 2))
    lines = text.splitlines(True)
    source.write_text(''.join(line for line in lines if 'type=PATH' not in line))
    batch = read(source)
    assert batch['pending'] and batch['output'] == '' and batch['checkpoint']['offset'] == 0
    with source.open('a') as output:
        output.write(next(line for line in lines if 'type=PATH' in line))
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
