"""Concurrent append progress and rewrite rollback on private MySQL."""
import hashlib

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw


def line(index):
    return ('2026-11-05T12:00:00Z host [UFW BLOCK] SRC=192.0.2.1 '
            'DST=198.51.100.1 PROTO=TCP DPT=' + str(1000 + index) + '\n').encode()


def checkpoints(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ufw_file_checkpoints ORDER BY id')
        return cursor.fetchall()


def events(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,event_time,event_hash,raw_line FROM ufw_log ORDER BY id')
        return cursor.fetchall()


def test_growth_during_verification_commits_progress_and_rewrite_rolls_back(mysql, tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    path.write_bytes(line(0))
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    original = continuity.digest_prefixes
    calls = [0]
    next_line = [1]
    def append(source, sizes, deadline):
        result = original(source, sizes, deadline)
        calls[0] += 1
        if calls[0] == 2:
            with path.open('ab') as output:
                output.write(line(next_line[0]))
            next_line[0] += 1
        return result
    generation = None
    with monkeypatch.context() as growing:
        growing.setattr(continuity, 'digest_prefixes', append)
        for _attempt in range(3):
            calls[0] = 0
            snapshot = path.read_bytes()
            result = ufw.process_log(mysql)
            assert result['inserted'] == 1
            assert result['status'] == 'SUCCESS'
            assert result['active_state'] == result['collection_state'] == 'BACKLOG'
            assert calls[0] == 3
            with mysql.cursor() as cursor:
                cursor.execute('SELECT byte_position,prefix_sha,generation_key FROM ufw_file_checkpoints')
                position, digest, current_generation = cursor.fetchone()
                assert position == len(snapshot)
                assert digest == hashlib.sha256(snapshot).hexdigest()
            if generation is None:
                generation = current_generation
            assert current_generation == generation
    assert ufw.process_log(mysql)['inserted'] == 1
    assert ufw.process_log(mysql)['inserted'] == 0
    before_events = events(mysql)
    before_checkpoints = checkpoints(mysql)
    assert len(before_events) == next_line[0] == 4
    with path.open('ab') as output:
        output.write(line(next_line[0]))
    calls[0] = 0
    def rewrite_and_append(source, sizes, deadline):
        result = original(source, sizes, deadline)
        calls[0] += 1
        if calls[0] == 2:
            with path.open('ab') as output:
                output.write(b'first concurrent append\n')
        elif calls[0] == 3:
            with path.open('r+b') as output:
                output.write(b'X')
            with path.open('ab') as output:
                output.write(b'another line\n')
        return result
    with monkeypatch.context() as damaged:
        damaged.setattr(continuity, 'digest_prefixes', rewrite_and_append)
        result = ufw.process_log(mysql)
        assert result['status'] == 'FAILED'
        assert result['stop_reason'] == 'verification_time_limit'
        assert calls[0] == 3
    assert events(mysql) == before_events
    assert checkpoints(mysql) == before_checkpoints
