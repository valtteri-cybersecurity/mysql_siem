"""Savepoint isolation with real event inserts and persistent file checkpoints."""
import pymysql
import pytest

from ingestion import ufw_continuity as continuity
from ingestion import ufw_to_mysql as ufw


def line(port):
    return ('2026-11-05T12:00:00Z host [UFW BLOCK] SRC=192.0.2.1 '
            'DST=198.51.100.1 PROTO=TCP DPT=' + str(port) + '\n').encode()


def ports(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT dst_port FROM ufw_log ORDER BY id')
        return cursor.fetchall()


def checkpoints(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ufw_file_checkpoints ORDER BY id')
        return cursor.fetchall()


def test_rotation_io_failure_keeps_active_commit_but_sql_failure_rolls_back_all(mysql, tmp_path, monkeypatch):
    active = tmp_path / 'ufw.log'
    rotation = tmp_path / 'ufw.log.2'
    active.write_bytes(line(1000))
    rotation.write_bytes(line(2000))
    monkeypatch.setattr(ufw, 'LOGFILE', str(active))
    assert ufw.process_log(mysql)['inserted'] == 2
    previous = checkpoints(mysql)
    with active.open('ab') as output:
        output.write(line(1001))
    with rotation.open('ab') as output:
        output.write(line(2001))
    original = continuity.finish
    def fail_after_insert(cursor, source, filename, *args, **kwargs):
        if filename == str(rotation):
            raise PermissionError('synthetic I/O failure after batch INSERT')
        return original(cursor, source, filename, *args, **kwargs)
    with monkeypatch.context() as failure:
        failure.setattr(continuity, 'finish', fail_after_insert)
        result = ufw.process_log(mysql)
    assert result['status'] == 'FAILED'
    assert result['inserted'] == result['lines_read'] == 1
    assert result['source_errors'] == 1
    assert result['active_state'] == 'HEALTHY'
    assert result['collection_state'] == 'GAP_DETECTED'
    assert ports(mysql) == ((1000,), (2000,), (1001,))
    assert checkpoints(mysql)[1] == previous[1]
    with mysql.cursor() as cursor:
        cursor.execute("SELECT checkpoint_id,resolved FROM ufw_collection_gaps WHERE reason='SOURCE_UNAVAILABLE'")
        assert cursor.fetchall() == ((previous[1][0], 0),)
    assert ufw.process_log(mysql)['inserted'] == 1
    assert ports(mysql) == ((1000,), (2000,), (1001,), (2001,))
    original_events = ports(mysql)
    original_checkpoints = checkpoints(mysql)
    with active.open('ab') as output:
        output.write(line(1002))
    with rotation.open('ab') as output:
        output.write(line(2002))
    with mysql.cursor() as cursor:
        cursor.execute("CREATE TRIGGER reject_rotation BEFORE INSERT ON ufw_log FOR EACH ROW "
                       "BEGIN IF NEW.dst_port=2002 THEN SIGNAL SQLSTATE '45000' "
                       "SET MESSAGE_TEXT='synthetic database failure'; END IF; END")
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(mysql)
    assert ports(mysql) == original_events
    assert checkpoints(mysql) == original_checkpoints
    with mysql.cursor() as cursor:
        cursor.execute('DROP TRIGGER reject_rotation')
    assert ufw.process_log(mysql)['inserted'] == 2
    assert len(ports(mysql)) == 6
