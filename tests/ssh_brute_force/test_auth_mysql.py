"""Opt-in private MySQL server; never read the project's database credentials."""

from datetime import datetime

import pymysql
import pytest

from detection.ssh_brute_force.detector import detect_ssh_brute_force
from ingestion.auth.collector import AUTH_WRITER_LOCK, collect_auth_events
from ingestion.auth.db import save_event
from ingestion.auth.parser import parse_auth_line


def line(index=0):
    return (f"2026-10-22T12:00:{index:02d}.123456Z server-a sshd[{100 + index}]: "
            f"Failed password for user{index} from 2001:db8::1 port 54321 ssh2\n")


def read_events(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT * FROM auth_events ORDER BY event_time, id")
        return cursor.fetchall()


def read_states(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT file_inode, last_position, position_hash FROM auth_ingestion_state ORDER BY file_inode")
        return cursor.fetchall()


def test_repeatable_migration_and_end_to_end_detection(mysql, tmp_path, apply_migration):
    apply_migration(mysql, "007_auth_events.sql")
    logfile = tmp_path / "auth.log"
    logfile.write_text("".join(line(i) for i in range(5)))
    assert collect_auth_events(mysql, logfile, collector_id="test") == {"inserted": 5, "skipped": 0}
    events = read_events(mysql)
    assert events[0]["event_time"] == datetime(2026, 10, 22, 12, 0, 0, 123456)
    result = detect_ssh_brute_force(events)
    assert len(result) == 1
    assert result[0]["failure_count"] == 5
    assert len(result[0]["evidence_ids"]) == 5
    assert collect_auth_events(mysql, logfile, collector_id="test")["inserted"] == 0
    assert len(read_events(mysql)) == 5


def test_append_and_partial_line(mysql, tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_text(line(0) + line(1).rstrip("\n"))
    assert collect_auth_events(mysql, logfile, collector_id="test")["inserted"] == 1
    assert read_states(mysql)[0][1] == len(line(0).encode())
    with logfile.open("a") as outfile:
        outfile.write("\n" + line(2))
    assert collect_auth_events(mysql, logfile, collector_id="test")["inserted"] == 2
    assert len(read_events(mysql)) == 3


def test_rename_rotation_drains_old_inode_and_new_file(mysql, tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_text(line(0))
    collect_auth_events(mysql, logfile, collector_id="test")
    with logfile.open("a") as outfile:
        outfile.write(line(1))
    logfile.rename(tmp_path / "auth.log.1")
    logfile.write_text(line(2))
    assert collect_auth_events(mysql, logfile, collector_id="test")["inserted"] == 2
    assert len(read_states(mysql)) == 2
    assert len(read_events(mysql)) == 3


def test_copytruncate_and_regrow_past_old_position(mysql, tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_text(line(0))
    collect_auth_events(mysql, logfile, collector_id="test")
    (tmp_path / "auth.log.1").write_text(line(0))
    logfile.write_text(line(1) + line(2))
    assert collect_auth_events(mysql, logfile, collector_id="test")["inserted"] == 2
    assert len(read_events(mysql)) == 3


def test_changed_source_path_replay_does_not_duplicate(mysql, tmp_path):
    first = tmp_path / "auth.log"
    second = tmp_path / "other-auth.log"
    first.write_text(line(0))
    collect_auth_events(mysql, first, collector_id="test")
    second.write_text(line(0) + line(1))
    assert collect_auth_events(mysql, second, collector_id="test")["inserted"] == 1
    assert len(read_events(mysql)) == 2


def test_database_error_rolls_back_events_and_position_and_allows_retry(mysql, tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_text(line(0))
    collect_auth_events(mysql, logfile, collector_id="test")
    before = read_states(mysql)
    with logfile.open("a") as outfile:
        outfile.write(line(1) + line(2))
    with mysql.cursor() as cursor:
        cursor.execute("""
            CREATE TRIGGER fail_auth BEFORE INSERT ON auth_events FOR EACH ROW
            BEGIN
                IF NEW.username = 'user2' THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure';
                END IF;
            END
        """)
    with pytest.raises(pymysql.MySQLError):
        collect_auth_events(mysql, logfile, collector_id="test")
    assert len(read_events(mysql)) == 1
    assert read_states(mysql) == before
    with mysql.cursor() as cursor:
        cursor.execute("DROP TRIGGER fail_auth")
    assert collect_auth_events(mysql, logfile, collector_id="test")["inserted"] == 2
    assert len(read_events(mysql)) == 3


def test_duplicate_hash_unique_constraint(mysql):
    event = parse_auth_line(line())
    with mysql.cursor() as cursor:
        assert save_event(cursor, event) == 1
        assert save_event(cursor, event) == 0
    mysql.commit()
    assert len(read_events(mysql)) == 1


def test_competing_collector_lock(mysql, private_server, tmp_path):
    lock_name = AUTH_WRITER_LOCK
    with (pymysql.connect(unix_socket=private_server, user="root") as other,
          other.cursor() as cursor):
        cursor.execute("SELECT GET_LOCK(%s, 0)", (lock_name,))
        assert cursor.fetchone() == (1,)
        with pytest.raises(RuntimeError, match="Another auth collector"):
            collect_auth_events(mysql, tmp_path / "auth.log", collector_id="test")
        cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
    assert not read_events(mysql)
