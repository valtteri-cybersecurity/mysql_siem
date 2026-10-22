"""Real UFW transactions on the existing opt-in private test server only."""

from datetime import datetime, timedelta

import pymysql
import pytest

from database.schema import ensure_tables, prepare_schema
from detection.port_scan.runner import run_automatic
from ingestion import ufw_to_mysql as ufw


def line(index):
    return (f"2026-10-22T12:00:{index:02d} host kernel: [UFW BLOCK] "
            f"SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT={1000 + index}\n").encode()


@pytest.fixture
def collection(mysql, monkeypatch, tmp_path):
    ensure_tables(mysql, ("ufw_state",))
    with mysql.cursor() as cursor:
        cursor.execute("SET time_zone = '+00:00'")
    logfile = tmp_path / "ufw.log"
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    return mysql, logfile


def state(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT logfile, last_position FROM ufw_state ORDER BY logfile")
        return dict(cursor.fetchall())


def events(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT dst_port FROM ufw_log ORDER BY id")
        return [row[0] for row in cursor.fetchall()]


def test_bounded_passes_resume_all_rotations_without_duplicates_or_gaps(collection):
    connection, logfile = collection
    oldest = logfile.with_name("ufw.log.2")
    newer = logfile.with_name("ufw.log.1")
    oldest.write_bytes(line(0) + line(1))
    newer.write_bytes(line(2) + line(3))
    logfile.write_bytes(line(4) + line(5))
    first = ufw.process_log(connection, max_lines=3)
    assert first == {"inserted": 3, "lines_read": 3, "stop_reason": "line_limit"}
    assert state(connection) == {str(oldest): len(line(0)) + len(line(1)), str(newer): len(line(2))}
    assert events(connection) == [1000, 1001, 1002]
    assert ufw.process_log(connection, max_lines=3)["inserted"] == 3
    assert events(connection) == list(range(1000, 1006))
    assert ufw.process_log(connection, max_lines=3)["inserted"] == 0
    assert events(connection) == list(range(1000, 1006))


def test_continuous_appends_are_committed_one_snapshot_at_a_time(collection, monkeypatch):
    connection, logfile = collection
    logfile.write_bytes(line(0))
    save = ufw.save_event
    count = [0]

    def save_and_append(cursor, value):
        inserted = save(cursor, value)
        count[0] += 1
        if count[0] < 4:
            with logfile.open("ab") as out:
                out.write(line(count[0]))
        return inserted

    monkeypatch.setattr(ufw, "save_event", save_and_append)
    for expected in range(1, 5):
        assert ufw.process_log(connection)["inserted"] == 1
        assert events(connection) == list(range(1000, 1000 + expected))
        assert state(connection)[str(logfile)] == sum(len(line(index)) for index in range(expected))
    assert ufw.process_log(connection)["inserted"] == 0


def test_time_budget_commits_progress_and_next_pass_finishes(collection, monkeypatch):
    connection, logfile = collection
    logfile.write_bytes(line(0) + line(1) + line(2))
    clock = [0.0]
    save = ufw.save_event
    monkeypatch.setattr(ufw.time, "monotonic", lambda: clock[0])

    def save_and_expire(cursor, value):
        inserted = save(cursor, value)
        clock[0] += 2.0
        return inserted

    monkeypatch.setattr(ufw, "save_event", save_and_expire)
    for expected in range(1, 4):
        result = ufw.process_log(connection, max_seconds=1)
        assert result == {"inserted": 1, "lines_read": 1, "stop_reason": "time_limit"}
        assert len(events(connection)) == expected
        assert state(connection)[str(logfile)] == sum(len(line(index)) for index in range(expected))


def test_partial_line_completed_after_snapshot_waits_for_next_pass(collection, monkeypatch):
    connection, logfile = collection
    logfile.write_bytes(line(0) + line(1)[:-1])
    save = ufw.save_event

    def save_and_complete(cursor, value):
        inserted = save(cursor, value)
        with logfile.open("ab") as out:
            out.write(b"\n")
        return inserted

    monkeypatch.setattr(ufw, "save_event", save_and_complete)
    assert ufw.process_log(connection)["inserted"] == 1
    assert state(connection)[str(logfile)] == len(line(0))
    monkeypatch.setattr(ufw, "save_event", save)
    assert ufw.process_log(connection)["inserted"] == 1
    assert events(connection) == [1000, 1001]


def test_database_failure_rolls_back_all_files_and_preserves_prior_commit(collection):
    connection, logfile = collection
    logfile.write_bytes(line(0))
    ufw.process_log(connection)
    before = state(connection)
    with logfile.open("ab") as out:
        out.write(line(1) + line(2))
    with connection.cursor() as cursor:
        cursor.execute("""CREATE TRIGGER reject_ufw BEFORE INSERT ON ufw_log FOR EACH ROW
            BEGIN
                IF NEW.dst_port = 1002 THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure';
                END IF;
            END""")
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(connection, max_lines=3)
    assert state(connection) == before
    assert events(connection) == [1000]
    with connection.cursor() as cursor:
        cursor.execute("SELECT IS_FREE_LOCK(%s)", (ufw.LOCK_NAME,))
        assert cursor.fetchone() == (1,)
        cursor.execute("DROP TRIGGER reject_ufw")
    assert ufw.process_log(connection)["inserted"] == 2
    assert events(connection) == [1000, 1001, 1002]


def test_read_failure_in_later_file_rolls_back_earlier_file(collection):
    connection, logfile = collection
    logfile.with_name("ufw.log.1").write_bytes(line(0))
    logfile.write_bytes(b"x" * (ufw.MAX_LINE_BYTES + 1) + b"\n")
    with pytest.raises(RuntimeError, match="read limit"):
        ufw.process_log(connection)
    assert events(connection) == [] and state(connection) == {}


def test_busy_writer_lock_leaves_data_and_positions_unchanged(collection, analysis_private_server):
    connection, logfile = collection
    logfile.write_bytes(line(0))
    other = pymysql.connect(unix_socket=analysis_private_server, user="root")
    try:
        with other.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (ufw.LOCK_NAME,))
            assert cursor.fetchone() == (1,)
        with pytest.raises(RuntimeError, match="Another UFW collector"):
            ufw.process_log(connection)
        assert events(connection) == [] and state(connection) == {}
    finally:
        other.close()


def test_each_commit_is_visible_to_port_scan_detection_between_collection_passes(collection, analysis_private_server):
    connection, logfile = collection
    prepare_schema(connection, "detection")
    logfile.write_bytes(b"".join(line(index) for index in range(10)))
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        name = cursor.fetchone()[0]
    observer = pymysql.connect(unix_socket=analysis_private_server, user="root", database=name, autocommit=False)
    try:
        config = {"batch_size": 100, "max_buffer_events": 100, "late_seconds": 600}
        now = datetime(2026, 10, 22, 12, 1)
        assert ufw.process_log(connection, max_lines=5)["inserted"] == 5
        first = run_automatic(observer, config, now=now)
        assert first["new_events_fetched"] == 5 and first["scans_detected"] == 0
        assert ufw.process_log(connection, max_lines=5)["inserted"] == 5
        second = run_automatic(observer, config, now=now + timedelta(minutes=1))
        assert second["new_events_fetched"] == 5
        assert second["scans_detected"] == second["new_alerts_saved"] == 1
        with observer.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM alert_evidence")
            assert cursor.fetchone() == (10,)
    finally:
        observer.close()
