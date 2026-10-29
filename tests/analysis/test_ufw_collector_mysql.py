"""Real UFW transactions on the existing opt-in private test server only."""

from datetime import datetime, timedelta

import pymysql
import pytest

from database.migrate import migrate
from database.schema import ensure_tables, prepare_schema
from detection.port_scan.runner import run_automatic
from ingestion import ufw_to_mysql as ufw


def line(index):
    return (f"2026-10-22T12:00:{index:02d}Z host kernel: [UFW BLOCK] "
            f"SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT={1000 + index}\n").encode()


@pytest.fixture
def collection(mysql, monkeypatch, tmp_path):
    migrate(mysql)
    ensure_tables(mysql, ("ufw_state",))
    with mysql.cursor() as cursor:
        cursor.execute("SET time_zone = '+00:00'")
    logfile = tmp_path / "ufw.log"
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    return mysql, logfile


def state(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT filename, byte_position FROM ufw_file_checkpoints ORDER BY filename")
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
    assert first["inserted"] == first["lines_read"] == 3
    assert first["stop_reason"] == "line_limit"
    assert state(connection) == {str(oldest): len(line(0)) + len(line(1)), str(logfile): len(line(4))}
    assert events(connection) == [1004, 1000, 1001]
    assert ufw.process_log(connection, max_lines=3)["inserted"] == 3
    assert sorted(events(connection)) == list(range(1000, 1006))
    assert ufw.process_log(connection, max_lines=3)["inserted"] == 0
    assert sorted(events(connection)) == list(range(1000, 1006))


def test_continuous_appends_are_committed_one_snapshot_at_a_time(collection, monkeypatch):
    connection, logfile = collection
    logfile.write_bytes(line(0))
    from ingestion import ufw_records
    save = ufw_records.process_line
    count = [0]

    def save_and_append(cursor, value, *arguments, **options):
        inserted = save(cursor, value, *arguments, **options)
        count[0] += 1
        if count[0] < 4:
            with logfile.open("ab") as out:
                out.write(line(count[0]))
        return inserted

    monkeypatch.setattr(ufw_records, "process_line", save_and_append)
    for expected in range(1, 5):
        assert ufw.process_log(connection)["inserted"] == 1
        assert events(connection) == list(range(1000, 1000 + expected))
        assert state(connection)[str(logfile)] == sum(len(line(index)) for index in range(expected))
    assert ufw.process_log(connection)["inserted"] == 0


def test_time_budget_commits_progress_and_next_pass_finishes(collection, monkeypatch):
    connection, logfile = collection
    logfile.write_bytes(line(0) + line(1) + line(2))
    clock = [0.0]
    from ingestion import ufw_records
    save = ufw_records.process_line
    monkeypatch.setattr(ufw.time, "monotonic", lambda: clock[0])

    def save_and_expire(cursor, value, *arguments, **options):
        inserted = save(cursor, value, *arguments, **options)
        clock[0] += 0.8
        return inserted

    monkeypatch.setattr(ufw_records, "process_line", save_and_expire)
    for expected in range(1, 4):
        clock[0] = 0.0
        result = ufw.process_log(connection, max_seconds=1)
        assert result["inserted"] == result["lines_read"] == 1
        if expected < 3:
            assert result["stop_reason"] == "time_limit"
        else:
            assert result["stop_reason"] == "snapshot_end"
        assert len(events(connection)) == expected
        assert state(connection)[str(logfile)] == sum(len(line(index)) for index in range(expected))


def test_partial_line_completed_after_snapshot_waits_for_next_pass(collection, monkeypatch):
    connection, logfile = collection
    logfile.write_bytes(line(0) + line(1)[:-1])
    from ingestion import ufw_records
    save = ufw_records.process_line

    def save_and_complete(cursor, value, *arguments, **options):
        inserted = save(cursor, value, *arguments, **options)
        with logfile.open("ab") as out:
            out.write(b"\n")
        return inserted

    monkeypatch.setattr(ufw_records, "process_line", save_and_complete)
    assert ufw.process_log(connection)["inserted"] == 1
    assert state(connection)[str(logfile)] == len(line(0))
    monkeypatch.setattr(ufw_records, "process_line", save)
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


def test_nul_recovery_deduplicates_and_commits_original_byte_offset(collection):
    connection, logfile = collection
    clean = line(0).replace(b'12:00:00Z ', b'12:00:00+02:00 ')
    raw = clean + b"\x00" * 3000 + clean
    logfile.write_bytes(raw)
    assert ufw.process_log(connection)['inserted'] == 1
    assert state(connection)[str(logfile)] == len(raw)
    with connection.cursor() as cursor:
        cursor.execute('SELECT event_time,raw_line FROM ufw_log')
        assert cursor.fetchall() == ((datetime(2026, 10, 22, 10, 0), clean.decode().strip()),)
    assert ufw.process_log(connection)['inserted'] == 0
    before = state(connection)
    with logfile.open('ab') as output:
        output.write(clean.replace(b'12:00:00', b'12:00:01'))
        output.write(b'\x00' * 3000 + b'bad host [UFW BLOCK]\n')
    result = ufw.process_log(connection)
    assert result['inserted'] == 1
    assert result['quarantined'] == 1
    assert state(connection)[str(logfile)] == logfile.stat().st_size
    assert state(connection) != before
    assert events(connection) == [1000, 1000]
