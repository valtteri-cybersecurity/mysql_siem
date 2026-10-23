"""File/state and transaction behavior without a database server."""

from unittest.mock import MagicMock

import pymysql
import pytest

from ingestion.auth.collector import (
    collect_auth_events,
    get_logfiles,
    position_hash,
    process_file,
)
from ingestion.auth.db import save_event
from ingestion.auth.parser import parse_auth_line

LINE = b"2026-10-22T12:00:00Z server-a sshd[12]: Failed password for alice from 192.0.2.1 port 22 ssh2\n"


def test_duplicate_event_only_suppresses_duplicate_key_error():
    cursor = MagicMock()
    event = parse_auth_line(LINE.decode())
    assert save_event(cursor, event) == 1
    cursor.execute.side_effect = pymysql.IntegrityError(1062, "duplicate")
    assert save_event(cursor, event) == 0
    cursor.execute.side_effect = pymysql.IntegrityError(1048, "not null")
    with pytest.raises(pymysql.IntegrityError):
        save_event(cursor, event)
    cursor.execute.side_effect = RuntimeError("programming bug")
    with pytest.raises(RuntimeError, match="programming bug"):
        save_event(cursor, event)


def test_partial_line_waits_for_next_run(tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE + LINE[:-1])
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    assert process_file(cursor, str(logfile), "collector") == (1, 0)
    assert cursor.execute.call_args_list[-1].args[1][4] == len(LINE)


def test_resumes_position_and_reads_only_new_complete_lines(tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE * 2)
    with logfile.open("rb") as infile:
        digest = position_hash(infile, len(LINE))
    cursor = MagicMock()
    cursor.fetchone.return_value = (len(LINE), digest)
    assert process_file(cursor, str(logfile), "collector") == (1, 0)
    assert cursor.execute.call_args_list[-1].args[1][4] == len(LINE) * 2


def test_rotations_are_read_oldest_first_and_compressed_files_excluded(tmp_path):
    logfile = tmp_path / "auth.log"
    for suffix in ("", ".1", ".2", ".10", ".3.gz", ".backup"):
        (tmp_path / ("auth.log" + suffix)).touch()
    assert get_logfiles(str(logfile)) == [str(logfile) + suffix for suffix in (".10", ".2", ".1", "")]


def test_invalid_bytes_and_lines_do_not_stop_collection(tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(b"\xff\ninvalid\n" + LINE)
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    assert process_file(cursor, str(logfile), "collector") == (1, 2)


@pytest.mark.parametrize("previous_position,digest", [(10000, "a" * 64), (1, "b" * 64)])
def test_truncation_or_changed_checkpoint_restarts_file(tmp_path, previous_position, digest):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE)
    cursor = MagicMock()
    cursor.fetchone.return_value = (previous_position, digest)
    assert process_file(cursor, str(logfile), "collector") == (1, 0)


def test_database_failure_rolls_back_and_releases_lock(tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE)
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.fetchone.side_effect = [(1,), None]

    def fail_insert(sql, values):
        if "INSERT INTO auth_events" in sql:
            raise pymysql.OperationalError(2013, "connection lost")

    cursor.execute.side_effect = fail_insert
    with pytest.raises(pymysql.OperationalError):
        collect_auth_events(connection, str(logfile), collector_id="collector")
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()
    assert "RELEASE_LOCK" in cursor.execute.call_args.args[0]
    assert not any("INSERT INTO auth_ingestion_state" in call.args[0] for call in cursor.execute.call_args_list)
    cursor.close.assert_called_once()


def test_busy_lock_does_not_read_or_release_another_collectors_lock(tmp_path):
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.fetchone.return_value = (0,)
    with pytest.raises(RuntimeError, match="Another auth collector"):
        collect_auth_events(connection, tmp_path / "missing.log", collector_id="collector")
    connection.commit.assert_not_called()
    connection.begin.assert_not_called()
    assert len(cursor.execute.call_args_list) == 1


def test_missing_active_log_does_not_commit_progress(tmp_path):
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = (1,)
    with pytest.raises(FileNotFoundError):
        collect_auth_events(connection, tmp_path / "missing.log", collector_id="collector")
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


@pytest.mark.parametrize("collector_id", [None, "", "  ", [], "a" * 256, " " * 255 + "x"])
def test_invalid_collector_id_fails_before_database_access(collector_id):
    connection = MagicMock()
    with pytest.raises(ValueError, match="collector_id"):
        collect_auth_events(connection, collector_id=collector_id)
    connection.cursor.assert_not_called()


def test_rotation_disappearing_between_listing_and_open_is_safe(tmp_path, monkeypatch):
    logfile = tmp_path / "auth.log"
    logfile.write_bytes(LINE)
    connection = MagicMock()
    connection.cursor.return_value.fetchone.side_effect = [(1,), None]
    monkeypatch.setattr("ingestion.auth.collector.get_logfiles",
                        lambda _: [str(logfile) + ".1", str(logfile)])
    assert collect_auth_events(connection, logfile, collector_id="test")["inserted"] == 1
    connection.commit.assert_called_once()


@pytest.mark.parametrize("process", ["sshd-session", "sshd-auth"])
def test_new_openssh_failures_are_collected_and_detected(tmp_path, process, monkeypatch):
    from detection.ssh_brute_force.detector import detect_ssh_brute_force

    logfile = tmp_path / "auth.log"
    lines = []
    for pid in range(1, 6):
        line = LINE.decode().replace("sshd[12]", f"{process}[{pid}]")
        lines.append(line)
    logfile.write_text("".join(lines))
    events = []

    def capture_event(cursor, event, *, identity=None):
        events.append(event)
        return 1

    monkeypatch.setattr("ingestion.auth.collector.save_event", capture_event)
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    assert process_file(cursor, str(logfile), "local-debian") == (5, 0)
    assert cursor.execute.call_args_list[-1].args[1][4] == logfile.stat().st_size
    assert detect_ssh_brute_force(events)[0]["failure_count"] == 5
