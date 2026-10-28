"""Bounded UFW passes with synthetic files and no collection database access."""

from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from ingestion import ufw_to_mysql as ufw


def line(index=0):
    return (
        f"2026-10-22T12:00:{index:02d}.123456+03:00 host kernel: [UFW BLOCK] "
        f"SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT={1000 + index}\n"
    ).encode()

def cursor_at(position=None):
    cursor = MagicMock()
    cursor.fetchone.return_value = None if position is None else (position,)
    cursor.rowcount = 1
    return cursor


def saved_position(cursor):
    writes = [call.args[1] for call in cursor.execute.call_args_list if "INSERT INTO ufw_state" in call.args[0]]
    return writes[-1][1]


def connection_for_files():
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.rowcount = 1
    # Only GET_LOCK and position reads call fetchone; RELEASE_LOCK has no read.
    cursor.fetchone.side_effect = [(1,)] + [None] * 20
    return connection


def test_growing_log_stops_at_initial_size_and_resumes_next_pass(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line())
    seen = []

    def save(cursor, value, *, identity=None):
        seen.append(value)
        if len(seen) <= 3:
            with logfile.open("ab") as out:
                out.write(line(len(seen)))
        return 1

    monkeypatch.setattr(ufw, "save_event", save)
    cursor = cursor_at()
    assert ufw.process_file(cursor, str(logfile)) == 1
    assert saved_position(cursor) == len(line())
    cursor.fetchone.return_value = (saved_position(cursor),)
    assert ufw.process_file(cursor, str(logfile)) == 1
    assert saved_position(cursor) == len(line()) + len(line(1))
    assert seen == [line().decode(), line(1).decode()]
    assert logfile.read_bytes() == line() + line(1) + line(2)


def test_newline_appended_during_pass_does_not_complete_snapshot_partial_line(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line() + line(1).rstrip(b"\n"))
    seen = []

    def save(cursor, value, *, identity=None):
        seen.append(value)
        if len(seen) == 1:
            with logfile.open("ab") as out:
                out.write(b"\n")
        return 1

    monkeypatch.setattr(ufw, "save_event", save)
    cursor = cursor_at()
    assert ufw.process_file(cursor, str(logfile)) == 1
    assert saved_position(cursor) == len(line())
    cursor.fetchone.return_value = (saved_position(cursor),)
    assert ufw.process_file(cursor, str(logfile)) == 1
    assert seen == [line().decode(), line(1).decode()]


def test_partial_line_keeps_its_start_for_next_pass(tmp_path):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line() + line(1)[:-1])
    cursor = cursor_at()
    assert ufw.process_file(cursor, str(logfile)) == 1
    assert saved_position(cursor) == len(line())


def test_line_budget_counts_blank_and_duplicate_lines(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(b"\n" + line() + line(1))
    monkeypatch.setattr(ufw, "save_event", Mock(return_value=0))
    cursor = cursor_at()
    stats = {"lines_read": 0, "stop_reason": "snapshot_end"}
    assert ufw.process_file(cursor, str(logfile), stats=stats, max_lines=2) == 0
    assert stats == {"lines_read": 2, "stop_reason": "line_limit"}
    assert saved_position(cursor) == 1 + len(line())


def test_single_line_read_is_bounded_and_does_not_advance_state_on_failure(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(b"x" * 65 + b"\n")
    monkeypatch.setattr(ufw, "MAX_LINE_BYTES", 64)
    cursor = cursor_at()
    with pytest.raises(RuntimeError, match="read limit"):
        ufw.process_file(cursor, str(logfile))
    assert not any("INSERT" in call.args[0] for call in cursor.execute.call_args_list)


def test_rotations_are_numeric_oldest_first_and_glob_path_is_literal(tmp_path, monkeypatch):
    folder = tmp_path / "logs[1]"
    folder.mkdir()
    logfile = folder / "ufw.log"
    for suffix in ("", ".1", ".2", ".10", ".3.gz", ".backup", ".\u00b2"):
        (folder / ("ufw.log" + suffix)).touch()
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    assert ufw.get_logfiles() == [str(logfile) + suffix for suffix in (".10", ".2", ".1", "")]


def test_line_limit_is_shared_across_all_files_and_commits_before_unlock(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line(2) + line(3))
    (tmp_path / "ufw.log.1").write_bytes(line() + line(1))
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    connection = connection_for_files()
    result = ufw.process_log(connection, max_lines=3)
    assert result == {"inserted": 3, "lines_read": 3, "stop_reason": "line_limit"}
    writes = [call.args[1] for call in connection.cursor.return_value.execute.call_args_list
              if "INSERT INTO ufw_state" in call.args[0]]
    assert [(row[0], row[1]) for row in writes] == [
        (str(logfile) + ".1", len(line()) + len(line(1))), (str(logfile), len(line(2)))]
    connection.begin.assert_called_once()
    connection.commit.assert_called_once()
    assert not connection.rollback.called
    calls = connection.mock_calls
    commit = next(index for index, call in enumerate(calls) if call == ("commit", (), {}))
    release = next(index for index, call in enumerate(calls) if call[0] == "cursor().execute" and "RELEASE_LOCK" in call.args[0])
    assert commit < release


def test_time_limit_is_shared_and_commits_processed_lines(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line(2))
    (tmp_path / "ufw.log.1").write_bytes(line() + line(1))
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    clock = [0.0]
    monkeypatch.setattr(ufw.time, "monotonic", lambda: clock[0])
    seen = []

    def save(cursor, value, *, identity=None):
        seen.append(value)
        clock[0] = 2.0
        return 1

    monkeypatch.setattr(ufw, "save_event", save)
    connection = connection_for_files()
    result = ufw.process_log(connection, max_seconds=1)
    assert result == {"inserted": 1, "lines_read": 1, "stop_reason": "time_limit"}
    assert seen == [line().decode()]
    assert saved_position(connection.cursor.return_value) == len(line())
    connection.commit.assert_called_once()


def test_expired_budget_does_not_open_another_file(monkeypatch):
    opener = Mock()
    monkeypatch.setattr(ufw, "open", opener, raising=False)
    monkeypatch.setattr(ufw.time, "monotonic", lambda: 2.0)
    stats = {"lines_read": 0, "stop_reason": "snapshot_end"}
    assert ufw.process_file(cursor_at(), "not-opened", stats=stats, deadline=1.0) == 0
    assert stats["stop_reason"] == "time_limit"
    opener.assert_not_called()


def test_deadline_during_read_keeps_the_unprocessed_line(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line())
    # Before open and before read there is time; after read the budget expires.
    clock = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(ufw.time, "monotonic", lambda: next(clock))
    cursor = cursor_at()
    stats = {"lines_read": 0, "stop_reason": "snapshot_end"}
    assert ufw.process_file(cursor, str(logfile), stats=stats, deadline=1.0) == 0
    assert saved_position(cursor) == 0
    assert stats == {"lines_read": 0, "stop_reason": "time_limit"}


@pytest.mark.parametrize("failed_operation", ["INSERT INTO ufw_log", "INSERT INTO ufw_state", "commit"])
def test_database_failures_roll_back_and_release_writer_lock(tmp_path, monkeypatch, failed_operation):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line())
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    connection = connection_for_files()

    def execute(query, values):
        if failed_operation in query:
            raise pymysql.OperationalError(2013, "synthetic failure")

    connection.cursor.return_value.execute.side_effect = execute
    if failed_operation == "commit":
        connection.commit.side_effect = pymysql.OperationalError(2013, "synthetic failure")
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(connection)
    connection.rollback.assert_called_once()
    assert "RELEASE_LOCK" in connection.cursor.return_value.execute.call_args.args[0]
    connection.cursor.return_value.close.assert_called_once()


@pytest.mark.parametrize("lock_result", [None, (None,), (0,)])
def test_unavailable_lock_never_reads_files_or_releases_someone_elses_lock(monkeypatch, lock_result):
    connection = connection_for_files()
    connection.cursor.return_value.fetchone.side_effect = [lock_result]
    files = Mock()
    monkeypatch.setattr(ufw, "get_logfiles", files)
    with pytest.raises(RuntimeError):
        ufw.process_log(connection)
    files.assert_not_called()
    connection.begin.assert_not_called()
    connection.commit.assert_not_called()
    assert len(connection.cursor.return_value.execute.call_args_list) == 1


@pytest.mark.parametrize("lines,seconds", [(0, 20), (100001, 20), (True, 20), (1, 0), (1, 51), (1, True)])
def test_invalid_limits_never_access_database(lines, seconds):
    connection = MagicMock()
    with pytest.raises(ValueError):
        ufw.process_log(connection, max_lines=lines, max_seconds=seconds)
    connection.cursor.assert_not_called()


def test_missing_active_log_rolls_back_progress(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    (tmp_path / "ufw.log.1").write_bytes(line())
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    connection = connection_for_files()
    with pytest.raises(FileNotFoundError):
        ufw.process_log(connection)
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


def test_disappearing_rotation_does_not_block_active_file(tmp_path, monkeypatch):
    logfile = tmp_path / "ufw.log"
    logfile.write_bytes(line())
    monkeypatch.setattr(ufw, "LOGFILE", str(logfile))
    monkeypatch.setattr(ufw, "get_logfiles", lambda: [str(logfile) + ".1", str(logfile)])
    connection = connection_for_files()
    assert ufw.process_log(connection)["inserted"] == 1
    connection.commit.assert_called_once()


def test_existing_cron_command_without_options_uses_bounded_defaults(monkeypatch):
    connection = MagicMock()
    monkeypatch.setattr(ufw, "get_connection", Mock(return_value=connection))
    run = Mock()
    monkeypatch.setattr(ufw, "process_log", run)
    ufw.main([])
    run.assert_called_once_with(connection, max_lines=5000, max_seconds=20)
    connection.close.assert_called_once()


@pytest.mark.parametrize("args", [["--max-lines", "0"], ["--max-seconds", "51"]])
def test_invalid_cli_limits_fail_before_connecting(monkeypatch, args):
    connect = Mock()
    monkeypatch.setattr(ufw, "get_connection", connect)
    with pytest.raises(SystemExit):
        ufw.main(args)
    connect.assert_not_called()


@pytest.mark.parametrize('padding', [1, 3000])
def test_nul_prefix_recovery_preserves_event_hash_and_byte_position(tmp_path, capsys, padding):
    import hashlib
    from datetime import datetime

    clean = line()
    padded = b"\x00" * padding + clean
    logfile = tmp_path / 'ufw.log'
    logfile.write_bytes(clean + padded)
    cursor = cursor_at()
    assert ufw.process_file(cursor, str(logfile)) == 2
    writes = []
    for call in cursor.execute.call_args_list:
        if 'INSERT INTO ufw_log' in call.args[0]:
            writes.append(call.args[1])
    assert writes[0] == writes[1]
    assert writes[0][:7] == (datetime(2026, 10, 22, 9, 0, 0, 123456), 'BLOCK',
                             '192.0.2.1', '198.51.100.1', 'TCP', 0, 1000)
    assert writes[0][7] == clean.decode().strip()
    assert writes[0][8] == hashlib.sha256(clean.decode().strip().encode()).hexdigest()
    assert saved_position(cursor) == len(clean) + len(padded)
    diagnostic = capsys.readouterr().out
    assert 'position=' + str(len(clean)) in diagnostic
    assert 'nul_count=' + str(padding) in diagnostic
    assert hashlib.sha256(padded).hexdigest() in diagnostic
    assert str(logfile) in diagnostic
    assert '192.0.2.1' not in diagnostic
    assert '\x00' not in diagnostic


@pytest.mark.parametrize('damaged', [
    b'\x00' * 3000 + b'bad host [UFW BLOCK]\n',
    b'\x00' + b'2026-10-22T12:00:00Z host ordinary message\n',
    b'\x00' + line().replace(b'SRC=', b'\x00SRC='),
    b'\x00' + line().replace(b'host', b'\xffhost'),
    b'\x00' * 10 + b'\n',
])
def test_unrecoverable_nul_event_rolls_back_entire_pass(tmp_path, monkeypatch, damaged):
    logfile = tmp_path / 'ufw.log'
    logfile.write_bytes(line() + damaged)
    monkeypatch.setattr(ufw, 'LOGFILE', str(logfile))
    connection = connection_for_files()
    with pytest.raises(ValueError):
        ufw.process_log(connection)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()
    cursor = connection.cursor.return_value
    for call in cursor.execute.call_args_list:
        assert 'INSERT INTO ufw_state' not in call.args[0]


def test_middle_nul_is_not_removed_from_ordinary_line():
    raw = line().replace(b'host', b'ho\x00st')
    assert ufw.decode_log_line(raw, 'synthetic.log', 0) == raw.decode()


def test_nul_padding_still_counts_towards_raw_line_limit(tmp_path):
    logfile = tmp_path / 'ufw.log'
    logfile.write_bytes(b'\x00' * ufw.MAX_LINE_BYTES + line())
    cursor = cursor_at()
    with pytest.raises(RuntimeError, match='64 KiB'):
        ufw.process_file(cursor, str(logfile))
    for call in cursor.execute.call_args_list:
        assert 'INSERT INTO' not in call.args[0]


def test_recovered_line_obeys_line_budget(tmp_path):
    raw = b'\x00' * 3000 + line()
    logfile = tmp_path / 'ufw.log'
    logfile.write_bytes(raw + line(1))
    cursor = cursor_at()
    stats = {'lines_read': 0, 'stop_reason': 'snapshot_end'}
    assert ufw.process_file(cursor, str(logfile), stats=stats, max_lines=1) == 1
    assert stats == {'lines_read': 1, 'stop_reason': 'line_limit'}
    assert saved_position(cursor) == len(raw)
