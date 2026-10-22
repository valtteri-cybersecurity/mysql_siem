"""One bounded UFW collection pass; events and file positions commit together."""

import argparse
import glob
import hashlib
import os
import time

from database.connection import get_connection
from ingestion.splitter import parse_ufw_line

LOGFILE = "/var/log/ufw.log"
LOCK_NAME = "mysql_siem_ufw_ingestion"
MAX_LINES = 5000
MAX_SECONDS = 20
MAX_LINE_BYTES = 65536


def convert_port(port_value):
    if port_value:
        try:
            return int(port_value)
        except ValueError:
            return 0

    return 0


def get_logfiles():
    """Drain uncompressed numeric rotations oldest first, then the active log.

    Reading the growing active log first could starve rotations on every bounded
    pass. Numeric ordering also keeps .10 older than .2.
    """
    rotations = []
    for filename in glob.glob(glob.escape(LOGFILE) + ".*"):
        suffix = filename[len(LOGFILE) + 1:]
        if suffix.isascii() and suffix.isdigit():
            rotations.append((int(suffix), filename))
    rotations.sort(reverse=True)
    return [filename for _, filename in rotations] + [LOGFILE]


def validate_limits(max_lines, max_seconds):
    if type(max_lines) is not int or not 1 <= max_lines <= 100000:
        raise ValueError("--max-lines must be within 1..100000.")
    if type(max_seconds) is not int or not 1 <= max_seconds <= 50:
        raise ValueError("--max-seconds must be within 1..50.")


def save_event(cursor, line):
    clean_line = line.strip()

    if clean_line == "":
        return 0

    info_table = parse_ufw_line(line)

    event_time = info_table.get("timestamp")
    action = info_table.get("action")
    src_ip = info_table.get("src_ip")
    dst_ip = info_table.get("dst_ip")
    protocol = info_table.get("protocol")

    src_port = convert_port(info_table.get("src_prt"))
    dst_port = convert_port(info_table.get("dst_prt"))

    event_hash = hashlib.sha256(
        clean_line.encode("utf-8")
    ).hexdigest()

    sql = """
        INSERT IGNORE INTO ufw_log (
            event_time,
            action,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            raw_line,
            event_hash
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    values = (
        event_time,
        action,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        clean_line,
        event_hash
    )

    cursor.execute(sql, values)

    if cursor.rowcount == 1:
        return 1

    return 0


def process_file(cursor, filename, *, stats=None, max_lines=MAX_LINES, deadline=None):
    """Read complete lines only, up to this file's initial size and shared budget.

    stats counts every complete line, including blank and duplicate lines. The
    caller owns the transaction. A partial line keeps its starting byte offset;
    appends beyond the initial size are always left for the next pass.
    """
    if type(max_lines) is not int or not 1 <= max_lines <= 100000:
        raise ValueError("--max-lines must be within 1..100000.")
    if stats is None:
        stats = {"lines_read": 0, "stop_reason": "snapshot_end"}
    if stats["lines_read"] >= max_lines:
        stats["stop_reason"] = "line_limit"
        return 0
    if deadline is not None and time.monotonic() >= deadline:
        stats["stop_reason"] = "time_limit"
        return 0
    inserted_rows = 0

    try:
        infile = open(filename, "rb")  # noqa: SIM115 - missing rotations are handled before the context manager
    except FileNotFoundError:
        if filename == LOGFILE:
            raise

        print(f"Rotated logfile disappeared: {filename}")
        return 0

    with infile:
        file_info = os.fstat(infile.fileno())

        file_device = file_info.st_dev
        file_inode = file_info.st_ino
        current_size = file_info.st_size

        cursor.execute(
            """
            SELECT last_position
            FROM ufw_state
            WHERE file_device = %s
              AND file_inode = %s
            """,
            (file_device, file_inode)
        )

        result = cursor.fetchone()

        if result is None:
            last_position = 0
        else:
            last_position = result[0]

        if current_size < last_position:
            print(f"Logfile has become smaller: {filename}")
            last_position = 0

        infile.seek(last_position)

        while infile.tell() < current_size:
            if stats["lines_read"] >= max_lines:
                stats["stop_reason"] = "line_limit"
                break
            if deadline is not None and time.monotonic() >= deadline:
                stats["stop_reason"] = "time_limit"
                break
            line_start = infile.tell()
            # Bound both a growing file and a single unexpectedly large line.
            raw_line = infile.readline(min(current_size - line_start, MAX_LINE_BYTES + 1))
            if len(raw_line) > MAX_LINE_BYTES:
                raise RuntimeError("UFW log line exceeds the 64 KiB read limit; collection rolled back.")
            if not raw_line.endswith(b"\n"):
                infile.seek(line_start)
                break
            if deadline is not None and time.monotonic() >= deadline:
                infile.seek(line_start)
                stats["stop_reason"] = "time_limit"
                break
            line = raw_line.decode("utf-8", errors="ignore")
            inserted_rows += save_event(cursor, line)
            stats["lines_read"] += 1

        new_position = infile.tell()

        cursor.execute(
            """
            INSERT INTO ufw_state (
                logfile,
                last_position,
                file_device,
                file_inode
            )
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                logfile = %s,
                last_position = %s
            """,
            (
                filename,
                new_position,
                file_device,
                file_inode,
                filename,
                new_position
            )
        )

    return inserted_rows


def process_log(connection, *, max_lines=MAX_LINES, max_seconds=MAX_SECONDS):
    """Commit one bounded pass using a dedicated autocommit=False connection.

    Line/time budgets cover all files, not each file separately. The monotonic
    deadline is checked between operations; an individual filesystem/DB call
    can overrun it and remains subject to the connection's existing I/O timeouts.
    Budget exhaustion is normal progress: commit the processed lines and their
    offsets. Database/read failures roll back the entire pass. The writer lock
    is held through commit so ID-based detection sees committed batches in order.
    """
    validate_limits(max_lines, max_seconds)
    stats = {"lines_read": 0, "stop_reason": "snapshot_end"}
    cursor = None
    lock_acquired = False

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT GET_LOCK(%s, 0)",
            (LOCK_NAME,)
        )

        result = cursor.fetchone()

        if result is None or result[0] is None:
            raise RuntimeError("Unable to acquire the UFW collector lock.")
        if result[0] != 1:
            raise RuntimeError("Another UFW collector is running.")

        lock_acquired = True
        deadline = time.monotonic() + max_seconds
        connection.begin()
        inserted_rows = 0

        logfiles = get_logfiles()

        for filename in logfiles:
            if stats["lines_read"] >= max_lines:
                stats["stop_reason"] = "line_limit"
                break
            if time.monotonic() >= deadline:
                stats["stop_reason"] = "time_limit"
                break
            inserted_rows += process_file(cursor, filename, stats=stats,
                                          max_lines=max_lines, deadline=deadline)
        if stats["lines_read"] >= max_lines:
            stats["stop_reason"] = "line_limit"
        elif time.monotonic() >= deadline:
            stats["stop_reason"] = "time_limit"
        connection.commit()

        print(f"Done. New UFW rows inserted: {inserted_rows}; "
              f"lines read: {stats['lines_read']}; stop: {stats['stop_reason']}")
        return {"inserted": inserted_rows, **stats}

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            try:
                if lock_acquired:
                    cursor.execute(
                        "SELECT RELEASE_LOCK(%s)",
                        (LOCK_NAME,)
                    )
            finally:
                cursor.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect one bounded pass of UFW log events.")
    parser.add_argument("--max-lines", type=int, default=MAX_LINES,
                        help="Complete lines across all files; default: 5000.")
    parser.add_argument("--max-seconds", type=int, default=MAX_SECONDS,
                        help="Cooperative processing budget; default: 20, maximum: 50 seconds.")
    args = parser.parse_args(argv)
    try:
        validate_limits(args.max_lines, args.max_seconds)
    except ValueError as error:
        parser.error(str(error))
    connection = None

    try:
        connection = get_connection()

        if not connection:
            print("Database connection failed.")
            return

        process_log(connection, max_lines=args.max_lines, max_seconds=args.max_seconds)

    except Exception as error:  # noqa: BLE001 - retain the existing CLI error behavior
        print(f"Error during program execution: {error}")

    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    main()
