import argparse
import glob
import hashlib
import os
import time
from datetime import datetime, timezone

import pymysql

from database.connection import get_connection
from database.identity import configured_identity, identity_schema_enabled
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


def convert_timestamp(timestamp):
    """Convert a UFW timestamp to UTC for MySQL."""

    if not isinstance(timestamp, str):
        # Invalid log data is handled as a validation error.
        raise ValueError("Invalid UFW timestamp.")  # noqa: TRY004

    try:
        event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    except ValueError:
        raise ValueError("Invalid UFW timestamp.") from None

    if event_time.tzinfo is None:
        raise ValueError("UFW timestamp has no timezone.")

    if event_time.utcoffset() is None:
        raise ValueError("UFW timestamp has no timezone.")

    try:
        utc_time = event_time.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError("UFW timestamp is outside the MySQL range.") from None
    if utc_time.year < 1000:
        raise ValueError("UFW timestamp is outside the MySQL range.")

    # MySQL DATETIME does not store timezone information.
    # The value has already been converted to UTC.
    mysql_time = utc_time.replace(tzinfo=None)

    return mysql_time


def get_logfiles():
    """Return rotated logfiles first, then the active logfile."""

    rotations = []

    filenames = glob.glob(glob.escape(LOGFILE) + ".*")

    for filename in filenames:
        suffix = filename[len(LOGFILE) + 1:]

        if suffix.isascii() and suffix.isdigit():
            number = int(suffix)
            rotations.append((number, filename))

    rotations.sort(reverse=True)

    logfiles = []

    for rotation in rotations:
        filename = rotation[1]
        logfiles.append(filename)

    logfiles.append(LOGFILE)

    return logfiles


def validate_limits(max_lines, max_seconds):
    if type(max_lines) is not int:
        raise ValueError("--max-lines must be an integer.")

    if max_lines < 1 or max_lines > 100000:
        raise ValueError("--max-lines must be within 1..100000.")

    if type(max_seconds) is not int:
        raise ValueError("--max-seconds must be an integer.")

    if max_seconds < 1 or max_seconds > 50:
        raise ValueError("--max-seconds must be within 1..50.")


def decode_log_line(raw_line, filename, position):
    """Recover only unambiguous leading NUL padding; retain ordinary decoding."""
    if not raw_line.startswith(b"\x00"):
        return raw_line.decode("utf-8", errors="ignore")
    recovered = raw_line.lstrip(b"\x00")
    nul_count = len(raw_line) - len(recovered)
    if b"\x00" in recovered:
        raise ValueError("Ambiguous NUL bytes in UFW log line; collection rolled back.")
    try:
        line = recovered.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-8 in NUL-prefixed UFW line; collection rolled back.") from None
    parsed = parse_ufw_line(line)
    convert_timestamp(parsed.get("timestamp"))
    if parsed.get("action") not in ("BLOCK", "ALLOW", "AUDIT"):
        raise ValueError("NUL-prefixed line has no recognized UFW event; collection rolled back.")
    digest = hashlib.sha256(raw_line).hexdigest()
    print(f"UFW NUL prefix recovered: file={filename!r} position={position} "
          f"nul_count={nul_count} sha256={digest}")
    return line


def save_event(cursor, line, *, identity=None):
    """Parse and save one UFW event."""

    clean_line = line.strip()

    if clean_line == "":
        return 0

    info_table = parse_ufw_line(line)

    event_time = convert_timestamp(info_table.get("timestamp"))

    action = info_table.get("action")
    src_ip = info_table.get("src_ip")
    dst_ip = info_table.get("dst_ip")
    protocol = info_table.get("protocol")

    src_port = convert_port(info_table.get("src_prt"))
    dst_port = convert_port(info_table.get("dst_prt"))

    event_hash = hashlib.sha256(
        clean_line.encode("utf-8")
    ).hexdigest()

    fields = (
        "event_time",
        "action",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "raw_line",
        "event_hash"
    )

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

    if identity is not None:
        fields += (
            "host_id",
            "source_id",
            "collector_id",
            "sender_id",
            "source_scope",
            "reported_hostname"
        )

        values += identity.values()

        values += (
            identity.source_id,
            info_table.get("reported_hostname")
        )

    placeholders_list = []

    for _ in fields:
        placeholders_list.append("%s")

    placeholders = ", ".join(placeholders_list)
    column_names = ", ".join(fields)

    sql = (
        f"INSERT INTO ufw_log ({column_names}) "
        f"VALUES ({placeholders})"
    )

    try:
        cursor.execute(sql, values)

    except pymysql.IntegrityError as error:
        if error.args[0] != 1062:
            raise

        return 0

    if cursor.rowcount == 1:
        return 1

    return 0


def process_file(
    cursor,
    filename,
    *,
    stats=None,
    max_lines=MAX_LINES,
    deadline=None,
    identity=None
):
    """Read complete UFW log lines and save the file position."""

    if type(max_lines) is not int:
        raise ValueError("--max-lines must be an integer.")

    if max_lines < 1 or max_lines > 100000:
        raise ValueError("--max-lines must be within 1..100000.")

    if stats is None:
        stats = {
            "lines_read": 0,
            "stop_reason": "snapshot_end"
        }

    if stats["lines_read"] >= max_lines:
        stats["stop_reason"] = "line_limit"
        return 0

    if deadline is not None and time.monotonic() >= deadline:
        stats["stop_reason"] = "time_limit"
        return 0

    inserted_rows = 0

    try:
        # A rotated logfile may disappear before it can be opened.
        infile = open(filename, "rb")  # noqa: SIM115

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

        source_scope = 0

        if identity is not None:
            source_scope = identity.source_id

        scoped = identity is not None

        if not scoped:
            scoped = identity_schema_enabled(cursor.connection)

        scope_filter = ""

        position_parameters = (
            file_device,
            file_inode
        )

        if scoped:
            scope_filter = " AND source_scope = %s"
            position_parameters += (source_scope,)

        sql = (
            "SELECT last_position "
            "FROM ufw_state "
            "WHERE file_device = %s "
            "AND file_inode = %s "
            f"{scope_filter}"
        )

        cursor.execute(sql, position_parameters)

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

            remaining_bytes = current_size - line_start
            read_limit = min(remaining_bytes, MAX_LINE_BYTES + 1)

            raw_line = infile.readline(read_limit)

            if len(raw_line) > MAX_LINE_BYTES:
                raise RuntimeError(
                    "UFW log line exceeds the 64 KiB read limit; "
                    "collection rolled back."
                )

            if not raw_line.endswith(b"\n"):
                infile.seek(line_start)
                break

            if deadline is not None and time.monotonic() >= deadline:
                infile.seek(line_start)
                stats["stop_reason"] = "time_limit"
                break

            line = decode_log_line(raw_line, filename, line_start)

            inserted_rows += save_event(
                cursor,
                line,
                identity=identity
            )

            stats["lines_read"] += 1

        new_position = infile.tell()

        fields = (
            "logfile",
            "last_position",
            "file_device",
            "file_inode"
        )

        values = (
            filename,
            new_position,
            file_device,
            file_inode
        )

        if scoped:
            fields += ("source_scope",)
            values += (source_scope,)

        placeholders_list = []

        for _ in fields:
            placeholders_list.append("%s")

        placeholders = ", ".join(placeholders_list)
        column_names = ", ".join(fields)

        sql = (
            f"INSERT INTO ufw_state ({column_names}) "
            f"VALUES ({placeholders}) "
            "ON DUPLICATE KEY UPDATE "
            "logfile = %s, last_position = %s"
        )

        parameters = values + (filename, new_position)

        cursor.execute(sql, parameters)

    return inserted_rows


def process_log(
    connection,
    *,
    max_lines=MAX_LINES,
    max_seconds=MAX_SECONDS
):
    """Collect UFW events and commit events with file positions."""

    validate_limits(max_lines, max_seconds)

    stats = {
        "lines_read": 0,
        "stop_reason": "snapshot_end"
    }

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
            raise RuntimeError(
                "Unable to acquire the UFW collector lock."
            )

        if result[0] != 1:
            raise RuntimeError(
                "Another UFW collector is running."
            )

        lock_acquired = True

        deadline = time.monotonic() + max_seconds

        connection.begin()

        identity = configured_identity(cursor, "ufw")

        inserted_rows = 0

        logfiles = get_logfiles()

        for filename in logfiles:

            if stats["lines_read"] >= max_lines:
                stats["stop_reason"] = "line_limit"
                break

            if time.monotonic() >= deadline:
                stats["stop_reason"] = "time_limit"
                break

            inserted_rows += process_file(
                cursor,
                filename,
                stats=stats,
                max_lines=max_lines,
                deadline=deadline,
                identity=identity
            )

        if stats["lines_read"] >= max_lines:
            stats["stop_reason"] = "line_limit"

        elif time.monotonic() >= deadline:
            stats["stop_reason"] = "time_limit"

        connection.commit()

        print(
            f"Done. New UFW rows inserted: {inserted_rows}; "
            f"lines read: {stats['lines_read']}; "
            f"stop: {stats['stop_reason']}"
        )

        return {
            "inserted": inserted_rows,
            **stats
        }

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
    parser = argparse.ArgumentParser(
        description="Collect one bounded pass of UFW log events."
    )

    parser.add_argument(
        "--max-lines",
        type=int,
        default=MAX_LINES,
        help="Complete lines across all files; default: 5000."
    )

    parser.add_argument(
        "--max-seconds",
        type=int,
        default=MAX_SECONDS,
        help="Cooperative processing budget; default: 20, maximum: 50 seconds."
    )

    args = parser.parse_args(argv)

    try:
        validate_limits(
            args.max_lines,
            args.max_seconds
        )

    except ValueError as error:
        parser.error(str(error))

    connection = None

    try:
        connection = get_connection()

        if not connection:
            print("Database connection failed.")
            return

        process_log(
            connection,
            max_lines=args.max_lines,
            max_seconds=args.max_seconds
        )

    except (pymysql.MySQLError, OSError, ValueError, RuntimeError):
        print(
            "UFW collection failed. "
            "Check schema, source access and identity configuration."
        )

    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    main()
