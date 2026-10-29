import argparse
import glob
import hashlib
import os
import stat
import time

import pymysql

from database.connection import get_connection
from database.identity import configured_identity, identity_schema_enabled
from ingestion.splitter import parse_ufw_line
from ingestion.ufw_validation import convert_port, convert_timestamp, validate_event

LOGFILE = "/var/log/ufw.log"
LOCK_NAME = "mysql_siem_ufw_ingestion"

MAX_LINES = 5000
MAX_SECONDS = 20
MAX_LINE_BYTES = 65536



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

    info_table = validate_event(line)
    if info_table is None:
        return 0

    event_time = info_table["event_time"]

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

        scoped = identity is not None or identity_schema_enabled(cursor.connection)
        query = 'SELECT 1 FROM ufw_log WHERE event_hash=%s'
        parameters = (event_hash,)
        if scoped:
            scope = 0
            if identity is not None:
                scope = identity.source_id
            query += ' AND source_scope=%s'
            parameters += (scope,)
        cursor.execute(query, parameters)
        if cursor.fetchone() != (1,):
            raise
        return 0

    if cursor.rowcount == 1:
        return 1

    return 0


def process_file(cursor, filename, *, stats=None, max_lines=MAX_LINES, deadline=None, identity=None, batch=False, policy=None):
    """Commit only complete lines from a content-verified file generation."""
    from ingestion import ufw_continuity as continuity
    from ingestion.ufw_records import process_line

    validate_limits(max_lines, MAX_SECONDS)
    if stats is None:
        stats = {'lines_read': 0, 'stop_reason': 'snapshot_end'}
    if stats['lines_read'] >= max_lines:
        stats['stop_reason'] = 'line_limit'
        return 0
    if deadline is not None and time.monotonic() >= deadline:
        stats['stop_reason'] = 'time_limit'
        return 0
    scope = 0
    if identity is not None:
        scope = identity.source_id
    inserted = 0
    read_deadline = deadline
    if deadline is not None:
        now = time.monotonic()
        read_deadline = now + max(0, deadline - now) * 0.7
    checkpoint = None
    writer = None
    if batch:
        from ingestion.ufw_batch import EventBatch
        writer = EventBatch(cursor, identity, policy, stats)
    try:
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise OSError('UFW source must be a regular file.')
            checkpoint, prefix, observed = continuity.start(cursor, source, filename, info, scope, deadline)
            while source.tell() < info.st_size:
                if stats['lines_read'] >= max_lines:
                    stats['stop_reason'] = 'line_limit'
                    break
                if read_deadline is not None and time.monotonic() >= read_deadline:
                    stats['stop_reason'] = 'time_limit'
                    break
                start = source.tell()
                raw = source.readline(min(info.st_size - start, MAX_LINE_BYTES + 1))
                if len(raw) > MAX_LINE_BYTES:
                    raise RuntimeError('UFW log line exceeds the 64 KiB read limit; collection rolled back.')
                if not raw.endswith(b'\n'):
                    source.seek(start)
                    stats['stop_reason'] = 'partial_line'
                    break
                if read_deadline is not None and time.monotonic() >= read_deadline:
                    source.seek(start)
                    stats['stop_reason'] = 'time_limit'
                    break
                stats['file'] = filename
                stats['position'] = start
                inserted += process_line(cursor, raw, filename, start, info.st_dev, info.st_ino, identity, stats, writer=writer)
                prefix.update(raw)
                stats['lines_read'] += 1
            if writer is not None:
                writer.flush()
                inserted = writer.inserted
            status = continuity.finish(cursor, source, filename, info, scope, checkpoint, prefix, observed, deadline)
            stats['file_state'] = status
    except OSError as error:
        if not isinstance(error, TimeoutError):
            stats['source_failure'] = (checkpoint or 0, filename)
        raise
    return inserted


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
    committed = None
    scope = 0
    diagnostics_ready = False
    from ingestion import ufw_continuity as continuity

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

        overall_deadline = time.monotonic() + max_seconds
        identity = configured_identity(cursor, "ufw")
        scope = 0
        if identity is not None:
            scope = identity.source_id
        cursor.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() "
                       "AND table_name='ufw_file_checkpoints'")
        if cursor.fetchone() != (1,):
            raise RuntimeError('UFW continuity migration 025 is required.')
        diagnostics_ready = True
        continuity.mark_running(connection, scope)
        from ingestion.ufw_filters import load
        policy = load(cursor, identity)
        connection.__dict__['_siem_ufw_policy'] = policy
        connection.begin()
        has_archives = bool(glob.glob(glob.escape(LOGFILE) + '.*.gz'))
        cursor.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() "
                       "AND table_name=%s", ("ufw_archives",))
        if cursor.fetchone() == (1,):
            cursor.execute("SELECT 1 FROM ufw_archives WHERE source_scope=%s AND status <> 'COMPLETE' LIMIT 1", (scope,))
            pending = cursor.fetchone()
            cursor.execute('SELECT 1 FROM ufw_archive_failures WHERE source_scope=%s LIMIT 1', (scope,))
            failed = cursor.fetchone()
            has_archives = has_archives or pending is not None or failed is not None
        elif identity_schema_enabled(connection):
            raise RuntimeError('UFW archive migration is missing or not visible.')
        deadline = overall_deadline
        raw_lines = max_lines
        if has_archives:
            deadline -= max_seconds / 4
            raw_lines -= max(1, max_lines // 4)
            raw_lines = max(1, raw_lines)

        inserted_rows = 0

        logfiles = get_logfiles()

        if len(logfiles) > continuity.MAX_FILES:
            raise RuntimeError("UFW_FILE_DISCOVERY_LIMIT")
        if LOGFILE in logfiles:
            logfiles.remove(LOGFILE)
            logfiles.insert(0, LOGFILE)
        skip_active = False
        if max_lines == 1 and (has_archives or len(logfiles) > 1):
            cursor.execute('SELECT pass_number FROM ufw_collection_health WHERE source_scope=%s', (scope,))
            turn = cursor.fetchone()[0] % 3
            if has_archives and turn == 0:
                raw_lines = 0
            if len(logfiles) > 1 and turn == 2:
                skip_active = True
        active_limit = raw_lines
        active_deadline = deadline
        if len(logfiles) > 1:
            active_limit = raw_lines // 2
            if raw_lines == 1:
                active_limit = 1
            active_deadline = time.monotonic() + max(0, deadline - time.monotonic()) / 2
        processed_files = 0
        verification_failed = False
        for filename in logfiles:
            if filename == LOGFILE and skip_active:
                stats['active_state'] = 'BACKLOG'
                continue
            file_limit = raw_lines
            file_deadline = deadline
            if filename == LOGFILE:
                file_limit = active_limit
                file_deadline = active_deadline
            if stats['lines_read'] >= file_limit or time.monotonic() >= file_deadline:
                stats['stop_reason'] = 'budget_limit'
                break
            before = stats['lines_read']
            previous_stats = stats.copy()
            cursor.execute('SAVEPOINT ufw_file')
            try:
                inserted_rows += process_file(cursor, filename, stats=stats, max_lines=file_limit,
                                              deadline=file_deadline, identity=identity, batch=True, policy=policy)
            except TimeoutError:
                cursor.execute('ROLLBACK TO SAVEPOINT ufw_file')
                stats.clear()
                stats.update(previous_stats)
                stats['stop_reason'] = 'verification_time_limit'
                stats['active_state'] = 'UNKNOWN'
                verification_failed = True
                continue
            finally:
                cursor.execute('RELEASE SAVEPOINT ufw_file')
            processed_files += 1
            if filename == LOGFILE:
                stats['active_lines'] = stats['lines_read'] - before
                stats['active_state'] = 'HEALTHY'
                if stats.get('file_state') != 'CAUGHT_UP':
                    stats['active_state'] = 'BACKLOG'

        stats['plain_backlog'] = processed_files < len(logfiles)
        if stats["lines_read"] >= raw_lines:
            stats["stop_reason"] = "line_limit"

        elif time.monotonic() >= deadline:
            stats["stop_reason"] = "time_limit"

        connection.commit()
        committed = (inserted_rows, stats.get('quarantined', 0))

        print(
            f"UFW active pass: COMMITTED; inserted: {inserted_rows}; "
            f"lines read: {stats['lines_read']}; "
            f"stop: {stats['stop_reason']}; "
            f"duplicates: {stats.get('duplicates', 0)}; quarantined: {stats.get('quarantined', 0)}; "
            f"non-UFW: {stats.get('non_ufw', 0)}"
        )

        result = {"inserted": inserted_rows, **stats}
        result.pop("file", None)
        result.pop("position", None)
        result.pop("file_state", None)
        if has_archives:
            from ingestion.ufw_archives import process_archives
            try:
                archives = {}
                process_archives(connection, LOGFILE, max_lines=max_lines - stats['lines_read'],
                                 deadline=overall_deadline, totals=archives)
            except (OSError, ValueError, RuntimeError, pymysql.MySQLError) as error:
                connection.rollback()
                committed = (inserted_rows + archives.get('inserted', 0),
                             stats.get('quarantined', 0) + archives.get('quarantined', 0))
                print(f"UFW collection: FAILED class={type(error).__name__} stage=archives "
                      f"committed_counts={committed}")
                raise
            result['archive_lines'] = archives['lines_read']
            for key, value in archives.items():
                result[key] = result.get(key, 0) + value
            print(f"UFW archives: pending={archives['archives_pending']} errors={archives['archive_errors']} "
                  f"inserted={archives['inserted']} quarantined={archives['quarantined']}")
            if archives['archive_errors']:
                result['status'] = 'FAILED'
                print(f"UFW collection: FAILED; committed_inserted={result['inserted']}; "
                      f"quarantined={result.get('quarantined', 0)}")
                continuity.save_health(connection, scope, result, error='ArchiveError')
                result['collection_state'] = continuity.read_health(connection, scope)['state']
                return result
        if not continuity.reconcile(cursor, scope, logfiles, overall_deadline):
            result['active_state'] = 'UNKNOWN'
        if result.get('archives_unscanned'):
            result['active_state'] = 'UNKNOWN'
        # Raw rotations also contribute available backlog, independently of active progress.
        cursor.execute("SELECT 1 FROM ufw_file_checkpoints WHERE source_scope=%s AND status='READING' LIMIT 1", (scope,))
        if cursor.fetchone() is not None:
            result['plain_backlog'] = True
        if verification_failed:
            result['status'] = 'FAILED'
            result['active_state'] = 'UNKNOWN'
            result['stop_reason'] = 'verification_time_limit'
            continuity.save_health(connection, scope, result, error='CheckpointVerificationTimeout')
            result['collection_state'] = continuity.read_health(connection, scope)['state']
            return result
        continuity.save_health(connection, scope, result)
        result['collection_state'] = continuity.read_health(connection, scope)['state']
        result['status'] = 'SUCCESS'
        print(f"UFW collection: SUCCESS; lines_read={result['lines_read']}; inserted={result['inserted']}; "
              f"duplicates={result.get('duplicates', 0)}; quarantined={result.get('quarantined', 0)}; "
              f"non_ufw={result.get('non_ufw', 0)}; stop={result['stop_reason']}")
        return result

    except BaseException as error:
        connection.rollback()
        if lock_acquired and diagnostics_ready:
            try:
                failed_source = stats.get('source_failure')
                if failed_source is not None:
                    checkpoint, filename = failed_source
                    continuity.gap(cursor, scope, checkpoint, 'SOURCE_UNAVAILABLE', filename)
                continuity.save_health(connection, scope, stats, error=type(error).__name__)
            except (OSError, RuntimeError, pymysql.MySQLError):
                connection.rollback()
                print('UFW diagnostics: persistence failed; collection state is unconfirmed.')
        print(f"UFW collection: FAILED class={type(error).__name__} stage=collection "
              f"file={stats.get('file')!r} position={stats.get('position')} "
              f"committed_counts={committed or (0, 0)} lines_read={stats['lines_read']}")
        raise

    finally:
        connection.__dict__.pop('_siem_ufw_policy', None)
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

    parser.add_argument("--status", action="store_true", help="Read UTC continuity diagnostics without changing checkpoints.")
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
            return 1

        if args.status:
            from ingestion.ufw_continuity import read_health
            with connection.cursor() as cursor:
                identity = configured_identity(cursor, 'ufw')
            scope = 0
            if identity is not None:
                scope = identity.source_id
            print(read_health(connection, scope))
            return 0
        result = process_log(
            connection,
            max_lines=args.max_lines,
            max_seconds=args.max_seconds
        )
        if result.get('status') == 'FAILED':
            return 1

    except (pymysql.MySQLError, OSError, ValueError, RuntimeError):
        print("UFW collection: FAILED stage=main; check safe collection diagnostics.")
        return 1

    finally:
        if connection:
            connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
