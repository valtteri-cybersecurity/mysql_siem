"""Read bounded auth.log batches and commit events with their checkpoints."""

import glob
import hashlib
import math
import os
import stat
import time
from pathlib import Path

from database.identity import configured_identity
from ingestion.auth import archives
from ingestion.auth import identity as origin
from ingestion.auth.db import load_position, save_event, save_position
from ingestion.auth.identity import AuthCollectionError
from ingestion.auth.parser import (
    ISO_TIME,
    SYSLOG_TIME,
    AuthParseError,
    parse_auth_line,
    parse_event_time,
)

# Serialize all auth ID allocation through commit, including different collectors.
AUTH_WRITER_LOCK = "mysql_siem_auth_events_writer"
MAX_LINES = 5000
MAX_SECONDS = 30
MAX_LINE_BYTES = 60002


class AuthCollectionBusy(RuntimeError):
    """Another run holds the auth writer lock."""


def get_logfiles(logfile, *, stats=None, include_gzip=True):
    """List numbered rotations oldest first, then the active log."""
    if stats is not None:
        stats.setdefault("compressed_rotations", 0)
        stats.setdefault("unsupported_rotations", 0)
    rotations = []
    for filename in glob.glob(glob.escape(logfile) + ".*"):
        suffix = filename[len(logfile) + 1:]
        number, _, extension = suffix.partition(".")
        if not number.isascii() or not number.isdigit():
            continue
        if not extension and suffix == number:
            rotations.append((int(number), True, filename))
        elif extension in ("gz", "xz", "bz2", "zst"):
            if stats is not None:
                stats["compressed_rotations"] += 1
            if extension == "gz":
                if include_gzip:
                    rotations.append((int(number), False, filename))
            elif stats is not None:
                stats["unsupported_rotations"] += 1
    rotations.sort(reverse=True)
    filenames = []
    for _, _plain, filename in rotations:
        filenames.append(filename)
    filenames.append(logfile)
    return filenames


def open_logfile(filename):
    """Reject non-files without blocking on a misconfigured pipe or device."""
    descriptor = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_NOFOLLOW)
    infile = os.fdopen(descriptor, "rb")
    info = os.fstat(infile.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        infile.close()
        raise origin.AuthSourceError("The auth source must be a regular file.")
    return infile


def check_source_format(logfile, *, syslog_start=None, syslog_end=None, syslog_timezone=None):
    """Check at most 100 complete source records without a database or writes."""
    checked = timestamps = 0
    deadline = time.monotonic() + MAX_SECONDS
    active = str(Path(logfile).resolve())
    with open_logfile(active):
        pass
    for filename in get_logfiles(active, include_gzip=False):
        if checked >= 100:
            break
        try:
            infile = open_logfile(filename)
        except FileNotFoundError:
            if filename == active:
                raise
            continue
        with infile:
            while checked < 100:
                if time.monotonic() >= deadline:
                    raise AuthCollectionError("Auth timestamp preflight exceeded its time budget.")
                raw_line = infile.readline(MAX_LINE_BYTES)
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    if len(raw_line) == MAX_LINE_BYTES:
                        raise AuthCollectionError("Auth line exceeds the safe size limit.")
                    break
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    raise AuthCollectionError("Invalid UTF-8 in auth source.") from None
                checked += 1
                timestamp = ISO_TIME.match(line)
                if timestamp is None:
                    timestamp = SYSLOG_TIME.match(line)
                if timestamp is not None:
                    parse_event_time(timestamp[0], syslog_start, syslog_end, syslog_timezone)
                    timestamps += 1
                parse_auth_line(line, syslog_start=syslog_start, syslog_end=syslog_end,
                                syslog_timezone=syslog_timezone)
    return {"lines_checked": checked, "timestamps_checked": timestamps}


def position_hash(infile, position):
    """Fingerprint bytes before the checkpoint to notice truncate-and-regrow."""
    infile.seek(max(0, position - 256))
    digest = hashlib.sha256(infile.read(min(position, 256))).hexdigest()
    infile.seek(position)
    return digest


def record_defaults(stats):
    for key in ("lines_read", "failures_recognized", "successes_recognized",
                "local_logins_recognized", "unrecognized_lines", "invalid_lines",
                "duplicates", "remaining_bytes", "files_processed"):
        stats.setdefault(key, 0)
    stats.setdefault("budget_exhausted", False)
    stats.setdefault("waiting_for_line", False)
    stats.setdefault("coverage_gaps", 0)
    stats.setdefault("source_resets", 0)


def read_records(cursor, infile, size, generation, stats, *, identity, prefix=None,
                 line_limit, deadline, syslog_start, syslog_end, syslog_timezone):
    """Parse bounded complete records at logical byte positions."""
    inserted = skipped = lines_read = 0
    # Bound memory as well as lines; never consume an unfinished log record.
    while infile.tell() < size:
        if lines_read >= line_limit:
            stats["budget_exhausted"] = True
            break
        if deadline is not None and time.monotonic() >= deadline:
            stats["budget_exhausted"] = True
            break
        start = infile.tell()
        raw_line = infile.readline(min(size - start, MAX_LINE_BYTES))
        if not raw_line:
            raise origin.AuthRecordError("Auth source was truncated during collection.")
        if not raw_line.endswith(b"\n"):
            infile.seek(start)
            if len(raw_line) == MAX_LINE_BYTES:
                stats["invalid_lines"] += 1
                raise origin.AuthRecordError("Auth line exceeds the safe size limit.")
            stats["waiting_for_line"] = True
            break
        if prefix is not None:
            prefix.update(raw_line)
        lines_read += 1
        stats["lines_read"] += 1
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            stats["invalid_lines"] += 1
            raise origin.AuthRecordError("Invalid UTF-8 in auth source; checkpoint retained.") from None
        try:
            event = parse_auth_line(line, syslog_start=syslog_start,
                                    syslog_end=syslog_end, syslog_timezone=syslog_timezone)
        except AuthParseError:
            stats["invalid_lines"] += 1
            raise
        if event is None:
            skipped += 1
            stats["unrecognized_lines"] += 1
            continue
        if event["event_type"] == "SSH_AUTH_FAILURE":
            stats["failures_recognized"] += 1
        elif event["event_type"] == "SSH_LOGIN_SUCCESS":
            stats["successes_recognized"] += 1
        else:
            stats["local_logins_recognized"] += 1
        saved = save_event(cursor, event, identity=identity, generation=generation, position=start)
        inserted += saved
        stats["duplicates"] += 1 - saved

    return inserted, skipped


def process_file(cursor, filename, collector_id, *, stats=None, line_limit=MAX_LINES,
                 identity=None, deadline=None, syslog_start=None, syslog_end=None,
                 syslog_timezone=None):
    if stats is None:
        stats = {}
    record_defaults(stats)
    with open_logfile(filename) as infile:
        info = os.fstat(infile.fileno())
        source_scope = 0
        if identity is not None:
            source_scope = identity.source_id
        state = load_position(cursor, collector_id, info.st_dev, info.st_ino,
                              source_scope=source_scope, with_origin=True)
        verification_started = time.monotonic()
        generation, prefix, observed = origin.start(infile, info, state, stats, deadline)
        read_deadline = deadline
        if deadline is not None:
            now = time.monotonic()
            remaining = max(0, deadline - now)
            reserve = max(remaining * 0.3, (now - verification_started) * 1.25)
            reserve = min(reserve, remaining * 0.9)
            read_deadline = now + max(0, remaining - reserve)

        inserted, skipped = read_records(
            cursor, infile, info.st_size, generation, stats, identity=identity, prefix=prefix,
            line_limit=line_limit, deadline=read_deadline, syslog_start=syslog_start,
            syslog_end=syslog_end, syslog_timezone=syslog_timezone,
        )

        position = infile.tell()
        digest = position_hash(infile, position)
        mtime_ns = origin.finish(infile, info, prefix, observed, deadline)
        current = (position, digest, generation, prefix.hexdigest(), info.st_size, observed, mtime_ns)
        if state != current:
            save_position(cursor, collector_id, info.st_dev, info.st_ino,
                          filename, position, digest, source_scope=source_scope, generation=generation,
                          prefix_sha=prefix.hexdigest(), observed_size=info.st_size,
                          observed_sha=observed, mtime_ns=mtime_ns)
        stats["files_processed"] += 1
        stats["remaining_bytes"] += max(0, info.st_size - position)
    return inserted, skipped


def collect_auth_events(connection, logfile="/var/log/auth.log", *, collector_id,
                        stats=None, max_lines=MAX_LINES, max_seconds=MAX_SECONDS,
                        syslog_start=None, syslog_end=None, syslog_timezone=None):
    """Commit events and file positions together, or roll back and propagate.

    collector_id is the stable legacy checkpoint reader label. Trusted numeric
    identities still come only from the approved database registry bindings.
    The time budget bounds work between I/O calls; database socket timeouts also
    apply to each operation. Use a dedicated autocommit=False connection.
    """
    if (not isinstance(collector_id, str) or not collector_id.strip()
            or len(collector_id) > 255):
        raise ValueError("collector_id must be a nonempty string of at most 255 characters.")
    if type(max_lines) is not int or not 1 <= max_lines <= 100000:
        raise ValueError("Auth collection line limit must be within 1..100000.")
    if (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds)
            or not 0 < max_seconds <= 50):
        raise ValueError("Auth collection time budget must be within 0..50 seconds.")
    if stats is None:
        stats = {}
    stats.update(lines_read=0, failures_recognized=0, successes_recognized=0,
                 local_logins_recognized=0, unrecognized_lines=0, invalid_lines=0,
                 duplicates=0, remaining_bytes=0, files_processed=0,
                 files_pending=0, budget_exhausted=False, waiting_for_line=False,
                 elapsed_seconds=0.0, state_updated="NO", coverage_gaps=0,
                 compressed_rotations=0, unsupported_rotations=0, vanished_rotations=0, source_resets=0,
                 archives_complete=0, archives_unverified=0, archives_failed=0, archives_pending=0,
                 archive_diagnostics=[])
    started = time.monotonic()
    deadline = started + max_seconds
    archive_deadline = started + max_seconds * 0.6
    logfile = str(Path(logfile).resolve())
    cursor = connection.cursor()
    locked = False
    try:
        cursor.execute("SELECT GET_LOCK(%s, 0)", (AUTH_WRITER_LOCK,))
        result = cursor.fetchone()
        if result is None or result[0] is None:
            raise AuthCollectionError("Unable to acquire the auth writer lock.")
        if result[0] != 1:
            raise AuthCollectionBusy("Another auth collector is running.")
        locked = True
        connection.begin()
        identity = configured_identity(cursor, "auth")
        # Check the active source even when rotations alone could fill the budget.
        with open_logfile(logfile):
            pass
        inserted = skipped = 0
        filenames = get_logfiles(logfile, stats=stats)
        for index, filename in enumerate(filenames):
            if time.monotonic() >= deadline:
                stats["budget_exhausted"] = True
                stats["files_pending"] = len(filenames) - index
                break
            remaining = max_lines - stats["lines_read"]
            try:
                if filename != logfile and filename.endswith(".gz"):
                    new, ignored = archives.process(
                        cursor, logfile, filename, collector_id, stats, identity=identity,
                        line_limit=remaining, deadline=archive_deadline, syslog_start=syslog_start,
                        syslog_end=syslog_end, syslog_timezone=syslog_timezone,
                    )
                else:
                    new, ignored = process_file(cursor, filename, collector_id,
                                                stats=stats, line_limit=remaining, identity=identity,
                                                deadline=deadline, syslog_start=syslog_start,
                                                syslog_end=syslog_end, syslog_timezone=syslog_timezone)
            except FileNotFoundError:
                if filename == logfile:
                    raise
                # Keep collecting available sources, but report the coverage gap.
                stats["vanished_rotations"] += 1
                stats["coverage_gaps"] += 1
                continue
            inserted += new
            skipped += ignored
        stats["state_updated"] = "UNKNOWN"
        connection.commit()
        stats["state_updated"] = "YES"
        return {"inserted": inserted, "skipped": skipped}
    except BaseException:
        # A failed or interrupted commit cannot confirm any new completion.
        if stats["state_updated"] != "YES":
            stats["archives_complete"] = 0
        connection.rollback()
        raise
    finally:
        try:
            if locked:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (AUTH_WRITER_LOCK,))
        finally:
            cursor.close()
            stats["elapsed_seconds"] = time.monotonic() - started
