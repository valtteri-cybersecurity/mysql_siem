"""Read bounded auth.log batches and commit events with their checkpoints."""

import glob
import hashlib
import math
import os
import stat
import time
from pathlib import Path

from database.identity import configured_identity
from ingestion.auth.db import load_position, save_event, save_position
from ingestion.auth.parser import AuthParseError, parse_auth_line

# Serialize all auth ID allocation through commit, including different collectors.
AUTH_WRITER_LOCK = "mysql_siem_auth_events_writer"
MAX_LINES = 5000
MAX_SECONDS = 30
MAX_LINE_BYTES = 60002


class AuthCollectionError(RuntimeError):
    """An expected source or checkpoint failure prevents safe progress."""


class AuthCollectionBusy(RuntimeError):
    """Another run holds the auth writer lock."""


def get_logfiles(logfile):
    """Read numbered, uncompressed rotations oldest first, then the active log."""
    rotations = []
    for filename in glob.glob(glob.escape(logfile) + ".*"):
        suffix = filename[len(logfile) + 1:]
        if suffix.isascii() and suffix.isdigit():
            rotations.append((int(suffix), filename))
    rotations.sort(reverse=True)
    filenames = []
    for _, filename in rotations:
        filenames.append(filename)
    filenames.append(logfile)
    return filenames


def open_logfile(filename):
    """Reject non-files without blocking on a misconfigured pipe or device."""
    descriptor = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    infile = os.fdopen(descriptor, "rb")
    if not stat.S_ISREG(os.fstat(infile.fileno()).st_mode):
        infile.close()
        raise AuthCollectionError("The auth source must be a regular file.")
    return infile


def position_hash(infile, position):
    """Fingerprint bytes before the checkpoint to notice truncate-and-regrow."""
    infile.seek(max(0, position - 256))
    digest = hashlib.sha256(infile.read(min(position, 256))).hexdigest()
    infile.seek(position)
    return digest


def process_file(cursor, filename, collector_id, *, stats=None, line_limit=MAX_LINES,
                 identity=None, deadline=None, syslog_start=None, syslog_end=None,
                 syslog_timezone=None):
    inserted = skipped = lines_read = 0
    if stats is None:
        stats = {}
    for key in ("lines_read", "failures_recognized", "successes_recognized",
                "local_logins_recognized", "unrecognized_lines", "invalid_lines",
                "duplicates", "remaining_bytes", "files_processed"):
        stats.setdefault(key, 0)
    stats.setdefault("budget_exhausted", False)
    stats.setdefault("waiting_for_line", False)
    with open_logfile(filename) as infile:
        info = os.fstat(infile.fileno())
        source_scope = 0
        if identity is not None:
            source_scope = identity.source_id
        state = load_position(cursor, collector_id, info.st_dev, info.st_ino,
                              source_scope=source_scope)
        position = 0
        if state is not None:
            previous_position, previous_hash = state
            if type(previous_position) is not int or previous_position < 0:
                raise AuthCollectionError("Invalid auth checkpoint position.")
            if (previous_position <= info.st_size
                    and position_hash(infile, previous_position) == previous_hash):
                position = previous_position
        anchor_position = max(position, min(info.st_size, 256))
        anchor_digest = position_hash(infile, anchor_position)
        infile.seek(position)

        # Bound memory as well as lines; never consume an unfinished log record.
        while infile.tell() < info.st_size:
            if lines_read >= line_limit:
                stats["budget_exhausted"] = True
                break
            if deadline is not None and time.monotonic() >= deadline:
                stats["budget_exhausted"] = True
                break
            start = infile.tell()
            raw_line = infile.readline(min(info.st_size - start, MAX_LINE_BYTES))
            if not raw_line:
                raise AuthCollectionError("Auth source was truncated during collection.")
            if not raw_line.endswith(b"\n"):
                infile.seek(start)
                if len(raw_line) == MAX_LINE_BYTES:
                    stats["invalid_lines"] += 1
                    raise AuthCollectionError("Auth line exceeds the safe size limit.")
                stats["waiting_for_line"] = True
                break
            lines_read += 1
            stats["lines_read"] += 1
            try:
                line = raw_line.decode("utf-8")
            except UnicodeDecodeError:
                stats["invalid_lines"] += 1
                raise AuthCollectionError("Invalid UTF-8 in auth source; checkpoint retained.") from None
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
            saved = save_event(cursor, event, identity=identity)
            inserted += saved
            stats["duplicates"] += 1 - saved

        position = infile.tell()
        if os.fstat(infile.fileno()).st_size < position:
            raise AuthCollectionError("Auth source was truncated during collection.")
        if position_hash(infile, anchor_position) != anchor_digest:
            raise AuthCollectionError("Auth source content changed during collection.")
        digest = position_hash(infile, position)
        # Idle minute passes need SELECT and a bounded fingerprint, not an UPDATE.
        if state != (position, digest):
            save_position(cursor, collector_id, info.st_dev, info.st_ino,
                          filename, position, digest, source_scope=source_scope)
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
                 elapsed_seconds=0.0)
    started = time.monotonic()
    deadline = started + max_seconds
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
        filenames = get_logfiles(logfile)
        for index, filename in enumerate(filenames):
            if time.monotonic() >= deadline:
                stats["budget_exhausted"] = True
                stats["files_pending"] = len(filenames) - index
                break
            remaining = max_lines - stats["lines_read"]
            try:
                new, ignored = process_file(cursor, filename, collector_id,
                                            stats=stats, line_limit=remaining, identity=identity,
                                            deadline=deadline, syslog_start=syslog_start,
                                            syslog_end=syslog_end, syslog_timezone=syslog_timezone)
            except FileNotFoundError:
                if filename == logfile:
                    raise
                # A rotation can disappear between directory listing and open.
                continue
            inserted += new
            skipped += ignored
        connection.commit()
        return {"inserted": inserted, "skipped": skipped}
    except Exception:
        # Transaction cleanup only: programming errors are re-raised, never hidden.
        connection.rollback()
        raise
    finally:
        stats["elapsed_seconds"] = time.monotonic() - started
        try:
            if locked:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (AUTH_WRITER_LOCK,))
        finally:
            cursor.close()
