"""Incrementally read the existing auth.log source, following UFW conventions."""

import glob
import hashlib
import os
from pathlib import Path

from ingestion.auth.db import load_position, save_event, save_position
from ingestion.auth.parser import parse_auth_line

# Serialize all auth ID allocation through commit, including different collectors.
AUTH_WRITER_LOCK = "mysql_siem_auth_events_writer"
MAX_LINES = 5000


class AuthCollectionError(RuntimeError):
    """The database could not establish the collection lock."""


class AuthCollectionBusy(RuntimeError):
    """Another run holds the lock for this log-reading machine."""


def get_logfiles(logfile):
    """Read numbered, uncompressed rotations oldest first, then the active log."""
    rotations = []
    for filename in glob.glob(glob.escape(logfile) + ".*"):
        suffix = filename[len(logfile) + 1:]
        if suffix.isascii() and suffix.isdigit():
            rotations.append((int(suffix), filename))
    rotations.sort(reverse=True)
    return [filename for _, filename in rotations] + [logfile]


def position_hash(infile, position):
    """Fingerprint bytes before the checkpoint to notice truncate-and-regrow."""
    infile.seek(max(0, position - 256))
    digest = hashlib.sha256(infile.read(min(position, 256))).hexdigest()
    infile.seek(position)
    return digest


def process_file(cursor, filename, collector_id, *, stats=None, line_limit=MAX_LINES):
    inserted = skipped = lines_read = 0
    if stats is None:
        stats = {"lines_read": 0, "failures_recognized": 0, "duplicates": 0}
    with open(filename, "rb") as infile:
        info = os.fstat(infile.fileno())
        state = load_position(cursor, collector_id, info.st_dev, info.st_ino)
        position = 0
        if state is not None:
            previous_position, previous_hash = state
            if (previous_position <= info.st_size
                    and position_hash(infile, previous_position) == previous_hash):
                position = previous_position
        infile.seek(position)

        # Stop at the initial size so an actively growing log cannot block forever.
        while infile.tell() < info.st_size and lines_read < line_limit:
            start = infile.tell()
            raw_line = infile.readline(info.st_size - start)
            if not raw_line.endswith(b"\n"):
                infile.seek(start)
                break
            lines_read += 1
            stats["lines_read"] += 1
            try:
                line = raw_line.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                continue
            event = parse_auth_line(line)
            if event is None:
                skipped += 1
                continue
            stats["failures_recognized"] += 1
            saved = save_event(cursor, event)
            inserted += saved
            stats["duplicates"] += 1 - saved

        position = infile.tell()
        digest = position_hash(infile, position)
        save_position(cursor, collector_id, info.st_dev, info.st_ino,
                      filename, position, digest)
    return inserted, skipped


def collect_auth_events(connection, logfile="/var/log/auth.log", *, collector_id,
                        stats=None, max_lines=MAX_LINES):
    """Commit events and file positions together, or roll back and propagate.

    collector_id identifies the machine reading the logs, not the target host
    in a log line. Keep it stable when moving to a different rsyslog file path.
    Use a dedicated connection with autocommit=False, as get_connection provides.
    """
    if (not isinstance(collector_id, str) or not collector_id.strip()
            or len(collector_id) > 255):
        raise ValueError("collector_id must be a nonempty string of at most 255 characters.")
    if type(max_lines) is not int or not 1 <= max_lines <= 100000:
        raise ValueError("Auth collection line limit must be within 1..100000.")
    if stats is None:
        stats = {}
    stats.update(lines_read=0, failures_recognized=0, duplicates=0)
    logfile = str(Path(logfile).resolve())
    lock_name = AUTH_WRITER_LOCK
    cursor = connection.cursor()
    locked = False
    try:
        cursor.execute("SELECT GET_LOCK(%s, 0)", (lock_name,))
        result = cursor.fetchone()
        if result is None or result[0] is None:
            raise AuthCollectionError("Unable to acquire the auth writer lock.")
        if result[0] != 1:
            raise AuthCollectionBusy("Another auth collector is running.")
        locked = True
        connection.begin()
        inserted = skipped = 0
        for filename in get_logfiles(logfile):
            remaining = max_lines - stats["lines_read"]
            if remaining <= 0:
                break
            try:
                new, ignored = process_file(cursor, filename, collector_id,
                                            stats=stats, line_limit=remaining)
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
        try:
            if locked:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
        finally:
            cursor.close()
