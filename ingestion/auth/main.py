"""One bounded auth.log collection pass for manual use or cron."""

import argparse
import io
import math
import os
import signal
import socket
import sys
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

import pymysql

from config.run_logging import close_log, open_log, report
from database.connection import get_connection
from ingestion.auth.collector import (
    AuthCollectionBusy,
    AuthCollectionError,
    check_source_format,
    collect_auth_events,
)
from ingestion.auth.parser import AuthParseError, validate_syslog_context


def stop_collection(signum, frame):
    """Make cron watchdog termination visible and let transaction cleanup run."""
    raise AuthCollectionError("Auth collection interrupted; retry from the committed checkpoint.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect supported SSH and local login events.")
    parser.add_argument("--logfile", default=os.getenv("SSH_AUTH_LOGFILE", "/var/log/auth.log"))
    parser.add_argument("--collector-id", default=os.getenv("SSH_AUTH_COLLECTOR_ID") or socket.gethostname())
    parser.add_argument("--allow-missing-source", action="store_true", help="Report a missing source as SKIPPED.")
    parser.add_argument("--check-source", action="store_true",
                        help="Check a bounded timestamp sample without a database or writes.")
    parser.add_argument("--max-lines", type=int, default=5000)
    parser.add_argument("--max-seconds", type=float, default=os.getenv("SSH_AUTH_MAX_SECONDS", "30"))
    parser.add_argument("--syslog-start", default=os.getenv("SSH_AUTH_SYSLOG_START") or None,
                        help="Administrator-verified source interval start, ISO 8601 with offset.")
    parser.add_argument("--syslog-end", default=os.getenv("SSH_AUTH_SYSLOG_END") or None,
                        help="Administrator-verified source interval end, ISO 8601 with offset.")
    parser.add_argument("--syslog-timezone", default=os.getenv("SSH_AUTH_SYSLOG_TIMEZONE") or None,
                        help="Administrator-verified IANA timezone for traditional syslog.")
    parser.add_argument("--log-file", help="Rotate at 1 MB, retaining three backups.")
    args = parser.parse_args(argv)
    if not 1 <= args.max_lines <= 100000:
        parser.error("--max-lines must be within 1..100000.")
    if not math.isfinite(args.max_seconds) or not 0 < args.max_seconds <= 50:
        parser.error("--max-seconds must be greater than 0 and at most 50.")
    context = (args.syslog_start, args.syslog_end, args.syslog_timezone)
    if any(context):
        if not all(context):
            parser.error("Traditional syslog requires start, end and timezone together.")
        try:
            args.syslog_start = datetime.fromisoformat(args.syslog_start.replace("Z", "+00:00"))
            args.syslog_end = datetime.fromisoformat(args.syslog_end.replace("Z", "+00:00"))
            args.syslog_start, args.syslog_end, args.syslog_timezone = validate_syslog_context(
                args.syslog_start, args.syslog_end, args.syslog_timezone)
        except (ValueError, OverflowError):
            parser.error("Invalid administrator-verified syslog context; maximum interval is 366 days.")
    try:
        logger, handler = open_log("mysql_siem.auth_collection", args.log_file)
    except OSError:
        print("Cannot open the Auth collection log.", file=sys.stderr)
        return 1
    previous_handler = signal.signal(signal.SIGTERM, stop_collection)
    connection = None
    stats = {}
    report(logger, f"Started: {datetime.now().isoformat(timespec='seconds')}")
    try:
        if args.allow_missing_source and not Path(args.logfile).exists():
            report(logger, "Status: SKIPPED - Auth log source is absent; collection state unchanged.")
            return 0
        if args.check_source:
            result = check_source_format(args.logfile, syslog_start=args.syslog_start,
                                         syslog_end=args.syslog_end,
                                         syslog_timezone=args.syslog_timezone)
            report(logger, f"Source timestamp sample: {result['lines_checked']} complete lines; {result['timestamps_checked']} timestamps verified.")
            if result["timestamps_checked"] == 0:
                report(logger, "Source timestamp check: INCONCLUSIVE - no timestamped complete records in the bounded sample.")
                return 2
            report(logger, "Source timestamp check: SUCCESS - bounded sample only; no collection state changed.")
            return 0
        with redirect_stdout(io.StringIO()):
            connection = get_connection()
        if connection is None:
            report(logger, "Auth collection: database connection failed.", error=True)
            report(logger, "Status: FAILED")
            return 1
        result = collect_auth_events(connection, args.logfile, collector_id=args.collector_id,
                                     stats=stats, max_lines=args.max_lines, max_seconds=args.max_seconds,
                                     syslog_start=args.syslog_start, syslog_end=args.syslog_end,
                                     syslog_timezone=args.syslog_timezone)
        report(logger, f"New auth events: {result['inserted']}; skipped lines: {result['skipped']}")
        report(logger, "Collection state updated: YES")
        if stats.get("coverage_gaps"):
            report(logger, "Auth coverage gap: compressed or missing rotations or a source reset prevent verification of complete history.", error=True)
            report(logger, "Status: PARTIAL - available records committed; historical coverage is unverified.")
        elif stats.get("budget_exhausted"):
            report(logger, "Status: PARTIAL - collection budget reached; remaining work retained.")
        else:
            report(logger, "Status: SUCCESS")
        return 0
    except AuthCollectionBusy:
        report(logger, "Status: SKIPPED - another auth collector holds the writer lock.")
        return 0
    except FileNotFoundError:
        if args.allow_missing_source:
            report(logger, "Status: SKIPPED - Auth source disappeared; collection state unchanged.")
            return 0
        report(logger, "Auth collection failed: log source is missing; check rsyslog/source configuration.", error=True)
        state_updated = stats.get("state_updated", "NO")
        report(logger, f"Collection state updated: {state_updated}")
        report(logger, "Status: FAILED")
        return 1
    except (AuthParseError, AuthCollectionError) as error:
        # These exceptions contain static reasons only, never source payloads.
        report(logger, f"Auth coverage gap: {error}", error=True)
        state_updated = stats.get("state_updated", "NO")
        report(logger, f"Collection state updated: {state_updated}")
        report(logger, "Status: FAILED")
        return 1
    except (OSError, pymysql.MySQLError, ValueError):
        report(logger, "Auth collection failed. Check migration, log access and identity configuration.", error=True)
        state_updated = stats.get("state_updated", "NO")
        report(logger, f"Collection state updated: {state_updated}")
        report(logger, "Status: FAILED")
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            if stats:
                report(logger, f"Log lines read: {stats.get('lines_read', 0)}")
                report(logger, f"SSH successes recognized: {stats.get('successes_recognized', 0)}")
                report(logger, f"SSH failures recognized: {stats.get('failures_recognized', 0)}")
                report(logger, f"Local logins recognized: {stats.get('local_logins_recognized', 0)}")
                report(logger, f"Unrecognized lines: {stats.get('unrecognized_lines', 0)}; invalid lines: {stats.get('invalid_lines', 0)}")
                report(logger, f"Duplicate events skipped: {stats.get('duplicates', 0)}")
                report(logger, f"Collection seconds: {stats.get('elapsed_seconds', 0):.3f}")
                if stats.get("state_updated") == "NO":
                    report(logger, "Remaining work: UNKNOWN - this collection pass was not committed.")
                else:
                    report(logger, f"Remaining observed bytes: {stats.get('remaining_bytes', 0)}; uninspected files: {stats.get('files_pending', 0)}")
                report(logger, f"Coverage gaps: {stats.get('coverage_gaps', 0)}; compressed rotations: {stats.get('compressed_rotations', 0)}; vanished rotations: {stats.get('vanished_rotations', 0)}; source resets: {stats.get('source_resets', 0)}")
                report(logger, f"Waiting for complete line: {stats.get('waiting_for_line', False)}")
            report(logger, f"Finished: {datetime.now().isoformat(timespec='seconds')}")
            close_log(logger, handler)
            signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())
