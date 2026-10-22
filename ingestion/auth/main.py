"""One bounded auth.log collection pass for manual use or cron."""

import argparse
import io
import os
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
    collect_auth_events,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect timestamped SSH password failures.")
    parser.add_argument("--logfile", default=os.getenv("SSH_AUTH_LOGFILE", "/var/log/auth.log"))
    parser.add_argument("--collector-id", default=os.getenv("SSH_AUTH_COLLECTOR_ID") or socket.gethostname())
    parser.add_argument("--allow-missing-source", action="store_true", help="Report a missing source as SKIPPED.")
    parser.add_argument("--max-lines", type=int, default=5000)
    parser.add_argument("--log-file", help="Rotate at 1 MB, retaining three backups.")
    args = parser.parse_args(argv)
    if not 1 <= args.max_lines <= 100000:
        parser.error("--max-lines must be within 1..100000.")
    try:
        logger, handler = open_log("mysql_siem.auth_collection", args.log_file)
    except OSError:
        print("Cannot open the SSH collection log.", file=sys.stderr)
        return 1
    connection = None
    report(logger, f"Started: {datetime.now().isoformat(timespec='seconds')}")
    try:
        if args.allow_missing_source and not Path(args.logfile).exists():
            report(logger, "Status: SKIPPED - SSH log source is absent; collection state unchanged.")
            return 0
        with redirect_stdout(io.StringIO()):
            connection = get_connection()
        if connection is None:
            report(logger, "Auth collection: database connection failed.", error=True)
            report(logger, "Status: FAILED")
            return 1
        stats = {"lines_read": 0, "failures_recognized": 0, "duplicates": 0}
        result = collect_auth_events(connection, args.logfile, collector_id=args.collector_id,
                                     stats=stats, max_lines=args.max_lines)
        report(logger, f"Log lines read: {stats['lines_read']}")
        report(logger, f"SSH failures recognized: {stats['failures_recognized']}")
        report(logger, f"New auth events: {result['inserted']}; skipped lines: {result['skipped']}")
        report(logger, f"Duplicate events skipped: {stats['duplicates']}")
        report(logger, "Collection state updated: YES")
        report(logger, "Status: SUCCESS")
        return 0
    except AuthCollectionBusy:
        report(logger, "Status: SKIPPED - another auth collector holds the writer lock.")
        return 0
    except FileNotFoundError:
        if args.allow_missing_source:
            report(logger, "Status: SKIPPED - SSH source disappeared; collection state unchanged.")
            return 0
        report(logger, "Auth collection failed: log source is missing.", error=True)
        report(logger, "Collection state updated: NO")
        report(logger, "Status: FAILED")
        return 1
    except (OSError, pymysql.MySQLError, AuthCollectionError, ValueError):
        report(logger, "Auth collection failed. Check migration, log access and configuration.", error=True)
        report(logger, "Collection state updated: NO")
        report(logger, "Status: FAILED")
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            report(logger, f"Finished: {datetime.now().isoformat(timespec='seconds')}")
            close_log(logger, handler)


if __name__ == "__main__":
    raise SystemExit(main())
