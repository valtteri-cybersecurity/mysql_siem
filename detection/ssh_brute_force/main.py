"""One automatic pass (--automatic), or an explicit manual UTC interval."""

import argparse
import io
import sys
from contextlib import redirect_stdout
from datetime import datetime

import pymysql

from config.run_logging import close_log, open_log, report
from database.connection import get_connection
from detection.common.alerts import AlertStorageError
from detection.ssh_brute_force.config import load_config
from detection.ssh_brute_force.db import SSHDetectionError, validate_time_range
from detection.ssh_brute_force.runner import run_automatic, run_detection


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run SSH brute-force detection once.")
    parser.add_argument("--automatic", action="store_true", help="Process one new ID batch and persist its tail.")
    parser.add_argument("--start", type=datetime.fromisoformat, help="Inclusive manual UTC start, without an offset.")
    parser.add_argument("--end", type=datetime.fromisoformat, help="Exclusive manual UTC end, without an offset.")
    parser.add_argument("--log-file", help="Rotate at 1 MB, retaining three backups.")
    args = parser.parse_args(argv)
    if args.automatic:
        if args.start is not None or args.end is not None:
            parser.error("Use --automatic or a manual interval, not both.")
    else:
        try:
            validate_time_range(args.start, args.end)
        except ValueError as error:
            parser.error(str(error))
    try:
        logger, handler = open_log("mysql_siem.ssh_detection", args.log_file)
    except OSError:
        print("Cannot open the SSH detection log.", file=sys.stderr)
        return 1
    connection = None
    report(logger, f"Started: {datetime.now().isoformat(timespec='seconds')}")
    try:
        config = load_config() if args.automatic else None
        with redirect_stdout(io.StringIO()):
            connection = get_connection()
        if connection is None:
            report(logger, "SSH detection: database connection failed.", error=True)
            report(logger, "Detection state updated: NO")
            report(logger, "Status: FAILED")
            return 1
        summary = (run_automatic(connection, config) if args.automatic
                   else run_detection(connection, args.start, args.end))
        report(logger, f"New SSH events fetched: {summary.get('new_events_fetched', 0)}")
        report(logger, f"SSH events analyzed: {summary['events_analyzed']}")
        report(logger, f"Brute-force episodes detected: {summary['detections_found']}")
        report(logger, f"New alerts saved: {summary['new_alerts_saved']}")
        report(logger, f"Alerts updated: {summary['alerts_updated']}")
        report(logger, f"Existing alerts skipped: {summary['existing_alerts_skipped']}")
        report(logger, "Detection state updated: " + ("YES" if summary.get("state_updated") else "NO"))
        report(logger, f"Status: {summary['status']}")
        if summary.get("reason"):
            report(logger, summary["reason"])
        return 0
    except (pymysql.MySQLError, AlertStorageError, SSHDetectionError) as error:
        message = "SSH detection failed. Check migrations 004/007/008, permissions and rule settings."
        if isinstance(error, SSHDetectionError):
            message = str(error)
        report(logger, message, error=True)
        if not args.automatic:
            report(logger, "Earlier manual alerts may already be committed; retrying is safe.", error=True)
        report(logger, "Detection state updated: NO")
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
