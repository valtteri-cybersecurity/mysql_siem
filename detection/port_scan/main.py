"""Run one automatic pass by default, or an explicit manual time range."""

import argparse
import io
import logging
import sys
from contextlib import redirect_stdout
from datetime import datetime
from logging.handlers import RotatingFileHandler

import pymysql

from database.connection import get_connection
from detection.common.alerts import AlertStorageError
from detection.port_scan.config import DetectionRunError, load_config
from detection.port_scan.db import get_db_data, validate_time_range
from detection.port_scan.detector import detect_port_scans
from detection.port_scan.formatting import build_alert
from detection.port_scan.runner import run_automatic, store_detection
from detection.port_scan.state import acquire_lock, release_lock

__all__ = ["build_alert", "main", "run_detection"]


def run_detection(connection, start_time, end_time):
    """Use a dedicated connection; each alert is an independent transaction."""
    events = get_db_data(connection, start_time, end_time)
    connection.rollback()  # Release the read snapshot before saving alerts.
    detections = detect_port_scans(events)
    summary = {
        "events_analyzed": len(events),
        "scans_detected": len(detections),
        "new_alerts_saved": 0,
        "existing_alerts_skipped": 0,
        "alerts_updated": 0,
    }
    for detection in detections:
        committed = False
        try:
            connection.begin()
            outcome = store_detection(connection, detection)
            connection.commit()
            committed = True
            summary[outcome] += 1
        finally:
            if not committed:
                connection.rollback()
    return summary


def report(logger, message, *, error=False):
    if logger is None:
        print(message, file=sys.stderr if error else sys.stdout)
    elif error:
        logger.error(message)
    else:
        logger.info(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run port-scan detection once.")
    parser.add_argument(
        "--start",
        type=datetime.fromisoformat,
        help="Inclusive manual start in the UFW naive time basis.",
    )
    parser.add_argument(
        "--end", type=datetime.fromisoformat, help="Exclusive manual end."
    )
    parser.add_argument(
        "--log-file", help="Rotate this log at 1 MB; retain three backups."
    )
    args = parser.parse_args(argv)
    manual = args.start is not None or args.end is not None
    if manual:
        try:
            validate_time_range(args.start, args.end)
        except ValueError as error:
            parser.error(str(error))

    logger = None
    handler = None
    if args.log_file:
        try:
            handler = RotatingFileHandler(
                args.log_file, maxBytes=1000000, backupCount=3, encoding="utf-8"
            )
        except OSError:
            print("Cannot open the port-scan log file.", file=sys.stderr)
            return 1
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger = logging.getLogger("mysql_siem.port_scan")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(handler)

    connection = None
    manual_locked = False
    report(logger, "Port Scan Detection")
    report(logger, f"Started: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    try:
        config = load_config() if not manual else None
        # The shared connector prints its own connection status. This entry point
        # reports status itself so cron can write only to the bounded log.
        with redirect_stdout(io.StringIO()):
            connection = get_connection()
        if connection is None:
            report(
                logger, "Port scan detection: database connection failed.", error=True
            )
            report(logger, "Detection state updated: NO")
            report(logger, "Status: FAILED")
            return 1
        if manual:
            manual_locked = acquire_lock(connection)
            if not manual_locked:
                report(
                    logger, "Status: SKIPPED - another port-scan run holds the lock."
                )
                return 0
            summary = run_detection(connection, args.start, args.end)
        else:
            summary = run_automatic(connection, config)
        if "new_events_fetched" in summary:
            report(logger, f"New UFW events fetched: {summary['new_events_fetched']}")
        report(logger, f"UFW events analyzed: {summary['events_analyzed']}")
        report(logger, f"Port scans detected: {summary['scans_detected']}")
        report(logger, f"New alerts saved: {summary['new_alerts_saved']}")
        report(logger, f"Existing alerts skipped: {summary['existing_alerts_skipped']}")
        report(logger, f"Alerts updated: {summary.get('alerts_updated', 0)}")
        report(
            logger,
            "Detection state updated: "
            + ("YES" if summary.get("state_updated") else "NO"),
        )
        report(logger, "Status: " + summary.get("status", "SUCCESS"))
        if summary.get("reason"):
            report(logger, summary["reason"])
        return 0
    except (pymysql.MySQLError, AlertStorageError, DetectionRunError) as error:
        message = "Port scan detection failed. Check schema, permissions, limits and rule settings."
        if isinstance(error, DetectionRunError):
            message = str(error)
        report(logger, message, error=True)
        report(logger, "Detection state updated: NO")
        report(logger, "Status: FAILED")
        return 1
    finally:
        try:
            if connection is not None:
                try:
                    if manual_locked:
                        release_lock(connection)
                finally:
                    connection.close()
        finally:
            report(
                logger,
                f"Finished: {datetime.now().isoformat(sep=' ', timespec='seconds')}",
            )
            if handler is not None:
                logger.removeHandler(handler)
                handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
