"""Shared CLI for UFW source-IP and destination-port activity summaries."""

import argparse
import io
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta

import pymysql

from analysis.ufw.ports import PortAnalysisError, run_port_analysis
from analysis.ufw.source_ips import (
    MAX_EVENTS,
    SourceIPAnalysisError,
    run_source_ip_analysis,
    validate_time_range,
)
from config.run_logging import close_log, open_log, report
from database.connection import get_connection


def recent_hour_periods(now, hours=2):
    """Stable hourly keys, including the current provisional hour; no full backfill."""
    if not isinstance(now, datetime) or now.tzinfo is not None or now.year < 1000:
        raise ValueError("Use the local naive UFW time basis.")
    if type(hours) is not int or not 1 <= hours <= 24:
        raise ValueError("--recent-hours must be within 1..24.")
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    start = end - timedelta(hours=hours)
    return [(start + timedelta(hours=index), start + timedelta(hours=index + 1)) for index in range(hours)]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build descriptive UFW source-IP and port summaries.")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--source-ips", action="store_true", help="Source IP Analysis (legacy default).")
    selection.add_argument("--ports", action="store_true", help="Port Activity Analysis only.")
    selection.add_argument("--all", action="store_true", help="Run both analyses; each interval saves independently.")
    parser.add_argument("--start", type=datetime.fromisoformat, help="Inclusive start in the naive UFW time basis.")
    parser.add_argument("--end", type=datetime.fromisoformat, help="Exclusive end in the same time basis.")
    parser.add_argument("--recent-hours", type=int, help="Refresh 1..24 hourly buckets; default: 2 for source IPs, 3 for ports/all.")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS, help="Raw-row limit per interval; default: 100000.")
    parser.add_argument("--log-file", help="Rotate at 1 MB with three backups.")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.max_events <= 1000000:
            raise ValueError("--max-events must be within 1..1000000.")
        if args.start is not None or args.end is not None:
            if args.recent_hours is not None:
                raise ValueError("Use a manual interval or --recent-hours, not both.")
            validate_time_range(args.start, args.end)
            periods = [(args.start, args.end)]
        else:
            periods = recent_hour_periods(datetime.now(), args.recent_hours if args.recent_hours is not None else (3 if args.ports or args.all else 2))
    except (ValueError, OverflowError) as error:
        parser.error(str(error))
    try:
        logger, handler = open_log("mysql_siem.analysis.ufw", args.log_file)
    except OSError:
        print("Cannot open the UFW analysis log.", file=sys.stderr)
        return 1
    analyses = []
    if args.source_ips or args.all or not args.ports:
        analyses.append(("Source IP Analysis", run_source_ip_analysis))
    if args.ports or args.all:
        analyses.append(("Port Activity Analysis", run_port_analysis))
    connection = None
    report(logger, f"Started: {datetime.now().isoformat(timespec='seconds')}")
    try:
        with redirect_stdout(io.StringIO()):
            connection = get_connection()
        if connection is None:
            report(logger, "UFW analysis: database connection failed.", error=True)
            report(logger, "Status: FAILED")
            return 1
        for name, run_analysis in analyses:
            for start, end in periods:
                report(logger, f"Analysis: {name}")
                report(logger, f"Period: {start.isoformat(sep=' ')} <= event_time < {end.isoformat(sep=' ')}")
                summary = run_analysis(connection, start, end, max_events=args.max_events)
                if "source_count" in summary:
                    report(logger, f"Source IPs: {summary['source_count']}; valid-source events: {summary['total_events']}")
                else:
                    report(logger, f"Port groups: {summary['group_count']}; accepted events: {summary['total_events']}")
                report(logger, f"Status: {summary['status']}")
                if summary.get("reason"):
                    report(logger, summary["reason"])
                    break
        return 0
    except (pymysql.MySQLError, SourceIPAnalysisError, PortAnalysisError) as error:
        message = "UFW analysis failed. Check migrations 009/011, permissions and the row limit."
        if isinstance(error, (SourceIPAnalysisError, PortAnalysisError)):
            message = str(error)
        report(logger, message, error=True)
        report(logger, "Status: FAILED; uncommitted changes were rolled back. Completed intervals may be committed.")
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
