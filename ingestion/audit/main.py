"""Manual metadata preview or one registered, transactional Audit collection."""

import argparse
import json
import os
import sys
from datetime import datetime

import pymysql

from config.run_logging import close_log, open_log, report
from database.connection import get_connection
from ingestion.audit import database
from ingestion.audit.get import read_batch, read_log_batch, runtime_health
from ingestion.audit.parser import parse_events


def collect(*, targets=None, **settings):
    batch = read_batch(**settings)
    parsed = parse_events(batch["output"], source_id=batch["source_id"],
                          targets=targets, max_events=batch["max_events"])
    if parsed["issues"]:
        return {"events": parsed["events"], "issues": parsed["issues"],
                "checkpoint": None, "coverage": "invalid_or_incomplete"}
    events = []
    for event in parsed["events"]:
        if batch["start"] <= event["event_time"] < batch["end"]:
            events.append(event)
    anchor = batch["anchor"]
    for candidate in parsed["anchors"]:
        # Ausearch end times include the boundary second; keep the window half-open.
        instant = datetime.fromisoformat(candidate["event_time"])
        if (batch["start"] <= instant < batch["end"]
                and (anchor is None or instant >= datetime.fromisoformat(anchor["event_time"]))):
            anchor = candidate
    checkpoint = {
        "version": 1, "source_id": batch["source_id"], "until": batch["end"].isoformat(),
        "anchor": anchor, "lost": batch["status"]["lost"], "boot_id": batch["status"]["boot_id"],
    }
    return {"events": events, "issues": [], "checkpoint": checkpoint,
            "coverage": "anchor_available" if anchor is not None else "retention_unverified"}


def collect_to_mysql(connection, *, logfile=None, **limits):
    """One approved writer commits events and its proposed position together."""
    if logfile is None:
        logfile = os.environ.get('SIEM_AUDIT_LOGFILE', '/var/log/audit/audit.log')
    lock = None
    try:
        identity, lock = database.begin_collection(connection)
        if identity is None:
            return {'status': 'busy', 'inserted': 0}
        with connection.cursor() as cursor:
            targets = database.load_targets(cursor)
            checkpoint = database.load_checkpoint(cursor, identity)
        batch = read_log_batch(logfile=logfile, checkpoint=checkpoint, source_id=str(identity.source_id),
                               health=runtime_health(), targets=targets, **limits)
        parsed = parse_events(batch['output'], source_id=str(identity.source_id), targets=targets,
                              max_events=limits.get('max_events', 1000))
        if parsed['issues']:
            raise ValueError('Audit batch is incomplete; no position committed.')
        with connection.cursor() as cursor:
            inserted = database.save_batch(cursor, identity, parsed['events'], batch['checkpoint'])
        connection.commit()
        return {'status': 'pending' if batch['pending'] or batch['limited'] else 'success',
                'inserted': inserted, 'duplicates': len(parsed['events']) - inserted,
                'bytes_read': batch['bytes_read'], 'initial': batch['initial']}
    except BaseException:
        connection.rollback()
        raise
    finally:
        database.release_lock(connection, lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read one Linux Audit development batch.")
    parser.add_argument("--show-events", action="store_true", help="Print selected metadata only.")
    parser.add_argument("--limit", type=int, default=10, help="Maximum displayed events (0..20).")
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument('--automatic', action='store_true', help='Collect to MySQL with transactional file positions.')
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)
    if not 0 <= args.limit <= 20:
        parser.error("--limit must be within 0..20.")
    if args.automatic and args.show_events:
        parser.error('--show-events is only available for development collection.')
    connection = logger = handler = None
    try:
        if args.automatic:
            if os.geteuid() == 0:
                raise ValueError('Audit database collection must not run as root.')
            logger, handler = open_log('mysql_siem.audit', args.log_file)
            connection = get_connection(quiet=True)
            if connection is None:
                raise RuntimeError('Audit database connection failed.')
            result = collect_to_mysql(connection)
            report(logger, 'Audit collection: ' + json.dumps(result, sort_keys=True))
            return 75 if result['status'] == 'busy' else 0
        result = collect(window_seconds=args.window_seconds)
        if result["issues"]:
            print(f'Audit collection incomplete: {len(result["issues"])} issues; no checkpoint.', file=sys.stderr)
            return 1
        print(f'Audit events: {len(result["events"])}; coverage: {result["coverage"]}; checkpoint not saved.')
        if args.show_events:
            for event in result["events"][:args.limit]:
                printable = dict(event)
                printable["event_time"] = event["event_time"].isoformat()
                print(json.dumps(printable, ensure_ascii=True))
        return 0
    except KeyboardInterrupt:
        print("Audit collection interrupted; checkpoint not saved.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError, TypeError, pymysql.MySQLError):
        # Never expose subprocess diagnostics or raw log data to development output.
        report(logger, 'Audit collection failed; checkpoint not advanced. '
               'Check identity, source/rotation integrity, read permissions and database.', error=True)
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            close_log(logger, handler)


if __name__ == "__main__":
    raise SystemExit(main())
