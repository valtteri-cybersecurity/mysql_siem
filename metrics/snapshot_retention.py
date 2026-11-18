"""Explicit, scoped retention for Process and Services observation summaries."""

import argparse
import json
from datetime import datetime, timedelta

import pymysql

from config.run_logging import report
from config.snapshot_policy import SnapshotSettingError, retention_policy
from database.connection import get_connection
from database.identity import validate_id
from metrics.measurement_window import TABLES as WINDOW_TABLES
from metrics.measurement_window import utc_datetime
from metrics.snapshot import (
    TABLES,
    CollectionBusy,
    SnapshotError,
    acquire_snapshot_lock,
    release_snapshot_lock,
    utc_now,
)


def validate_scope(cursor, kind, scope):
    cursor.execute('SELECT 1 FROM log_sources WHERE host_id = %s AND source_id = %s AND source_type = %s',
                   scope + (kind,))
    if cursor.fetchone() != (1,):
        raise SnapshotError('No registered snapshot source matches this scope.')


def expired_health(cursor, scope, kind, cutoff, apply):
    sql = 'SELECT transitions FROM collector_health WHERE host_id = %s AND source_id = %s AND collector_type = %s'
    if apply:
        sql += ' FOR UPDATE'
    args = scope + (kind,)
    cursor.execute(sql, args)
    row = cursor.fetchone()
    if row is None:
        return 0
    transitions = json.loads(row[0])
    kept = []
    for transition in transitions:
        try:
            observed_at = utc_datetime(datetime.fromisoformat(transition['at']))
        except (TypeError, ValueError, KeyError):
            raise SnapshotError('Invalid stored health transition timestamp.') from None
        if observed_at >= cutoff:
            kept.append(transition)
    expired = len(transitions) - len(kept)
    if apply and expired:
        cursor.execute('UPDATE collector_health SET transitions = %s '
                       'WHERE host_id = %s AND source_id = %s AND collector_type = %s', (json.dumps(kept),) + args)
    return expired


def window_retention(cursor, kind, scope, cutoff, detail_cutoff, batch_rows, apply):
    table, columns = WINDOW_TABLES[kind]
    cursor.execute(f'SELECT MAX(window_start) FROM {table} WHERE host_id = %s AND source_id = %s', scope)  # nosec B608
    latest, = cursor.fetchone()
    if latest is None:
        return 0, 0
    # The latest row is also the replay watermark. The window end is start + 5 minutes.
    window_filter = 'WHERE host_id = %s AND source_id = %s AND window_start < %s AND window_start <= %s'
    detail_columns = columns[1:]
    predicates = []
    resets = []
    for column in detail_columns:
        predicates.append(f'JSON_LENGTH({column}) > 0')
        resets.append(f'{column} = JSON_OBJECT()')
    detail_filter = window_filter + ' AND window_start > %s AND (' + ' OR '.join(predicates) + ')'
    where = scope + (latest, cutoff)
    detail_where = scope + (latest, detail_cutoff, cutoff)
    if not apply:
        cursor.execute(f'SELECT COUNT(*) FROM {table} {window_filter}', where)  # nosec B608
        windows, = cursor.fetchone()
        cursor.execute(f'SELECT COUNT(*) FROM {table} {detail_filter}', detail_where)  # nosec B608
        details, = cursor.fetchone()
        return windows, details

    cursor.execute(f'DELETE FROM {table} {window_filter} ORDER BY window_start LIMIT %s',  # nosec B608
                   where + (batch_rows,))
    windows = cursor.rowcount
    resets.append("metrics = JSON_SET(metrics, '$.details_expired', CAST('true' AS JSON))")
    cursor.execute(f'UPDATE {table} SET ' + ', '.join(resets) + f' {detail_filter} ORDER BY window_start LIMIT %s',  # nosec B608
                   detail_where + (batch_rows,))
    return windows, cursor.rowcount


def cleanup(connection, kind, host_id, source_id, policy, *, apply=False, now=None):
    """Preview expiry or commit one bounded batch per writable category."""
    if apply and not policy.enabled:
        raise SnapshotError('Snapshot retention writes require SIEM_SNAPSHOT_RETENTION_ENABLED=1.')
    scope = validate_id(host_id), validate_id(source_id)
    events = TABLES[kind][1]
    if now is None:
        now = utc_now()
    now = utc_datetime(now)
    lock = None
    failed = False
    started = False
    try:
        if apply:
            lock = acquire_snapshot_lock(connection, kind, host_id)
        with connection.cursor() as cursor:
            # SET TRANSACTION rejects an already open transaction. Starting
            # directly could implicitly commit the caller's pending work.
            if apply:
                cursor.execute('SET TRANSACTION READ WRITE')
            else:
                cursor.execute('SET TRANSACTION READ ONLY')
            connection.begin()
            started = True
            validate_scope(cursor, kind, scope)
            event_rows = None
            if not apply:
                cursor.execute(f'SELECT COUNT(*) FROM {events} '  # nosec B608
                               'WHERE host_id = %s AND source_id = %s AND event_time < %s',
                               scope + (now - timedelta(days=policy.event_days),))
                event_rows, = cursor.fetchone()
            windows, details = window_retention(
                cursor, kind, scope, now - timedelta(days=policy.window_days, minutes=5),
                now - timedelta(days=policy.detail_days, minutes=5), policy.batch_rows, apply,
            )
            health = expired_health(cursor, scope, kind, now - timedelta(days=policy.health_days), apply)
        if apply:
            connection.commit()
        else:
            connection.rollback()
        return event_rows, windows, details, health
    except BaseException:
        failed = True
        if started:
            try:
                connection.rollback()
            except pymysql.MySQLError:
                pass
        raise
    finally:
        try:
            release_snapshot_lock(connection, lock)
        except (pymysql.MySQLError, SnapshotError):
            if not failed:
                raise


def capacity_bytes(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.tables '
                       'WHERE table_schema = DATABASE() AND table_name IN (%s, %s, %s, %s, %s)',
                       ('process_events', 'service_events', 'process_measurement_windows',
                        'service_measurement_windows', 'collector_health'))
        return int(cursor.fetchone()[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description='Preview or apply one scoped snapshot retention batch.')
    parser.add_argument('--kind', choices=tuple(WINDOW_TABLES), required=True)
    parser.add_argument('--host-id', type=int, required=True)
    parser.add_argument('--source-id', type=int, required=True)
    parser.add_argument('--apply', action='store_true', help='Requires SIEM_SNAPSHOT_RETENTION_ENABLED=1.')
    args = parser.parse_args(argv)

    connection = None
    try:
        policy = retention_policy()
        if args.apply and not policy.enabled:
            raise SnapshotError('Snapshot retention writes require SIEM_SNAPSHOT_RETENTION_ENABLED=1.')
        connection = get_connection(quiet=True)
        if connection is None:
            raise SnapshotError('Database connection or configuration failed.')
        print(f'Retention days — security events {policy.event_days}, windows {policy.window_days}, '
              f'details {policy.detail_days}, health transitions {policy.health_days}.')
        size = capacity_bytes(connection)
        print(f'Snapshot history table estimate {size} bytes; warning level {policy.warning_mib} MiB.')
        if size >= policy.warning_mib * 1024 * 1024:
            report(None, 'Snapshot history exceeds the configured size warning level.', error=True)
        connection.rollback()
        events, windows, details, health = cleanup(
            connection, args.kind, args.host_id, args.source_id, policy, apply=args.apply,
        )
        if args.apply:
            print(f'Applied batch — window rows deleted {windows}, retained windows with details cleared {details}, '
                  f'health transitions removed {health}. Security events preserved.')
        else:
            print(f'Dry-run — aged security events (protected) {events}, window rows eligible {windows}, '
                  f'retained windows eligible for detail expiry {details}, eligible health transitions {health}.')
        return 0
    except CollectionBusy:
        report(None, 'Snapshot retention skipped because collection is active.', error=True)
        return 75
    except (pymysql.MySQLError, OSError):
        report(None, 'Snapshot retention database operation failed.', error=True)
        return 1
    except ValueError as error:
        # Only local validation errors carry a detailed message.
        if isinstance(error, (SnapshotError, SnapshotSettingError)):
            report(None, str(error), error=True)
        else:
            report(None, 'Invalid snapshot retention configuration or stored data.', error=True)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
