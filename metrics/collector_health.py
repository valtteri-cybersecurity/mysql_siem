"""Bounded health records for the local snapshot collectors."""

import json
import time
from contextlib import contextmanager

import psutil
import pymysql

from config.run_logging import report
from database.identity import IdentityError
from metrics.snapshot import (
    CollectionBusy,
    ObservationError,
    ResourceLimitError,
    SnapshotError,
    begin_snapshot_transaction,
    release_snapshot_lock,
    utc_now,
)

ERROR_CODES = frozenset((
    'SOURCE_UNAVAILABLE', 'PERMISSION_DENIED', 'OBSERVATION_TIMEOUT', 'INCOMPLETE_OBSERVATION',
    'INVALID_OBSERVATION', 'DATABASE_ERROR', 'IDENTITY_ERROR', 'COLLECTION_BUSY', 'UNKNOWN_ERROR',
))
STATUSES = ('SUCCESS', 'PARTIAL', 'FAILED', 'SKIPPED')
COVERAGE_FIELDS = {
    'processes': ('visible_pid_count', 'identified_process_count', 'incomplete_process_count',
                  'unverified_identity_count', 'partial_metadata_count', 'unknown_parent_count',
                  'unverified_executable_count'),
    'services': ('inventory_count', 'optional_metadata_missing_count', 'systemctl_failed_queries',
                 'systemctl_timeouts', 'uncertain_inventory_count'),
}
DELTA_FIELDS = ('added', 'changed', 'removed', 'unchanged')
MAX_TRANSITIONS = 16
MAX_COUNT = 2**32 - 1


def error_code(error):
    if isinstance(error, CollectionBusy):
        return 'COLLECTION_BUSY'
    if isinstance(error, IdentityError):
        return 'IDENTITY_ERROR'
    if isinstance(error, pymysql.MySQLError):
        return 'DATABASE_ERROR'
    if isinstance(error, (PermissionError, psutil.AccessDenied)):
        return 'PERMISSION_DENIED'
    if isinstance(error, TimeoutError):
        return 'OBSERVATION_TIMEOUT'
    if isinstance(error, ObservationError) and error.code in ERROR_CODES:
        return error.code
    if isinstance(error, (OSError, psutil.Error)):
        return 'SOURCE_UNAVAILABLE'
    if isinstance(error, ValueError):
        return 'INVALID_OBSERVATION'
    return 'UNKNOWN_ERROR'


def checked_count(value):
    if type(value) is not int or not 0 <= value <= MAX_COUNT:
        raise SnapshotError('Invalid collector health counter.')
    return value


class Attempt:
    def __init__(self, kind):
        self.kind = kind
        self.started = time.monotonic_ns()
        self.identity = None
        self.generation = None
        self.replayed = False
        self.coverage = {}
        self.delta_counts = (None, None, None, None)

    def bind(self, connection, identity):
        with connection.cursor() as cursor:
            # Read the generation before trying the named lock. A delayed skip can
            # then detect an outcome committed since its unsuccessful attempt.
            cursor.execute(
                "SELECT (SELECT status FROM schema_migrations WHERE version = '041'), "
                "COALESCE((SELECT generation FROM collector_health "
                "WHERE host_id = %s AND source_id = %s AND collector_type = %s), 0)",
                (identity.host_id, identity.source_id, self.kind),
            )
            status, generation = cursor.fetchone()
        if status != 'APPLIED':
            raise IdentityError('Collector health migration is incomplete.')
        self.identity = identity
        self.generation = generation

    def set_delta(self, delta):
        counts = []
        for field in DELTA_FIELDS:
            counts.append(len(delta[field]))
        self.delta_counts = tuple(counts)
        added, changed, _, unchanged = counts
        self.coverage.setdefault('observed_count', added + changed + unchanged)

    def write(self, connection, status, code=None):
        if status not in STATUSES or (status == 'SUCCESS' and code is not None):
            raise SnapshotError('Invalid collector health status.')
        if status != 'SUCCESS' and code not in ERROR_CODES:
            raise SnapshotError('Invalid collector health error code.')
        identity = self.identity
        observed_count = self.coverage.get('observed_count')
        if observed_count is not None:
            observed_count = checked_count(observed_count)
        coverage = {}
        if self.coverage.get('resource_limit_exceeded'):
            coverage['resource_limit_exceeded'] = 1
        for field in COVERAGE_FIELDS[self.kind]:
            if field in self.coverage:
                coverage[field] = checked_count(self.coverage[field])
        counts = (None, None, None, None)
        if status == 'SUCCESS':
            counts = self.delta_counts
        completed = utc_now()
        duration = max(0, (time.monotonic_ns() - self.started) // 1_000_000)
        scope = (identity.host_id, identity.source_id, self.kind)
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT generation, status, error_code, consecutive_failures, transitions FROM collector_health '
                'WHERE host_id = %s AND source_id = %s AND collector_type = %s FOR UPDATE', scope,
            )
            previous = cursor.fetchone()
            generation, old_status, old_code, failures, transitions = 0, None, None, 0, []
            if previous is not None:
                generation, old_status, old_code, failures, stored = previous
                transitions = json.loads(stored)
            if status == 'SKIPPED':
                if generation != self.generation:
                    return
            else:
                generation += 1
            if status == 'SUCCESS':
                failures = 0
            elif status in ('FAILED', 'PARTIAL'):
                failures = min(MAX_COUNT, failures + 1)
            if (status, code) != (old_status, old_code):
                transitions.append({'at': completed.isoformat() + 'Z', 'status': status, 'error_code': code})
                transitions = transitions[-MAX_TRANSITIONS:]
            cursor.execute(
                'INSERT INTO collector_health (host_id, source_id, collector_type, collector_id, generation, '
                'last_attempt_at, status, error_code, consecutive_failures, duration_ms, observed_count, '
                'added_count, changed_count, removed_count, unchanged_count, coverage, transitions) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) '
                'ON DUPLICATE KEY UPDATE collector_id = VALUES(collector_id), generation = VALUES(generation), '
                'last_attempt_at = VALUES(last_attempt_at), status = VALUES(status), error_code = VALUES(error_code), '
                'consecutive_failures = VALUES(consecutive_failures), duration_ms = VALUES(duration_ms), '
                'observed_count = VALUES(observed_count), added_count = VALUES(added_count), '
                'changed_count = VALUES(changed_count), removed_count = VALUES(removed_count), '
                'unchanged_count = VALUES(unchanged_count), coverage = VALUES(coverage), '
                'transitions = VALUES(transitions)',
                scope + (identity.collector_id, generation, completed, status, code, failures, duration, observed_count)
                + counts + (json.dumps(coverage), json.dumps(transitions)),
            )


def report_failed_attempt(connection, attempt, lock, error, logger, committing):
    if committing:
        report(logger, f'{attempt.kind}: snapshot commit outcome is unknown.', error=True)
    try:
        connection.rollback()
        if committing:
            return
        if attempt.identity is None or not isinstance(error, Exception):
            return
        status = 'FAILED'
        if isinstance(error, CollectionBusy):
            status = 'SKIPPED'
        elif lock is None:
            return
        elif isinstance(error, ObservationError) and error.partial:
            status = 'PARTIAL'
        if isinstance(error, ResourceLimitError):
            attempt.coverage['resource_limit_exceeded'] = 1
        begin_snapshot_transaction(connection)
        attempt.write(connection, status, error_code(error))
        connection.commit()
    except (pymysql.MySQLError, SnapshotError) as health_error:
        report(logger, f'{attempt.kind}: health record unavailable ({error_code(health_error)}).', error=True)
        try:
            connection.rollback()
        except pymysql.MySQLError:
            pass


@contextmanager
def collection(connection, kind, begin, logger=None):
    attempt = Attempt(kind)
    lock = None
    committing = False
    failed = False
    try:
        identity, previous, checkpoint, lock = begin(connection, attempt)
        yield attempt, identity, previous, checkpoint
        if attempt.replayed:
            connection.rollback()
            return
        attempt.write(connection, 'SUCCESS')
        committing = True
        connection.commit()
    except BaseException as error:
        failed = True
        report_failed_attempt(connection, attempt, lock, error, logger, committing)
        raise
    finally:
        try:
            release_snapshot_lock(connection, lock)
        except (pymysql.MySQLError, SnapshotError):
            if not failed:
                raise
