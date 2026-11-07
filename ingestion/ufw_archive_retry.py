"""Explicit retry policy shared by extraction, ingestion and discovery diagnostics."""
from ingestion.ufw_archives import (
    MAX_ATTEMPTS,
    RETRY_SECONDS,
    TRANSIENT,
    manifest_reason,
)


def resume_due(cursor, scope):
    placeholders = ','.join(['%s'] * len(TRANSIENT))
    cursor.execute("SELECT archive_sha FROM ufw_archives WHERE source_scope=%s AND status='FAILED' "
                   'AND failure_reason IN (' + placeholders + ') AND retry_count<%s '
                   'AND retry_after<=UTC_TIMESTAMP(6) ORDER BY retry_after,archive_sha LIMIT 16',
                   (scope,) + TRANSIENT + (MAX_ATTEMPTS - 1,))
    for row in cursor.fetchall():
        cursor.execute("UPDATE ufw_archives SET status='PENDING',retry_count=retry_count+1,retry_after=NULL "
                       "WHERE source_scope=%s AND archive_sha=%s AND status='FAILED'", (scope, row[0]))


def failed(cursor, scope, digest, reason, *, complete=False):
    after = 'NULL'
    parameters = (reason, scope, digest)
    if reason in TRANSIENT:
        after = 'DATE_ADD(UTC_TIMESTAMP(6), INTERVAL %s SECOND)'
        parameters = (reason, RETRY_SECONDS, scope, digest)
    state = "status='FAILED',"
    if complete:
        state = ''  # Imported events remain complete even if source rechecking fails.
    cursor.execute('UPDATE ufw_archives SET ' + state + 'failure_reason=%s,retry_after=' + after +
                   ',checked_at=UTC_TIMESTAMP(6) WHERE source_scope=%s AND archive_sha=%s', parameters)


def adopt_legacy(cursor, scope, digest, record):
    # Old FAILED rows alone prove neither failure cause nor safety of replay.
    if record is None or record.get('status') != 'ERROR':
        return
    reason = manifest_reason(record)
    if reason not in TRANSIENT:
        return
    attempts = record.get('attempts')
    if attempts is None:
        restarts = record.get('restarts', 0)
        if type(restarts) is not int or not 0 <= restarts <= 1:
            return
        attempts = restarts + 1
    if type(attempts) is not int or not 1 <= attempts <= MAX_ATTEMPTS:
        return
    cursor.execute('UPDATE ufw_archives SET failure_reason=%s,retry_count=%s,'
                   'retry_after=DATE_ADD(UTC_TIMESTAMP(6), INTERVAL %s SECOND) '
                   "WHERE source_scope=%s AND archive_sha=%s AND status='FAILED' AND failure_reason IS NULL",
                   (reason, attempts - 1, RETRY_SECONDS, scope, digest))


def resolve(cursor, scope, digest):
    # Only a bound, explicitly transient discovery failure can be resolved.
    cursor.execute('UPDATE ufw_archives SET retry_after=NULL WHERE source_scope=%s AND archive_sha=%s '
                   "AND status='COMPLETE'", (scope, digest))
    cursor.execute('UPDATE ufw_archive_failures f JOIN ufw_archives a '
                   'ON a.source_scope=f.source_scope AND a.archive_sha=f.archive_sha '
                   'SET f.resolved_at=UTC_TIMESTAMP(6) WHERE f.source_scope=%s AND f.archive_sha=%s '
                   "AND f.retryable=1 AND f.resolved_at IS NULL AND a.status='COMPLETE'", (scope, digest))


def discovery_allowed(cursor, scope, info):
    cursor.execute('SELECT archive_sha,status,failure_reason,retry_count,retry_after IS NOT NULL,'
                   'retry_after<=UTC_TIMESTAMP(6) FROM ufw_archives WHERE source_scope=%s '
                   'AND file_device=%s AND file_inode=%s AND file_mtime_ns=%s '
                   'ORDER BY checked_at DESC LIMIT 1', (scope, info.st_dev, info.st_ino, info.st_mtime_ns))
    row = cursor.fetchone()
    if row is None or row[2] not in TRANSIENT:
        return True
    digest, status, _reason, attempts, waiting, due = row
    if status == 'FAILED':
        return False  # Only resume_due may promote this state.
    if status == 'COMPLETE' and waiting:
        if attempts >= MAX_ATTEMPTS - 1 or not due:
            return False
        cursor.execute('UPDATE ufw_archives SET retry_count=retry_count+1,'
                       'retry_after=DATE_ADD(UTC_TIMESTAMP(6), INTERVAL %s SECOND) '
                       'WHERE source_scope=%s AND archive_sha=%s', (RETRY_SECONDS, scope, digest))
    return True
