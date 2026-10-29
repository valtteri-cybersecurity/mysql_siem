"""Content-verified file generations and UTC diagnostics; no legacy state resets."""
import hashlib
import os
import stat
import time

CHUNK = 65536
MAX_FILES = 256


def digest_prefix(source, size, deadline):
    source.seek(0)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('CHECKPOINT_VERIFY_TIME_LIMIT')
        block = source.read(min(CHUNK, remaining))
        if not block:
            raise OSError('SOURCE_CHANGED')
        digest.update(block)
        remaining -= len(block)
    return digest


def gap(cursor, scope, checkpoint, reason, filename):
    key = hashlib.sha256((str(checkpoint) + ':' + reason + ':' + filename).encode()).hexdigest()
    cursor.execute('INSERT INTO ufw_collection_gaps '
                   '(source_scope,gap_key,checkpoint_id,reason,detected_at) VALUES (%s,%s,%s,%s,UTC_TIMESTAMP(6)) '
                   'ON DUPLICATE KEY UPDATE gap_key=VALUES(gap_key)', (scope, key, checkpoint, reason))


def start(cursor, source, filename, info, scope, deadline):
    """Verify the entire observed snapshot and the committed prefix before seeking."""
    observed = digest_prefix(source, info.st_size, deadline).hexdigest()
    cursor.execute('SELECT id,byte_position,prefix_sha,observed_size,observed_sha,status '
                   'FROM ufw_file_checkpoints WHERE source_scope=%s AND file_device=%s AND file_inode=%s '
                   'ORDER BY id DESC LIMIT 1', (scope, info.st_dev, info.st_ino))
    row = cursor.fetchone()
    checkpoint = None
    position = 0
    if row is not None:
        checkpoint, position, prefix, old_size, old_sha, status = row
        same = status not in ('SUPERSEDED', 'RECOVERED') and position <= info.st_size
        if same:
            same = old_size <= info.st_size
        if same:
            same = digest_prefix(source, old_size, deadline).hexdigest() == old_sha
        if same:
            same = digest_prefix(source, position, deadline).hexdigest() == prefix
        if not same:
            gap(cursor, scope, checkpoint, 'CONTENT_CHANGED', filename)
            cursor.execute("UPDATE ufw_file_checkpoints SET status='SUPERSEDED' WHERE id=%s AND source_scope=%s",
                           (checkpoint, scope))
            checkpoint = None
            position = 0
    else:
        cursor.execute('SELECT last_position FROM ufw_state WHERE source_scope=%s AND file_device=%s AND file_inode=%s',
                       (scope, info.st_dev, info.st_ino))
        if cursor.fetchone() is not None:
            # No content proof existed. Replay the retained source, preserving the old row.
            gap(cursor, scope, 0, 'LEGACY_UNVERIFIED', filename)
    prefix_hash = digest_prefix(source, position, deadline)
    source.seek(position)
    return checkpoint, prefix_hash, observed


def finish(cursor, source, filename, info, scope, checkpoint, prefix_hash, observed, deadline):
    position = source.tell()
    # Appends are allowed; replacement or changes to any observed byte are not.
    before = os.fstat(source.fileno())
    if digest_prefix(source, position, deadline).hexdigest() != prefix_hash.hexdigest():
        raise OSError('SOURCE_CHANGED')
    if digest_prefix(source, info.st_size, deadline).hexdigest() != observed:
        raise OSError('SOURCE_CHANGED')
    current = os.fstat(source.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
        if current.st_size > before.st_size:
            raise TimeoutError('SOURCE_UNSTABLE_DURING_VERIFICATION')
        raise OSError('SOURCE_CHANGED')
    try:
        named = os.stat(filename, follow_symlinks=False)
    except FileNotFoundError:
        named = None
    if named is None or not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
        from ingestion.ufw_to_mysql import get_logfiles
        named = None
        candidates = get_logfiles()
        if len(candidates) > MAX_FILES:
            raise OSError('SOURCE_REPLACED')
        for candidate in candidates:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('CHECKPOINT_VERIFY_TIME_LIMIT')
            try:
                candidate_info = os.stat(candidate, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(candidate_info.st_mode) and (candidate_info.st_dev, candidate_info.st_ino) == (info.st_dev, info.st_ino):
                filename = candidate
                named = candidate_info
                break
        if named is None:
            raise OSError('SOURCE_REPLACED')
    if current.st_size < info.st_size:
        raise OSError('SOURCE_CHANGED')
    status = 'READING'
    if position == current.st_size:
        status = 'CAUGHT_UP'
    values = (filename, position, prefix_hash.hexdigest(), info.st_size, observed, status)
    if checkpoint is None:
        cursor.execute('INSERT INTO ufw_file_checkpoints '
                       '(filename,byte_position,prefix_sha,observed_size,observed_sha,status,source_scope,file_device,file_inode,checked_at) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))',
                       values + (scope, info.st_dev, info.st_ino))
    else:
        cursor.execute('UPDATE ufw_file_checkpoints SET filename=%s,byte_position=%s,prefix_sha=%s,'
                       'observed_size=%s,observed_sha=%s,status=%s,checked_at=UTC_TIMESTAMP(6) '
                       'WHERE id=%s AND source_scope=%s', values + (checkpoint, scope))
    source.seek(position)
    return status


def prove_archive(cursor, source, scope, archive_sha, size, deadline):
    """A rotated file may have grown after its last observation. Verify its retained prefix."""
    cursor.execute("SELECT DISTINCT observed_size,observed_sha FROM ufw_file_checkpoints "
                   "WHERE source_scope=%s AND status <> 'RECOVERED' AND observed_size <= %s "
                   "ORDER BY observed_size LIMIT 256", (scope, size))
    now = time.monotonic()
    proof_deadline = now + min(0.5, max(0, deadline - now) / 4)
    for observed_size, observed_sha in cursor.fetchall():
        try:
            actual = digest_prefix(source, observed_size, proof_deadline).hexdigest()
        except TimeoutError:
            break  # Proof is optional; an unproved gap stays unresolved.
        if actual == observed_sha:
            cursor.execute('INSERT INTO ufw_archive_proofs (source_scope,archive_sha,expanded_size,expanded_sha) '
                           'VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE archive_sha=VALUES(archive_sha)',
                           (scope, archive_sha, observed_size, actual))


def reconcile(cursor, scope, filenames, deadline):
    """Record unavailable generations; only a CRC-verified, fully committed archive resolves them."""
    available = set()
    for filename in filenames:
        if time.monotonic() >= deadline:
            return False
        try:
            info = os.stat(filename, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            available.add((info.st_dev, info.st_ino))
    cursor.execute("SELECT id,file_device,file_inode,filename,observed_size,observed_sha,status "
                   "FROM ufw_file_checkpoints WHERE source_scope=%s AND status <> 'RECOVERED' "
                   "ORDER BY checked_at DESC LIMIT 257", (scope,))
    rows = cursor.fetchall()
    if len(rows) > MAX_FILES:
        return False
    for checkpoint, device, inode, filename, size, digest, status in rows:
        if time.monotonic() >= deadline:
            return False
        if (device, inode) in available and status != 'SUPERSEDED':
            continue
        cursor.execute("SELECT 1 FROM ufw_archive_proofs p JOIN ufw_archives a "
                       "ON a.source_scope=p.source_scope AND a.archive_sha=p.archive_sha "
                       "WHERE p.source_scope=%s AND p.expanded_size=%s AND p.expanded_sha=%s "
                       "AND a.status='COMPLETE' LIMIT 1", (scope, size, digest))
        retained = cursor.fetchone() == (1,)
        if not retained:
            cursor.execute('SELECT 1 FROM ufw_file_checkpoints WHERE source_scope=%s AND id <> %s '
                           'AND observed_size=%s AND observed_sha=%s AND byte_position >= %s LIMIT 1',
                           (scope, checkpoint, size, digest, size))
            retained = cursor.fetchone() == (1,)
        if retained:
            cursor.execute("UPDATE ufw_collection_gaps SET resolved=TRUE WHERE source_scope=%s AND checkpoint_id=%s "
                           "AND reason IN ('MISSING_SOURCE','CONTENT_CHANGED')", (scope, checkpoint))
            cursor.execute("UPDATE ufw_file_checkpoints SET status='RECOVERED' WHERE source_scope=%s AND id=%s",
                           (scope, checkpoint))
        elif (device, inode) not in available:
            gap(cursor, scope, checkpoint, 'MISSING_SOURCE', filename)
    return True


def mark_running(connection, scope):
    # A killed process must leave UNKNOWN, not the preceding pass's HEALTHY state.
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO ufw_collection_health "
                       "(source_scope,active_state,pending_archives,stop_reason,active_lines,archive_lines,pass_number) "
                       "VALUES (%s,'UNKNOWN',0,'running',0,0,1) ON DUPLICATE KEY UPDATE "
                       "active_state='UNKNOWN',stop_reason='running',pass_number=pass_number+1", (scope,))
        cursor.execute('SELECT logfile FROM ufw_state WHERE source_scope=%s LIMIT 256', (scope,))
        for row in cursor.fetchall():
            gap(cursor, scope, 0, 'LEGACY_UNVERIFIED', row[0])
    connection.commit()


def save_health(connection, scope, result, *, error=None):
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO ufw_collection_health '
                       '(source_scope,active_state,pending_archives,stop_reason,active_lines,archive_lines,plain_backlog) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE active_state=VALUES(active_state),'
                       'pending_archives=VALUES(pending_archives),stop_reason=VALUES(stop_reason),'
                       'active_lines=VALUES(active_lines),archive_lines=VALUES(archive_lines),plain_backlog=VALUES(plain_backlog)',
                       (scope, result.get('active_state', 'UNKNOWN'), result.get('archives_pending', 0),
                        result.get('stop_reason', 'error'), result.get('active_lines', 0), result.get('archive_lines', 0), result.get('plain_backlog', False)))
        if error is None:
            cursor.execute('UPDATE ufw_collection_health SET last_success=UTC_TIMESTAMP(6) '
                           'WHERE source_scope=%s', (scope,))
        else:
            cursor.execute('UPDATE ufw_collection_health SET last_failure=UTC_TIMESTAMP(6),error_class=%s '
                           'WHERE source_scope=%s', (error, scope))
    connection.commit()


def read_health(connection, scope):
    """SELECT only. HEALTHY concerns observed sources, never historical Traffic coverage.

    GAP_DETECTED: unresolved possible loss. DEGRADED: last pass failed.
    UNKNOWN: legacy proof, incomplete inventory or no observation. BACKLOG: available
    unfinished data. HEALTHY: no known problem or backlog in the last confirmed pass.
    """
    with connection.cursor() as cursor:
        cursor.execute('SELECT last_success,last_failure,error_class,active_state,pending_archives,stop_reason,'
                       'active_lines,archive_lines,plain_backlog FROM ufw_collection_health WHERE source_scope=%s', (scope,))
        row = cursor.fetchone()
        cursor.execute('SELECT reason,COUNT(*) FROM ufw_collection_gaps WHERE source_scope=%s AND resolved=FALSE '
                       'GROUP BY reason', (scope,))
        gaps = dict(cursor.fetchall())
    state = 'UNKNOWN'
    if row is not None:
        _success, _failure, error, active, pending, _stop, _active_lines, _archive_lines, plain_backlog = row
        state = 'HEALTHY'
        if active == 'BACKLOG' or pending or plain_backlog:
            state = 'BACKLOG'
        if active == 'UNKNOWN' or gaps.get('LEGACY_UNVERIFIED'):
            state = 'UNKNOWN'
        if error and (_success is None or (_failure is not None and _failure >= _success)):
            state = 'DEGRADED'
    gap_count = 0
    for reason, count in gaps.items():
        if reason != 'LEGACY_UNVERIFIED':
            gap_count += count
    if gap_count:
        state = 'GAP_DETECTED'
    result = {'state': state, 'gaps': gap_count}
    if row is not None:
        names = ('last_success_utc', 'last_failure_utc', 'last_error_class', 'active_state',
                 'pending_archives', 'stop_reason', 'active_lines', 'archive_lines', 'plain_backlog')
        for name, value in zip(names, row):
            result[name] = value
    return result
