"""Content-verified file generations and UTC diagnostics; no legacy state resets."""
import hashlib
import os
import secrets
import stat
import time

CHUNK = 65536
MAX_FILES = 256


def digest_prefixes(source, sizes, deadline):
    """Hash several prefix boundaries in one bounded-memory forward pass."""
    source.seek(0)
    digest = hashlib.sha256()
    prefixes = {}
    position = 0
    for size in sorted(set(sizes)):
        if size < 0:
            raise ValueError('Negative UFW prefix size.')
        while position < size:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('CHECKPOINT_VERIFY_TIME_LIMIT')
            block = source.read(min(CHUNK, size - position))
            if not block:
                raise OSError('SOURCE_CHANGED')
            digest.update(block)
            position += len(block)
        prefixes[size] = digest.copy()
    return prefixes


def digest_prefix(source, size, deadline):
    return digest_prefixes(source, (size,), deadline)[size]


def gap(cursor, scope, checkpoint, reason, filename):
    key = hashlib.sha256((str(checkpoint) + ':' + reason + ':' + filename).encode()).hexdigest()
    cursor.execute('INSERT INTO ufw_collection_gaps '
                   '(source_scope,gap_key,checkpoint_id,reason,detected_at) VALUES (%s,%s,%s,%s,UTC_TIMESTAMP(6)) '
                   'ON DUPLICATE KEY UPDATE gap_key=VALUES(gap_key)', (scope, key, checkpoint, reason))


def start(cursor, source, filename, info, scope, deadline):
    """Verify the entire observed snapshot and the committed prefix before seeking."""
    cursor.execute('SELECT id,byte_position,prefix_sha,observed_size,observed_sha,status,generation_key,file_mtime_ns '
                   'FROM ufw_file_checkpoints WHERE source_scope=%s AND file_device=%s AND file_inode=%s '
                   'ORDER BY id DESC LIMIT 1', (scope, info.st_dev, info.st_ino))
    row = cursor.fetchone()
    sizes = [0, info.st_size]
    if row is not None:
        saved_position = row[1]
        saved_size = row[3]
        if saved_position <= info.st_size and saved_size <= info.st_size:
            sizes.extend((saved_position, saved_size))
    prefixes = digest_prefixes(source, sizes, deadline)
    observed = prefixes[info.st_size].hexdigest()
    checkpoint = None
    position = 0
    generation = None
    if row is not None:
        checkpoint, position, prefix, old_size, old_sha, status, generation, old_mtime = row
        if generation is None:
            cursor.execute("SELECT 1 FROM ufw_collection_gaps WHERE source_scope=%s AND checkpoint_id=%s "
                           "AND reason='MISSING_SOURCE' AND resolved=FALSE LIMIT 1", (scope, checkpoint))
            if cursor.fetchone() == (1,):
                from ingestion.ufw_batch import OccurrenceConflict
                raise OccurrenceConflict('UFW_UNVERIFIED_RECOVERY_GENERATION')
        same = status not in ('SUPERSEDED', 'RECOVERED') and position <= info.st_size
        if same:
            same = old_size <= info.st_size
        if same:
            same = prefixes[old_size].hexdigest() == old_sha
        if same:
            same = prefixes[position].hexdigest() == prefix
        if same and info.st_size == old_size and old_mtime is not None and info.st_mtime_ns != old_mtime:
            from ingestion.ufw_batch import OccurrenceConflict
            raise OccurrenceConflict('UFW_AMBIGUOUS_FILE_GENERATION')
        if not same:
            gap(cursor, scope, checkpoint, 'CONTENT_CHANGED', filename)
            cursor.execute("UPDATE ufw_file_checkpoints SET status='SUPERSEDED' WHERE id=%s AND source_scope=%s",
                           (checkpoint, scope))
            checkpoint = None
            position = 0
            generation = None
    else:
        cursor.execute('SELECT last_position FROM ufw_state WHERE source_scope=%s AND file_device=%s AND file_inode=%s',
                       (scope, info.st_dev, info.st_ino))
        if cursor.fetchone() is not None:
            # No content proof existed. Replay the retained source, preserving the old row.
            gap(cursor, scope, 0, 'LEGACY_UNVERIFIED', filename)
    prefix_hash = prefixes[position]
    source.seek(position)
    if generation is None:
        generation = secrets.token_bytes(32)
    return checkpoint, prefix_hash, observed, generation


def verify_snapshot(source, position, size, prefix_hash, observed, deadline):
    """Verify only the original ranges, never a concurrently appended tail."""
    prefixes = digest_prefixes(source, (position, size), deadline)
    if prefixes[position].hexdigest() != prefix_hash.hexdigest():
        raise OSError('SOURCE_CHANGED')
    if prefixes[size].hexdigest() != observed:
        raise OSError('SOURCE_CHANGED')


def finish(cursor, source, filename, info, scope, checkpoint, prefix_hash, observed, deadline, *, generation=None):
    position = source.tell()
    # Appends are allowed; replacement or changes to any observed byte are not.
    before = os.fstat(source.fileno())
    verify_snapshot(source, position, info.st_size, prefix_hash, observed, deadline)
    current = os.fstat(source.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
        if current.st_size <= before.st_size:
            raise OSError('SOURCE_CHANGED')
        # Growth may coincide with a rewrite behind the first read cursor.
        # Recheck once, under the original time budget. This final read must be
        # stable: growth alone cannot prove that earlier bytes were unchanged.
        before = current
        verify_snapshot(source, position, info.st_size, prefix_hash, observed, deadline)
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
    verified_generation = False
    if checkpoint is not None and generation is not None and status == 'CAUGHT_UP':
        cursor.execute('SELECT generation_key FROM ufw_file_checkpoints WHERE id=%s AND source_scope=%s',
                       (checkpoint, scope))
        verified_generation = cursor.fetchone() == (generation,)
    values = (filename, position, prefix_hash.hexdigest(), info.st_size, observed, status)
    if checkpoint is None:
        cursor.execute('INSERT INTO ufw_file_checkpoints '
                       '(filename,byte_position,prefix_sha,observed_size,observed_sha,status,source_scope,file_device,file_inode,checked_at) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))',
                       values + (scope, info.st_dev, info.st_ino))
        checkpoint = cursor.lastrowid
    else:
        cursor.execute('UPDATE ufw_file_checkpoints SET filename=%s,byte_position=%s,prefix_sha=%s,'
                       'observed_size=%s,observed_sha=%s,status=%s,checked_at=UTC_TIMESTAMP(6) '
                       'WHERE id=%s AND source_scope=%s', values + (checkpoint, scope))
    if generation is not None:
        cursor.execute('UPDATE ufw_file_checkpoints SET generation_key=%s,file_mtime_ns=%s '
                       'WHERE id=%s AND source_scope=%s',
                       (generation, current.st_mtime_ns, checkpoint, scope))
        if verified_generation:
            cursor.execute("UPDATE ufw_collection_gaps SET resolved=TRUE "
                           "WHERE source_scope=%s AND checkpoint_id=%s AND reason='MISSING_SOURCE'",
                           (scope, checkpoint))
    source.seek(position)
    return status


def record_proof(cursor, scope, archive_sha, size, digest):
    cursor.execute('SELECT expanded_sha FROM ufw_archive_proofs '
                   'WHERE source_scope=%s AND archive_sha=%s AND expanded_size=%s', (scope, archive_sha, size))
    row = cursor.fetchone()
    if row is None:
        cursor.execute('INSERT INTO ufw_archive_proofs (source_scope,archive_sha,expanded_size,expanded_sha) '
                       'VALUES (%s,%s,%s,%s)', (scope, archive_sha, size, digest))
    elif row != (digest,):
        from ingestion.ufw_batch import OccurrenceConflict
        raise OccurrenceConflict('UFW_ARCHIVE_PROOF_CHANGED')


def prove_archive(cursor, source, scope, archive_sha, size, deadline):
    """Record prefix-content matches, not proof of a checkpoint generation."""
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
            record_proof(cursor, scope, archive_sha, observed_size, actual)


def reconcile(cursor, scope, filenames, deadline):
    """Record missing generations without inferring lineage from equal content."""
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
                   "FROM ufw_file_checkpoints WHERE source_scope=%s AND status NOT IN ('RECOVERED','ARCHIVED') "
                   "ORDER BY checked_at DESC LIMIT 257", (scope,))
    rows = cursor.fetchall()
    if len(rows) > MAX_FILES:
        return False
    for checkpoint, device, inode, filename, size, digest, status in rows:
        if time.monotonic() >= deadline:
            return False
        if (device, inode) in available and status != 'SUPERSEDED':
            continue
        # Only a producer-recorded generation binding can recover a missing source.
        from ingestion.ufw_lineage import recover_checkpoint
        if recover_checkpoint(cursor, scope, checkpoint):
            continue
        if (device, inode) not in available:
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
    unverified_recoveries counts legacy RECOVERED checkpoints whose generation
    lineage was never proved; resolved gap rows do not make those recoveries valid.
    """
    with connection.cursor() as cursor:
        cursor.execute('SELECT last_success,last_failure,error_class,active_state,pending_archives,stop_reason,'
                       'active_lines,archive_lines,plain_backlog FROM ufw_collection_health WHERE source_scope=%s', (scope,))
        row = cursor.fetchone()
        cursor.execute('SELECT reason,COUNT(*) FROM ufw_collection_gaps WHERE source_scope=%s AND resolved=FALSE '
                       'GROUP BY reason', (scope,))
        gaps = dict(cursor.fetchall())
        # Old RECOVERED rows were based on content matches, not generation lineage.
        # Audit them even if their original gaps were already marked resolved.
        from ingestion.ufw_lineage import VERIFIED_RECOVERY
        cursor.execute("SELECT /*+ MAX_EXECUTION_TIME(1000) */ COUNT(*) FROM ufw_file_checkpoints f "
                       "WHERE f.source_scope=%s AND (f.status='RECOVERED' OR "
                       "(f.status='ARCHIVED' AND NOT " + VERIFIED_RECOVERY + '))', (scope,))
        audit = cursor.fetchone()
        if audit is None or len(audit) != 1 or type(audit[0]) is not int or audit[0] < 0:
            raise RuntimeError('UFW_RECOVERY_AUDIT_UNVERIFIED')
        unverified_recoveries = audit[0]
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
    if gap_count or unverified_recoveries:
        state = 'GAP_DETECTED'
    result = {'state': state, 'gaps': gap_count, 'unverified_recoveries': unverified_recoveries}
    if row is not None:
        names = ('last_success_utc', 'last_failure_utc', 'last_error_class', 'active_state',
                 'pending_archives', 'stop_reason', 'active_lines', 'archive_lines', 'plain_backlog')
        for name, value in zip(names, row):
            result[name] = value
    return result
