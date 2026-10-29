"""Transactional line classification and durable, replay-safe quarantine."""
import hashlib
import json

import pymysql

from ingestion.ufw_validation import InvalidUFW, validate_event


def quarantine(cursor, raw, reason, filename, position, device, inode, identity, archive_sha):
    from ingestion.ufw_to_mysql import MAX_LINE_BYTES
    if len(raw) > MAX_LINE_BYTES:
        raise RuntimeError('QUARANTINE_LINE_LIMIT')
    host = None
    source = None
    collector = None
    scope = 0
    if identity is not None:
        scope = identity.source_id
        host = identity.host_id
        source = identity.source_id
        collector = identity.collector_id
    digest = hashlib.sha256(raw).hexdigest()
    try:
        cursor.execute('INSERT INTO ufw_quarantine '
                       '(source_scope,raw_sha,raw_bytes,reason,host_id,source_id,collector_id) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s)', (scope, digest, raw, reason, host, source, collector))
        inserted = True
    except pymysql.IntegrityError as error:
        if error.args[0] != 1062:
            raise
        inserted = False
    cursor.execute('SELECT id,raw_bytes FROM ufw_quarantine WHERE source_scope=%s AND raw_sha=%s', (scope, digest))
    row = cursor.fetchone()
    if row is None or row[1] != raw:
        raise RuntimeError('QUARANTINE_NOT_VERIFIED')
    identity_key = ('plain', device, inode)
    if archive_sha is not None:
        identity_key = ('gzip', archive_sha)
    file_key = hashlib.sha256(json.dumps(identity_key).encode('ascii')).hexdigest()
    # An existing occurrence is verified rather than overwritten.
    try:
        cursor.execute('INSERT INTO ufw_quarantine_origins '
                       '(source_scope,file_key,byte_position,quarantine_id,filename,file_device,file_inode,archive_sha) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                       (scope, file_key, position, row[0], filename, device, inode, archive_sha))
    except pymysql.IntegrityError as error:
        if error.args[0] != 1062:
            raise
        cursor.execute('SELECT quarantine_id FROM ufw_quarantine_origins WHERE source_scope=%s '
                       'AND file_key=%s AND byte_position=%s AND quarantine_id=%s', (scope, file_key, position, row[0]))
        if cursor.fetchone() != (row[0],):
            raise
    if inserted:
        return 'quarantined'
    return 'duplicates'


def process_line(cursor, raw, filename, position, device, inode, identity, stats, *, archive_sha=None, partial=False, writer=None):
    from ingestion.ufw_to_mysql import decode_log_line, save_event

    reason = None
    try:
        if partial:
            raise InvalidUFW('INCOMPLETE_ARCHIVE_LINE')
        # Normal lines are strict here; the phase-1 decoder retains its public interface.
        if raw.startswith(b'\x00'):
            line = decode_log_line(raw, filename, position)
        else:
            line = raw.decode('utf-8')
        parsed = validate_event(line)
    except UnicodeDecodeError:
        reason = 'INVALID_UTF8'
    except ValueError as error:
        reason = 'INVALID_NUL_RECOVERY'
        if isinstance(error, InvalidUFW):
            reason = str(error)
    if reason is not None:
        category = quarantine(cursor, raw, reason, filename, position, device, inode, identity, archive_sha)
        stats[category] = stats.get(category, 0) + 1
        return 0
    if parsed is None:
        stats['non_ufw'] = stats.get('non_ufw', 0) + 1
        return 0
    if writer is not None:
        writer.add(line, parsed)
        return 0
    inserted = save_event(cursor, line, identity=identity)
    if not inserted:
        stats['duplicates'] = stats.get('duplicates', 0) + 1
    return inserted
