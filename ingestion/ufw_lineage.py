"""Consume producer-recorded lineage; never infer generation from equal content."""
from ingestion.ufw_batch import OccurrenceConflict

# Both recovery and health auditing use this exact same evidence requirement.
# f is the checkpoint alias; all identifiers are repository constants.
VERIFIED_RECOVERY = '''EXISTS (
    SELECT 1 FROM ufw_archive_lineage l
    JOIN ufw_compression_jobs j ON j.id=l.job_id AND j.source_scope=l.source_scope
    JOIN ufw_archives a ON a.source_scope=l.source_scope AND a.archive_sha=l.archive_sha
    WHERE l.source_scope=f.source_scope AND l.checkpoint_id=f.id
      AND l.generation_key=f.generation_key AND j.status='READY'
      AND j.source_device=f.file_device AND j.source_inode=f.file_inode
      AND l.expanded_size>=f.observed_size AND l.expanded_size>=f.byte_position
      AND a.status='COMPLETE' AND a.logical_position=l.expanded_size
)'''


def output_job(cursor, scope, info):
    cursor.execute('SELECT j.status,l.archive_sha,l.compressed_size FROM ufw_compression_jobs j '
                   'LEFT JOIN ufw_archive_lineage l ON l.job_id=j.id WHERE j.source_scope=%s '
                   'AND j.archive_device=%s AND j.archive_inode=%s ORDER BY j.id DESC LIMIT 1',
                   (scope, info.st_dev, info.st_ino))
    return cursor.fetchone()


def archive_binding(cursor, scope, digest):
    cursor.execute('SELECT l.checkpoint_id,l.generation_key,l.expanded_size,l.expanded_sha,l.compressed_size '
                   'FROM ufw_archive_lineage l JOIN ufw_compression_jobs j ON j.id=l.job_id '
                   "WHERE l.source_scope=%s AND l.archive_sha=%s AND j.status='READY'", (scope, digest))
    return cursor.fetchone()


def verify_binding(binding, record):
    if binding is None:
        return
    _checkpoint, generation, size, digest, _compressed_size = binding
    if len(generation) != 32 or generation == bytes(32):
        raise OccurrenceConflict('UFW_INVALID_ARCHIVE_LINEAGE')
    if (size, digest) != (record['signature'][2], record['expanded_sha256']):
        raise OccurrenceConflict('UFW_ARCHIVE_LINEAGE_CONTENT_CHANGED')


def recover_checkpoint(cursor, scope, checkpoint):
    cursor.execute('SELECT 1 FROM ufw_file_checkpoints f WHERE f.source_scope=%s AND f.id=%s AND '
                   + VERIFIED_RECOVERY, (scope, checkpoint))
    if cursor.fetchone() != (1,):
        return False
    cursor.execute("UPDATE ufw_file_checkpoints SET status='ARCHIVED' WHERE source_scope=%s AND id=%s",
                   (scope, checkpoint))
    cursor.execute('UPDATE ufw_collection_gaps SET resolved=TRUE WHERE source_scope=%s AND checkpoint_id=%s '
                   "AND reason IN ('MISSING_SOURCE','CONTENT_CHANGED')", (scope, checkpoint))
    return True
