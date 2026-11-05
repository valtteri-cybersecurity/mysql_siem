"""Migration 030: compression-time provenance, preserving existing history."""
from database.migration_steps import replace_key
from database.ufw_occurrence_schema import index

DDL = (
    '''CREATE TABLE IF NOT EXISTS ufw_compression_jobs (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        source_scope BIGINT UNSIGNED NOT NULL,
        checkpoint_id BIGINT UNSIGNED NOT NULL,
        generation_key BINARY(32) NOT NULL,
        source_device BIGINT UNSIGNED NOT NULL,
        source_inode BIGINT UNSIGNED NOT NULL,
        archive_device BIGINT UNSIGNED NOT NULL,
        archive_inode BIGINT UNSIGNED NOT NULL,
        expanded_size BIGINT UNSIGNED NOT NULL,
        expanded_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        finished_at DATETIME(6) NULL,
        UNIQUE KEY uq_ufw_compression_proof (id,source_scope,checkpoint_id,generation_key,expanded_size,expanded_sha),
        KEY ix_ufw_compression_output (source_scope,archive_device,archive_inode,id),
        CONSTRAINT fk_ufw_compression_source FOREIGN KEY
          (checkpoint_id,source_scope,generation_key,source_device,source_inode)
          REFERENCES ufw_file_checkpoints (id,source_scope,generation_key,file_device,file_inode),
        CONSTRAINT chk_ufw_compression_state CHECK (status IN ('WRITING','READY','FAILED'))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin''',
    '''CREATE TABLE IF NOT EXISTS ufw_archive_lineage (
        source_scope BIGINT UNSIGNED NOT NULL,
        archive_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        job_id BIGINT UNSIGNED NOT NULL,
        checkpoint_id BIGINT UNSIGNED NOT NULL,
        generation_key BINARY(32) NOT NULL,
        expanded_size BIGINT UNSIGNED NOT NULL,
        expanded_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        compressed_size BIGINT UNSIGNED NOT NULL,
        created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        PRIMARY KEY (source_scope,archive_sha),
        UNIQUE KEY uq_ufw_lineage_job (job_id),
        KEY ix_ufw_lineage_checkpoint (source_scope,checkpoint_id,generation_key,expanded_size),
        CONSTRAINT fk_ufw_lineage_job FOREIGN KEY
          (job_id,source_scope,checkpoint_id,generation_key,expanded_size,expanded_sha)
          REFERENCES ufw_compression_jobs (id,source_scope,checkpoint_id,generation_key,expanded_size,expanded_sha)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin''',
)


def upgrade(connection):
    with connection.cursor() as cursor:
        replace_key(cursor, 'ufw_file_checkpoints', 'uq_ufw_checkpoint_lineage',
                    ('id', 'source_scope', 'generation_key', 'file_device', 'file_inode'))
        for statement in DDL:
            cursor.execute(statement)
    verify(connection)


def verify(connection):
    from database.migrate import MigrationError
    expected = {
        'ufw_compression_jobs': ('id', 'source_scope', 'checkpoint_id', 'generation_key', 'source_device',
                                 'source_inode', 'archive_device', 'archive_inode', 'expanded_size',
                                 'expanded_sha', 'status', 'created_at', 'finished_at'),
        'ufw_archive_lineage': ('source_scope', 'archive_sha', 'job_id', 'checkpoint_id', 'generation_key',
                               'expanded_size', 'expanded_sha', 'compressed_size', 'created_at'),
    }
    with connection.cursor() as cursor:
        for table, fields in expected.items():
            cursor.execute('SELECT engine,table_type FROM information_schema.tables '
                           'WHERE table_schema=DATABASE() AND table_name=%s', (table,))
            if cursor.fetchone() != ('InnoDB', 'BASE TABLE'):
                raise MigrationError('030: missing transactional lineage storage: ' + table)
            cursor.execute('SELECT column_name FROM information_schema.columns '
                           'WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position', (table,))
            actual = []
            for row in cursor.fetchall():
                actual.append(row[0])
            if tuple(actual) != fields:
                raise MigrationError('030: incompatible lineage storage: ' + table)
        indexes = (
            ('ufw_compression_jobs', 'PRIMARY', 0, ('id',)),
            ('ufw_compression_jobs', 'ix_ufw_compression_output', 1,
             ('source_scope', 'archive_device', 'archive_inode', 'id')),
            ('ufw_archive_lineage', 'PRIMARY', 0, ('source_scope', 'archive_sha')),
            ('ufw_archive_lineage', 'uq_ufw_lineage_job', 0, ('job_id',)),
            ('ufw_archive_lineage', 'ix_ufw_lineage_checkpoint', 1,
             ('source_scope', 'checkpoint_id', 'generation_key', 'expanded_size')),
        )
        for table, name, non_unique, fields in indexes:
            required = []
            for field in fields:
                required.append((non_unique, field))
            if index(cursor, table, name) != tuple(required):
                raise MigrationError('030: incompatible lineage key: ' + table + '.' + name)
        relations = (
            ('ufw_compression_jobs', 'fk_ufw_compression_source', 'ufw_file_checkpoints',
             ('checkpoint_id', 'source_scope', 'generation_key', 'source_device', 'source_inode'),
             ('id', 'source_scope', 'generation_key', 'file_device', 'file_inode')),
            ('ufw_archive_lineage', 'fk_ufw_lineage_job', 'ufw_compression_jobs',
             ('job_id', 'source_scope', 'checkpoint_id', 'generation_key', 'expanded_size', 'expanded_sha'),
             ('id', 'source_scope', 'checkpoint_id', 'generation_key', 'expanded_size', 'expanded_sha')),
        )
        for table, constraint, parent, fields, referenced in relations:
            cursor.execute('SELECT column_name,referenced_table_name,referenced_column_name '
                           'FROM information_schema.key_column_usage WHERE constraint_schema=DATABASE() '
                           'AND table_name=%s AND constraint_name=%s ORDER BY ordinal_position', (table, constraint))
            required = []
            for field, reference in zip(fields, referenced):
                required.append((field, parent, reference))
            if cursor.fetchall() != tuple(required):
                raise MigrationError('030: incompatible generation binding: ' + table)
