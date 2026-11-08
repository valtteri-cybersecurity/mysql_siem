"""Migration 033 stores gzip offsets independently of reusable plain inodes."""

from database.ufw_occurrence_schema import index

TABLE = 'auth_archive_checkpoints'
CHECK = 'chk_auth_archive_position'


def upgrade(connection):
    with connection.cursor() as cursor:
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_archive_checkpoints (
            source_scope BIGINT UNSIGNED NOT NULL,
            generation_key BINARY(32) NOT NULL,
            collector_id VARCHAR(255) NOT NULL,
            file_device BIGINT UNSIGNED NOT NULL,
            file_inode BIGINT UNSIGNED NOT NULL,
            archive_sha BINARY(32) NOT NULL,
            logical_position BIGINT UNSIGNED NOT NULL,
            expanded_size BIGINT UNSIGNED NOT NULL,
            PRIMARY KEY (source_scope, generation_key),
            CONSTRAINT chk_auth_archive_position CHECK (logical_position <= expanded_size)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin''')
    verify(connection)


def verify(connection):
    from database.migrate import MigrationError

    with connection.cursor() as cursor:
        cursor.execute('SELECT engine,table_type FROM information_schema.tables '
                       'WHERE table_schema=DATABASE() AND table_name=%s', (TABLE,))
        if cursor.fetchone() != ('InnoDB', 'BASE TABLE') or index(cursor, TABLE, 'PRIMARY') != (
                (0, 'source_scope'), (0, 'generation_key')):
            raise MigrationError('033: incompatible Auth gzip checkpoint storage.')
        cursor.execute('SELECT column_name,column_type,is_nullable FROM information_schema.columns '
                       'WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position', (TABLE,))
        expected = (
            ('source_scope', 'bigint unsigned', 'NO'),
            ('generation_key', 'binary(32)', 'NO'),
            ('collector_id', 'varchar(255)', 'NO'),
            ('file_device', 'bigint unsigned', 'NO'),
            ('file_inode', 'bigint unsigned', 'NO'),
            ('archive_sha', 'binary(32)', 'NO'),
            ('logical_position', 'bigint unsigned', 'NO'),
            ('expanded_size', 'bigint unsigned', 'NO'),
        )
        if cursor.fetchall() != expected:
            raise MigrationError('033: incompatible Auth gzip checkpoint columns.')
        cursor.execute('SELECT t.enforced,c.check_clause FROM information_schema.table_constraints t '
                       'JOIN information_schema.check_constraints c '
                       'USING (constraint_schema,constraint_name) WHERE t.constraint_schema=DATABASE() '
                       'AND t.table_name=%s AND t.constraint_name=%s', (TABLE, CHECK))
        constraint = cursor.fetchone()
        if constraint is None or constraint[0] != 'YES':
            raise MigrationError('033: missing Auth gzip checkpoint position constraint.')
        clause = constraint[1].replace('`', '').replace('(', '').replace(')', '').replace(' ', '')
        if clause != 'logical_position<=expanded_size':
            raise MigrationError('033: incompatible Auth gzip checkpoint position constraint.')
