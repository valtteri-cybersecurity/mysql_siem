"""Migration 031: bounded archive retries; original failures and offsets remain intact."""
from database.migration_steps import add_column, replace_key

COLUMNS = {
    'ufw_archives': (
        ('failure_reason', 'varchar(64)', 'YES', 'VARCHAR(64) NULL'),
        ('retry_count', 'tinyint unsigned', 'NO', 'TINYINT UNSIGNED NOT NULL DEFAULT 0'),
        ('retry_after', 'datetime(6)', 'YES', 'DATETIME(6) NULL'),
    ),
    'ufw_archive_failures': (
        ('archive_sha', 'char(64)', 'YES', 'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL'),
        ('retryable', 'tinyint unsigned', 'NO', 'TINYINT UNSIGNED NOT NULL DEFAULT 0'),
        ('resolved_at', 'datetime(6)', 'YES', 'DATETIME(6) NULL'),
    ),
}


def upgrade(connection):
    with connection.cursor() as cursor:
        for table, fields in COLUMNS.items():
            for name, _kind, _nullable, definition in fields:
                add_column(cursor, table, name, definition)
        replace_key(cursor, 'ufw_archive_failures', 'ix_ufw_archive_failure_recovery',
                    ('source_scope', 'resolved_at', 'archive_sha'), unique=False)
        replace_key(cursor, 'ufw_archives', 'ix_ufw_archive_source',
                    ('source_scope', 'file_device', 'file_inode', 'file_mtime_ns', 'checked_at'), unique=False)
    verify(connection)


def verify(connection):
    from database.migrate import MigrationError
    with connection.cursor() as cursor:
        for table, fields in COLUMNS.items():
            for name, kind, nullable, _definition in fields:
                cursor.execute('SELECT column_type,is_nullable FROM information_schema.columns '
                               'WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s', (table, name))
                if cursor.fetchone() != (kind, nullable):
                    raise MigrationError('031: incompatible archive retry storage: ' + table + '.' + name)
        indexes = (
            ('ufw_archive_failures', 'ix_ufw_archive_failure_recovery', ('source_scope', 'resolved_at', 'archive_sha')),
            ('ufw_archives', 'ix_ufw_archive_source', ('source_scope', 'file_device', 'file_inode', 'file_mtime_ns', 'checked_at')),
        )
        for table, name, fields in indexes:
            cursor.execute('SELECT non_unique,column_name FROM information_schema.statistics '
                           'WHERE table_schema=DATABASE() AND table_name=%s AND index_name=%s ORDER BY seq_in_index',
                           (table, name))
            expected = []
            for field in fields:
                expected.append((1, field))
            if cursor.fetchall() != tuple(expected):
                raise MigrationError('031: missing archive retry index: ' + name)
