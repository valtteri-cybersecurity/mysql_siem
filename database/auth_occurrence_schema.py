"""Migration 032: additive Auth occurrence identities; historical events stay untouched."""
from database.migration_steps import add_column, add_constraint
from database.ufw_occurrence_schema import index

ZERO = '0x' + '00' * 32
COLUMNS = (
    ('auth_events', 'file_generation', 'BINARY(32) NULL', 'binary(32)'),
    ('auth_events', 'file_position', 'BIGINT UNSIGNED NULL', 'bigint unsigned'),
    ('auth_ingestion_state', 'generation_key', 'BINARY(32) NULL', 'binary(32)'),
    ('auth_ingestion_state', 'prefix_sha', 'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL', 'char(64)'),
    ('auth_ingestion_state', 'observed_size', 'BIGINT UNSIGNED NULL', 'bigint unsigned'),
    ('auth_ingestion_state', 'observed_sha', 'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL', 'char(64)'),
    ('auth_ingestion_state', 'file_mtime_ns', 'BIGINT UNSIGNED NULL', 'bigint unsigned'),
)
INDEXES = {
    'uq_auth_legacy_content': ((0, 'source_scope'), (0, 'legacy_hash')),
    'uq_auth_occurrence': ((0, 'source_scope'), (0, 'file_generation'), (0, 'file_position')),
    'uq_auth_event_hash': ((1, 'source_scope'), (1, 'event_hash'), (1, 'file_generation')),
}


def verify_storage(cursor):
    from database.migrate import MigrationError
    for table in ('auth_events', 'auth_ingestion_state'):
        cursor.execute('SELECT engine,table_type FROM information_schema.tables '
                       'WHERE table_schema=DATABASE() AND table_name=%s', (table,))
        if cursor.fetchone() != ('InnoDB', 'BASE TABLE'):
            raise MigrationError('032: Auth events and checkpoints require InnoDB: ' + table)
    if index(cursor, 'auth_ingestion_state', 'PRIMARY') != (
            (0, 'collector_id'), (0, 'file_device'), (0, 'file_inode'), (0, 'source_scope')):
        raise MigrationError('032: incompatible Auth checkpoint namespace.')


def upgrade(connection):
    from database.migrate import MigrationError
    with connection.cursor() as cursor:
        verify_storage(cursor)
        old = index(cursor, 'auth_events', 'uq_auth_event_hash')
        if old not in (((0, 'source_scope'), (0, 'event_hash')), INDEXES['uq_auth_event_hash']):
            raise MigrationError('032: incompatible Auth content index; history was preserved.')
        for table, name, definition, _kind in COLUMNS:
            add_column(cursor, table, name, definition)
        add_column(cursor, 'auth_events', 'legacy_hash',
                   'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS '
                   '(CASE WHEN file_generation IS NULL THEN event_hash ELSE NULL END) VIRTUAL')
        for name in ('uq_auth_legacy_content', 'uq_auth_occurrence'):
            current = index(cursor, 'auth_events', name)
            if not current:
                fields = []
                for _unique, field in INDEXES[name]:
                    fields.append(field)
                cursor.execute('ALTER TABLE auth_events ADD UNIQUE KEY ' + name + ' (' + ','.join(fields) + ')')
            elif current != INDEXES[name]:
                raise MigrationError('032: incompatible Auth occurrence index: ' + name)
        add_constraint(cursor, 'auth_events', 'chk_auth_occurrence_origin',
                       'CHECK ((file_generation IS NULL AND file_position IS NULL) OR '
                       '(file_generation IS NOT NULL AND file_position IS NOT NULL AND file_generation <> ' + ZERO + '))')
        add_constraint(cursor, 'auth_ingestion_state', 'chk_auth_generation_origin',
                       'CHECK ((generation_key IS NULL AND prefix_sha IS NULL AND observed_size IS NULL '
                       'AND observed_sha IS NULL AND file_mtime_ns IS NULL) OR (generation_key IS NOT NULL '
                       'AND generation_key <> ' + ZERO + ' AND prefix_sha IS NOT NULL AND observed_size IS NOT NULL '
                       'AND observed_sha IS NOT NULL AND file_mtime_ns IS NOT NULL AND observed_size>=last_position))')
        if old != INDEXES['uq_auth_event_hash']:
            cursor.execute('ALTER TABLE auth_events DROP INDEX uq_auth_event_hash, '
                           'ADD KEY uq_auth_event_hash (source_scope,event_hash,file_generation)')
    verify(connection)


def verify(connection):
    from database.migrate import MigrationError
    with connection.cursor() as cursor:
        verify_storage(cursor)
        for name, fields in INDEXES.items():
            if index(cursor, 'auth_events', name) != fields:
                raise MigrationError('032: incompatible Auth occurrence index: ' + name)
        for table, name, _definition, kind in COLUMNS:
            cursor.execute('SELECT column_type,is_nullable FROM information_schema.columns '
                           'WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s', (table, name))
            if cursor.fetchone() != (kind, 'YES'):
                raise MigrationError('032: incompatible Auth origin column: ' + table + '.' + name)
        cursor.execute('SELECT generation_expression,extra FROM information_schema.columns '
                       "WHERE table_schema=DATABASE() AND table_name='auth_events' AND column_name='legacy_hash'")
        row = cursor.fetchone()
        if row is None or row[1] != 'VIRTUAL GENERATED':
            raise MigrationError('032: missing legacy Auth identity guard.')
        expression = row[0].lower()
        for character in (' ', '`', '(', ')'):
            expression = expression.replace(character, '')
        if expression != 'casewhenfile_generationisnullthenevent_hashelsenullend':
            raise MigrationError('032: incompatible legacy Auth identity guard.')
        for table, name in (('auth_events', 'chk_auth_occurrence_origin'),
                            ('auth_ingestion_state', 'chk_auth_generation_origin')):
            cursor.execute('SELECT enforced FROM information_schema.table_constraints '
                           'WHERE constraint_schema=DATABASE() AND table_name=%s AND constraint_name=%s '
                           "AND constraint_type='CHECK'", (table, name))
            if cursor.fetchone() != ('YES',):
                raise MigrationError('032: missing Auth origin constraint: ' + name)
