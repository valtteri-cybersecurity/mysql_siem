"""Resumable occurrence keys; original event rows and fingerprints are retained."""
from database.migration_steps import add_column, add_constraint

ZERO_GENERATION = '0x' + '00' * 32


def index(cursor, table, name):
    cursor.execute('SELECT non_unique,column_name FROM information_schema.statistics '
                   'WHERE table_schema=DATABASE() AND table_name=%s AND index_name=%s ORDER BY seq_in_index',
                   (table, name))
    return cursor.fetchall()


def upgrade(connection):
    with connection.cursor() as cursor:
        add_column(cursor, 'ufw_archives', 'file_mtime_ns', 'BIGINT UNSIGNED NULL')
        add_column(cursor, 'ufw_file_checkpoints', 'generation_key', 'BINARY(32) NULL')
        add_column(cursor, 'ufw_file_checkpoints', 'file_mtime_ns', 'BIGINT UNSIGNED NULL')
        add_column(cursor, 'ufw_log', 'file_generation', 'BINARY(32) NULL')
        add_column(cursor, 'ufw_log', 'file_position', 'BIGINT UNSIGNED NULL')
        add_column(cursor, 'ufw_log', 'legacy_hash',
                   'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin '
                   'GENERATED ALWAYS AS (CASE WHEN file_generation IS NULL THEN event_hash ELSE NULL END) VIRTUAL')
        if not index(cursor, 'ufw_log', 'uq_ufw_legacy_content'):
            cursor.execute('ALTER TABLE ufw_log ADD UNIQUE KEY uq_ufw_legacy_content (source_scope,legacy_hash)')
        add_column(cursor, 'ufw_filter_seen', 'file_generation', 'BINARY(32) NOT NULL DEFAULT ' + ZERO_GENERATION)
        add_column(cursor, 'ufw_filter_seen', 'file_position', 'BIGINT UNSIGNED NOT NULL DEFAULT 0')
        add_column(cursor, 'ufw_filter_seen', 'modern_position',
                   'BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN file_generation <> ' + ZERO_GENERATION +
                   ' THEN file_position ELSE NULL END) VIRTUAL')
        if not index(cursor, 'ufw_filter_seen', 'uq_ufw_filtered_occurrence'):
            cursor.execute('ALTER TABLE ufw_filter_seen ADD UNIQUE KEY uq_ufw_filtered_occurrence '
                           '(source_id,file_generation,modern_position)')
        add_constraint(cursor, 'ufw_log', 'chk_ufw_occurrence_origin',
                       'CHECK ((file_generation IS NULL AND file_position IS NULL) OR '
                       '(file_generation IS NOT NULL AND file_position IS NOT NULL AND file_generation <> ' +
                       ZERO_GENERATION + '))')
        if not index(cursor, 'ufw_log', 'uq_ufw_occurrence'):
            cursor.execute('ALTER TABLE ufw_log ADD UNIQUE KEY uq_ufw_occurrence '
                           '(source_scope,file_generation,file_position)')
        current = index(cursor, 'ufw_log', 'uq_ufw_event_hash')
        if current == ((0, 'source_scope'), (0, 'event_hash')):
            cursor.execute('ALTER TABLE ufw_log DROP INDEX uq_ufw_event_hash, '
                           'ADD KEY uq_ufw_event_hash (source_scope,event_hash)')
        current = index(cursor, 'ufw_filter_seen', 'PRIMARY')
        if current == ((0, 'source_id'), (0, 'event_hash')):
            cursor.execute('ALTER TABLE ufw_filter_seen DROP PRIMARY KEY, '
                           'ADD PRIMARY KEY (source_id,file_generation,file_position,event_hash), '
                           'ADD KEY ix_ufw_filter_content (source_id,event_hash)')
    verify(connection)


def verify(connection):
    from database.migrate import MigrationError
    from database.ufw_collection_schema import verify as verify_collection
    verify_collection(connection, continuity=True, filtering=True, occurrences=True)
    with connection.cursor() as cursor:
        expected = {
            'uq_ufw_legacy_content': ((0, 'source_scope'), (0, 'legacy_hash')),
            'uq_ufw_occurrence': ((0, 'source_scope'), (0, 'file_generation'), (0, 'file_position')),
            'uq_ufw_event_hash': ((1, 'source_scope'), (1, 'event_hash')),
        }
        for name, fields in expected.items():
            if index(cursor, 'ufw_log', name) != fields:
                raise MigrationError('029: incompatible UFW occurrence index: ' + name)
        if index(cursor, 'ufw_filter_seen', 'uq_ufw_filtered_occurrence') != (
            (0, 'source_id'), (0, 'file_generation'), (0, 'modern_position'),
        ):
            raise MigrationError('029: filtered occurrence uniqueness is missing.')
        for table, name, expected in (
            ('ufw_log', 'legacy_hash', 'casewhenfile_generationisnullthenevent_hashelsenullend'),
            ('ufw_filter_seen', 'modern_position',
             'casewhenfile_generation<>' + ZERO_GENERATION + 'thenfile_positionelsenullend'),
        ):
            cursor.execute('SELECT generation_expression,extra FROM information_schema.columns '
                           'WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s', (table, name))
            row = cursor.fetchone()
            if row is None or row[1] != 'VIRTUAL GENERATED':
                raise MigrationError('029: generated occurrence guard is missing: ' + table)
            expression = row[0].lower()
            for character in (' ', '`', '(', ')'):
                expression = expression.replace(character, '')
            if expression != expected:
                raise MigrationError('029: generated occurrence guard is incompatible: ' + table)
        for table, name, data_type, nullable in (
            ('ufw_archives', 'file_mtime_ns', 'bigint unsigned', 'YES'),
            ('ufw_log', 'file_generation', 'binary(32)', 'YES'),
            ('ufw_log', 'file_position', 'bigint unsigned', 'YES'),
            ('ufw_file_checkpoints', 'generation_key', 'binary(32)', 'YES'),
            ('ufw_file_checkpoints', 'file_mtime_ns', 'bigint unsigned', 'YES'),
            ('ufw_filter_seen', 'file_generation', 'binary(32)', 'NO'),
            ('ufw_filter_seen', 'file_position', 'bigint unsigned', 'NO'),
        ):
            cursor.execute('SELECT column_type,is_nullable FROM information_schema.columns '
                           'WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s', (table, name))
            if cursor.fetchone() != (data_type, nullable):
                raise MigrationError('029: incompatible occurrence column: ' + table + '.' + name)
