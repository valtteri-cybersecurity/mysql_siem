"""New resumable DDL. Kept separate from checksummed migrations 013–017."""

import re

from database.schema import SchemaError, ensure_tables, read_schema

BASE_TYPES = {'ufw', 'auth', 'dns', 'system', 'filesystem', 'security'}


def source_clause(clause):
    # MySQL 8.0 CHECK_CLAUSE escapes quotes; 8.4 may return plain quotes.
    clause = clause.replace("\\'", "'").replace('`', '')
    return re.sub(r"_\w+\s*'", "'", clause)


def upgrade_snapshots(connection, path, *, services=False):
    target = BASE_TYPES | {'processes'}
    if services:
        target.add('services')
    with connection.cursor() as cursor:
        cursor.execute(
            'SELECT cc.CHECK_CLAUSE FROM information_schema.check_constraints cc '
            'JOIN information_schema.table_constraints tc '
            'ON tc.CONSTRAINT_SCHEMA = cc.CONSTRAINT_SCHEMA AND tc.CONSTRAINT_NAME = cc.CONSTRAINT_NAME '
            "WHERE tc.TABLE_SCHEMA = DATABASE() AND tc.TABLE_NAME = 'log_sources' "
            "AND tc.CONSTRAINT_NAME = 'chk_source_type'",
        )
        row = cursor.fetchone()
        if row is None:
            raise SchemaError('Missing source-type constraint; inspect the registry.')
        # Accept only our known IN check. Never replace an unrelated constraint.
        clause = source_clause(row[0])
        actual = set(re.findall(r"'([^']+)'", clause))
        structure = re.sub(r"'[^']+'", "''", clause)
        if (not re.fullmatch(r"\(*source_type\s+in\s*\(''(?:\s*,\s*'')*\)\)*", structure, re.IGNORECASE)
                or not BASE_TYPES <= actual or not actual <= BASE_TYPES | {'processes', 'services'}):
            raise SchemaError('Unexpected source-type constraint; inspect the registry.')
        if not target <= actual:
            allowed = ', '.join("'" + name + "'" for name in sorted(actual | target))
            # One atomic ALTER: interruption cannot leave the check missing.
            cursor.execute('ALTER TABLE log_sources DROP CHECK chk_source_type, '
                           f'ADD CONSTRAINT chk_source_type CHECK (source_type IN ({allowed}))')
    tables, _ = read_schema(path)
    ensure_tables(connection, tuple(tables), schema_file=path)
    validate_tables(connection, tables)


def validate_tables(connection, tables):
    """Reject incompatible pre-existing tables instead of accepting IF NOT EXISTS."""
    with connection.cursor() as cursor:
        for name, definition in tables.items():
            cursor.execute('SELECT engine, table_collation FROM information_schema.tables '
                           'WHERE table_schema = DATABASE() AND table_name = %s', (name,))
            if cursor.fetchone() != ('InnoDB', 'utf8mb4_bin'):
                raise SchemaError(f'{name}: snapshot tables require InnoDB and utf8mb4_bin.')
            expected = []
            for column, kind, null in re.findall(
                    r'^    (\w+) (BIGINT UNSIGNED|VARCHAR\(\d+\)|JSON|DATETIME\(6\)) '
                    r'(?:CHARACTER SET ascii COLLATE ascii_bin )?(NOT NULL|NULL)', definition, re.MULTILINE):
                expected.append((column, kind.lower(), 'NO' if null == 'NOT NULL' else 'YES',
                                 'ascii_bin' if kind.startswith('VARCHAR') else None))
            cursor.execute('SELECT column_name, column_type, is_nullable, collation_name '
                           'FROM information_schema.columns WHERE table_schema = DATABASE() '
                           'AND table_name = %s ORDER BY ordinal_position', (name,))
            if list(cursor.fetchall()) != expected:
                raise SchemaError(f'{name}: incompatible columns; preserve and inspect history.')
            cursor.execute('SELECT index_name, column_name FROM information_schema.statistics '
                           'WHERE table_schema = DATABASE() AND table_name = %s ORDER BY index_name, seq_in_index', (name,))
            indexes = {}
            for index, column in cursor.fetchall():
                indexes.setdefault(index, []).append(column)
            expected_indexes = {'PRIMARY': re.search(r'PRIMARY KEY \(([^)]+)\)', definition)[1].split(', ')}
            for index, columns in re.findall(r'    KEY (\w+) \(([^)]+)\)', definition):
                expected_indexes[index] = columns.split(', ')
            if any(indexes.get(index) != columns for index, columns in expected_indexes.items()):
                raise SchemaError(f'{name}: incompatible snapshot indexes.')
            cursor.execute('SELECT constraint_name, column_name, referenced_table_name, referenced_column_name '
                           'FROM information_schema.key_column_usage WHERE table_schema = DATABASE() '
                           'AND table_name = %s AND referenced_table_name IS NOT NULL '
                           'ORDER BY constraint_name, ordinal_position', (name,))
            actual_foreign = {}
            for constraint, column, table, target in cursor.fetchall():
                actual_foreign.setdefault(constraint, []).append((column, table, target))
            expected_foreign = {
                tuple(zip(columns.split(', '), [table] * len(columns.split(', ')), targets.split(', ')))
                for columns, table, targets in re.findall(
                    r'FOREIGN KEY \(([^)]+)\) REFERENCES (\w+) \(([^)]+)\)', definition)
            }
            if {tuple(parts) for parts in actual_foreign.values()} != expected_foreign:
                raise SchemaError(f'{name}: incompatible snapshot foreign keys.')
