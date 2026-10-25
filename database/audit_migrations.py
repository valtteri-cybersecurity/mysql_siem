"""Migration 020 only: extend approved source kinds and validate additive DDL."""

import json
import re

from database.schema import SchemaError, ensure_tables, read_schema
from database.snapshot_migrations import BASE_TYPES, source_clause
from ingestion.audit.targets import DEFAULT_TARGETS


def upgrade_audit(connection, path):
    known = BASE_TYPES | {'processes', 'services', 'audit'}
    with connection.cursor() as cursor:
        cursor.execute(
            'SELECT cc.CHECK_CLAUSE FROM information_schema.check_constraints cc '
            'JOIN information_schema.table_constraints tc '
            'ON tc.CONSTRAINT_SCHEMA = cc.CONSTRAINT_SCHEMA AND tc.CONSTRAINT_NAME = cc.CONSTRAINT_NAME '
            "WHERE tc.TABLE_SCHEMA = DATABASE() AND tc.TABLE_NAME = 'log_sources' "
            "AND tc.CONSTRAINT_NAME = 'chk_source_type'")
        row = cursor.fetchone()
        if row is None:
            raise SchemaError('Missing source-type constraint.')
        clause = source_clause(row[0])
        actual = set(re.findall(r"'([^']+)'", clause))
        structure = re.sub(r"'[^']+'", "''", clause)
        if (not re.fullmatch(r"\(*source_type\s+in\s*\(''(?:\s*,\s*'')*\)\)*", structure, re.IGNORECASE)
                or not known - {'audit'} <= actual or not actual <= known):
            raise SchemaError('Unexpected source-type constraint; review registry before Audit upgrade.')
        if 'audit' not in actual:
            allowed = ', '.join("'" + name + "'" for name in sorted(known))
            cursor.execute('ALTER TABLE log_sources DROP CHECK chk_source_type, '
                           f'ADD CONSTRAINT chk_source_type CHECK (source_type IN ({allowed}))')
    tables, _ = read_schema(path)
    ensure_tables(connection, tuple(tables), schema_file=path)
    validate_audit_tables(connection, tables)
    with connection.cursor() as cursor:
        for target in DEFAULT_TARGETS:
            definition = {"files": target["files"], "directories": target["directories"],
                          "executables": target["executables"]}
            cursor.execute('INSERT INTO audit_targets (target_name, audit_key, definition, enabled) '
                           'VALUES (%s, %s, %s, 1) ON DUPLICATE KEY UPDATE target_name = audit_targets.target_name',
                           (target['name'], 'siem_' + target['name'], json.dumps(definition)))
    connection.commit()


def validate_audit_tables(connection, tables):
    """Fail on incompatible existing columns, unique keys, checks or relations."""
    with connection.cursor() as cursor:
        for name, definition in tables.items():
            cursor.execute('SELECT engine, table_collation FROM information_schema.tables '
                           'WHERE table_schema = DATABASE() AND table_name = %s', (name,))
            if cursor.fetchone() != ('InnoDB', 'utf8mb4_bin'):
                raise SchemaError('Audit tables require InnoDB and utf8mb4_bin.')
            expected = []
            for column, kind, charset, nullable in re.findall(
                    r'^    (\w+) (BIGINT UNSIGNED|TINYINT UNSIGNED|VARCHAR\(\d+\)|JSON|DATETIME\(6\)) '
                    r'(CHARACTER SET ascii COLLATE ascii_bin )?(NOT NULL|NULL)', definition, re.MULTILINE):
                collation = None
                if kind.startswith('VARCHAR'):
                    collation = 'ascii_bin' if charset else 'utf8mb4_bin'
                expected.append((column, kind.lower(), 'NO' if nullable == 'NOT NULL' else 'YES', collation))
            cursor.execute('SELECT column_name, column_type, is_nullable, collation_name '
                           'FROM information_schema.columns WHERE table_schema = DATABASE() '
                           'AND table_name = %s ORDER BY ordinal_position', (name,))
            if list(cursor.fetchall()) != expected:
                raise SchemaError('Incompatible Audit columns; preserve and inspect existing data.')
            cursor.execute('SELECT index_name, non_unique, column_name FROM information_schema.statistics '
                           'WHERE table_schema = DATABASE() AND table_name = %s '
                           'ORDER BY index_name, seq_in_index', (name,))
            indexes = {}
            for index, non_unique, column in cursor.fetchall():
                indexes.setdefault(index, (non_unique, []))[1].append(column)
            required = {'PRIMARY': (0, re.search(r'PRIMARY KEY \(([^)]+)\)', definition)[1].split(', '))}
            for unique, index, columns in re.findall(r'    (UNIQUE )?KEY (\w+) \(([^)]+)\)', definition):
                required[index] = (0 if unique else 1, columns.split(', '))
            if any(indexes.get(index) != columns for index, columns in required.items()):
                raise SchemaError('Incompatible Audit indexes.')
            cursor.execute('SELECT constraint_name, column_name, referenced_table_name, referenced_column_name '
                           'FROM information_schema.key_column_usage WHERE table_schema = DATABASE() '
                           'AND table_name = %s AND referenced_table_name IS NOT NULL '
                           'ORDER BY constraint_name, ordinal_position', (name,))
            foreign = {}
            for constraint, column, table, target in cursor.fetchall():
                foreign.setdefault(constraint, []).append((column, table, target))
            required_foreign = set()
            for columns, table, targets in re.findall(
                    r'FOREIGN KEY \(([^)]+)\) REFERENCES (\w+) \(([^)]+)\)', definition):
                columns = columns.split(', ')
                required_foreign.add(tuple(zip(columns, [table] * len(columns), targets.split(', '))))
            if {tuple(value) for value in foreign.values()} != required_foreign:
                raise SchemaError('Incompatible Audit identity foreign keys.')
            cursor.execute('SELECT constraint_name FROM information_schema.table_constraints '
                           "WHERE table_schema = DATABASE() AND table_name = %s AND constraint_type = 'CHECK' "
                           "AND enforced = 'YES'", (name,))
            checks = {row[0] for row in cursor.fetchall()}
            if not set(re.findall(r'CONSTRAINT (chk_\w+) CHECK', definition)) <= checks:
                raise SchemaError('Audit checks are missing or disabled.')
