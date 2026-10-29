"""Preserve original analysis history proofs and guard parallel UTC writes."""
import hashlib
import json
import time

KEY = '_analysis_baseline'
TABLES = ('analysis_source_ips', 'analysis_ufw_ports', 'analysis_ufw_traffic', 'analysis_ufw_traffic_daily')


def marked(connection, table):
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() '
                       "AND table_name=%s AND column_name='time_basis'", (table,))
        return cursor.fetchone() == (1,)


def snapshot(connection, table, layout=None, *, basis='HISTORICAL'):
    from database.migrate import MigrationError
    if table not in TABLES:
        raise ValueError('Unknown analysis table.')
    if layout is None:
        fields = []
        with connection.cursor() as cursor:
            cursor.execute('SELECT column_name,data_type FROM information_schema.columns '
                           'WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position', (table,))
            for name, kind in cursor.fetchall():
                if name != 'time_basis':
                    fields.append([name, kind])
            cursor.execute("SELECT column_name FROM information_schema.statistics WHERE table_schema=DATABASE() "
                           "AND table_name=%s AND index_name='PRIMARY' ORDER BY seq_in_index", (table,))
            primary = []
            for row in cursor.fetchall():
                if row[0] != 'time_basis':
                    primary.append(row[0])
        if not fields or not primary:
            raise MigrationError('Analysis history requires an existing primary key.')
        layout = {'fields': fields, 'primary': primary}
    expressions = []
    positions = []
    names = []
    for name, kind in layout['fields']:
        quoted = '`' + name.replace('`', '``') + '`'
        if kind == 'timestamp':
            quoted = 'UNIX_TIMESTAMP(' + quoted + ')'
        expressions.append(quoted)
        names.append(name)
    keys = []
    for name in layout['primary']:
        keys.append('`' + name.replace('`', '``') + '`')
        positions.append(names.index(name))
    key_sql = ','.join(keys)
    last = None
    count = 0
    digest = hashlib.sha256()
    deadline = time.monotonic() + 120
    historical = marked(connection, table)
    while True:
        if time.monotonic() >= deadline:
            raise MigrationError('Analysis history verification exceeded its time budget.')
        where = '1=1'
        params = ()
        if historical:
            where += " AND time_basis=%s"
            params = (basis,)
        if last is not None:
            where += ' AND (' + key_sql + ') > (' + ','.join(['%s'] * len(keys)) + ')'
            params += tuple(last)
        with connection.cursor() as cursor:
            cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(5000) */ ' + ','.join(expressions)
                           + ' FROM `' + table + '` WHERE ' + where + ' ORDER BY ' + key_sql + ' LIMIT 256', params)
            rows = cursor.fetchall()
        if not rows:
            break
        for row in rows:
            digest.update(json.dumps(row, default=str, ensure_ascii=True).encode('ascii') + b'\n')
            count += 1
            last = []
            for position in positions:
                last.append(row[position])
    return {'fields': layout['fields'], 'primary': layout['primary'], 'count': count, 'sha256': digest.hexdigest()}


def capture(connection):
    from database.migrate import MigrationError
    result = {}
    for table in TABLES:
        if marked(connection, table):
            raise MigrationError('Analysis isolation marker has no recorded baseline: ' + table)
        result[table] = snapshot(connection, table)
    return result


def verify(connection, baseline, *, final=False):
    from database.migrate import MigrationError
    for table in TABLES:
        if snapshot(connection, table, baseline[table]) != baseline[table]:
            raise MigrationError('Protected analysis history changed: ' + table)
        if final:
            with connection.cursor() as cursor:
                cursor.execute('SELECT column_default,column_type,is_nullable,collation_name '
                               'FROM information_schema.columns WHERE table_schema=DATABASE() '
                               "AND table_name=%s AND column_name='time_basis'", (table,))
                if cursor.fetchone() != ('UTC_VERIFIED', 'varchar(24)', 'NO', 'ascii_bin'):
                    raise MigrationError('Analysis history isolation schema is incomplete.')
                cursor.execute('SELECT COUNT(*) FROM `' + table + "` WHERE time_basis NOT IN ('HISTORICAL','UTC_VERIFIED')")
                if cursor.fetchone()[0]:
                    raise MigrationError('Unknown analysis time basis.')


def upgrade(connection):
    from database.migrate import ROOT
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='023'")
        baseline = json.loads(cursor.fetchone()[0])[KEY]
    verify(connection, baseline)
    statements = (ROOT / 'migrations/023_ufw_analysis_history.sql').read_text().split(';')
    for table, statement in zip(TABLES, statements):
        if not marked(connection, table):
            with connection.cursor() as cursor:
                cursor.execute(statement.strip())
    verify(connection, baseline)
    for table in TABLES:
        with connection.cursor() as cursor:
            cursor.execute('ALTER TABLE `' + table + "` ALTER COLUMN time_basis SET DEFAULT 'UTC_VERIFIED'")
    verify(connection, baseline, final=True)


def protect_interval(connection, table, start, end):
    """Run in the writer transaction before DELETE or UPSERT."""
    if table not in TABLES:
        raise ValueError('Unknown analysis table.')
    from database.ufw_analysis_keys import require_ready
    require_ready(connection, table)
