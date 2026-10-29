"""Resumable analysis key expansion, preserving the original 023 history proof."""
import json
from datetime import timedelta

from database import ufw_analysis_history as history

KEY = '_analysis_parallel_baseline'
KEYS = {
    'analysis_source_ips': ('PRIMARY', ('period_start', 'period_end', 'source_ip', 'host_scope')),
    'analysis_ufw_ports': ('uq_ufw_ports_period', ('period_start', 'period_end', 'destination_ip', 'destination_port', 'protocol', 'host_scope')),
    'analysis_ufw_traffic': ('uq_traffic_period', ('period_start', 'period_end', 'host_scope')),
    'analysis_ufw_traffic_daily': ('uq_traffic_period', ('analysis_date', 'host_scope')),
}


def applied(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() "
                       "AND table_name='schema_migrations'")
        if cursor.fetchone() != (1,):
            return False
        cursor.execute("SELECT status FROM schema_migrations WHERE version='027'")
        return cursor.fetchone() == ('APPLIED',)


def key_state(connection, table):
    from database.migrate import MigrationError
    if table not in KEYS:
        raise ValueError('Unknown analysis table.')
    name, old = KEYS[table]
    fields = []
    with connection.cursor() as cursor:
        cursor.execute('SELECT column_name,non_unique,sub_part,is_visible,index_type FROM information_schema.statistics '
                       'WHERE table_schema=DATABASE() AND table_name=%s AND index_name=%s ORDER BY seq_in_index', (table, name))
        for column, non_unique, prefix, visible, kind in cursor.fetchall():
            if non_unique != 0 or prefix is not None or visible != 'YES' or kind != 'BTREE':
                raise MigrationError('027: invalid unique analysis key: ' + table + '.' + name)
            fields.append(column)
    if tuple(fields) == old:
        return False
    if tuple(fields) == old + ('time_basis',):
        return True
    raise MigrationError('027: incompatible or missing analysis key: ' + table + '.' + name)


def validate_table(connection, table, parallel):
    from analysis.ufw.ports import validate_ports_schema
    from analysis.ufw.traffic import validate_traffic_schema
    from database.migrate import MigrationError
    from database.schema import validate_source_ips_schema
    if table == 'analysis_source_ips':
        validate_source_ips_schema(connection, parallel=parallel)
    elif table == 'analysis_ufw_ports':
        validate_ports_schema(connection, parallel=parallel)
    else:
        validate_traffic_schema(connection, parallel=parallel, only_table=table)
    with connection.cursor() as cursor:
        cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(5000) */ 1 FROM `' + table + "` WHERE time_basis NOT IN ('HISTORICAL','UTC_VERIFIED') LIMIT 1")
        if cursor.fetchone() is not None:
            raise MigrationError('027: unknown analysis time_basis: ' + table)
        cursor.execute('SELECT referenced_table_name,referenced_column_name FROM information_schema.key_column_usage '
                       'WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s AND referenced_table_name IS NOT NULL',
                       (table, 'host_id'))
        if cursor.fetchall() != (('hosts', 'host_id'),):
            raise MigrationError('027: incompatible host foreign key: ' + table)
        cursor.execute('SELECT column_default,column_type,is_nullable,collation_name FROM information_schema.columns '
                       "WHERE table_schema=DATABASE() AND table_name=%s AND column_name='time_basis'", (table,))
        if cursor.fetchone() != ('UTC_VERIFIED', 'varchar(24)', 'NO', 'ascii_bin'):
            raise MigrationError('027: incompatible time_basis column: ' + table)
        cursor.execute('SELECT tc.constraint_name,cc.check_clause FROM information_schema.table_constraints tc '
                       'JOIN information_schema.check_constraints cc ON cc.constraint_schema=tc.constraint_schema '
                       "AND cc.constraint_name=tc.constraint_name WHERE tc.table_schema=DATABASE() "
                       "AND tc.table_name=%s AND tc.constraint_type='CHECK' AND tc.enforced='YES'", (table,))
        checks = {}
        for name, clause in cursor.fetchall():
            normalized = clause.lower()
            for token in ('`', ' ', '(', ')', chr(92), '\t', '\n', '\r', '_ascii', '_utf8mb4'):
                normalized = normalized.replace(token, '')
            checks[name] = normalized
        required = {'chk_' + table + '_scope': 'host_scope=coalescehost_id,0'}
        if table == 'analysis_source_ips':
            required['chk_source_analysis_period'] = 'period_start<period_end'
            required['chk_source_analysis_seen'] = 'first_seen>=period_startandfirst_seen<=last_seenandlast_seen<period_end'
        elif table in ('analysis_ufw_traffic', 'analysis_ufw_traffic_daily'):
            required['chk_' + table + '_status'] = "period_statusin'open','closed'"
            if table == 'analysis_ufw_traffic':
                required['chk_analysis_ufw_traffic_hour'] = ('timestampdiffsecond,period_start,period_end=3600'
                                                          'andminuteperiod_start=0andsecondperiod_start=0andmicrosecondperiod_start=0')
                required['chk_analysis_ufw_traffic_seen'] = ('total_events=0andfirst_seenisnullandlast_seenisnullor'
                                                          'total_events>0andfirst_seenisnotnullandlast_seenisnotnulland'
                                                          'first_seen>=period_startandfirst_seen<=last_seenandlast_seen<period_end')
        for name, clause in required.items():
            if checks.get(name) != clause:
                raise MigrationError('027: incompatible analysis CHECK: ' + table + '.' + name)
        cursor.execute('SELECT referenced_column_name FROM information_schema.key_column_usage '
                       'WHERE referenced_table_schema=DATABASE() AND referenced_table_name=%s', (table,))
        for row in cursor.fetchall():
            if row[0] in KEYS[table][1]:
                raise MigrationError('027: logical analysis key has incoming foreign keys: ' + table)


def verify_raw_schema(connection):
    from database.migrate import MigrationError, ufw_timestamp_schema
    if ufw_timestamp_schema(connection) != ('datetime', 6, 'YES', None):
        raise MigrationError('027 requires the verified UFW DATETIME(6) schema.')
    with connection.cursor() as cursor:
        cursor.execute("SELECT column_type,is_nullable,collation_name,column_default FROM information_schema.columns "
                       "WHERE table_schema=DATABASE() AND table_name='ufw_log' AND column_name='time_basis'")
        if cursor.fetchone() != ('varchar(24)', 'NO', 'ascii_bin', 'UTC_VERIFIED'):
            raise MigrationError('UFW raw UTC isolation is missing or incompatible.')


def dependencies(connection):
    from database.migrate import MigrationError
    with connection.cursor() as cursor:
        for version in ('022', '023'):
            cursor.execute('SELECT status,row_counts FROM schema_migrations WHERE version=%s', (version,))
            row = cursor.fetchone()
            if row is None or row[0] != 'APPLIED':
                raise MigrationError('027 requires completed migration ' + version)
            if version == '023':
                saved = json.loads(row[1])
    try:
        history.verify(connection, saved[history.KEY], final=True)
    except (KeyError, TypeError, ValueError):
        raise MigrationError('027: original migration 023 baseline is invalid.') from None
    verify_raw_schema(connection)


def capture(connection):
    from database.migrate import MigrationError
    dependencies(connection)
    result = {}
    for table in history.TABLES:
        if key_state(connection, table):
            raise MigrationError('027: parallel key has no original migration snapshot: ' + table)
        validate_table(connection, table, False)
        result[table] = {}
        for basis in ('HISTORICAL', 'UTC_VERIFIED'):
            result[table][basis] = history.snapshot(connection, table, basis=basis)
    return result


def verify_rows(connection, baseline):
    from database.migrate import MigrationError
    if not isinstance(baseline, dict) or set(baseline) != set(history.TABLES):
        raise MigrationError('027: missing original analysis snapshot.')
    for table in history.TABLES:
        if not isinstance(baseline[table], dict) or set(baseline[table]) != {'HISTORICAL', 'UTC_VERIFIED'}:
            raise MigrationError('027: original analysis snapshot is invalid: ' + table)
        for basis in ('HISTORICAL', 'UTC_VERIFIED'):
            saved = baseline[table][basis]
            if history.snapshot(connection, table, saved, basis=basis) != saved:
                raise MigrationError('027: original analysis rows changed: ' + table + ' ' + basis)


def upgrade(connection):
    from database.migrate import ROOT
    dependencies(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='027'")
        baseline = json.loads(cursor.fetchone()[0])[KEY]
    verify_rows(connection, baseline)
    statements = (ROOT / 'migrations/027_ufw_analysis_parallel_time_basis.sql').read_text().split(';')
    # Validate every table before the first implicit DDL commit.
    for table in history.TABLES:
        validate_table(connection, table, key_state(connection, table))
    for table, statement in zip(history.TABLES, statements):
        if not key_state(connection, table):
            with connection.cursor() as cursor:
                cursor.execute(statement.strip())
        validate_table(connection, table, True)
        verify_rows(connection, baseline)
    dependencies(connection)


def preflight(connection):
    """Read-only on both pending DDL and already-applied migrations."""
    from database.migrate import MigrationError
    with connection.cursor() as cursor:
        cursor.execute("SELECT status,row_counts FROM schema_migrations WHERE version='027'")
        row = cursor.fetchone()
    if row is None:
        return
    dependencies(connection)
    if row[0] not in ('RUNNING', 'FAILED', 'APPLIED'):
        raise MigrationError('027: unknown migration status.')
    for table in history.TABLES:
        state = key_state(connection, table)
        if row[0] == 'APPLIED' and not state:
            raise MigrationError('027: APPLIED migration still has an old analysis key: ' + table)
        validate_table(connection, table, state)
    if row[0] != 'APPLIED':
        verify_rows(connection, json.loads(row[1]).get(KEY))


def require_ready(connection, table):
    """Writers must never use the pre-027 replacement keys, even on an empty interval."""
    from database.migrate import MigrationError
    if not applied(connection):
        raise MigrationError('UFW analysis requires completed migration 027; no analysis rows were changed.')
    with connection.cursor() as cursor:
        cursor.execute("SELECT version,status FROM schema_migrations WHERE version IN ('022','023') ORDER BY version")
        if cursor.fetchall() != (('022', 'APPLIED'), ('023', 'APPLIED')):
            raise MigrationError('027 requires completed migrations 022 and 023.')
    verify_raw_schema(connection)
    if not key_state(connection, table):
        raise MigrationError('027: unsafe analysis key: ' + table)
    validate_table(connection, table, True)


def read_results(connection, table, start, end, *, time_basis='UTC_VERIFIED', host_id=None, max_rows=1000):
    """Explicit time basis; host fields remain in every returned row. SELECT only."""
    import pymysql

    from analysis.ufw.source_ips import validate_time_range
    from database.identity import validate_id
    validate_time_range(start, end)
    if table not in KEYS or time_basis not in ('HISTORICAL', 'UTC_VERIFIED'):
        raise ValueError('Choose a known analysis table and explicit time basis.')
    if type(max_rows) is not int or not 1 <= max_rows <= 100000:
        raise ValueError('max_rows must be within 1..100000.')
    require_ready(connection, table)
    predicate = 'period_start < %s AND period_end > %s'
    bounds = (end, start)
    if table == 'analysis_ufw_traffic_daily':
        upper = end.date()
        if end.time().isoformat() != '00:00:00':
            upper += timedelta(days=1)
        predicate = 'analysis_date >= %s AND analysis_date < %s'
        bounds = (start.date(), upper)
    parameters = (time_basis,) + bounds
    if host_id is not None:
        validate_id(host_id)
        predicate += ' AND host_id=%s'
        parameters += (host_id,)
    order = ','.join(KEYS[table][1]) + ',time_basis'
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute('SELECT * FROM `' + table + '` WHERE time_basis=%s AND ' + predicate
                       + ' ORDER BY ' + order + ' LIMIT %s', parameters + (max_rows + 1,))
        rows = cursor.fetchall()
    if len(rows) > max_rows:
        raise ValueError('Too many analysis results; use a shorter interval.')
    return rows
