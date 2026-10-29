"""Additive UFW isolation and current-baseline evidence, not invented provenance."""

import hashlib
import json
import time

KEY = '_ufw_compatibility'
SSH_KEY = '_ssh_baseline'


def active_filter(connection):
    """Old schemas keep their interface; a partially isolated schema excludes old rows."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() "
                       "AND table_name='ufw_log' AND column_name='time_basis'")
        present = cursor.fetchone() == (1,)
    if present:
        return " AND time_basis = 'UTC_VERIFIED'"
    return ''


def fingerprint(connection, table, fields, upper=None):
    """Stream fixed repository identifiers; bind every range/limit value."""
    from database.migrate import MigrationError

    deadline = time.monotonic() + 120
    if upper is None:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COALESCE(MAX(id),0) FROM ' + table)
            upper = int(cursor.fetchone()[0])
    last = count = 0
    digest = hashlib.sha256()
    while last < upper:
        if time.monotonic() >= deadline:
            raise MigrationError('History baseline verification exceeded its time budget.')
        with connection.cursor() as cursor:
            cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(5000) */ ' + fields + ' FROM ' + table
                           + ' WHERE id > %s AND id <= %s ORDER BY id LIMIT %s', (last, upper, 256))
            rows = cursor.fetchall()
        if not rows:
            break
        for row in rows:
            if time.monotonic() >= deadline:
                raise MigrationError('History baseline verification exceeded its time budget.')
            digest.update(json.dumps(row, default=str, ensure_ascii=True).encode('ascii') + b'\n')
            last = row[0]
            count += 1
    return {'count': count, 'max_id': upper, 'sha256': digest.hexdigest()}


def raw_baseline(connection):
    from database.migrate import ufw_timestamp_schema

    result = fingerprint(connection, 'ufw_log', 'id,event_time,raw_line')
    result['precision'] = ufw_timestamp_schema(connection)[1]
    result['origin'] = 'CURRENT_BASELINE'
    from database.ufw_time_basis import UTC_VERIFIED, classify_history
    summary = classify_history(connection, max_rows=100000, max_seconds=120)
    result['all_utc'] = summary['complete'] and summary[UTC_VERIFIED] == result['count']
    return result


def check_baseline(connection, table, fields, baseline):
    from database.migrate import MigrationError

    if not isinstance(baseline, dict):
        raise MigrationError('Invalid baseline evidence.')
    for name in ('count', 'max_id'):
        if type(baseline.get(name)) is not int or not 0 <= baseline[name] < 2**64:
            raise MigrationError('Invalid baseline bounds.')
    if not isinstance(baseline.get('sha256'), str) or len(baseline['sha256']) != 64:
        raise MigrationError('Invalid baseline digest.')
    actual = fingerprint(connection, table, fields, baseline['max_id'])
    for name in ('count', 'max_id', 'sha256'):
        if actual[name] != baseline[name]:
            raise MigrationError('Current upgrade baseline changed or rows disappeared: ' + table)


def check_counts(connection, saved, current):
    """Counts can prove a deficit, never original event identities."""
    from database.migrate import HISTORY_TABLES, MigrationError

    if not isinstance(saved, dict):
        raise MigrationError('Migration history counts are invalid.')
    for table in HISTORY_TABLES:
        expected = saved.get(table, 0)
        if type(expected) is not int or expected < 0:
            raise MigrationError('Migration history counts are invalid.')
        if current.get(table, 0) < expected:
            raise MigrationError('Historical row counts decreased: ' + table)


def check_detection(connection, *, allow_port=False):
    from database.migrate import MigrationError
    from detection.ssh_brute_force.state import load_state

    allowed = ['SSH_BRUTE_FORCE_001']
    if allow_port:
        allowed.append('PORT_SCAN_001')
    with connection.cursor() as cursor:
        for table in ('detection_state', 'detection_alerts'):
            cursor.execute('SELECT DISTINCT r.rule_key FROM ' + table
                           + ' s LEFT JOIN detection_rules r ON r.id=s.rule_id')
            for row in cursor.fetchall():
                if row[0] not in allowed:
                    raise MigrationError('Unisolated UFW or unknown detection history blocks upgrade.')
        cursor.execute("SELECT COUNT(*) FROM alert_evidence e LEFT JOIN detection_alerts a ON a.id=e.alert_id "
                       "LEFT JOIN detection_rules r ON r.id=a.rule_id LEFT JOIN auth_events h ON h.id=e.event_id "
                       "WHERE NOT (r.rule_key <=> 'PORT_SCAN_001') AND "
                       "(NOT (r.rule_key <=> 'SSH_BRUTE_FORCE_001') OR NOT (e.event_type <=> 'AUTH') "
                       "OR h.id IS NULL OR NOT (h.event_type <=> 'SSH_AUTH_FAILURE') "
                       "OR NOT (h.service <=> 'sshd'))")
        if cursor.fetchone()[0]:
            raise MigrationError('Unknown or contradictory evidence binding blocks upgrade.')
        if allow_port:
            cursor.execute("SELECT COUNT(*) FROM alert_evidence e JOIN detection_alerts a ON a.id=e.alert_id "
                           "JOIN detection_rules r ON r.id=a.rule_id LEFT JOIN ufw_log u ON u.id=e.event_id "
                           "WHERE r.rule_key='PORT_SCAN_001' AND (e.event_type <> 'UFW' "
                           "OR u.id IS NULL OR u.time_basis <> 'UTC_VERIFIED')")
            if cursor.fetchone()[0]:
                raise MigrationError('Port scan evidence references isolated or missing events.')
        cursor.execute("SELECT s.rule_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                       "WHERE r.rule_key='SSH_BRUTE_FORCE_001'")
        rules = cursor.fetchall()
    for row in rules:
        try:
            _last, records = load_state(connection, row[0])
        except RuntimeError:
            raise MigrationError('Invalid SSH detection state.') from None
        with connection.cursor() as cursor:
            for record in records:
                event = record['event']
                cursor.execute("SELECT id FROM auth_events WHERE id=%s AND event_hash=%s "
                               "AND event_type='SSH_AUTH_FAILURE' AND service='sshd'", (event['id'], event['event_hash']))
                if cursor.fetchone() != (event['id'],):
                    raise MigrationError('SSH state references an unverified event.')
    if allow_port:
        from detection.port_scan.state import load_state as load_port_state
        with connection.cursor() as cursor:
            cursor.execute("SELECT s.rule_id FROM detection_state s JOIN detection_rules r ON r.id=s.rule_id "
                           "WHERE r.rule_key='PORT_SCAN_001'")
            rules = cursor.fetchall()
        for row in rules:
            try:
                _last, records = load_port_state(connection, row[0])
            except RuntimeError:
                raise MigrationError('Invalid port scan state.') from None
            with connection.cursor() as cursor:
                for record in records:
                    event = record['event']
                    cursor.execute("SELECT event_time FROM ufw_log WHERE id=%s AND time_basis='UTC_VERIFIED'",
                                   (event['id'],))
                    if cursor.fetchone() != (event['event_time'],):
                        raise MigrationError('Port scan state contains isolated events.')


def preflight(connection):
    """Read-only; the verified backup is still mandatory before any DDL."""
    from database.migrate import (
        ANALYSIS_TABLES,
        MigrationError,
        history_counts,
        migration_status,
    )

    records = migration_status(connection)
    for version in ('017', '022'):
        if records.get(version, (None, None))[1] not in (None, 'RUNNING', 'FAILED', 'APPLIED'):
            raise MigrationError('Unknown UFW migration state.')
    current = history_counts(connection)
    modern = records.get('022', (None, None))[1] == 'APPLIED'
    with connection.cursor() as cursor:
        for version in ('017', '022'):
            state = records.get(version, (None, None))[1]
            if state not in (None, 'RUNNING', 'FAILED', 'APPLIED'):
                raise MigrationError('Unknown UFW migration state.')
            if state is None:
                continue
            cursor.execute('SELECT row_counts FROM schema_migrations WHERE version=%s', (version,))
            row = cursor.fetchone()
            if row is None:
                raise MigrationError('Migration ledger is missing.')
            try:
                saved = json.loads(row[0])
            except (ValueError, TypeError):
                raise MigrationError('Migration history counts are invalid.') from None
            check_counts(connection, saved, current)
            required = ('ufw_log',) + ANALYSIS_TABLES + ('detection_state', 'detection_alerts', 'alert_evidence')
            for table in required:
                if table not in saved:
                    raise MigrationError('Migration history counts are invalid: missing ' + table)
            if version == '022' and (KEY not in saved or SSH_KEY not in saved):
                raise MigrationError('Isolation baseline evidence is missing.')
            if version == '017' and KEY not in saved and saved.get('_ufw_utc_proof') is None:
                for table, field in (('ufw_log', 'created_at'), ('detection_alerts', 'detected_at')):
                    if saved.get(table, 0):
                        cursor.execute('SELECT COUNT(*) FROM ' + table + ' WHERE ' + field
                                       + " <= (SELECT started_at FROM schema_migrations WHERE version='017')")
                        if cursor.fetchone()[0] < saved[table]:
                            raise MigrationError('Historical rows may have disappeared: ' + table)
                if saved.get('alert_evidence', 0):
                    cursor.execute("SELECT COUNT(*) FROM alert_evidence e "
                                   "JOIN detection_alerts a ON a.id=e.alert_id "
                                   "JOIN detection_rules r ON r.id=a.rule_id "
                                   "JOIN auth_events h ON h.id=e.event_id "
                                   "WHERE r.rule_key='SSH_BRUTE_FORCE_001' AND e.event_type='AUTH' "
                                   "AND a.detected_at <= (SELECT started_at FROM schema_migrations WHERE version='017') "
                                   "AND h.created_at <= (SELECT started_at FROM schema_migrations WHERE version='017')")
                    if cursor.fetchone()[0] < saved['alert_evidence']:
                        raise MigrationError('Historical evidence may have disappeared.')
            if version == '017' and saved.get('_ufw_utc_proof') is not None:
                from database.migrate import check_ufw_raw_history
                check_ufw_raw_history(connection, saved['ufw_log'], saved=saved)
            if SSH_KEY in saved:
                verify_ssh_baseline(connection, saved[SSH_KEY])
            if KEY in saved:
                check_baseline(connection, 'ufw_log', 'id,event_time,raw_line', saved[KEY])
    from database.ufw_analysis_history import KEY as ANALYSIS_KEY
    from database.ufw_analysis_history import capture, verify
    analysis_state = records.get('023', (None, None))[1]
    if analysis_state not in (None, 'RUNNING', 'FAILED', 'APPLIED'):
        raise MigrationError('Unknown analysis isolation state.')
    if analysis_state is None:
        has_analysis = False
        for table in ANALYSIS_TABLES:
            if current.get(table, 0):
                has_analysis = True
        if has_analysis:
            capture(connection)
    else:
        with connection.cursor() as cursor:
            cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='023'")
            analysis_saved = json.loads(cursor.fetchone()[0])
        check_counts(connection, analysis_saved, current)
        verify(connection, analysis_saved[ANALYSIS_KEY], final=analysis_state == 'APPLIED')
    check_detection(connection, allow_port=modern)
    if modern:
        from database.migrate import ufw_timestamp_schema
        if ufw_timestamp_schema(connection) != ('datetime', 6, 'YES', None):
            raise MigrationError('UFW precision schema changed after isolation.')
        verify_isolation(connection)


def ssh_baseline(connection):
    result = {}
    for table, fields in (('detection_alerts', 'id,rule_id,UNIX_TIMESTAMP(detected_at)'),
                          ('alert_evidence', 'id,alert_id,event_type,event_id')):
        result[table] = fingerprint(connection, table, fields)
    with connection.cursor() as cursor:
        cursor.execute('SELECT rule_id,last_event_id FROM detection_state ORDER BY rule_id')
        result['states'] = cursor.fetchall()
    return result


def verify_ssh_baseline(connection, baseline):
    from database.migrate import MigrationError

    for table, fields in (('detection_alerts', 'id,rule_id,UNIX_TIMESTAMP(detected_at)'),
                          ('alert_evidence', 'id,alert_id,event_type,event_id')):
        check_baseline(connection, table, fields, baseline[table])
    with connection.cursor() as cursor:
        for rule_id, last_id in baseline['states']:
            cursor.execute('SELECT last_event_id FROM detection_state WHERE rule_id=%s', (rule_id,))
            row = cursor.fetchone()
            if row is None or row[0] < last_id:
                raise MigrationError('An original detection checkpoint disappeared or moved backwards.')


def isolate(connection):
    from database.migrate import ROOT, MigrationError
    from database.ufw_time_basis import classify_event_time

    preflight(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='022'")
        saved = json.loads(cursor.fetchone()[0])
    baseline = saved[KEY]
    check_baseline(connection, 'ufw_log', 'id,event_time,raw_line', baseline)
    verify_ssh_baseline(connection, saved[SSH_KEY])
    if not active_filter(connection):
        with connection.cursor() as cursor:
            cursor.execute((ROOT / 'migrations/022_ufw_history_isolation.sql').read_text().strip())
    deadline = time.monotonic() + 120
    last = 0
    while last < baseline['max_id']:
        if time.monotonic() >= deadline:
            raise MigrationError('UFW isolation exceeded its time budget; keep maintenance.')
        with connection.cursor() as cursor:
            cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(5000) */ id,event_time,raw_line FROM ufw_log '
                           'WHERE id>%s AND id<=%s ORDER BY id LIMIT %s', (last, baseline['max_id'], 256))
            rows = cursor.fetchall()
        if not rows:
            raise MigrationError('UFW baseline rows disappeared.')
        with connection.cursor() as cursor:
            for event_id, stored, raw in rows:
                precision = baseline['precision']
                if event_id <= baseline.get('previous_max_id', 0):
                    precision = baseline['previous_precision']
                basis = classify_event_time(raw, stored, precision)
                cursor.execute('UPDATE ufw_log SET time_basis=%s WHERE id=%s', (basis, event_id))
                last = event_id
        connection.commit()
    verify_isolation(connection, saved=saved)
    with connection.cursor() as cursor:
        cursor.execute("ALTER TABLE ufw_log ALTER COLUMN time_basis SET DEFAULT 'UTC_VERIFIED'")


def verify_isolation(connection, *, saved=None):
    from database.migrate import MigrationError
    from database.ufw_time_basis import classify_event_time

    if saved is None:
        with connection.cursor() as cursor:
            cursor.execute("SELECT row_counts FROM schema_migrations WHERE version='022' AND status='APPLIED'")
            row = cursor.fetchone()
        if row is None:
            raise MigrationError('UFW isolation migration is incomplete.')
        saved = json.loads(row[0])
        with connection.cursor() as cursor:
            cursor.execute("SELECT column_default FROM information_schema.columns WHERE table_schema=DATABASE() "
                           "AND table_name='ufw_log' AND column_name='time_basis'")
            if cursor.fetchone() != ('UTC_VERIFIED',):
                raise MigrationError('UFW isolation schema is incomplete.')
    baseline = saved[KEY]
    check_baseline(connection, 'ufw_log', 'id,event_time,raw_line', baseline)
    verify_ssh_baseline(connection, saved[SSH_KEY])
    deadline = time.monotonic() + 120
    last = 0
    while last < baseline['max_id']:
        if time.monotonic() >= deadline:
            raise MigrationError('UFW isolation verification exceeded its time budget.')
        with connection.cursor() as cursor:
            cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(5000) */ id,event_time,raw_line,time_basis FROM ufw_log '
                           'WHERE id>%s AND id<=%s ORDER BY id LIMIT %s', (last, baseline['max_id'], 256))
            rows = cursor.fetchall()
        if not rows:
            raise MigrationError('UFW baseline rows disappeared.')
        for event_id, stored, raw, actual in rows:
            precision = baseline['precision']
            if event_id <= baseline.get('previous_max_id', 0):
                precision = baseline['previous_precision']
            if actual != classify_event_time(raw, stored, precision):
                raise MigrationError('UFW historical isolation changed.')
            last = event_id
