"""One explicit, opt-in rule. Loopback traffic is not evidence of a harmless process."""
import json
import time
from datetime import datetime, timedelta, timezone

from database.identity import validate_id
from ingestion.ufw_validation import InvalidUFW, validate_event

RULE_KEY = 'LOCALHOST_MYSQL_AUDIT_001'
RULE_VERSION = 1
DESCRIPTION = 'AUDIT TCP 127.0.0.1 -> 127.0.0.1:3306 on unambiguous lo interfaces'
RISK = ('Filtering removes detailed evidence of local MySQL attempts, including malicious ones. '
        'UFW cannot identify the originating process. Local scan visibility is reduced.')
DEFINITION = {'action': 'AUDIT', 'protocol': 'TCP', 'src_ip': '127.0.0.1',
              'dst_ip': '127.0.0.1', 'dst_port': 3306, 'interface': 'lo'}


def match(line, parsed):
    for name in ('action', 'protocol', 'src_ip', 'dst_ip', 'dst_port'):
        if parsed[name] != DEFINITION[name]:
            return 'NO_MATCH'
    interfaces = {}
    for part in line.split():
        name, equals, value = part.partition('=')
        if name not in ('IN', 'OUT'):
            continue
        if not equals or name in interfaces:
            return 'AMBIGUOUS_INTERFACE'
        interfaces[name] = value
    # Both fields must be explicit; an absent counterpart is not proof of an empty one.
    if set(interfaces) != {'IN', 'OUT'}:
        return 'AMBIGUOUS_INTERFACE'
    for value in interfaces.values():
        if value not in ('', 'lo'):
            return 'AMBIGUOUS_INTERFACE'
    if 'lo' not in interfaces.values():
        return 'AMBIGUOUS_INTERFACE'
    return 'MATCH'


def load(cursor, identity):
    """Read and verify the audited configuration once while the collector lock is held."""
    if identity is None:
        return None
    cursor.execute('SELECT host_id,rule_key,rule_version,definition,enabled,audit_id '
                   'FROM ufw_filter_rules WHERE source_id=%s LIMIT 2', (identity.source_id,))
    rows = cursor.fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError('UFW_FILTER_CONFIGURATION_CONFLICT')
    host, key, version, definition, enabled, audit_id = rows[0]
    try:
        definition = json.loads(definition)
    except (TypeError, ValueError):
        raise ValueError('UFW_FILTER_DEFINITION_INVALID') from None
    if host != identity.host_id or key != RULE_KEY or version != RULE_VERSION or definition != DEFINITION:
        raise ValueError('UFW_FILTER_DEFINITION_INVALID')
    if enabled not in (0, 1):
        raise ValueError('UFW_FILTER_ENABLED_INVALID')
    cursor.execute('SELECT id,host_id,rule_version,definition,enabled FROM ufw_filter_audit '
                   'WHERE source_id=%s AND rule_key=%s ORDER BY id DESC LIMIT 1', (identity.source_id, key))
    audit = cursor.fetchone()
    if audit is None or audit[:3] != (audit_id, host, version) or audit[4] != enabled:
        raise ValueError('UFW_FILTER_AUDIT_MISMATCH')
    if json.loads(audit[3]) != definition:
        raise ValueError('UFW_FILTER_AUDIT_MISMATCH')
    return bool(enabled)


def change(connection, source_id, host_id, enabled, *, actor, reason, acknowledge_risk=False):
    """Administrator-only change; runtime accounts receive SELECT on configuration."""
    from ingestion.ufw_to_mysql import LOCK_NAME
    validate_id(source_id)
    validate_id(host_id)
    if type(enabled) is not bool:
        raise ValueError('Use an explicit enable or disable operation.')
    if enabled and not acknowledge_risk:
        raise ValueError(RISK + ' Explicit risk acknowledgement is required.')
    for value, maximum in ((actor, 255), (reason, 512)):
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise ValueError('Actor and reason are required and must fit their documented limits.')
        for character in value:
            if ord(character) < 32 or ord(character) == 127:
                raise ValueError('Control characters are forbidden in audit metadata.')
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s,0)', (LOCK_NAME,))
            if cursor.fetchone() != (1,):
                raise RuntimeError('Collector is running; filter settings were not changed.')
            locked = True
            connection.begin()
            cursor.execute('SELECT s.host_id,s.source_type,s.enabled,h.enrollment_status '
                           'FROM log_sources s JOIN hosts h ON h.host_id=s.host_id WHERE s.source_id=%s', (source_id,))
            row = cursor.fetchone()
            if row is None or row[:2] != (host_id, 'ufw'):
                raise ValueError('Filter requires the exact registered UFW host/source binding.')
            if enabled and row[2:] != (1, 'ACTIVE'):
                raise ValueError('Enable requires an active host and enabled UFW source.')
            definition = json.dumps(DEFINITION, sort_keys=True)
            cursor.execute('INSERT INTO ufw_filter_audit '
                           '(source_id,host_id,rule_key,rule_version,definition,enabled,actor,reason,changed_at) '
                           'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))',
                           (source_id, host_id, RULE_KEY, RULE_VERSION, definition, enabled, actor, reason))
            audit_id = cursor.lastrowid
            cursor.execute('INSERT INTO ufw_filter_rules '
                           '(source_id,host_id,rule_key,rule_version,definition,enabled,audit_id) '
                           'VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE '
                           'host_id=VALUES(host_id),rule_version=VALUES(rule_version),definition=VALUES(definition),'
                           'enabled=VALUES(enabled),audit_id=VALUES(audit_id)',
                           (source_id, host_id, RULE_KEY, RULE_VERSION, definition, enabled, audit_id))
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        if locked:
            with connection.cursor() as cursor:
                cursor.execute('SELECT RELEASE_LOCK(%s)', (LOCK_NAME,))


def preview(connection, source_id, host_id, start, end, *, max_rows=100000, max_seconds=20):
    """SELECT-only keyset scan; use event_time, never created_at, for the UTC interval."""
    from analysis.ufw.source_ips import validate_time_range
    from database.ufw_history import active_filter
    validate_time_range(start, end)
    validate_id(source_id)
    validate_id(host_id)
    if type(max_rows) is not int or not 1 <= max_rows <= 1000000:
        raise ValueError('max_rows must be within 1..1000000.')
    if type(max_seconds) is not int or not 1 <= max_seconds <= 120:
        raise ValueError('max_seconds must be within 1..120.')
    deadline = time.monotonic() + max_seconds
    result = {'rule_key': RULE_KEY, 'rule_version': RULE_VERSION, 'conditions': DEFINITION.copy(),
              'examined': 0, 'matching': 0, 'ambiguous_interfaces': 0, 'invalid': 0,
              'complete': False, 'risk': RISK, 'percentage': 0.0}
    last_id = 0
    utc_only = active_filter(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT host_id,source_type FROM log_sources WHERE source_id=%s', (source_id,))
        if cursor.fetchone() != (host_id, 'ufw'):
            raise ValueError('Preview requires the exact UFW host/source binding.')
        cursor.execute('SELECT COALESCE(MAX(id),0) FROM ufw_log WHERE source_scope=%s', (source_id,))
        upper = cursor.fetchone()[0]
        while last_id < upper:
            if time.monotonic() >= deadline or result['examined'] >= max_rows:
                break
            limit = min(256, max_rows - result['examined'])
            cursor.execute('SELECT /*+ MAX_EXECUTION_TIME(1000) */ id,raw_line FROM ufw_log '
                           'WHERE source_scope=%s AND host_id=%s AND id>%s AND id<=%s '
                           'AND event_time>=%s AND event_time<%s' + utc_only + ' ORDER BY id LIMIT %s',
                           (source_id, host_id, last_id, upper, start, end, limit))
            rows = cursor.fetchall()
            if not rows:
                result['complete'] = True
                break
            for event_id, line in rows:
                if time.monotonic() >= deadline:
                    break
                last_id = event_id
                result['examined'] += 1
                try:
                    parsed = validate_event(line)
                    if parsed is None:
                        raise InvalidUFW('NON_UFW')
                except ValueError:
                    result['invalid'] += 1
                    continue
                status = match(line, parsed)
                if status == 'MATCH':
                    result['matching'] += 1
                elif status == 'AMBIGUOUS_INTERFACE':
                    result['ambiguous_interfaces'] += 1
            if (len(rows) < limit and last_id == rows[-1][0]) or last_id == upper:
                result['complete'] = True
                break
    if last_id >= upper:
        result['complete'] = True
    if result['examined']:
        result['percentage'] = result['matching'] * 100 / result['examined']
    return result


def statistics(connection, source_id, start, end):
    """Exact unique counts by UTC event hour. Half-open intervals must be whole hours."""
    from analysis.ufw.source_ips import validate_time_range
    validate_time_range(start, end)
    validate_id(source_id)
    if start.minute or start.second or start.microsecond or end.minute or end.second or end.microsecond:
        raise ValueError('Filter statistics require whole UTC hours.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT rule_key,rule_version,SUM(filtered_count),MIN(first_event_time),MAX(last_event_time) '
                       'FROM ufw_filter_stats WHERE source_id=%s AND period_start>=%s AND period_start<%s '
                       'GROUP BY rule_key,rule_version', (source_id, start, end))
        return cursor.fetchall()


def record_counts(cursor, identity, entries):
    """Seen keys, hourly unique counts and the checkpoint share the caller's transaction."""
    buckets = {}
    values = []
    recorded_at = datetime.now(timezone.utc).replace(tzinfo=None)
    for digest, parsed in entries:
        event_time = parsed['event_time']
        values.append((identity.source_id, bytes.fromhex(digest), identity.host_id, RULE_KEY, RULE_VERSION, event_time, recorded_at))
        start = event_time.replace(minute=0, second=0, microsecond=0)
        if start not in buckets:
            buckets[start] = [0, event_time, event_time]
        bucket = buckets[start]
        bucket[0] += 1
        bucket[1] = min(bucket[1], event_time)
        bucket[2] = max(bucket[2], event_time)
    if not values:
        return
    cursor.executemany('INSERT INTO ufw_filter_seen '
                       '(source_id,event_hash,host_id,rule_key,rule_version,event_time,recorded_at) '
                       'VALUES (%s,%s,%s,%s,%s,%s,%s)', values)
    for start, (count, first, last) in buckets.items():
        cursor.execute('INSERT INTO ufw_filter_stats '
                       '(source_id,host_id,rule_key,rule_version,period_start,period_end,filtered_count,'
                       'first_event_time,last_event_time,recorded_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6)) '
                       'ON DUPLICATE KEY UPDATE filtered_count=filtered_count+VALUES(filtered_count),'
                       'first_event_time=LEAST(first_event_time,VALUES(first_event_time)),'
                       'last_event_time=GREATEST(last_event_time,VALUES(last_event_time)),recorded_at=UTC_TIMESTAMP(6)',
                       (identity.source_id, identity.host_id, RULE_KEY, RULE_VERSION, start,
                        start + timedelta(hours=1), count, first, last))


def coverage_notice(connection, start, end):
    """Analysis summaries describe stored rows and report intentional exclusions separately."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() "
                       "AND table_name='ufw_filter_seen'")
        if cursor.fetchone() != (1,):
            return {}
        cursor.execute('SELECT COUNT(*) FROM ufw_filter_seen WHERE event_time>=%s AND event_time<%s', (start, end))
        count = cursor.fetchone()[0]
    if not count:
        return {}
    return {'input_scope': 'STORED_UFW_EVENTS', 'intentionally_filtered_events': count,
            'filtering_visibility': RISK}
