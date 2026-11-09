"""Process bounded FIM batches using the shared Detection storage."""

import json

from detection.common.alerts import save_alert
from detection.filesystem.detector import (
    CRITICAL_DIRECTORIES,
    CRITICAL_FILES,
    EVIDENCE_TYPE,
    RULE_KEYS,
    FimDetectionError,
    build_alert,
    confirm_event,
)
from metrics.filesystem.file_integrity import approved_path
from metrics.filesystem.permissions import DEFAULT_RULES, index_rules
from metrics.snapshot import release_snapshot_lock

LOCK_NAME = 'mysql_siem_detection_FIM'
STATE = {'version': 1}


def _checkpoint(cursor, rule_id):
    cursor.execute('SELECT last_event_id, state_data FROM detection_state WHERE rule_id = %s', (rule_id,))
    row = cursor.fetchone()
    if row is None:
        return 0
    last_id, raw = row
    try:
        data = json.loads(raw)
        if type(last_id) is not int or not 0 <= last_id < 2**64 or data != STATE or type(data['version']) is not int:
            raise ValueError
    except (ValueError, TypeError):
        raise FimDetectionError('Invalid FIM detection checkpoint.') from None
    return last_id


def _process_rule(connection, cursor, rule_key, rule_id, files, directories, policy, batch_size):
    last_id = _checkpoint(cursor, rule_id)
    # The FIM writer serializes event commits across hosts, so no lower ID can appear later.
    cursor.execute('SELECT e.id, e.host_id, e.source_id, e.collector_id, e.sender_id, e.file_path, e.event_type, '
                   'e.previous_state, e.current_state, e.observed_at, s.source_type FROM filesystem_file_events e '
                   'LEFT JOIN log_sources s ON s.source_id = e.source_id AND s.host_id = e.host_id '
                   'WHERE e.id > %s ORDER BY e.id LIMIT %s FOR SHARE', (last_id, batch_size))
    rows = cursor.fetchall()
    count = 0
    for row in rows:
        event = confirm_event(row)
        alert = build_alert(rule_key, event, files, directories, policy)
        if alert is not None and save_alert(connection, alert, [(EVIDENCE_TYPE, event[0])], manage_transaction=False):
            count += 1
    if rows:
        last_id = rows[-1][0]
        cursor.execute('INSERT INTO detection_state (rule_id, last_event_id, state_data) VALUES (%s, %s, %s) '
                       'ON DUPLICATE KEY UPDATE last_event_id = %s', (rule_id, last_id, json.dumps(STATE), last_id))
    return count


def run_automatic(connection, *, critical_files=CRITICAL_FILES, critical_directories=CRITICAL_DIRECTORIES,
                  permission_rules=DEFAULT_RULES, batch_size=500):
    """Use a dedicated connection. Return the number of newly committed alerts."""
    if type(batch_size) is not int or not 1 <= batch_size <= 10000:
        raise ValueError('Invalid FIM detection batch size.')
    files = set(map(approved_path, critical_files))
    directories = tuple(map(approved_path, critical_directories))
    policy = index_rules(permission_rules)
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s, 0)', (LOCK_NAME,))
            if cursor.fetchone() != (1,):
                raise FimDetectionError('FIM detection lock is unavailable.')
            locked = True
            connection.begin()
            cursor.execute("SELECT status FROM schema_migrations WHERE version = '035'")
            if cursor.fetchone() != ('APPLIED',):
                raise FimDetectionError('FIM detection migration 035 is incomplete.')
            count = 0
            for key in RULE_KEYS:
                cursor.execute('SELECT id, enabled FROM detection_rules WHERE rule_key = %s FOR SHARE', (key,))
                rule = cursor.fetchone()
                if rule is None:
                    raise FimDetectionError('A FIM detection rule is missing.')
                rule_id, enabled = rule
                if enabled:
                    count += _process_rule(connection, cursor, key, rule_id, files, directories, policy, batch_size)
        connection.commit()
        return count
    except BaseException:
        if connection.open:
            connection.rollback()
        raise
    finally:
        if locked and connection.open:
            release_snapshot_lock(connection, LOCK_NAME)
