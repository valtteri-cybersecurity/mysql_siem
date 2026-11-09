import json
from datetime import datetime, timedelta

import pymysql
import pytest

from database import migrate, ufw_history
from database.identity import (
    approve_collector_source,
    register_collector,
    register_host,
    register_source,
)
from detection.filesystem import detector, runner
from metrics.filesystem.fim_db import INSERT_EVENT
from metrics.filesystem.permissions import DEFAULT_RULES, PermissionRule, index_rules

STAMP = datetime(2026, 11, 9, 12, 30, 0, 123456)
SSH = b'/etc/ssh/sshd_config'
SUDO = b'/etc/sudoers'
APPROVED = b'/opt/site/approved'
OLD_HASH = 'a' * 64
NEW_HASH = 'b' * 64


def state(mode=0o644, *, digest=OLD_HASH, uid=0):
    return json.dumps({'mode': mode, 'owner_uid': uid, 'group_gid': 0, 'size_bytes': 100, 'content_sha256': digest})


def evidence(path, kind, before, after, *, host=1, source_type='filesystem'):
    return (1, host, 2, 3, None, path, kind, before, after, STAMP, source_type)


def alert(rule, row, rules=DEFAULT_RULES):
    return detector.build_alert(rule, detector.confirm_event(row), {SSH, SUDO}, (), index_rules(rules))


def test_critical_change_and_deletion_are_scoped_and_fingerprinted():
    row = evidence(SSH, 'CONTENT_CHANGED', state(), state(digest=NEW_HASH))
    original = alert(detector.CRITICAL_RULE, row)
    other = alert(detector.CRITICAL_RULE, evidence(SSH, 'CONTENT_CHANGED', state(), state(digest=NEW_HASH), host=2))
    assert original['alert_fingerprint'] != other['alert_fingerprint']
    assert original['host_id'] == 1 and original['first_seen'] == STAMP
    assert original['details']['source_id'] == 2 and original['details']['path'] == SSH.decode()
    assert original['details']['previous_state']['content_sha256'] == OLD_HASH
    deletion = alert(detector.CRITICAL_RULE, evidence(SUDO, 'DELETED', state(), None))
    assert deletion['details']['current_state'] is None
    assert alert(detector.CRITICAL_RULE, evidence(b'/etc/default/app', 'CONTENT_CHANGED', state(), state(digest=NEW_HASH))) is None


def test_permission_alert_uses_phase_six_risks_and_only_new_risk():
    risk = alert(detector.PERMISSION_RULE, evidence(SSH, 'PERMISSION_CHANGED', state(), state(0o6757)))
    kinds = []
    for item in risk['details']['risks']:
        kinds.append(item['kind'])
    assert kinds == ['WORLD_WRITABLE', 'SUID', 'SGID']
    assert risk['details']['risks'][1]['severity'] == 'CRITICAL'
    assert alert(detector.PERMISSION_RULE, evidence(SSH, 'PERMISSION_CHANGED', state(0o646), state(0o746))) is None
    assert alert(detector.PERMISSION_RULE, evidence(SSH, 'OWNER_CHANGED', state(), state(uid=1000)))['details']['risks'][0]['kind'] == 'OWNER_MISMATCH'


def test_permission_exception_does_not_hide_unrelated_world_write():
    rules = (PermissionRule('site', paths=(APPROVED,), special_exceptions=((APPROVED, 0o4000),), critical=True),)
    assert alert(detector.PERMISSION_RULE, evidence(APPROVED, 'CREATED', None, state(0o4755)), rules) is None
    result = alert(detector.PERMISSION_RULE, evidence(APPROVED, 'CREATED', None, state(0o4757)), rules)
    assert len(result['details']['risks']) == 1 and result['details']['risks'][0]['kind'] == 'WORLD_WRITABLE'


@pytest.mark.parametrize('row', [
    evidence(SSH, 'PERMISSION_CHANGED', state(), state()),
    evidence(SSH, 'CONTENT_CHANGED', state(digest=None), state()),
    evidence(SSH, 'CREATED', None, state(), source_type='auth'),
    evidence(SSH, 'CREATED', None, '{"mode":420}'),
    evidence(SSH, 'CREATED', state(), state(0o646)),
])
def test_invalid_evidence_is_rejected(row):
    with pytest.raises(detector.FimDetectionError, match='Invalid FIM evidence'):
        detector.confirm_event(row)


def _enroll(cursor, name):
    host = register_host(cursor, name, reported_hostname='shared-name')
    source = register_source(cursor, host, 'filesystem', 'filesystem', enabled=True)
    collector = register_collector(cursor, name, enabled=True)
    approve_collector_source(cursor, collector, source)
    return host, source, collector, None


def _saved(connection):
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute('SELECT r.rule_key, a.host_id, a.severity, a.details, e.event_type, e.event_id '
                       'FROM detection_alerts a JOIN detection_rules r ON r.id=a.rule_id '
                       'JOIN alert_evidence e ON e.alert_id=a.id ORDER BY a.id')
        alerts = cursor.fetchall()
        cursor.execute('SELECT r.rule_key, s.last_event_id FROM detection_state s '
                       'JOIN detection_rules r ON r.id=s.rule_id ORDER BY r.rule_key')
        return alerts, cursor.fetchall()


def _granted_runtime(cursor, database):
    cursor.execute("CREATE USER 'fim_detection_test'@'localhost' IDENTIFIED BY 'private-test'")
    for table in ('schema_migrations', 'log_sources', 'filesystem_file_events', 'detection_rules'):
        cursor.execute(f"GRANT SELECT ON `{database}`.`{table}` TO 'fim_detection_test'@'localhost'")
    for table in ('detection_alerts', 'detection_state'):
        cursor.execute(f"GRANT SELECT, INSERT, UPDATE ON `{database}`.`{table}` TO 'fim_detection_test'@'localhost'")
    for table in ('alert_evidence', 'alert_hosts'):
        cursor.execute(f"GRANT SELECT, INSERT ON `{database}`.`{table}` TO 'fim_detection_test'@'localhost'")


def test_private_mysql_detection_and_migration(empty_mysql, identity_server, monkeypatch):
    admin = empty_mysql
    with monkeypatch.context() as before:
        before.setattr(migrate, 'MIGRATIONS', migrate.MIGRATIONS[:-1])
        assert migrate.migrate(admin)[-1] == '034'
    with admin.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        cursor.execute("INSERT INTO detection_rules (rule_key,name,severity,enabled) VALUES (%s,'Operator title','MEDIUM',FALSE)",
                       (detector.CRITICAL_RULE,))
        rule_id = cursor.lastrowid
        cursor.execute('SELECT id,name,severity,enabled FROM detection_rules WHERE rule_key=%s', ('PORT_SCAN_001',))
        old_rule = cursor.fetchone()
        cursor.execute("INSERT INTO detection_alerts (rule_id,severity,title,description,first_seen,last_seen,alert_fingerprint,details) "
                       "VALUES (%s,'HIGH','Legacy alert','Preserved',%s,%s,%s,'{}')", (old_rule[0], STAMP, STAMP, '0' * 64))
        old_alert = cursor.lastrowid
    admin.commit()
    assert migrate.migrate(admin) == ['035']
    migrate.apply_one(admin, '035')
    admin.commit()
    assert migrate.migrate(admin) == []
    with admin.cursor() as cursor:
        cursor.execute('SELECT id,name,severity,enabled FROM detection_rules WHERE rule_key=%s', (detector.CRITICAL_RULE,))
        assert cursor.fetchone() == (rule_id, 'Operator title', 'MEDIUM', 0)
        cursor.execute('SELECT id,name,severity,enabled FROM detection_rules WHERE rule_key=%s', ('PORT_SCAN_001',))
        assert cursor.fetchone() == old_rule
        cursor.execute('SELECT title FROM detection_alerts WHERE id=%s', (old_alert,))
        assert cursor.fetchone() == ('Legacy alert',)
        first = _enroll(cursor, 'first')
        other = _enroll(cursor, 'other')
        ids = []
        for scope, path, kind, old, new in (
                (first, SSH, 'CONTENT_CHANGED', state(), state(digest=NEW_HASH)),
                (first, b'/etc/default/app', 'CONTENT_CHANGED', state(), state(digest=NEW_HASH)),
                (first, SSH, 'PERMISSION_CHANGED', state(), state(0o4757)),
                (other, SSH, 'CONTENT_CHANGED', state(), state(digest=NEW_HASH)),
                (first, SUDO, 'DELETED', state(), None),
                (first, APPROVED, 'CREATED', None, state(0o4755))):
            cursor.execute(INSERT_EVENT, scope + (path, kind, old, new, STAMP))
            ids.append(cursor.lastrowid)
        _granted_runtime(cursor, database)
    admin.commit()

    runtime = pymysql.connect(unix_socket=identity_server, user='fim_detection_test', password='private-test',
                              database=database, charset='utf8mb4', autocommit=False)
    rules = DEFAULT_RULES + (PermissionRule('site', paths=(APPROVED,), critical=True,
                                            special_exceptions=((APPROVED, 0o4000),)),)
    with runtime:
        assert runner.run_automatic(runtime, permission_rules=rules) == 1
        initial = _saved(admin)
        assert initial[1] == ((detector.PERMISSION_RULE, ids[-1]),)
        assert initial[0][0][4:] == ('FIM', ids[2])

        with admin.cursor() as cursor:
            cursor.execute('UPDATE detection_rules SET enabled=TRUE WHERE id=%s', (rule_id,))
            cursor.execute("CREATE TRIGGER reject_fim_checkpoint BEFORE INSERT ON detection_state FOR EACH ROW "
                           "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic FIM checkpoint failure'")
        admin.commit()
        with pytest.raises(pymysql.MySQLError, match='synthetic FIM checkpoint failure'):
            runner.run_automatic(runtime, permission_rules=rules)
        assert _saved(admin) == initial
        with admin.cursor() as cursor:
            cursor.execute('DROP TRIGGER reject_fim_checkpoint')
            cursor.execute('SELECT GET_LOCK(%s, 0)', (runner.LOCK_NAME,))
            assert cursor.fetchone() == (1,)
            try:
                with pytest.raises(detector.FimDetectionError, match='lock'):
                    runner.run_automatic(runtime, permission_rules=rules)
            finally:
                cursor.execute('SELECT RELEASE_LOCK(%s)', (runner.LOCK_NAME,))
        assert _saved(admin) == initial

        assert runner.run_automatic(runtime, permission_rules=rules) == 4
        committed = _saved(admin)
        assert len(committed[0]) == 5
        assert committed[1] == ((detector.CRITICAL_RULE, ids[-1]), (detector.PERMISSION_RULE, ids[-1]))
        assert committed[0][1][:3] == (detector.CRITICAL_RULE, first[0], 'MEDIUM')
        assert committed[0][3][1] == other[0] and committed[0][3][-1] == ids[3]
        assert json.loads(committed[0][3][3])['source_id'] == other[1]
        with admin.cursor() as cursor:
            cursor.execute('UPDATE detection_state SET last_event_id=0')
        admin.commit()
        assert runner.run_automatic(runtime, permission_rules=rules) == 0
        assert _saved(admin) == committed

        with admin.cursor() as cursor:
            cursor.execute(INSERT_EVENT, first + (SSH, 'CONTENT_CHANGED', state(digest=NEW_HASH), state(), STAMP + timedelta(seconds=1)))
        admin.commit()
        assert runner.run_automatic(runtime, permission_rules=rules) == 1
        committed = _saved(admin)
        ufw_history.preflight(admin)

        with admin.cursor() as cursor:
            cursor.execute(INSERT_EVENT, first + (SSH, 'PERMISSION_CHANGED', state(), state(), STAMP))
        admin.commit()
        with pytest.raises(detector.FimDetectionError, match='Invalid FIM evidence'):
            runner.run_automatic(runtime, permission_rules=rules)
        assert _saved(admin) == committed

    with admin.cursor() as cursor:
        cursor.execute("UPDATE alert_evidence SET event_id=%s WHERE event_type='FIM' AND event_id=%s", (ids[3], ids[0]))
    admin.commit()
    with pytest.raises(migrate.MigrationError, match='Invalid FIM evidence binding'):
        ufw_history.preflight(admin)
