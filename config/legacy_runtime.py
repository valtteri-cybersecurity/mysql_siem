"""Approved removal of exact historical runtime grants; never deletes data."""

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import UUID

import pymysql

from config import installation_state as journal
from config import reset_installation as reset
from config.service_installation import trusted_directory

OWNER = 0
BACKUP = 'legacy-runtime-grants.json'


def server_identity(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT @@server_uuid')
        row = cursor.fetchone()
    if not isinstance(row, (tuple, list)) or len(row) != 1 or str(UUID(row[0])) != row[0]:
        raise reset.ResetError('Cannot verify the local MySQL server identity.')
    return row[0]


def read_plan(connection):
    rows = reset.read_account_grants(connection)
    if rows is None:
        return [], []
    return rows, reset.legacy_runtime_grant_plan(rows)


def require_subset(plan, approved):
    for entry in plan:
        matched = False
        for previous in approved:
            if (entry['schema'], entry['table']) == (previous['schema'], previous['table']):
                matched = set(entry['privileges']) <= set(previous['privileges'])
        if not matched:
            raise reset.ResetError('Legacy grant plan changed; preserve the backup and review before retrying.')


def read_backup(path, server):
    if not path.exists() and not path.is_symlink():
        return None
    record = json.loads(journal.read_file(path))
    fields = {'version', 'account', 'server', 'phase', 'plan', 'original_grants'}
    if (not isinstance(record, dict) or set(record) != fields or type(record['version']) is not int
            or record['version'] != 1 or record['account'] != 'pythonuser@localhost'
            or record['server'] != server or record['phase'] not in ('approved', 'complete')
            or not isinstance(record['original_grants'], list)):
        raise reset.ResetError('Invalid legacy grant backup; it was not overwritten.')
    rows = []
    for grant in record['original_grants']:
        rows.append((grant,))
    if reset.legacy_runtime_grant_plan(rows) != record['plan']:
        raise reset.ResetError('Legacy grant backup conflicts with its original rights.')
    return record


def prepare_grants(connection, state, *, confirm=input):
    rows, plan = read_plan(connection)
    path = state / BACKUP
    if not plan:
        if path.exists() or path.is_symlink():
            read_backup(path, server_identity(connection))
        return
    server = server_identity(connection)
    previous = read_backup(path, server)
    if previous is not None:
        require_subset(plan, previous['plan'])
    print('The following historical pythonuser rights will be removed; database contents are preserved:')
    for entry in plan:
        print('  ' + entry['schema'] + '.' + entry['table'] + ': ' + ', '.join(entry['privileges']))
    print('Approve only if pythonuser no longer needs the old ufw_monitor application or legacy summary tables.')
    if confirm('Remove these legacy rights during installation [y/N]? ').strip().casefold() not in ('y', 'yes'):
        raise reset.ResetError('Legacy grant removal declined; no MySQL rights were changed.')
    if previous is None:
        original = []
        for row in rows:
            original.append(row[0])
        previous = {'version': 1, 'account': 'pythonuser@localhost', 'server': server,
                    'phase': 'approved', 'plan': plan, 'original_grants': original}
    previous['phase'] = 'approved'
    journal.write_file(path, json.dumps(previous, sort_keys=True) + '\n')


def apply_grants(connection, state):
    journal.require_maintenance(state)
    _rows, plan = read_plan(connection)
    path = state / BACKUP
    if not plan and not path.exists() and not path.is_symlink():
        return
    record = read_backup(path, server_identity(connection))
    if record is None or plan and record['phase'] != 'approved':
        raise reset.ResetError('Legacy grant removal requires its separately approved backup.')
    require_subset(plan, record['plan'])
    with connection.cursor() as cursor:
        cursor.execute('SELECT GET_LOCK(%s, 0)', (reset.LOCK_NAME,))
        if cursor.fetchone() != (1,):
            raise reset.ResetError('Another database migration is running; no legacy rights were changed.')
    try:
        if plan:
            reset.pause_cron(state)
            reset.pause_systemd()
            reset.wait_for_legacy_jobs()
            _rows, current = read_plan(connection)
            require_subset(current, record['plan'])
            for entry in current:
                privileges = ', '.join(entry['privileges'])
                # Names and privileges came from the finite historical policy.
                statement = (f"REVOKE {privileges} ON `{entry['schema']}`.`{entry['table']}` "
                             "FROM 'pythonuser'@'localhost'")
                with connection.cursor() as cursor:
                    cursor.execute(statement)
        reset.validate_account(connection)
        record['phase'] = 'complete'
        journal.write_file(path, json.dumps(record, sort_keys=True) + '\n')
        print('Legacy runtime grants removed and strict privileges verified; no database content was changed.')
    finally:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (reset.LOCK_NAME,))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('approve', 'apply'))
    parser.add_argument('--project', type=Path, required=True)
    args = parser.parse_args(argv)
    connection = None
    try:
        if os.geteuid() != OWNER:
            raise reset.ResetError('Legacy grant preparation requires the installer administrator.')
        journal.require_install_lock()
        trusted_directory(journal.STATE_DIR)
        trusted_directory(args.project)
        record = journal.read_deployment(journal.STATE_DIR)
        if (record is None or record['phase'] != 'staged' or record['stage'] != str(args.project)
                or record['user'] != 'mysql_siem' or record['target'] != '/usr/local/lib/mysql_siem'
                or reset.get_installation_role(path=args.project / 'config/role.env') != 'server'):
            raise reset.ResetError('Legacy grant preparation requires the protected Server staging journal.')
        reset.validate_settings(os.environ)
        if args.action == 'apply':
            journal.require_stage(journal.STATE_DIR, args.project)
        connection = pymysql.connect(unix_socket=reset.SOCKET, user='root', charset='utf8mb4', autocommit=True,
                                     connect_timeout=5, read_timeout=15, write_timeout=15)
        reset.check_server_version(connection)
        if args.action == 'approve':
            prepare_grants(connection, journal.STATE_DIR)
        else:
            apply_grants(connection, journal.STATE_DIR)
        return 0
    except pymysql.MySQLError:
        print('Legacy grant preparation failed: MySQL operation failed; keep maintenance and the backup.', file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RuntimeError, EOFError) as error:
        print('Legacy grant preparation stopped: ' + str(error), file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
