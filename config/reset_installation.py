"""Server reset or additive upgrade, only inside the installer maintenance lock."""

import argparse
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pymysql

from config import installation_state as journal
from config.installation_backup import BackupError
from config.installation_role import RoleConfigurationError, get_installation_role
from config.service_installation import InstallationError, trusted_directory
from database.migrate import LOCK_NAME, MigrationError

DATABASE = 'mysql_siem'
ACCOUNT = 'pythonuser'
SOCKET = '/run/mysqld/mysqld.sock'
RESET_WARNING = """WARNING: RESET INSTALLATION

This operation will permanently delete the
existing MySQL SIEM application database data.

All collected events, metrics, alerts and
collection checkpoints may be lost.

Type RESET to confirm: """


class ResetError(RuntimeError):
    """A reset precondition failed; keep collection paused."""


def validate_settings(settings):
    if (settings.get('DB_NAME') != DATABASE or settings.get('DB_HOST') != 'localhost'
            or settings.get('DB_USER') != ACCOUNT or not settings.get('DB_PASSWORD')
            or settings.get('DB_PORT', '3306') != '3306'):
        raise ResetError('Reset requires local mysql_siem, pythonuser, port 3306 and a nonempty password.')


def database_exists(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=%s', (DATABASE,))
        return cursor.fetchone()[0] == 1


def confirm_reset(exists, confirm=input):
    if exists and confirm(RESET_WARNING) != 'RESET':
        raise ResetError('Reset cancelled. No database was deleted.')


def run_command(arguments, **options):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=30,
                          env=dict(os.environ, LC_ALL='C'), check=False, **options)


def collection_command(command):
    # Do not match unrelated jobs merely because they also use Python or MySQL.
    path = re.search(r'/mysql_siem(?:[/\s\"\']|$)', command)
    known_path = False
    settings_source = os.environ.get('SIEM_BOOTSTRAP_SETTINGS')
    if settings_source:
        known_path = re.search(re.escape(settings_source) + r'(?:[/\s\"\']|$)', command) is not None
    component = False
    for signature in ('ingestion/ufw_to_mysql.py', 'ingestion/auth/', 'ingestion/dns/',
                      'metrics/system/', 'metrics/filesystem/', 'metrics/security/',
                      'metrics/processes/', 'metrics/services/', 'ingestion/audit/', 'config/audit_launcher.py',
                      'analysis/ufw/', 'analysis/daily_counts/', 'detection/port_scan/',
                      'detection/ssh_brute_force/', '-m ingestion.', '-m metrics.',
                      '-m analysis.ufw', '-m detection.'):
        if signature in command:
            component = True
            break
    return (path is not None or known_path) and component


def pause_cron(state):
    plans = []
    for account in pwd.getpwall():
        result = run_command(['crontab', '-u', account.pw_name, '-l'])
        if result.returncode:
            if result.stderr.strip() == 'no crontab for ' + account.pw_name:
                continue
            raise ResetError('Cannot inspect crontab for ' + account.pw_name + '; no database reset was performed.')
        kept = []
        removed = False
        for line in result.stdout.splitlines():
            if line.lstrip().startswith('#') or not collection_command(line):
                kept.append(line)
            else:
                removed = True
        text = '\n'.join(kept) + '\n'
        if removed:
            plans.append((account.pw_name, result.stdout, text))
    # Save before replacing any crontab. Never restore old jobs after a reset error.
    backup = state / 'reset-cron.json'
    if not backup.exists():
        journal.write_file(backup, json.dumps(plans))
    for user, _previous, text in plans:
        result = run_command(['crontab', '-u', user, '-'], input=text)
        if result.returncode:
            raise ResetError('Cannot pause legacy cron for ' + user + '; collection remains paused.')


def check_system_cron(directory=Path('/etc')):
    paths = [directory / 'crontab']
    cron_d = directory / 'cron.d'
    if cron_d.exists():
        paths.extend(cron_d.iterdir())
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            if not line.lstrip().startswith('#') and collection_command(line):
                raise ResetError('Legacy mysql_siem system cron remains in ' + str(path)
                                 + '; disable this job and retry. The database was not reset.')


def pause_systemd():
    # Unit files include bare templates such as apport-coredump-hook@.service.
    # systemctl show cannot inspect these as runnable units without an instance.
    installed = run_command(['systemctl', 'list-unit-files', '--type=service,timer',
                             '--no-legend', '--no-pager'])
    if installed.returncode:
        raise ResetError('Cannot inspect systemd unit files; the database was not reset.')

    # Also inspect loaded instances (including template instances), so ignoring
    # uninstantiated templates never skips a running mysql_siem collector.
    loaded = run_command(['systemctl', 'list-units', '--all', '--type=service,timer',
                          '--no-legend', '--no-pager', '--plain'])
    if loaded.returncode:
        raise ResetError('Cannot inspect loaded systemd units; the database was not reset.')

    names = set()
    for output in (installed.stdout, loaded.stdout):
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            # A failed unit can have a leading bullet in list-units output.
            name = parts[1] if parts[0] == '●' and len(parts) > 1 else parts[0]
            if not name.endswith(('.service', '.timer')):
                continue
            if name.endswith(('@.service', '@.timer')):
                # Bare template, not an actual instance. Real instances such
                # as collector@host.service are included and checked below.
                continue
            names.add(name)

    services = []
    timers = []
    for name in sorted(names):
        if name.endswith('.service'):
            detail = run_command(['systemctl', 'show', name,
                                  '--property=ExecStart', '--property=WorkingDirectory', '--value'])
            if detail.returncode:
                raise ResetError('Cannot inspect systemd service ' + name)
            if collection_command(detail.stdout):
                services.append(name)
        else:
            timers.append(name)

    matching_timers = []
    for name in timers:
        detail = run_command(['systemctl', 'show', name, '--property=Unit', '--value'])
        if detail.returncode:
            raise ResetError('Cannot inspect systemd timer ' + name)
        if detail.stdout.strip() in services:
            matching_timers.append(name)

    # Stop timers before the services they could restart.
    for name in matching_timers + services:
        stopped = run_command(['systemctl', 'stop', name])
        if stopped.returncode:
            raise ResetError('Cannot stop legacy mysql_siem unit ' + name)
        disabled = run_command(['systemctl', 'disable', name])
        if disabled.returncode:
            raise ResetError('Cannot disable legacy mysql_siem unit ' + name)


def wait_for_legacy_jobs(processes=Path('/proc'), timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        busy = False
        for process in processes.iterdir():
            if not process.name.isdigit() or int(process.name) == os.getpid():
                continue
            try:
                command = (process / 'cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8', errors='replace')
            except (FileNotFoundError, ProcessLookupError):
                continue
            module_job = re.search(r'-m (?:ingestion\.(?:auth|dns|audit)|metrics\.(?:system|filesystem|security|processes|services)|analysis\.ufw|detection\.(?:port_scan|ssh_brute_force))(?:[.\s]|$)', command)
            try:
                directory = os.readlink(process / 'cwd')
            except (FileNotFoundError, ProcessLookupError):
                directory = ''
            if collection_command(command + ' ' + directory) or module_job is not None:
                busy = True
                break
        if not busy:
            return
        if time.monotonic() >= deadline:
            raise ResetError('A legacy mysql_siem job is still running. Stop it gracefully and retry; no reset was performed.')
        time.sleep(0.2)


# Maximum approved rights, matching the installer table grants. Missing rights
# are allowed here: the normal installer grants them after schema preparation.
RUNTIME_TABLE_PRIVILEGES = {
    'filesystem_metrics': 'SELECT, INSERT, UPDATE',
    'security_metrics': 'SELECT, INSERT, UPDATE',
    'system_metrics': 'SELECT, INSERT',
    'process_events': 'SELECT, INSERT',
    'service_events': 'SELECT, INSERT',
    'process_state': 'SELECT, INSERT, DELETE',
    'service_state': 'SELECT, INSERT, DELETE',
    'collector_snapshots': 'SELECT, INSERT, UPDATE',
    'audit_events': 'SELECT, INSERT',
    'audit_checkpoints': 'SELECT, INSERT, UPDATE',
    'audit_targets': 'SELECT',
    'analysis_source_ips': 'SELECT, INSERT, DELETE',
    'analysis_ufw_ports': 'SELECT, INSERT, DELETE',
    'analysis_ufw_traffic': 'SELECT, INSERT, UPDATE',
    'analysis_ufw_traffic_daily': 'SELECT, INSERT, UPDATE',
    'ufw_log': 'SELECT, INSERT',
    'ufw_state': 'SELECT, INSERT, UPDATE',
    'schema_migrations': 'SELECT',
    'hosts': 'SELECT',
    'host_groups': 'SELECT',
    'host_group_members': 'SELECT',
    'log_sources': 'SELECT',
    'collectors': 'SELECT',
    'collector_sources': 'SELECT',
    'sender_identities': 'SELECT',
    'sender_sources': 'SELECT',
    'sender_certificates': 'SELECT',
    'alert_hosts': 'SELECT, INSERT',
    'dns_sources': 'SELECT, INSERT, UPDATE',
    'dns_events': 'SELECT, INSERT, DELETE',
    'dns_collection_state': 'SELECT, INSERT, UPDATE',
    'dns_client_filters': 'SELECT, INSERT, UPDATE, DELETE',
    'dns_domain_filters': 'SELECT, INSERT, UPDATE, DELETE',
    'detection_rules': 'SELECT',
    'detection_alerts': 'SELECT, INSERT, UPDATE',
    'alert_evidence': 'SELECT, INSERT',
    'detection_state': 'SELECT, INSERT, UPDATE',
    'auth_events': 'SELECT, INSERT',
    'auth_ingestion_state': 'SELECT, INSERT, UPDATE',
}


# Historical installers granted these exact table permissions. They may only
# be removed through the separate, administrator-approved legacy transition.
LEGACY_RUNTIME_PRIVILEGES = {
    'mysql_siem': {
        'top_attacking_ips': 'SELECT, INSERT, UPDATE',
        'top_targeted_ports': 'SELECT, INSERT, UPDATE',
        'ufw_daily_actions_counts': 'SELECT, INSERT, UPDATE',
    },
    'ufw_monitor': {
        'filesystem_metrics': 'SELECT, INSERT, UPDATE',
        'security_metrics': 'SELECT, INSERT, UPDATE',
        'system_metrics': 'SELECT, INSERT',
        'top_attacking_ips': 'SELECT, INSERT, UPDATE',
        'top_targeted_ports': 'SELECT, INSERT, UPDATE',
        'ufw_daily_actions_counts': 'SELECT, INSERT, UPDATE',
        'ufw_log': 'SELECT, INSERT',
        'ufw_state': 'SELECT, INSERT, UPDATE',
    },
}


def parse_runtime_grant(row):
    if not isinstance(row, (tuple, list)) or len(row) != 1 or not isinstance(row[0], str):
        raise ResetError('Cannot verify pythonuser privileges: invalid SHOW GRANTS result.')
    grant = re.fullmatch(
        r'GRANT ([A-Z_]+(?:, *[A-Z_]+)*) ON (\*|`[a-zA-Z0-9_]+`)\.'
        r'(\*|`[a-zA-Z0-9_]+`) TO `pythonuser`@`localhost`', row[0])
    if grant is None:
        raise ResetError('Unsafe runtime privileges: unsupported grant, role or GRANT OPTION for '
                         'pythonuser@localhost. Review manually.')
    privileges = set()
    for privilege in grant[1].split(','):
        privileges.add(privilege.strip())
    return grant[2].strip('`'), grant[3].strip('`'), privileges


def runtime_grant_allowed(schema, table, privileges):
    if privileges == {'USAGE'} and schema == '*' and table == '*':
        return True
    allowed = set(RUNTIME_TABLE_PRIVILEGES.get(table, '').split(', '))
    return schema == DATABASE and table in RUNTIME_TABLE_PRIVILEGES and privileges <= allowed


def validate_runtime_grants(rows):
    """Accept only approved table rights; legacy recognition never grants trust."""
    if not rows:
        raise ResetError('Cannot verify pythonuser privileges: SHOW GRANTS returned no rows.')
    for row in rows:
        schema, table, privileges = parse_runtime_grant(row)
        if not runtime_grant_allowed(schema, table, privileges):
            raise ResetError('Unsafe runtime privileges: unapproved rights or target '
                             + schema + '.' + table + ' (' + ', '.join(sorted(privileges))
                             + ') for pythonuser@localhost. Review manually.')


def legacy_runtime_grant_plan(rows):
    """Classify a finite historical policy, without changing or approving it."""
    if not rows:
        raise ResetError('Cannot verify pythonuser privileges: SHOW GRANTS returned no rows.')
    planned = {}
    for row in rows:
        schema, table, privileges = parse_runtime_grant(row)
        if runtime_grant_allowed(schema, table, privileges):
            continue
        maximum = LEGACY_RUNTIME_PRIVILEGES.get(schema, {}).get(table)
        if maximum is None or not privileges <= set(maximum.split(', ')):
            validate_runtime_grants([row])
        planned.setdefault((schema, table), set()).update(privileges)
    result = []
    for (schema, table), privileges in sorted(planned.items()):
        result.append({'schema': schema, 'table': table, 'privileges': sorted(privileges)})
    return result


def read_account_grants(connection, *, allow_missing=True):
    """Read and validate direct/implicit rights; never repair an account."""
    try:
        with connection.cursor() as cursor:
            # SHOW GRANTS FOR a named account omits mandatory roles. Reject them
            # explicitly rather than assuming an empty direct grant list is safe.
            cursor.execute('SELECT @@GLOBAL.mandatory_roles')
            if cursor.fetchone() != ('',):
                raise ResetError('Cannot approve pythonuser privileges with mandatory roles or unknown role state. '
                                 'Review manually.')
            cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User='pythonuser' AND Host='localhost'")
            count = cursor.fetchone()
            if count == (0,) and allow_missing:
                return
            if count == (0,):
                raise ResetError('Runtime account pythonuser@localhost is missing; upgrade requires it.')
            if count != (1,):
                raise ResetError('Cannot verify the runtime account; installation stopped.')
            cursor.execute("SHOW GRANTS FOR 'pythonuser'@'localhost'")
            rows = cursor.fetchall()
    except pymysql.MySQLError:
        raise ResetError('Cannot verify pythonuser privileges: MySQL account/SHOW GRANTS query failed. '
                         'Review administrator access.') from None
    return rows


def validate_account(connection, *, allow_missing=True, allow_legacy=False):
    rows = read_account_grants(connection, allow_missing=allow_missing)
    if rows is None:
        return []
    if allow_legacy:
        return legacy_runtime_grant_plan(rows)
    validate_runtime_grants(rows)
    return []


def clear_old_identity(state, project):
    record = journal.require_stage(state, project)
    # A reset deliberately invalidates old DB identities, not other settings.
    for path in (project / 'config/identity.env', state / 'receipt.json', state / 'legacy-confirmed'):
        if path.is_symlink():
            raise ResetError('Unsafe identity recovery link; reset stopped.')
    record['identity'] = {}
    record['checkpoint_transition'] = False
    record['cron_digest'] = None
    journal.save_deployment(state, record)
    for path in (project / 'config/identity.env', state / 'receipt.json', state / 'legacy-confirmed'):
        path.unlink(missing_ok=True)
    journal.sync_directory(state)


def check_server_version(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT VERSION()')
        version = cursor.fetchone()[0]
        if not re.match(r'^8\.(?:0|4)\.', version) or 'MariaDB' in version:
            raise ResetError('The local socket must serve Oracle MySQL 8.0 or 8.4; no reset was performed.')


def validate_reset_database(connection):
    """Prove a known application schema before permitting destructive RESET.

    A matching database name is not ownership evidence. Ledgerless historical
    databases require an administrator's separate review, never a blind reset.
    """
    from database.migrate import check_migration_history

    connection.select_db(DATABASE)
    try:
        records = check_migration_history(connection)
    except MigrationError:
        raise ResetError('Cannot verify the application migration ledger; database was preserved.') from None
    if records.get('013', (None, None))[1] != 'APPLIED':
        raise ResetError('Cannot prove this mysql_siem database belongs to the application; '
                         'a verified baseline migration is required. Database was preserved.')
    required = {
        'ufw_log': {'id', 'event_time', 'raw_line', 'event_hash'},
        'auth_events': {'id', 'event_time', 'event_type', 'raw_message', 'event_hash'},
        'auth_ingestion_state': {'collector_id', 'file_device', 'file_inode', 'last_position', 'position_hash'},
        'detection_rules': {'id', 'rule_key', 'enabled'},
        'detection_alerts': {'id', 'rule_id'},
    }
    tables = tuple(required)
    with connection.cursor() as cursor:
        cursor.execute('SELECT table_name, engine, table_type FROM information_schema.tables '
                       'WHERE table_schema = DATABASE()')
        existing = set()
        for name, engine, kind in cursor.fetchall():
            if name not in RUNTIME_TABLE_PRIVILEGES:
                raise ResetError('Unknown tables share the application database; database was preserved.')
            if engine != 'InnoDB' or kind != 'BASE TABLE':
                raise ResetError('Unexpected application table type; database was preserved.')
            existing.add(name)
        if not set(required) <= existing:
            raise ResetError('Application schema is incomplete or unknown; database was preserved.')
        cursor.execute('SELECT table_name, column_name FROM information_schema.columns '
                       'WHERE table_schema = DATABASE() AND table_name IN %s', (tables,))
        columns = {}
        for name, column in cursor.fetchall():
            columns.setdefault(name, set()).add(column)
        for name, expected in required.items():
            if not expected <= columns.get(name, set()):
                raise ResetError('Application schema identity does not match; database was preserved.')


def reset_database(connection, settings, *, approved=False, prepare=lambda: None):
    """Only the fixed local DB is reset; never accept a database name argument."""
    validate_settings(settings)
    exists = database_exists(connection)
    if exists and not approved:
        raise ResetError('Existing mysql_siem database requires an explicit RESET confirmation.')
    check_server_version(connection)
    validate_account(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT GET_LOCK(%s, 0)', (LOCK_NAME,))
        if cursor.fetchone() != (1,):
            raise ResetError('Another database migration is running; no reset was performed.')
    step = 'application database ownership verification'
    try:
        if exists:
            validate_reset_database(connection)
        step = 'identity reset preparation'
        prepare()
        with connection.cursor() as cursor:
            if exists:
                step = 'approved database deletion'
                cursor.execute('DROP DATABASE `mysql_siem`')
            step = 'database creation'
            cursor.execute('CREATE DATABASE `mysql_siem` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
            step = 'application account/password synchronization'
            cursor.execute("CREATE USER IF NOT EXISTS 'pythonuser'@'localhost' IDENTIFIED BY %s", (settings['DB_PASSWORD'],))
            cursor.execute("ALTER USER 'pythonuser'@'localhost' IDENTIFIED BY %s", (settings['DB_PASSWORD'],))
        connection.select_db(DATABASE)
        from database.migrate import check_ufw_utc_readiness, migrate
        step = 'fresh schema initialization'
        migrate(connection)
        step = 'fresh schema UTC verification'
        check_ufw_utc_readiness(connection)
    except (pymysql.MySQLError, OSError, ValueError, MigrationError) as error:
        code = error.args[0] if error.args and type(error.args[0]) is int else type(error).__name__
        raise ResetError(step + ' failed (' + str(code)
                         + '). Collection remains paused; rerun the installer after correcting the cause.') from None
    finally:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (LOCK_NAME,))


def check_ufw_before_upgrade(connection):
    """Validate legacy UFW history without changing the database."""

    from database.ufw_history import preflight

    try:
        preflight(connection)
    except MigrationError as error:
        raise ResetError('UFW history compatibility check failed: ' + str(error)) from None


def check_upgrade_database(connection):
    """Reuse the existing read-only upgrade requirements before maintenance."""

    if not database_exists(connection):
        raise ResetError(
            "Upgrade requires an existing local database."
        )

    check_server_version(connection)
    validate_account(connection, allow_missing=False)

    connection.select_db(DATABASE)
    from database.migrate import check_migration_history

    try:
        check_migration_history(connection)
    except MigrationError as error:
        raise ResetError('Migration history preflight failed: ' + str(error)) from None

    # NEW: Check historical data before modifying the schema.
    # Migration 017 is not required to be complete yet.
    check_ufw_before_upgrade(connection)


def upgrade_database(connection, settings, *, project, state=None):
    """Back up and verify before DDL; never restore production automatically."""
    from config.installation_backup import (
        create_verified_backup,
        mark_upgrade_phase,
        verify_rows,
    )
    from database.migrate import check_ufw_utc_readiness, migrate

    validate_settings(settings)
    check_upgrade_database(connection)
    if state is None:
        state = journal.STATE_DIR
    with connection.cursor() as cursor:
        cursor.execute('SELECT GET_LOCK(%s, 0)', (LOCK_NAME,))
        if cursor.fetchone() != (1,):
            raise ResetError('Another migration is running; upgrade stopped before backup or DDL.')
    try:
        folder, manifest = create_verified_backup(connection, project, state=state)
        print('Verified upgrade backup retained at ' + str(folder))
        mark_upgrade_phase(folder, state, 'MIGRATING')
        try:
            migrate(connection)
            check_ufw_utc_readiness(connection)
            verify_rows(connection, folder, manifest['tables'])
        except BaseException:
            mark_upgrade_phase(folder, state, 'FAILED')
            raise
        mark_upgrade_phase(folder, state, 'MIGRATED')
    finally:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (LOCK_NAME,))



def database_preflight(operation, *, allow_legacy=False):
    """Check the running local server using SELECT/SHOW only; never start it."""
    if operation not in ('reset', 'upgrade'):
        raise ResetError('Unknown database preflight operation.')
    if allow_legacy and operation != 'reset':
        raise ResetError('Legacy grant preparation requires an explicit RESET installation.')
    result = run_command(['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql.service'])
    if result.returncode:
        raise ResetError('MySQL must already be running; preflight does not start services.')
    if not stat.S_ISSOCK(Path(SOCKET).lstat().st_mode):
        raise ResetError('The local MySQL endpoint must be a socket, not a file or symbolic link.')
    connection = pymysql.connect(unix_socket=SOCKET, user='root', charset='utf8mb4', autocommit=True,
                                 connect_timeout=5, read_timeout=15, write_timeout=15)
    try:
        if operation == 'upgrade':
            check_upgrade_database(connection)
        else:
            check_server_version(connection)
            if allow_legacy:
                validate_account(connection, allow_legacy=True)
            else:
                validate_account(connection)
    finally:
        connection.close()


def prepared_reset_recovery(project):
    """Prove completed database/identities; a started flag alone is not proof."""
    from database.local_identity import check_staged_receipt, read_receipt

    record = journal.read_deployment(journal.STATE_DIR)
    if record is None or record['phase'] != 'staged' or record['stage'] != str(project):
        raise ResetError('RESET recovery requires the protected staging journal.')
    if not record['identity']:
        receipt = read_receipt(journal.STATE_DIR / 'receipt.json')
        if receipt is not None and receipt['phase'] == 'database_ready':
            raise ResetError('Completed receipt conflicts with missing journal identities; preserve recovery files. No RESET was attempted.')
        return False
    if not record['database_started']:
        raise ResetError('Conflicting RESET recovery history; no database reset was attempted.')
    journal.require_stage(journal.STATE_DIR, project)
    connection = pymysql.connect(unix_socket=SOCKET, user='root', database=DATABASE,
                                 charset='utf8mb4', autocommit=True,
                                 connect_timeout=5, read_timeout=15, write_timeout=15)
    try:
        check_staged_receipt(connection, journal.STATE_DIR, project, Path(record['target']), record['user'])
        # Reuse migration/history/account checks, without applying migrations.
        check_upgrade_database(connection)
    finally:
        connection.close()
    return True


def stop_installation(signum, frame):
    raise ResetError('Installation interrupted; collection remains paused. Preserve backups and retry the same approved operation.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'reset', 'upgrade', 'verify-upgrade', 'recovery-check', 'resume'))
    parser.add_argument('--operation', choices=('reset', 'upgrade'), default='upgrade')
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--allow-legacy-grants', action='store_true')
    args = parser.parse_args(argv)
    connection = None
    previous_handler = signal.signal(signal.SIGTERM, stop_installation)
    try:
        if args.action in ('recovery-check', 'resume'):
            if os.geteuid() != 0:
                raise ResetError('RESET recovery requires administrator privileges.')
            trusted_directory(args.project)
            validate_settings(os.environ)
            recovered = prepared_reset_recovery(args.project)
            if args.action == 'resume' and not recovered:
                raise ResetError('Completed RESET recovery was not proven; no destructive fallback is allowed.')
            print(int(recovered) if args.action == 'recovery-check' else
                  'Completed RESET database verified; database and local identities preserved.')
            return 0
        if args.action == 'check':
            if os.geteuid() != 0:
                raise ResetError('Database preflight requires administrator privileges.')
            trusted_directory(args.project)
            validate_settings(os.environ)
            if args.allow_legacy_grants:
                database_preflight(args.operation, allow_legacy=True)
            else:
                database_preflight(args.operation)
            if args.operation == 'reset':
                check_system_cron()
            if args.operation == 'upgrade':
                from config.installation_backup import check_prerequisites

                connection = pymysql.connect(unix_socket=SOCKET, user='root', database=DATABASE,
                                             charset='utf8mb4', autocommit=True, connect_timeout=5,
                                             read_timeout=15, write_timeout=15)
                check_prerequisites(connection)
            print('Database preflight passed; no database or scheduler changes were made.')
            return 0
        journal.require_maintenance(journal.STATE_DIR)
        if args.action != 'verify-upgrade':
            journal.require_stage(journal.STATE_DIR, args.project)
        if get_installation_role(path=args.project / 'config/role.env') != 'server':
            raise ResetError('Database setup is available only for the Server installation role.')
        validate_settings(os.environ)
        connection = pymysql.connect(unix_socket=SOCKET, user='root', charset='utf8mb4', autocommit=True,
                                     connect_timeout=5, read_timeout=30, write_timeout=30,
                                     init_command="SET time_zone = '+00:00'")
        if args.action == 'verify-upgrade':
            from config.installation_backup import verify_final_backup

            connection.select_db(DATABASE)
            verify_final_backup(connection, args.project, journal.read_deployment(journal.STATE_DIR))
            print('Original database values and settings verified before releasing collection.')
            return 0
        if args.action == 'upgrade':
            upgrade_database(connection, os.environ, project=args.project)
            print('Database upgraded; history and identities preserved.')
            return 0
        exists = database_exists(connection)
        approved = os.environ.get('SIEM_DATABASE_RESET_APPROVED') == '1'
        if exists and not approved:
            confirm_reset(True)
            approved = True
        check_system_cron()
        pause_cron(journal.STATE_DIR)
        pause_systemd()
        wait_for_legacy_jobs()
        reset_database(connection, os.environ, approved=approved,
                       prepare=lambda: clear_old_identity(journal.STATE_DIR, args.project))
        print('Fresh mysql_siem database initialized; migrations and UTC readiness verified.')
        return 0
    except (ResetError, RoleConfigurationError, BackupError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, EOFError, subprocess.SubprocessError, InstallationError,
            journal.InstallationStateError):
        if args.action == 'check':
            print('Database preflight failed: filesystem or service validation failed; no database changes were made.', file=sys.stderr)
        else:
            print('Database setup stopped: filesystem, scheduler or maintenance validation failed. Collection remains paused.', file=sys.stderr)
        return 1
    except (pymysql.MySQLError, MigrationError) as error:
        # SQL/driver messages can contain credentials. Report the failed operation safely.
        if args.action == 'check':
            print('Database preflight failed (' + type(error).__name__
                  + '); check the local socket and administrator connection. No database changes were made.', file=sys.stderr)
        else:
            print('Database setup failed (' + type(error).__name__
                  + '). Collection remains paused; correct the error and rerun the installer.', file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == '__main__':
    raise SystemExit(main())
