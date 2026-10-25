"""Server reset or additive upgrade, only inside the installer maintenance lock."""

import argparse
import json
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path

import pymysql

from config import installation_state as journal
from config.installation_role import RoleConfigurationError, get_installation_role
from config.service_installation import InstallationError
from database.migrate import LOCK_NAME, MigrationError

DATABASE = 'mysql_siem'
ACCOUNT = 'pythonuser'
SOCKET = '/run/mysqld/mysqld.sock'
RESET_WARNING = """Existing mysql_siem database detected on the local MySQL socket.
Reinstallation will permanently delete all collected events, historical metrics,
detection alerts and previous database records. A fresh database will be created.
Type RESET to continue: """


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


def validate_account(connection):
    # Changing a shared account's password would affect other applications.
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User='pythonuser' AND Host='localhost'")
        if cursor.fetchone()[0] == 0:
            return
        cursor.execute("SHOW GRANTS FOR 'pythonuser'@'localhost'")
        for row in cursor.fetchall():
            grant = row[0]
            if grant.startswith('GRANT USAGE ON *.* TO '):
                continue
            if re.match(r'^GRANT [A-Z_, ]+ ON `mysql_siem`\.', grant):
                continue
            raise ResetError('pythonuser has grants outside mysql_siem or role grants; review this shared account before resetting.')


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


def reset_database(connection, settings, *, approved=False, prepare=lambda: None):
    """Only the fixed local DB is reset; never accept a database name argument."""
    validate_settings(settings)
    exists = database_exists(connection)
    if exists and not approved:
        raise ResetError('Existing mysql_siem database requires an explicit RESET confirmation.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT VERSION()')
        version = cursor.fetchone()[0]
        if not re.match(r'^8\.(?:0|4)\.', version) or 'MariaDB' in version:
            raise ResetError('The local socket must serve Oracle MySQL 8.0 or 8.4; no reset was performed.')
    validate_account(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT GET_LOCK(%s, 0)', (LOCK_NAME,))
        if cursor.fetchone() != (1,):
            raise ResetError('Another database migration is running; no reset was performed.')
    step = 'identity reset preparation'
    try:
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

    from database.migrate import (
        ANALYSIS_TABLES,
        check_ufw_utc_readiness,
        history_counts,
        migration_status,
    )

    # Check whether migration 017 is already complete.
    state = migration_status(connection).get(
        "017", (None, None)
    )[1]

    if state == "APPLIED":
        check_ufw_utc_readiness(connection)
        return

    if state not in (None, "RUNNING", "FAILED"):
        raise ResetError(
            "Unknown UFW migration 017 state; upgrade stopped."
        )

    # These tables may contain historical UFW-related data.
    tables = ("ufw_log",) + ANALYSIS_TABLES + (
        "detection_state",
        "detection_alerts",
        "alert_evidence",
    )

    # Read current row counts without modifying anything.
    counts = history_counts(connection)

    # An interrupted migration may have stored older row counts.
    # Check those too before allowing the migration to resume.
    if state in ("RUNNING", "FAILED"):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT row_counts FROM schema_migrations "
                "WHERE version = %s",
                ("017",),
            )
            row = cursor.fetchone()

        if row is None:
            raise ResetError(
                "UFW migration 017 ledger is missing; "
                "upgrade stopped."
            )

        try:
            saved = json.loads(row[0])

            if not isinstance(saved, dict):
                raise TypeError

            for table in tables:
                value = saved.get(table, 0)

                if type(value) is not int or value < 0:
                    raise ValueError

                counts[table] = max(
                    counts.get(table, 0),
                    value,
                )

        except (TypeError, ValueError):
            raise ResetError(
                "UFW migration 017 history counts are invalid; "
                "upgrade stopped."
            ) from None

    # Do not migrate ambiguous historical timestamps.
    for table in tables:
        if counts.get(table, 0):
            raise ResetError(
                "UFW-related history predates a verified UTC migration. "
                "Upgrade stopped before schema changes. "
                "Review historical timestamps offline; "
                "no data was converted or deleted."
            )


def upgrade_database(connection, settings):
    """Additive upgrade without deleting existing data."""

    from database.migrate import (
        check_ufw_utc_readiness,
        migrate,
    )

    validate_settings(settings)

    if not database_exists(connection):
        raise ResetError(
            "Upgrade requires an existing local database."
        )

    # Validate MySQL version and runtime account permissions.
    with connection.cursor() as cursor:
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()[0]

        if (
            not re.match(r"^8\.(?:0|4)\.", version)
            or "MariaDB" in version
        ):
            raise ResetError(
                "Upgrade requires Oracle MySQL 8.0 or 8.4."
            )

        cursor.execute(
            "SHOW GRANTS FOR 'pythonuser'@'localhost'"
        )

        registry = {
            "hosts",
            "log_sources",
            "collectors",
            "collector_sources",
            "sender_identities",
            "sender_sources",
            "sender_certificates",
            "schema_migrations",
            "audit_targets",
        }

        for (grant,) in cursor.fetchall():

            if grant.startswith(
                "GRANT USAGE ON *.* TO "
            ):
                continue

            binding = re.match(
                r"^GRANT ([A-Z_, ]+) "
                r"ON `mysql_siem`\.`(\w+)` TO ",
                grant,
            )

            if (
                binding is None
                or "WITH GRANT OPTION" in grant
            ):
                raise ResetError(
                    "Unsafe runtime account grants; "
                    "review before upgrading."
                )

            privileges = set(
                binding[1].split(", ")
            )

            if binding[2] in registry:
                allowed = {"SELECT"}
            else:
                allowed = {
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                }

            if not privileges <= allowed:
                raise ResetError(
                    "Runtime account has administrative "
                    "privileges; review before upgrading."
                )

    connection.select_db(DATABASE)

    # NEW: Check historical data before modifying the schema.
    # Migration 017 is not required to be complete yet.
    check_ufw_before_upgrade(connection)

    # Apply missing migrations using the existing framework.
    migrate(connection)

    # REQUIRED: Verify UTC readiness after migration 017.
    # Never bypass the existing historical timestamp policy.
    check_ufw_utc_readiness(connection)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('reset', 'upgrade'))
    parser.add_argument('--project', type=Path, required=True)
    args = parser.parse_args(argv)
    connection = None
    try:
        journal.require_maintenance(journal.STATE_DIR)
        journal.require_stage(journal.STATE_DIR, args.project)
        if get_installation_role(path=args.project / 'config/role.env') != 'server':
            raise ResetError('Database setup is available only for the Server installation role.')
        validate_settings(os.environ)
        connection = pymysql.connect(unix_socket=SOCKET, user='root', charset='utf8mb4', autocommit=True,
                                     connect_timeout=5, read_timeout=30, write_timeout=30,
                                     init_command="SET time_zone = '+00:00'")
        if args.action == 'upgrade':
            upgrade_database(connection, os.environ)
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
    except (ResetError, RoleConfigurationError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, EOFError, subprocess.SubprocessError, InstallationError,
            journal.InstallationStateError):
        print('Database setup stopped: filesystem, scheduler or maintenance validation failed. Collection remains paused.', file=sys.stderr)
        return 1
    except (pymysql.MySQLError, MigrationError) as error:
        # SQL/driver messages can contain credentials. Report the failed operation safely.
        print('Database setup failed (' + type(error).__name__
              + '). Collection remains paused; correct the error and rerun the installer.', file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
