"""Read-only deployment, migration and identity health verification."""

import argparse
import hashlib
import os
import sys
from pathlib import Path

import pymysql

from config import installation_state as journal
from config.installation_role_setup import read_owned_role
from config.service_installation import (
    InstallationError,
    preserved,
    read_revision,
    tree_files,
    trusted_directory,
    validate_virtualenv,
)
from database import migrate
from database.connection import get_connection
from database.local_identity import (
    database_key,
    read_crontab,
    read_receipt,
    read_settings,
    validate_bindings,
)


class HealthError(RuntimeError):
    """Deployment is not verified; do not release maintenance."""


def verify_schema(connection):
    records = migrate.check_migration_history(connection)
    for version, _name, _path in migrate.MIGRATIONS:
        if records.get(version, (None, None))[1] != 'APPLIED':
            raise HealthError('Database migrations are incomplete; keep collection paused.')
    migrate.check_ufw_utc_readiness(connection)
    from database.ufw_analysis_keys import preflight
    preflight(connection)
    from database.ufw_collection_schema import verify
    verify(connection, continuity=True, filtering=True)
    with connection.cursor() as cursor:
        cursor.execute('SELECT auth_method, source_port FROM auth_events LIMIT 0')
        cursor.execute("SELECT is_nullable FROM information_schema.columns "
                       "WHERE table_schema = DATABASE() AND table_name = 'auth_events' AND column_name = 'source_ip'")
        if cursor.fetchone() != ('YES',):
            raise HealthError('Auth database schema is incompatible with local login events.')


def verify_health(connection, project, *, state=journal.STATE_DIR, during_maintenance=False, revision=None):
    trusted_directory(project)
    trusted_directory(state)
    record = journal.read_deployment(state)
    if record is None or record['target'] != str(project):
        raise HealthError('Installed program does not match the deployment journal.')
    if during_maintenance:
        journal.require_maintenance(state)
        if record['phase'] != 'activated':
            raise HealthError('New deployment has not been activated.')
    elif (state / 'maintenance').exists() or (state / 'maintenance').is_symlink() or record['phase'] != 'complete':
        raise HealthError('Installation is incomplete; preserve maintenance and rerun the same approved operation.')
    for path in tree_files(project):
        if preserved(path.relative_to(project)):
            continue
        trusted_directory(path.parent)
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise HealthError('Installed program files have unsafe ownership or permissions.')
    installed = read_revision(project)
    if revision is not None and installed != revision:
        raise HealthError('Installed revision differs from the approved commit.')
    stable = Path(record['stable'])
    validate_virtualenv(stable, stable=True)
    if not stable.is_symlink() or os.readlink(stable) != record['candidate']:
        raise HealthError('Installed Python environment differs from the deployment journal.')
    if read_owned_role(record['user'], path=project / 'config/role.env') != 'server':
        raise HealthError('Unsupported installation role; no role was changed.')
    settings = read_settings(project / 'config/identity.env')
    receipt = read_receipt(state / 'receipt.json')
    if (receipt is None or receipt['phase'] not in ('ready', 'database_ready')
            or receipt['identity'] != settings or settings != record['identity']
            or database_key(connection) != (receipt['database'], receipt['server'])):
        raise HealthError('Installed identities do not match the protected database receipt.')
    with connection.cursor() as cursor:
        if validate_bindings(cursor, settings) != receipt['host_id']:
            raise HealthError('Installed host identity changed.')
    verify_schema(connection)
    text = read_crontab(record['user'])
    if hashlib.sha256(text.encode('utf-8')).hexdigest() != record['cron_digest']:
        raise HealthError('Scheduled jobs differ from the verified deployment.')
    return installed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path('/usr/local/lib/mysql_siem'))
    parser.add_argument('--revision')
    parser.add_argument('--during-maintenance', action='store_true')
    args = parser.parse_args(argv)
    connection = None
    try:
        if os.geteuid() != 0:
            raise HealthError('Deployment verification requires administrator privileges.')
        connection = get_connection(quiet=True)
        if connection is None:
            raise HealthError('Runtime database connection failed.')
        revision = verify_health(connection, args.project, during_maintenance=args.during_maintenance,
                                 revision=args.revision)
        print('Status: HEALTHY - approved commit ' + revision + '; schema, identities and jobs verified.')
        return 0
    except (HealthError, InstallationError, migrate.MigrationError, journal.InstallationStateError,
            OSError, ValueError, pymysql.MySQLError):
        print('Status: FAILED - deployment, runtime connection, migration, identity or scheduler '
              'verification failed. Preserve recovery files; do not RESET.', file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
