"""Prepare and verify filesystem jobs inside the existing server deployment."""

import argparse
import json
import pwd
import shlex
import sys
from pathlib import Path

import pymysql

from config import installation_state
from config.reset_installation import (
    FILESYSTEM_RUNTIME_PRIVILEGES,
    parse_runtime_grant,
    validate_runtime_grants,
)
from database.connection import get_connection
from database.identity import resolve_identity
from database.local_identity import atomic_write, read_private, read_settings
from detection.filesystem.detector import RULE_KEYS
from metrics.filesystem.inventory import (
    DEFAULT_CONFIG,
    InventoryConfig,
    config_digest,
    validate_config,
)

CONFIG_PATH = Path('config/filesystem.env')
JOBS = (
    ('FILESYSTEM_MOUNT_MINUTES', 5, 'filesystem-mounts', 'metrics.filesystem.mount_main'),
    ('FILESYSTEM_FIM_MINUTES', 30, 'filesystem-fim', 'metrics.filesystem.fim_main'),
    ('FILESYSTEM_DETECTION_MINUTES', 5, 'filesystem-detection', 'detection.filesystem.main'),
)
REQUIRED_GRANTS = {
    **FILESYSTEM_RUNTIME_PRIVILEGES,
    'detection_rules': 'SELECT',
    'detection_alerts': 'SELECT, INSERT, UPDATE',
    'detection_state': 'SELECT, INSERT, UPDATE',
    'alert_evidence': 'INSERT',
    'alert_hosts': 'INSERT',
}


class FilesystemSetupError(RuntimeError):
    """Filesystem jobs are not ready to activate."""


def read_config(path, *, owner=None):
    keys = {'FIM_INVENTORY'}
    for key, _, _, _ in JOBS:
        keys.add(key)
    values = {}
    for line in read_private(path, owner=owner).splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in keys or key in values:
            raise FilesystemSetupError('Invalid filesystem setting.')
        values[key] = json.loads(value)
    intervals = {}
    for key, default, component, _ in JOBS:
        minutes = values.get(key, default)
        if type(minutes) is not int or not 1 <= minutes <= 60 or 60 % minutes:
            raise FilesystemSetupError('Filesystem intervals must divide one hour evenly.')
        intervals[component] = minutes
    config = InventoryConfig(**values.get('FIM_INVENTORY', {}))
    validate_config(config)
    return intervals, config


def cron_lines(project, python, intervals):
    project_arg = shlex.quote(str(project))
    wrapper = shlex.quote(str(project / 'config/run_with_env.sh'))
    python_arg = shlex.quote(str(python))
    lines = []
    for _, _, component, module in JOBS:
        minutes = intervals[component]
        schedule = f'*/{minutes}'
        if minutes == 60:
            schedule = '0'
        timeout = min(270, minutes * 60 - 10)
        command = (f'{schedule} * * * * cd {project_arg} && umask 077 && PYTHONPATH={project_arg} {wrapper} '
                   f'/usr/bin/timeout --signal=TERM --kill-after=5s {timeout}s {python_arg} -m {module} '
                   f'--log-file /var/log/mysql_siem/{component}/cron.log')
        if component == 'filesystem-fim':
            command += ' --config ' + shlex.quote(str(project / CONFIG_PATH))
        lines.append(command)
    return lines


def _checkpoint_config(connection, settings):
    with connection.cursor() as cursor:
        cursor.execute("SELECT version FROM schema_migrations WHERE version IN ('034','035') AND status='APPLIED' ORDER BY version")
        if cursor.fetchall() != (('034',), ('035',)):
            raise FilesystemSetupError('Filesystem migrations are incomplete.')
        cursor.execute('SHOW GRANTS')
        rows = cursor.fetchall()
        validate_runtime_grants(rows)
        grants = {}
        for row in rows:
            _, table, privileges = parse_runtime_grant(row)
            grants.setdefault(table, set()).update(privileges)
        for table, privileges in REQUIRED_GRANTS.items():
            if not set(privileges.split(', ')) <= grants.get(table, set()):
                raise FilesystemSetupError('A required filesystem runtime grant is missing.')
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() "
                       "AND engine = 'InnoDB' AND table_name IN %s", (tuple(REQUIRED_GRANTS),))
        tables = set()
        for row in cursor.fetchall():
            tables.add(row[0])
        if tables != set(REQUIRED_GRANTS):
            raise FilesystemSetupError('Required transactional filesystem tables are missing.')
        identity = resolve_identity(cursor, settings['SIEM_FILESYSTEM_SOURCE_ID'], settings['SIEM_COLLECTOR_ID'],
                                    source_type='filesystem')
        cursor.execute('SELECT COUNT(*) FROM detection_rules WHERE rule_key IN %s', (RULE_KEYS,))
        if cursor.fetchone() != (len(RULE_KEYS),):
            raise FilesystemSetupError('A FIM detection rule is missing.')
        cursor.execute('SELECT config_sha256, baseline_complete FROM filesystem_scan_state WHERE host_id=%s AND source_id=%s',
                       (identity.host_id, identity.source_id))
        row = cursor.fetchone()
    if row is not None:
        if not row[1]:
            raise FilesystemSetupError('The saved FIM baseline is incomplete.')
        return row[0]
    return None


def _digest(config):
    files, directories = validate_config(config)
    return config_digest(config, files, directories)


def _verify_config(config, saved):
    if saved is not None and _digest(config) != saved:
        raise FilesystemSetupError('FIM settings do not match the saved baseline. Restore the approved inventory settings.')


def prepare(connection, project, user, python):
    installation_state.require_maintenance(installation_state.STATE_DIR)
    account = pwd.getpwnam(user)
    saved = _checkpoint_config(connection, read_settings(project / 'config/identity.env'))
    path = project / CONFIG_PATH
    if not path.exists() and not path.is_symlink():
        inventory = {'metadata_only': ['/etc/sudoers']}
        if saved == _digest(DEFAULT_CONFIG):
            inventory = {}
        _verify_config(InventoryConfig(**inventory), saved)
        atomic_write(path, 'FIM_INVENTORY=' + json.dumps(inventory) + '\n', gid=account.pw_gid, mode=0o640)
    intervals, config = read_config(path, owner=account.pw_uid)
    _verify_config(config, saved)
    return cron_lines(project, python, intervals)


def verify(connection, project, user, python, settings, cron):
    saved = _checkpoint_config(connection, settings)
    intervals, config = read_config(project / CONFIG_PATH, owner=pwd.getpwnam(user).pw_uid)
    _verify_config(config, saved)
    lines = cron.splitlines()
    for line in cron_lines(project, python, intervals):
        if lines.count(line) != 1:
            raise FilesystemSetupError('Filesystem schedules are missing or duplicated.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('user')
    parser.add_argument('python', type=Path)
    args = parser.parse_args(argv)
    connection = None
    try:
        connection = get_connection(quiet=True)
        if connection is None:
            raise FilesystemSetupError('Filesystem runtime database connection failed.')
        for line in prepare(connection, args.project, args.user, args.python):
            print(line)
        return 0
    except FilesystemSetupError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, pymysql.MySQLError):
        print('Filesystem deployment validation failed. Collection remains paused.', file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
