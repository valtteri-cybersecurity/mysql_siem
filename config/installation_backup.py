"""Verified local upgrade backups. No production restore or automatic rollback."""

import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import pymysql

from config import installation_state as journal
from config.service_installation import trusted_directory

DATABASE = 'mysql_siem'
BACKUPS = Path('/var/backups/mysql_siem')
RESTORE_PARENT = Path('/var/lib/mysql')
TIMEOUT = 1800
MIN_FREE = 512 * 1024 * 1024


class BackupError(RuntimeError):
    """Keep maintenance and all backup evidence when verification fails."""


def identifier(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_]+', value) is None:
        raise BackupError('Unsupported database identifier; upgrade stopped.')
    return '`' + value + '`'


def digest_file(path):
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise BackupError('Unsafe backup file; upgrade stopped.')
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def encode_row(row):
    values = []
    for value in row:
        if value is None:
            values.append(['null', None])
        elif isinstance(value, bytes):
            values.append(['bytes', value.hex()])
        else:
            values.append([type(value).__name__, str(value)])
    return json.dumps(values, ensure_ascii=True, separators=(',', ':'))


def schema_digest(cursor, name):
    # SHOW CREATE may render implicit CHARACTER SET clauses differently after
    # restore. Compare the actual column/index/constraint metadata instead.
    queries = (
        ('SELECT column_name,column_type,is_nullable,column_default,extra,character_set_name,collation_name,'
        'generation_expression,column_comment FROM information_schema.columns '
        'WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position'),
        ('SELECT index_name,non_unique,seq_in_index,column_name,collation,sub_part,index_type,is_visible,expression '
        'FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=%s '
        'ORDER BY index_name,seq_in_index'),
        ('SELECT constraint_name,ordinal_position,column_name,referenced_table_name,referenced_column_name '
        'FROM information_schema.key_column_usage WHERE table_schema=DATABASE() AND table_name=%s '
        'ORDER BY constraint_name,ordinal_position'),
        ('SELECT constraint_name,update_rule,delete_rule FROM information_schema.referential_constraints '
        'WHERE constraint_schema=DATABASE() AND table_name=%s ORDER BY constraint_name'),
        ('SELECT t.constraint_name,c.check_clause,t.enforced FROM information_schema.table_constraints t '
        'JOIN information_schema.check_constraints c ON c.constraint_schema=t.constraint_schema '
        'AND c.constraint_name=t.constraint_name WHERE t.table_schema=DATABASE() AND t.table_name=%s '
        'ORDER BY t.constraint_name'),
        ('SELECT engine,table_collation,row_format,create_options FROM information_schema.tables '
        'WHERE table_schema=DATABASE() AND table_name=%s'),
        ('SELECT trigger_name,action_timing,event_manipulation,action_statement,definer,sql_mode '
        'FROM information_schema.triggers WHERE trigger_schema=DATABASE() AND event_object_table=%s '
        'ORDER BY trigger_name'),
    )
    digest = hashlib.sha256()
    for query in queries:
        cursor.execute(query, (name,))
        for row in cursor.fetchall():
            digest.update(encode_row(row).encode('ascii') + b'\n')
        digest.update(b'\0')
    return digest.hexdigest()


def global_objects_digest(connection):
    queries = (
        ('SELECT routine_name,routine_type,routine_definition,sql_data_access,security_type,is_deterministic,'
        'definer,sql_mode FROM information_schema.routines WHERE routine_schema=DATABASE() ORDER BY routine_name'),
        ('SELECT event_name,event_definition,event_type,execute_at,interval_value,interval_field,starts,ends,'
        'status,on_completion,time_zone,definer FROM information_schema.events '
        'WHERE event_schema=DATABASE() ORDER BY event_name'),
    )
    digest = hashlib.sha256()
    with connection.cursor() as cursor:
        for query in queries:
            cursor.execute(query)
            for row in cursor.fetchall():
                digest.update(encode_row(row).encode('ascii') + b'\n')
            digest.update(b'\0')
    return digest.hexdigest()


def table_layout(connection):
    result = {}
    with connection.cursor() as cursor:
        cursor.execute('SELECT table_name, engine, table_type FROM information_schema.tables '
                       'WHERE table_schema = DATABASE() ORDER BY table_name')
        tables = cursor.fetchall()
        for name, engine, kind in tables:
            identifier(name)
            if engine != 'InnoDB' or kind != 'BASE TABLE':
                raise BackupError('Upgrade backup requires ordinary InnoDB tables; review custom objects offline.')
            cursor.execute('SELECT column_name FROM information_schema.columns '
                           'WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ordinal_position', (name,))
            columns = []
            for row in cursor.fetchall():
                identifier(row[0])
                columns.append(row[0])
            cursor.execute("SELECT column_name FROM information_schema.statistics "
                           "WHERE table_schema = DATABASE() AND table_name = %s AND index_name = 'PRIMARY' "
                           'ORDER BY seq_in_index', (name,))
            primary = []
            for row in cursor.fetchall():
                identifier(row[0])
                primary.append(row[0])
            if not primary:
                raise BackupError('Upgrade backup requires stable table primary keys; review this schema offline.')
            ddl = schema_digest(cursor, name)
            cursor.execute(
                'SELECT auto_increment FROM information_schema.tables '
                'WHERE table_schema=DATABASE() AND table_name=%s',
                (name,),
            )
            sequence = cursor.fetchone()
            if sequence is None:
                raise BackupError(
                    'Cannot inspect AUTO_INCREMENT metadata: ' + name
                )
            next_id = sequence[0]
            if next_id is not None and (
                type(next_id) is not int or next_id < 1
            ):
                raise BackupError(
                    'Invalid AUTO_INCREMENT metadata: ' + name
                )
            result[name] = {
                'columns': columns,
                'primary': primary,
                'ddl_sha256': ddl,
                'auto_increment_next': next_id,
            }
    if not result:
        raise BackupError('Application database is empty or cannot be inspected.')
    return result


def select_rows(connection, name, layout):
    columns = []
    primary = []
    for value in layout['columns']:
        columns.append(identifier(value))
    for value in layout['primary']:
        primary.append(identifier(value))
    cursor = connection.cursor(pymysql.cursors.SSCursor)
    try:
        cursor.execute('SELECT ' + ', '.join(columns) + ' FROM ' + identifier(name)
                       + ' ORDER BY ' + ', '.join(primary))
    except BaseException:
        cursor.close()
        raise
    return cursor


def snapshot_rows(connection, folder):
    tables = table_layout(connection)
    deadline = time.monotonic() + TIMEOUT
    for index, (name, layout) in enumerate(tables.items()):
        path = folder / f'rows-{index:04d}.jsonl'
        positions = []
        for column in layout['primary']:
            positions.append(layout['columns'].index(column))
        count = 0
        with path.open('x', encoding='ascii') as output:
            os.fchmod(output.fileno(), 0o600)
            with select_rows(connection, name, layout) as cursor:
                while True:
                    row = cursor.fetchone()
                    if row is None:
                        break
                    if time.monotonic() > deadline:
                        raise BackupError('Database fingerprint exceeded its time budget.')
                    key = []
                    for position in positions:
                        key.append(row[position])
                    digest = hashlib.sha256(encode_row(row).encode('ascii')).hexdigest()
                    output.write(json.dumps([encode_row(key), digest]) + '\n')
                    count += 1
            output.flush()
            os.fsync(output.fileno())
        layout.update(file=path.name, sha256=digest_file(path), count=count)
    journal.sync_directory(folder)
    return tables


def _verified_022_baseline(connection, tables, *, exact):
    """Read-only proof for a partial UFW migration snapshot."""
    layout = tables.get("ufw_log")

    if exact or layout is None:
        return None

    if "time_basis" not in layout["columns"]:
        return None

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT status,row_counts FROM schema_migrations "
            "WHERE version='022'"
        )
        record = cursor.fetchone()

    if record is None:
        return None

    if record[0] not in ("RUNNING", "FAILED", "APPLIED"):
        return None

    from database.ufw_history import KEY, preflight

    # Verify historical evidence before allowing any exception.
    preflight(connection)

    try:
        saved = json.loads(record[1])
        baseline = saved[KEY]

        if not isinstance(baseline, dict):
            raise ValueError

        precision = baseline.get("precision")

        if type(precision) is not int or not 0 <= precision <= 6:
            raise ValueError

    except (KeyError, TypeError, ValueError):
        raise BackupError(
            "022: original classification proof is invalid."
        ) from None

    return baseline


def _allowed_022_classification_change(
    row, layout, original_digest, baseline
):
    """Accept only a cryptographically proven time_basis transition."""
    if baseline is None:
        return False

    columns = layout["columns"]

    required = ("id", "event_time", "raw_line", "time_basis")

    for name in required:
        if name not in columns:
            return False

    basis_index = columns.index("time_basis")
    current_basis = row[basis_index]

    if current_basis not in (
        "UTC_VERIFIED",
        "LOCAL_TIME_VERIFIED",
    ):
        return False

    # Reconstruct the exact original row, changing only time_basis.
    previous = list(row)
    previous[basis_index] = "UNVERIFIED"

    reconstructed_digest = hashlib.sha256(
        encode_row(tuple(previous)).encode("ascii")
    ).hexdigest()

    if reconstructed_digest != original_digest:
        return False

    event_id = row[columns.index("id")]
    precision = baseline["precision"]

    if event_id <= baseline.get("previous_max_id", 0):
        precision = baseline["previous_precision"]

    from database.ufw_time_basis import classify_event_time

    expected_basis = classify_event_time(
        row[columns.index("raw_line")],
        row[columns.index("event_time")],
        precision,
    )

    return current_basis == expected_basis


def verify_rows(connection, folder, tables, *, exact=False):
    """Preserve original rows; permit only proven 022 reclassification."""
    baseline_022 = _verified_022_baseline(
        connection, tables, exact=exact
    )
    deadline = time.monotonic() + TIMEOUT
    for name, layout in tables.items():
        if not exact and name == 'schema_migrations':
            continue
        path = folder / layout['file']
        if path.parent != folder or digest_file(path) != layout['sha256']:
            raise BackupError('Database fingerprint integrity check failed.')
        positions = []
        for column in layout['primary']:
            positions.append(layout['columns'].index(column))
        matched = count = 0
        with path.open('r', encoding='ascii') as original:
            line = original.readline()
            expected = None
            if line:
                expected = json.loads(line)
            with select_rows(connection, name, layout) as cursor:
                while True:
                    row = cursor.fetchone()
                    if row is None:
                        break
                    if time.monotonic() > deadline:
                        raise BackupError('Database verification exceeded its time budget.')
                    count += 1
                    key = []
                    for position in positions:
                        key.append(row[position])
                    if expected is None or encode_row(key) != expected[0]:
                        if exact:
                            raise BackupError('Restored database contains unexpected rows.')
                        continue
                    digest = hashlib.sha256(encode_row(row).encode('ascii')).hexdigest()
                    if digest != expected[1]:
                        if (
                            exact
                            or name != "ufw_log"
                            or not _allowed_022_classification_change(
                                row, layout, expected[1], baseline_022
                            )
                        ):
                            raise BackupError(
                                'Historical database values changed; keep collection paused.'
                            )
                    matched += 1
                    line = original.readline()
                    expected = None
                    if line:
                        expected = json.loads(line)
            if expected is not None or matched != layout['count'] or exact and count != layout['count']:
                raise BackupError('Historical database rows are missing; keep collection paused.')


def private_environment():
    # --no-defaults still reads .mylogin.cnf on MySQL 8.0. Explicitly bypass it.
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
            'MYSQL_TEST_LOGIN_FILE': '/dev/null', 'MALLOC_ARENA_MAX': '2'}


def binary(name):
    executable = shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin')
    if executable is None:
        raise BackupError('Upgrade backup requires installed MySQL client, dump and server binaries.')
    info = Path(executable).stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise BackupError('Unsafe MySQL executable; upgrade stopped.')
    return executable


def private_diagnostic(path, content):
    """Keep bounded diagnostics private; never print SQL details."""
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content[-65536:])
        output.flush()
        os.fsync(output.fileno())


def trusted_restore_parent(path):
    """Validate the MySQL-owned restore directory."""
    path = Path(path)

    if path != RESTORE_PARENT:
        trusted_directory(path)
        return

    trusted_directory(path.parent)

    account = pwd.getpwnam('mysql')
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)

    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != account.pw_uid
        or info.st_gid != account.pw_gid
        or mode & 0o022
    ):
        raise BackupError(
            'MySQL restore parent must be a secure mysql-owned directory.'
        )


def run(arguments, *, timeout=TIMEOUT, phase='MYSQL_COMMAND',
        diagnostic=None, **options):
    """Run commands without leaking stderr into installation output."""

    with tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(
                arguments,
                stderr=errors,
                env=private_environment(),
                timeout=timeout,
                check=False,
                **options,
            )

        except subprocess.TimeoutExpired:
            if diagnostic is not None:
                errors.seek(0)
                private_diagnostic(
                    diagnostic,
                    errors.read(65536),
                )

            raise BackupError(
                phase + ' timed out; no migration is allowed.'
            ) from None

        except OSError:
            if diagnostic is not None:
                errors.seek(0)
                private_diagnostic(
                    diagnostic,
                    errors.read(65536),
                )

            raise BackupError(
                phase + ' could not start; no migration is allowed.'
            ) from None

        if result.returncode != 0:
            if diagnostic is not None:
                errors.seek(0, os.SEEK_END)
                size = errors.tell()

                errors.seek(max(0, size - 65536))

                private_diagnostic(
                    diagnostic,
                    errors.read(65536),
                )

            raise BackupError(
                phase
                + ' failed with exit code '
                + str(result.returncode)
                + '; no migration is allowed.'
            )

        return result


def check_prerequisites(connection, *, backup_root=BACKUPS, restore_parent=RESTORE_PARENT):
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE(), @@server_uuid, VERSION()')
        database, server, version = cursor.fetchone()
        if database != DATABASE or re.match(r'^8\.(0|4)\.', version) is None or 'MariaDB' in version:
            raise BackupError('Upgrade backup requires the approved local MySQL application database.')
        cursor.execute('SELECT COALESCE(SUM(data_length + index_length), 0) '
                       'FROM information_schema.tables WHERE table_schema = DATABASE()')
        estimated = int(cursor.fetchone()[0])
    if os.geteuid() == 0:
        try:
            account = pwd.getpwnam('mysql')
        except KeyError:
            raise BackupError('Isolated restore requires an existing non-root MySQL system account.') from None
        if account.pw_uid == 0:
            raise BackupError('The MySQL restore system account must not be root.')
    for name in ('mysql', 'mysqldump', 'mysqld'):
        executable = binary(name)
        result = run([executable, '--no-defaults', '--version'], stdout=subprocess.PIPE, timeout=10)
        if 'Ver ' + '.'.join(version.split('.')[:2]) + '.' not in result.stdout.decode('ascii', errors='replace'):
            raise BackupError('MySQL restore binaries must match the database 8.0/8.4 release family.')
    for path in (backup_root, restore_parent):
        existing = path
        while not existing.exists() and not existing.is_symlink():
            existing = existing.parent
        if path == RESTORE_PARENT and path.exists():
            trusted_restore_parent(path)
        else:
            trusted_directory(existing)

        if shutil.disk_usage(existing).free < max(MIN_FREE, estimated * 6):
            raise BackupError('Insufficient disk space for the dump, fingerprints and isolated restore.')
    return {'database': database, 'server': server, 'mysql_version': version}


def verify_restored_auto_increment(name, original, restored):
    """Reject a restored sequence that could reuse an earlier ID."""
    if original is None:
        if restored is not None:
            raise BackupError(
                'Restored unexpected AUTO_INCREMENT: ' + name
            )
        return

    if type(original) is not int or original < 1:
        raise BackupError(
            'Invalid original AUTO_INCREMENT: ' + name
        )

    if type(restored) is not int or restored < original:
        raise BackupError(
            'Restored AUTO_INCREMENT is below original: ' + name
        )


def restore_check(dump, tables, *, restore_parent=RESTORE_PARENT, objects_sha256=None):
    """Restore only into our own socket-only child, never the application server."""
    trusted_restore_parent(restore_parent)
    workspace = Path(tempfile.mkdtemp(prefix='.mysql_siem-restore-', dir=restore_parent))
    process_options = {}

    if os.geteuid() == 0:
        account = pwd.getpwnam('mysql')

        if account.pw_uid == 0:
            raise BackupError(
                'Isolated restore needs a non-root MySQL account.'
            )

        os.chown(workspace, account.pw_uid, account.pw_gid)

        process_options = {
            'user': account.pw_uid,
            'group': account.pw_gid,
            'extra_groups': [],
        }
    process = connection = None
    try:
        data = workspace / 'data'
        socket = workspace / 'restore.sock'
        command = [binary('mysqld'), '--no-defaults', f'--datadir={data}',
                   f'--log-error={workspace / "server.log"}', '--performance-schema=OFF',
                   '--innodb-buffer-pool-size=32M', '--innodb-redo-log-capacity=64M',
                   '--max-connections=5', '--table-open-cache=64', '--table-definition-cache=400']
        run(
            command + ['--initialize-insecure'],
            stdout=subprocess.DEVNULL,
            timeout=60,
            phase='MYSQL_INITIALIZE',
            diagnostic=dump.parent / 'mysql-initialize.stderr',
            **process_options,
        )
        process = subprocess.Popen(command + [f'--socket={socket}', f'--pid-file={workspace / "server.pid"}',
                                              '--skip-networking', '--mysqlx=OFF', '--event-scheduler=OFF',
                                              '--local-infile=OFF', '--secure-file-priv=NULL'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=private_environment(), **process_options)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and process.poll() is None:
            try:
                connection = pymysql.connect(unix_socket=str(socket), user='root', autocommit=True,
                                             connect_timeout=2, read_timeout=30, write_timeout=30,
                                             init_command="SET time_zone = '+00:00'")
                break
            except pymysql.OperationalError:
                time.sleep(0.1)
        if connection is None:
            raise BackupError('Isolated MySQL restore server could not start; no migration is allowed.')
        with connection.cursor() as cursor:
            cursor.execute('SELECT @@datadir, @@skip_networking')
            directory, disabled = cursor.fetchone()
            if Path(directory).resolve() != data.resolve() or not disabled:
                raise BackupError('Restore isolation could not be verified.')
        with dump.open('rb') as source:
            run([binary('mysql'), '--no-defaults', '--protocol=socket', f'--socket={socket}', '--user=root',
                 '--binary-mode=1', '--local-infile=0', '--connect-timeout=5'],
                stdin=source, stdout=subprocess.DEVNULL,
                phase='SQL_RESTORE',
                diagnostic=dump.parent / 'mysql-restore.stderr')
        connection.select_db(DATABASE)
        if objects_sha256 is not None and global_objects_digest(connection) != objects_sha256:
            raise BackupError('Restored routines or scheduled events differ from the original.')
        restored = table_layout(connection)
        if set(restored) != set(tables):
            raise BackupError('Restored database table inventory differs from the backup.')
        for name, layout in tables.items():
            if restored[name]['ddl_sha256'] != layout['ddl_sha256']:
                raise BackupError(
                    'Restored database table definitions differ '
                    'from the original: ' + name
                )

            if 'auto_increment_next' not in layout:
                raise BackupError(
                    'Original AUTO_INCREMENT metadata missing: ' + name
                )

            verify_restored_auto_increment(
                name,
                layout['auto_increment_next'],
                restored[name]['auto_increment_next'],
            )
        verify_rows(connection, dump.parent, tables, exact=True)

    except BaseException:
        server_log = workspace / 'server.log'
        diagnostic = dump.parent / 'mysql-restore-server.log'

        if server_log.is_file() and not diagnostic.exists():
            with server_log.open('rb') as error_file:
                error_file.seek(0, os.SEEK_END)
                size = error_file.tell()

                error_file.seek(max(0, size - 65536))

                private_diagnostic(
                    diagnostic,
                    error_file.read(65536),
                )

        raise

    finally:
        if connection is not None:
            try:
                if process is not None and process.poll() is None:
                    with connection.cursor() as cursor:
                        cursor.execute('SHUTDOWN')
            except pymysql.MySQLError:
                pass
            finally:
                connection.close()
        if process is not None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        shutil.rmtree(workspace)


def verify_previous_backup(connection, state, backup_root):
    path = state / 'upgrade-backup.json'
    if not path.exists() and not path.is_symlink():
        return
    pointer = json.loads(journal.read_file(path))
    if pointer.get('phase') in ('COMPLETE', 'SUPERSEDED'):
        return
    folder = Path(pointer['folder'])
    if folder.parent != backup_root or not folder.name.startswith('upgrade-'):
        raise BackupError('Interrupted upgrade backup location is invalid; preserve recovery files.')
    trusted_directory(folder)
    manifest = json.loads(journal.read_file(folder / 'manifest.json'))
    if manifest['phase'] != 'VERIFIED' or digest_file(folder / 'database.sql') != manifest['dump_sha256']:
        raise BackupError('Interrupted upgrade backup is not verified; do not replace its recovery evidence.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE(), @@server_uuid')
        if cursor.fetchone() != (manifest['database'], manifest['server']):
            raise BackupError('Interrupted upgrade backup belongs to another database.')
    # Never replace the pre-failure baseline with already damaged current rows.
    verify_rows(connection, folder, manifest['tables'])


def mark_upgrade_phase(folder, state, phase):
    trusted_directory(folder)
    manifest = json.loads(journal.read_file(folder / 'manifest.json'))
    manifest['upgrade_phase'] = phase
    journal.write_file(folder / 'manifest.json', json.dumps(manifest, sort_keys=True) + '\n')
    journal.write_file(state / 'upgrade-backup.json', json.dumps({'folder': str(folder), 'phase': phase}) + '\n')


def verify_final_backup(connection, project, record, *, state=journal.STATE_DIR, backup_root=BACKUPS):
    from config.service_installation import read_revision

    journal.require_maintenance(state)
    if record is None or record['phase'] != 'activated' or record['target'] != str(project):
        raise BackupError('Final upgrade verification requires the activated protected deployment.')
    pointer = json.loads(journal.read_file(state / 'upgrade-backup.json'))
    folder = Path(pointer['folder'])
    if folder.parent != backup_root or pointer['phase'] not in ('MIGRATED', 'FINAL_VERIFIED'):
        raise BackupError('A verified migrated backup is required before releasing collection.')
    manifest = json.loads(journal.read_file(folder / 'manifest.json'))
    if (manifest['stage'] != record['stage'] or manifest['target'] != record['target']
            or manifest['revision'] != read_revision(project)):
        raise BackupError('Final upgrade backup belongs to another deployment.')
    verify_previous_backup(connection, state, backup_root)
    mark_upgrade_phase(folder, state, 'FINAL_VERIFIED')


def complete_upgrade_backup(state, record):
    path = state / 'upgrade-backup.json'
    if not path.exists() and not path.is_symlink():
        return
    pointer = json.loads(journal.read_file(path))
    if pointer.get('phase') in ('COMPLETE', 'SUPERSEDED'):
        return
    folder = Path(pointer['folder'])
    trusted_directory(folder)
    manifest = json.loads(journal.read_file(folder / 'manifest.json'))
    if manifest['stage'] == record['stage']:
        if pointer['phase'] != 'FINAL_VERIFIED':
            raise BackupError('Upgrade preservation checks are incomplete; keep collection paused.')
        mark_upgrade_phase(folder, state, 'COMPLETE')
    else:
        # A confirmed RESET may replace an older attempt; retain its backups.
        if not record['database_started_current']:
            raise BackupError('Backup belongs to a different deployment; preserve recovery files.')
        mark_upgrade_phase(folder, state, 'SUPERSEDED')


def create_verified_backup(connection, project, *, state=journal.STATE_DIR,
                           backup_root=BACKUPS, restore_parent=RESTORE_PARENT):
    from database.local_identity import (
        database_key,
        read_receipt,
        read_settings,
        validate_bindings,
    )

    record = journal.require_stage(state, project)
    receipt = read_receipt(state / 'receipt.json')
    settings = read_settings(project / 'config/identity.env')
    if (receipt is None or receipt['phase'] not in ('ready', 'database_ready')
            or database_key(connection) != (receipt['database'], receipt['server'])
            or settings != receipt['identity']):
        raise BackupError('Upgrade backup database/identity binding could not be verified.')
    with connection.cursor() as cursor:
        if validate_bindings(cursor, settings, complete=False) != receipt['host_id']:
            raise BackupError('Upgrade backup host binding differs from the protected receipt.')
    verify_previous_backup(connection, state, backup_root)
    manifest = check_prerequisites(connection, backup_root=backup_root, restore_parent=restore_parent)
    trusted_directory(backup_root.parent)
    if not backup_root.exists():
        backup_root.mkdir(mode=0o700)
    trusted_directory(backup_root)
    if stat.S_IMODE(backup_root.stat().st_mode) != 0o700:
        raise BackupError('Backup directory must be private (0700); permissions were not changed.')
    folder = Path(tempfile.mkdtemp(prefix='upgrade-', dir=backup_root))
    journal.sync_directory(backup_root)
    dump = folder / 'database.sql'
    from config.installation_health import read_revision

    manifest.update(version=1, revision=read_revision(project), stage=record['stage'], target=record['target'],
                    phase='STARTED', dump_sha256=None, tables={})
    journal.write_file(folder / 'manifest.json', json.dumps(manifest, sort_keys=True) + '\n')
    try:
        tables = table_layout(connection)
        lock_names = []
        for name in tables:
            lock_names.append(identifier(name) + ' READ')
        with connection.cursor() as cursor:
            cursor.execute('LOCK TABLES ' + ', '.join(lock_names))
        try:
            manifest['tables'] = snapshot_rows(connection, folder)
            manifest['objects_sha256'] = global_objects_digest(connection)
            with dump.open('xb') as output:
                os.fchmod(output.fileno(), 0o600)
                run([binary('mysqldump'), '--no-defaults', '--protocol=socket',
                     '--socket=' + connection.unix_socket, '--user=root', '--single-transaction', '--quick',
                     '--hex-blob', '--routines', '--events', '--triggers', '--set-gtid-purged=OFF',
                     '--no-tablespaces', '--skip-add-drop-table', '--skip-add-drop-database',
                     '--databases', DATABASE], stdout=output)
                output.flush()
                os.fsync(output.fileno())
        finally:
            with connection.cursor() as cursor:
                cursor.execute('UNLOCK TABLES')
        if dump.stat().st_size == 0:
            raise BackupError('Database dump is empty; no migration is allowed.')
        manifest['dump_sha256'] = digest_file(dump)
        restore_check(dump, manifest['tables'], restore_parent=restore_parent,
                      objects_sha256=manifest['objects_sha256'])
        if digest_file(dump) != manifest['dump_sha256']:
            raise BackupError('Backup integrity changed during verification.')
        manifest['phase'] = 'VERIFIED'
        journal.write_file(folder / 'manifest.json', json.dumps(manifest, sort_keys=True) + '\n')
        journal.write_file(state / 'upgrade-backup.json', json.dumps({'folder': str(folder), 'phase': 'VERIFIED'}) + '\n')
        return folder, manifest
    except BaseException:
        manifest['phase'] = 'FAILED'
        journal.write_file(folder / 'manifest.json', json.dumps(manifest, sort_keys=True) + '\n')
        raise
