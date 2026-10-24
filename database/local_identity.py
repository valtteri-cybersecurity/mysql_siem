"""Administrator-only local enrollment; event history is never rewritten.

The root-owned receipt records an installation attempt, not a second registry.
The existing registry supplies every host/source/collector ID. A database commit
may precede file publication; the receipt token makes that case recoverable.
"""

import argparse
import hashlib
import json
import os
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pymysql

from config import installation_state as installation
from config.service_installation import InstallationError
from database.identity import (
    IdentityError,
    approve_collector_source,
    identity_schema_enabled,
    register_collector,
    register_host,
    register_source,
    resolve_identity,
    validate_id,
)

LOCAL_TYPES = ('ufw', 'system', 'filesystem', 'security', 'auth')
COLLECTOR_KEY = 'SIEM_COLLECTOR_ID'
LOCAL_KEYS = {}
for _source_type in LOCAL_TYPES:
    LOCAL_KEYS[_source_type] = 'SIEM_' + _source_type.upper() + '_SOURCE_ID'
ALLOWED_KEYS = set(LOCAL_KEYS.values()) | {COLLECTOR_KEY, 'SIEM_DNS_SOURCE_ID'}
STATE_DIR = Path('/usr/local/lib/.mysql_siem-local')
BEGIN = '# BEGIN mysql_siem managed jobs'
END = '# END mysql_siem managed jobs'
LOCKS = ('mysql_siem_ufw_ingestion', 'mysql_siem_auth_events_writer')


def read_private(path, *, maximum=65536, owner=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_mode & 0o027 or info.st_uid not in (0, os.geteuid(), owner)):
            raise IdentityError('Unsafe local identity file ownership or permissions.')
        data = os.read(descriptor, maximum + 1)
        if len(data) > maximum:
            raise IdentityError('Local identity file is too large.')
        return data.decode('utf-8')
    finally:
        os.close(descriptor)


def read_settings(path):
    if not path.exists() and not path.is_symlink():
        return {}
    settings = {}
    for line in read_private(path).splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if key not in ALLOWED_KEYS or not separator or key in settings:
            raise IdentityError('Unknown or duplicate identity setting.')
        if not value.isascii() or not value.isdigit() or str(int(value)) != value:
            raise IdentityError('Identity settings must contain canonical positive numeric IDs.')
        settings[key] = validate_id(int(value))
    if settings and COLLECTOR_KEY not in settings:
        raise IdentityError('Identity configuration is missing its collector binding.')
    return settings


def atomic_write(path, text, *, gid=None, mode=0o600):
    """Only call in a trusted root-owned directory; never follow target links."""
    if path.exists() or path.is_symlink():
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise IdentityError('Unsafe identity publication target.')
        finally:
            os.close(descriptor)
    if gid is None:
        gid = os.getegid()
    descriptor, temporary = tempfile.mkstemp(prefix='.identity-', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            os.fchown(output.fileno(), os.geteuid(), gid)
            os.fchmod(output.fileno(), mode)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def write_settings(path, settings, gid):
    lines = []
    for key in sorted(settings):
        if key not in ALLOWED_KEYS:
            raise IdentityError('Unknown local identity setting.')
        lines.append(key + '=' + str(validate_id(settings[key])))
    atomic_write(path, '\n'.join(lines) + '\n', gid=gid, mode=0o640)


def read_receipt(path):
    if not path.exists() and not path.is_symlink():
        return None
    receipt = json.loads(read_private(path))
    expected = {'version', 'token', 'database', 'server', 'initial', 'identity', 'host_id', 'phase'}
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or type(receipt['version']) is not int or receipt['version'] != 1):
        raise IdentityError('Invalid local identity recovery receipt.')
    if str(uuid.UUID(receipt['token'], version=4)) != receipt['token']:
        raise IdentityError('Invalid local identity recovery token.')
    if receipt['phase'] not in ('prepared', 'database_ready', 'ready'):
        raise IdentityError('Invalid local identity recovery phase.')
    if receipt['host_id'] is not None:
        validate_id(receipt['host_id'])
    for field in ('initial', 'identity'):
        if not isinstance(receipt[field], dict):
            raise IdentityError('Invalid identity recovery settings.')
        for key, value in receipt[field].items():
            if key not in ALLOWED_KEYS:
                raise IdentityError('Unknown identity recovery setting.')
            validate_id(value)
    return receipt


def save_receipt(path, receipt):
    atomic_write(path, json.dumps(receipt, sort_keys=True) + '\n')


def without_managed_jobs(text):
    lines = []
    inside = False
    found = False
    for line in text.splitlines():
        if line == BEGIN:
            if inside or found:
                raise IdentityError('Ambiguous managed crontab; review manually.')
            inside = found = True
        elif line == END:
            if not inside:
                raise IdentityError('Invalid managed crontab markers.')
            inside = False
        elif not inside:
            lines.append(line)
    if inside:
        raise IdentityError('Unclosed managed crontab block.')
    return '\n'.join(lines) + '\n'


def begin_maintenance(state, installed, user, *, confirm=input, reset=False):
    from config.service_installation import trusted_directory

    installation.require_install_lock()
    trusted_directory(state.parent)
    if state.exists() or state.is_symlink():
        trusted_directory(state)
    else:
        state.mkdir(mode=0o755)
        state.chmod(0o755)
    state.chmod(0o755)
    (state / 'legacy-confirmed').unlink(missing_ok=True)
    already_paused = (state / 'maintenance').exists()
    atomic_write(state / 'maintenance', 'Local identity setup is incomplete.\n', mode=0o644)
    if not (state / 'runtime.lock').exists():
        atomic_write(state / 'runtime.lock', '', mode=0o644)
    result = subprocess.run(['crontab', '-u', user, '-l'], capture_output=True, text=True,
                            env=dict(os.environ, LC_ALL='C'), timeout=10, check=False)
    if result.returncode:
        if result.stderr.strip() != 'no crontab for ' + user:
            raise IdentityError('Cannot read crontab; collection remains paused. No jobs were replaced.')
        text = ''
    else:
        text = result.stdout
    paused = without_managed_jobs(text)
    kept = []
    for line in paused.splitlines():
        if line.strip() and not line.lstrip().startswith('#') and is_collection_command(line):
            from config.reset_installation import collection_command
            if not reset or not collection_command(line):
                raise IdentityError('Unmanaged mysql_siem cron jobs remain. Disable those jobs manually and rerun; '
                                    'do not restore legacy collection during identity setup.')
            continue
        kept.append(line)
    paused = '\n'.join(kept) + '\n'
    if not already_paused or not (state / 'previous.cron').exists():
        atomic_write(state / 'previous.cron', text)
    if text != paused:
        subprocess.run(['crontab', '-u', user, '-'], input=paused, text=True,
                       capture_output=True, timeout=10, check=True)
    wrapper = installed / 'config/run_with_env.sh'
    if not reset and installed.exists() and (not wrapper.is_file() or '# Local identity maintenance barrier.' not in wrapper.read_text()):
        answer = confirm('Managed cron jobs are paused. Stop any remaining mysql_siem jobs and confirm '
                         'legacy checkpoints belong to this machine and its unchanged logs. '
                         'Type LOCAL-LEGACY-STOPPED to continue: ')
        if answer != 'LOCAL-LEGACY-STOPPED':
            raise IdentityError('Legacy maintenance not confirmed; collection remains paused.')
        atomic_write(state / 'legacy-confirmed', 'Confirmed for this paused installation.\n')



def is_collection_command(command):
    for name in ('ingestion', 'metrics', 'analysis', 'detection'):
        if name + '/' in command or '-m ' + name + '.' in command:
            return True
    return False


def require_stopped_legacy_jobs(installed, user):
    """Fail rather than kill legacy/manual jobs that do not hold runtime.lock."""
    uid = pwd.getpwnam(user).pw_uid
    for process in Path('/proc').iterdir():
        if not process.name.isascii() or not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            owner = process.stat().st_uid
            raw_command = (process / 'cmdline').read_bytes()
            executable = Path(raw_command.split(b'\0', 1)[0].decode('utf-8', errors='replace')).name
            if not executable.startswith(('python', 'pypy')):
                continue
            command = raw_command.replace(b'\0', b' ').decode('utf-8', errors='replace')
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise IdentityError('Cannot check running legacy jobs; keep collection paused and inspect processes manually.') from None
        known_root_job = False
        if owner == 0:
            for signature in ('ingestion/ufw_to_mysql.py', 'ingestion/auth/main.py', 'ingestion/dns/main.py',
                              'metrics/system/main.py', 'metrics/filesystem/main.py', 'metrics/security/main.py',
                              '-m ingestion.', '-m metrics.', '-m analysis.ufw.', '-m detection.'):
                if signature in command:
                    known_root_job = True
        if is_collection_command(command) and (owner == uid or str(installed) + '/' in command or known_root_job):
            raise IdentityError(f'A legacy mysql_siem job is still running (PID {process.name}). '
                                'Let it finish or stop it gracefully, disable its old scheduler and rerun install.sh --role server.')

def validate_bindings(cursor, settings, *, complete=True):
    if COLLECTOR_KEY not in settings:
        raise IdentityError('A local collector binding is required.')
    host = None
    for source_type, key in LOCAL_KEYS.items():
        if key not in settings:
            if complete:
                raise IdentityError('A required local source binding is missing.')
            continue
        identity = resolve_identity(cursor, settings[key], settings[COLLECTOR_KEY], source_type=source_type)
        if host is not None and host != identity.host_id:
            raise IdentityError('Local sources refer to different hosts; no identities were changed.')
        host = identity.host_id
    if host is None:
        raise IdentityError('No persistent local host binding is available; administrative recovery is required.')
    if 'SIEM_DNS_SOURCE_ID' in settings:
        resolve_identity(cursor, settings['SIEM_DNS_SOURCE_ID'], settings[COLLECTOR_KEY], source_type='dns')
    return host



def existing_local_source(cursor, host_id, collector_id, source_type):
    """Reuse only one explicitly approved source; disabled rows are not absent.

    Lock the parent host before checking absence. The existing foreign key also
    makes concurrent source inserts wait on that host until this transaction ends.
    A source of this type bound elsewhere is ambiguous, never a reason to create
    or approve another source automatically.
    """
    validate_id(host_id)
    validate_id(collector_id)
    cursor.execute("SELECT host_id FROM hosts WHERE host_id = %s AND enrollment_status = 'ACTIVE' FOR UPDATE",
                   (host_id,))
    if cursor.fetchone() != (host_id,):
        raise IdentityError('Local host is missing or inactive; administrative recovery required.')
    cursor.execute(
        """SELECT s.source_id, s.enabled, cs.enabled FROM log_sources s
           LEFT JOIN collector_sources cs
             ON cs.source_id = s.source_id AND cs.collector_id = %s
           WHERE s.host_id = %s AND s.source_type = %s
           ORDER BY s.source_id FOR UPDATE""",
        (collector_id, host_id, source_type),
    )
    rows = cursor.fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise IdentityError('Multiple existing local sources match the missing binding; administrative recovery required.')
    source_id, source_enabled, binding_enabled = rows[0]
    if source_enabled != 1 or binding_enabled != 1:
        raise IdentityError('Existing local source is disabled or not approved for this collector; administrative recovery required.')
    identity = resolve_identity(cursor, source_id, collector_id, source_type=source_type)
    if identity.host_id != host_id:
        raise IdentityError('Existing local source belongs to another host; administrative recovery required.')
    return source_id


def database_key(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE(), @@server_uuid')
        return cursor.fetchone()


def legacy_present(cursor):
    for table in ('ufw_log', 'auth_events', 'system_metrics', 'filesystem_metrics', 'security_metrics'):
        cursor.execute(f'SELECT 1 FROM {table} WHERE host_id IS NULL LIMIT 1')
        if cursor.fetchone() is not None:
            return True
    for table in ('ufw_state', 'auth_ingestion_state'):
        cursor.execute(f'SELECT 1 FROM {table} WHERE source_scope = 0 LIMIT 1')
        if cursor.fetchone() is not None:
            return True
    return False


def validate_checkpoint(path, device, inode, offset, digest=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or (device, inode) != (info.st_dev, info.st_ino)
                or type(offset) is not int or not 0 <= offset <= info.st_size):
            raise IdentityError('Legacy checkpoint does not match an unchanged local log; manual recovery required.')
        with os.fdopen(os.dup(descriptor), 'rb') as infile:
            if offset:
                infile.seek(offset - 1)
                if infile.read(1) != b'\n':
                    raise IdentityError('Legacy checkpoint is not at a complete log line.')
            if digest is not None:
                from ingestion.auth.collector import position_hash
                if position_hash(infile, offset) != digest:
                    raise IdentityError('Legacy SSH checkpoint hash does not match the log.')
    finally:
        os.close(descriptor)


def checkpoint_path_matches(filename, base):
    """Only the configured file and its numbered, uncompressed rotations."""
    path = Path(filename)
    if not path.is_absolute() or str(path) != os.path.abspath(filename):
        return False
    if path == base:
        return True
    prefix = str(base) + '.'
    suffix = str(path)[len(prefix):]
    return str(path).startswith(prefix) and suffix.isascii() and suffix.isdigit()


def checkpoint_files(paths):
    """Take the same complete file set as both existing collectors."""
    from ingestion.auth.collector import get_logfiles

    if not paths:
        raise IdentityError('Legacy checkpoints have no configured log files; manual recovery required.')
    base = Path(paths[-1])
    if not checkpoint_path_matches(str(base), base):
        raise IdentityError('Configured checkpoint path must be absolute.')
    expected = set(get_logfiles(str(base)))
    supplied = set()
    for path in paths:
        if not checkpoint_path_matches(str(path), base):
            raise IdentityError('Checkpoint paths refer to different local log sources.')
        supplied.add(str(path))
    if supplied != expected or len(supplied) != len(paths):
        raise IdentityError('The local log file set changed or is incomplete; keep collection paused and retry.')
    files = {}
    for path in paths:
        try:
            info = Path(path).lstat()
        except OSError:
            raise IdentityError('A configured legacy log is missing or inaccessible; manual recovery required.') from None
        key = (info.st_dev, info.st_ino)
        if not stat.S_ISREG(info.st_mode) or key in files:
            raise IdentityError('A checkpoint log is a link, nonregular file or duplicate file identity.')
        files[key] = (str(path), info)
    return base, files


def unchanged_checkpoint_files(base, files):
    from ingestion.auth.collector import get_logfiles

    expected = set()
    for path, before in files.values():
        expected.add(path)
        try:
            after = Path(path).lstat()
        except OSError:
            raise IdentityError('A log changed during checkpoint validation; keep collection paused and retry.') from None
        for attribute in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            if getattr(after, attribute) != getattr(before, attribute):
                raise IdentityError('A log changed during checkpoint validation; keep collection paused and retry.')
    if set(get_logfiles(str(base))) != expected:
        raise IdentityError('Log rotation occurred during checkpoint validation; keep collection paused and retry.')


def validate_checkpoint_history(cursor, table, path, info, offset):
    """Prove consumed events exist in legacy history and unread events do not.

    UFW has no checkpoint fingerprint. Device/inode/size alone cannot detect
    truncate-and-regrow. Compare the entire fixed snapshot with committed legacy
    hashes instead of guessing from the last line. Never load a whole log in RAM.
    SSH additionally uses its existing 256-byte checkpoint fingerprint.
    """
    from ingestion.auth.parser import parse_auth_line

    # Bound one-off enrollment work. Large logs need administrative recovery,
    # not an unbounded scan or a silently weaker continuity check.
    if info.st_size > 64 * 1024 * 1024:
        raise IdentityError('Checkpoint history verification exceeds 64 MiB per log; manual recovery required.')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as infile:
        opened = os.fstat(infile.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise IdentityError('A log was replaced during checkpoint validation.')
        lines = 0
        while infile.tell() < info.st_size:
            start = infile.tell()
            raw = infile.readline(min(info.st_size - start, 65537))
            if not raw:
                raise IdentityError('A log shrank during checkpoint validation.')
            lines += 1
            if lines > 100000 or len(raw) > 65536:
                raise IdentityError('Checkpoint history verification limit exceeded; manual recovery required.')
            if not raw.endswith(b'\n'):
                if start < offset:
                    raise IdentityError('A legacy checkpoint crosses an incomplete line.')
                break
            if table == 'ufw_log':
                clean = raw.decode('utf-8', errors='ignore').strip()
                if not clean:
                    continue
                event_hash = hashlib.sha256(clean.encode('utf-8')).hexdigest()
            else:
                try:
                    line = raw.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                event = parse_auth_line(line)
                if event is None:
                    continue
                event_hash = event['event_hash']
            cursor.execute(f'SELECT 1 FROM {table} WHERE source_scope = 0 AND host_id IS NULL '
                           'AND source_id IS NULL AND collector_id IS NULL AND sender_id IS NULL '
                           'AND event_hash = %s LIMIT 1', (event_hash,))
            saved = cursor.fetchone() is not None
            if start < offset and not saved:
                raise IdentityError('Consumed log content is absent from legacy history; '
                                    'possible truncation, inode reuse or wrong source. Manual recovery required.')
            if start >= offset and saved:
                raise IdentityError('Unread log content already exists in legacy history; '
                                    'copy-truncate or a stale checkpoint may replay events. Manual recovery required.')


def copy_checkpoints(cursor, settings, *, auth_reader, ufw_paths, auth_paths):
    """Validate every current file before copying; preserve both existing scopes.

    The caller holds both collector locks and commits registry/state together.
    A missing position in a partially populated state table is never offset zero.
    """
    validate_bindings(cursor, settings)
    copies = []
    snapshots = []
    for table, events, source_type, paths in (
            ('ufw_state', 'ufw_log', 'ufw', ufw_paths),
            ('auth_ingestion_state', 'auth_events', 'auth', auth_paths)):
        fields = 'logfile, last_position, file_device, file_inode'
        if source_type == 'auth':
            fields += ', collector_id, position_hash'
        cursor.execute(f'SELECT {fields} FROM {table} WHERE source_scope = 0 FOR UPDATE')
        rows = cursor.fetchall()
        cursor.execute(f'SELECT 1 FROM {events} WHERE source_scope = 0 LIMIT 1')
        history_exists = cursor.fetchone() is not None
        if not rows:
            if history_exists:
                raise IdentityError('Legacy events have no trustworthy checkpoint; manual recovery required.')
            # Clean installations have no previous position to inherit. Existing
            # registered-only installations must also keep their state untouched.
            continue
        base, files = checkpoint_files(paths)
        snapshots.append((base, files))
        covered = set()
        source_id = settings[LOCAL_KEYS[source_type]]
        for row in rows:
            filename, offset, device, inode = row[:4]
            key = (device, inode)
            if not checkpoint_path_matches(filename, base):
                raise IdentityError('Legacy checkpoint path belongs to another local log source.')
            if key not in files or key in covered:
                raise IdentityError('A legacy checkpoint log is missing or rotated away; manual recovery required.')
            covered.add(key)
            matched, info = files[key]
            digest = None
            if source_type == 'auth':
                if row[4] != auth_reader:
                    raise IdentityError('Legacy SSH reader differs from the configured local reader.')
                digest = row[5]
            try:
                validate_checkpoint(matched, device, inode, offset, digest)
                validate_checkpoint_history(cursor, events, matched, info, offset)
            except OSError:
                raise IdentityError('Cannot safely read a checkpoint log; manual recovery required.') from None
            # A local file already claimed by a different registered source is
            # ambiguous even if scope zero happens to contain the same offset.
            cursor.execute(f'SELECT 1 FROM {table} WHERE file_device = %s AND file_inode = %s '
                           'AND source_scope NOT IN (0, %s) LIMIT 1 FOR UPDATE', (device, inode, source_id))
            if cursor.fetchone() is not None:
                raise IdentityError('The checkpoint file is bound to another registered source.')
            filter_sql = 'file_device = %s AND file_inode = %s AND source_scope = %s'
            parameters = (device, inode, source_id)
            if source_type == 'auth':
                filter_sql += ' AND collector_id = %s'
                parameters += (auth_reader,)
                cursor.execute(f'SELECT 1 FROM {table} WHERE file_device = %s AND file_inode = %s '
                               'AND source_scope = %s AND collector_id <> %s LIMIT 1 FOR UPDATE', parameters)
                if cursor.fetchone() is not None:
                    raise IdentityError('Registered SSH checkpoint has a different reader.')
            cursor.execute(f'SELECT {fields} FROM {table} WHERE {filter_sql} FOR UPDATE', parameters)
            existing = cursor.fetchone()
            if existing is not None:
                if existing[1:] != row[1:] or not checkpoint_path_matches(existing[0], base):
                    raise IdentityError('Registered and legacy checkpoints conflict; manual recovery required.')
                continue
            copies.append((table, fields, row + (source_id,)))
        if covered != set(files):
            for key, (path, _info) in files.items():
                if key not in covered:
                    raise IdentityError(f'{source_type}: current log file {path!r} has no legacy checkpoint; '
                                        'manual recovery required.')
    for base, files in snapshots:
        unchanged_checkpoint_files(base, files)
    for table, fields, values in copies:
        cursor.execute(f'INSERT INTO {table} ({fields}, source_scope) VALUES ({", ".join(["%s"] * len(values))})', values)
    for base, files in snapshots:
        unchanged_checkpoint_files(base, files)


def provision(connection, receipt_path, settings, *, confirmed=False, auth_reader,
              ufw_paths, auth_paths, confirm=input):
    """Commit registry and checkpoint copies together, recover using the receipt."""
    if not identity_schema_enabled(connection):
        raise IdentityError('Local enrollment requires completed identity migrations.')
    database, server = database_key(connection)
    receipt = read_receipt(receipt_path)
    if receipt is None:
        initial_host = None
        with connection.cursor() as cursor:
            if settings:
                initial_host = validate_bindings(cursor, settings, complete=False)
            else:
                for table in ('hosts', 'collectors', 'log_sources'):
                    cursor.execute(f'SELECT 1 FROM {table} LIMIT 1')
                    if cursor.fetchone() is not None:
                        raise IdentityError('Registry exists without a persistent local binding; administrative recovery required.')
        receipt = {'version': 1, 'token': str(uuid.uuid4()), 'database': database, 'server': server,
                   'initial': settings, 'identity': {}, 'host_id': initial_host, 'phase': 'prepared'}
        save_receipt(receipt_path, receipt)
    if receipt['database'] != database or receipt['server'] != server:
        raise IdentityError('Recovery receipt belongs to another database or server.')
    expected = receipt['identity'] or receipt['initial']
    for key, value in settings.items():
        if key not in expected or expected[key] != value:
            raise IdentityError('Identity file conflicts with the persistent installation receipt.')
    if receipt['phase'] in ('database_ready', 'ready'):
        if receipt['phase'] == 'database_ready':
            verify_pending_checkpoints(connection, receipt, auth_reader=auth_reader,
                                       ufw_paths=ufw_paths, auth_paths=auth_paths)
        with connection.cursor() as cursor:
            host = validate_bindings(cursor, receipt['identity'])
            if host != receipt['host_id']:
                raise IdentityError('Persistent local host binding has changed in the registry.')
        return receipt['identity']
    acquired = []
    try:
        with connection.cursor() as cursor:
            for name in LOCKS:
                cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
                if cursor.fetchone() != (1,):
                    raise IdentityError('A collector is still running; keep collection paused and retry.')
                acquired.append(name)
        connection.rollback()
        connection.begin()
        with connection.cursor() as cursor:
            result = dict(receipt['initial'])
            marker = 'local.' + receipt['token']
            recovered = False
            if not result:
                cursor.execute('SELECT collector_id FROM collectors WHERE collector_name = %s', (marker,))
                row = cursor.fetchone()
                if row is not None:
                    result[COLLECTOR_KEY] = row[0]
                    recovered = True
                else:
                    # Another administrator may have enrolled something since preflight.
                    for table in ('hosts', 'collectors', 'log_sources'):
                        cursor.execute(f'SELECT 1 FROM {table} LIMIT 1')
                        if cursor.fetchone() is not None:
                            raise IdentityError('Registry changed during local setup; manual recovery required.')
                    host = register_host(cursor, marker, reported_hostname=socket.gethostname())
                    cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host,))
                    result[COLLECTOR_KEY] = register_collector(cursor, marker, enabled=True)
            else:
                host = validate_bindings(cursor, result, complete=False)
            for source_type, key in LOCAL_KEYS.items():
                if key in result:
                    continue
                name = marker + '.' + source_type
                cursor.execute('SELECT source_id FROM log_sources WHERE source_name = %s', (name,))
                found = cursor.fetchall()
                if len(found) > 1:
                    raise IdentityError('Ambiguous recovery source binding.')
                if found:
                    result[key] = found[0][0]
                elif recovered:
                    raise IdentityError('Incomplete committed local registry; manual recovery required.')
                else:
                    source_id = existing_local_source(cursor, host, result[COLLECTOR_KEY], source_type)
                    if source_id is None:
                        source_id = register_source(cursor, host, name, source_type, enabled=True)
                        approve_collector_source(cursor, result[COLLECTOR_KEY], source_id)
                    result[key] = source_id
            actual_host = validate_bindings(cursor, result)
            if receipt['host_id'] is not None and receipt['host_id'] != actual_host:
                raise IdentityError('Local host conflicts with its persistent receipt.')
            if not recovered:
                has_legacy = legacy_present(cursor)
                if has_legacy and not confirmed:
                    answer = confirm('Confirm all legacy checkpoints belong to this machine, logs have not been '
                                     'truncated/replaced, and all old jobs are stopped. Type LOCAL-LEGACY-STOPPED: ')
                    if answer != 'LOCAL-LEGACY-STOPPED':
                        raise IdentityError('Legacy ownership/maintenance not confirmed; no database changes committed.')
                for table, state_table, source_type in (('ufw_log', 'ufw_state', 'ufw'),
                                                        ('auth_events', 'auth_ingestion_state', 'auth')):
                    cursor.execute(f'SELECT 1 FROM {table} WHERE host_id IS NULL LIMIT 1')
                    if cursor.fetchone() is not None:
                        cursor.execute(f'SELECT 1 FROM {state_table} WHERE source_scope IN (0, %s) LIMIT 1',
                                       (result[LOCAL_KEYS[source_type]],))
                        if cursor.fetchone() is None:
                            raise IdentityError('Legacy events have no trustworthy checkpoint; manual recovery required.')
            copy_checkpoints(cursor, result, auth_reader=auth_reader, ufw_paths=ufw_paths, auth_paths=auth_paths)
        connection.commit()
        receipt['host_id'] = actual_host
        receipt['identity'] = result
        receipt['phase'] = 'database_ready'
        save_receipt(receipt_path, receipt)
        return result
    except BaseException:
        connection.rollback()
        raise
    finally:
        with connection.cursor() as cursor:
            for name in reversed(acquired):
                cursor.execute('SELECT RELEASE_LOCK(%s)', (name,))



def verify_pending_checkpoints(connection, receipt, *, auth_reader, ufw_paths, auth_paths):
    """Recheck a committed first transition before publishing or unpausing."""
    if database_key(connection) != (receipt['database'], receipt['server']):
        raise IdentityError('Recovery receipt belongs to another database or server.')
    acquired = []
    try:
        with connection.cursor() as cursor:
            for name in LOCKS:
                cursor.execute('SELECT GET_LOCK(%s, 0)', (name,))
                if cursor.fetchone() != (1,):
                    raise IdentityError('A legacy collector is still running; collection remains paused.')
                acquired.append(name)
        connection.rollback()
        connection.begin()
        with connection.cursor() as cursor:
            if validate_bindings(cursor, receipt['identity']) != receipt['host_id']:
                raise IdentityError('Committed local host binding changed; administrative recovery required.')
            copy_checkpoints(cursor, receipt['identity'], auth_reader=auth_reader,
                             ufw_paths=ufw_paths, auth_paths=auth_paths)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        with connection.cursor() as cursor:
            for name in reversed(acquired):
                cursor.execute('SELECT RELEASE_LOCK(%s)', (name,))


def read_crontab(user):
    result = subprocess.run(['crontab', '-u', user, '-l'], capture_output=True, text=True,
                            env=dict(os.environ, LC_ALL='C'), timeout=10, check=False)
    if result.returncode:
        raise IdentityError('Cannot verify installed crontab; collection remains paused. Rerun install.sh --role server.')
    return result.stdout


def schedule_maintenance(state, project, cron_file, user):
    from config.service_installation import verify_publication

    installation.require_maintenance(state)
    record = installation.read_deployment(state)
    if record is None or record['target'] != str(project) or record['user'] != user:
        raise IdentityError('Cron publication does not match this deployment.')
    verify_publication(state, record)
    text = installation.read_file(cron_file)
    unmanaged = without_managed_jobs(text)
    for line in unmanaged.splitlines():
        if line.strip() and not line.lstrip().startswith('#') and is_collection_command(line):
            raise IdentityError('Unmanaged legacy cron jobs cannot be published alongside the protected jobs.')
    if text.splitlines().count(BEGIN) != 1 or text.splitlines().count(END) != 1:
        raise IdentityError('Cron publication requires exactly one managed job block.')
    inside = False
    for line in text.splitlines():
        if line == BEGIN:
            inside = True
        elif line == END:
            inside = False
        elif (inside and line.strip()
              and (str(project / 'config/run_with_env.sh') not in line
                   or record['stable'] + '/bin/python' not in line)):
            raise IdentityError('A cron job bypasses the protected service copy or interpreter.')
    record['cron_digest'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
    installation.save_deployment(state, record)


def finish_maintenance(state, identity_file, connection, *, user, installed, auth_reader, ufw_paths, auth_paths):
    from config.service_installation import trusted_directory, verify_publication

    installation.require_maintenance(state)
    require_stopped_legacy_jobs(installed, user)
    record = installation.read_deployment(state)
    if (record is None or record['target'] != str(installed) or record['user'] != user
            or identity_file != installed / 'config/identity.env'):
        raise IdentityError('finish requires the published installation, not an arbitrary identity file.')
    verify_publication(state, record)
    trusted_directory(identity_file.parent)
    info = identity_file.lstat()
    if info.st_uid != os.geteuid() or info.st_gid != pwd.getpwnam(user).pw_gid or stat.S_IMODE(info.st_mode) != 0o640:
        raise IdentityError('Published identity settings have unsafe ownership or permissions.')
    receipt = read_receipt(state / 'receipt.json')
    settings = read_settings(identity_file)
    if (receipt is None or receipt['phase'] not in ('database_ready', 'ready')
            or not settings or settings != receipt['identity'] or settings != record['identity']):
        raise IdentityError('Installed identity is not ready; collection remains paused.')
    if database_key(connection) != (receipt['database'], receipt['server']):
        raise IdentityError('Published settings refer to a different database or server.')
    with connection.cursor() as cursor:
        if validate_bindings(cursor, settings) != receipt['host_id']:
            raise IdentityError('Published host binding changed; collection remains paused.')
    if record['checkpoint_transition'] is not False:
        verify_pending_checkpoints(connection, receipt, auth_reader=auth_reader, ufw_paths=ufw_paths, auth_paths=auth_paths)
    text = read_crontab(user)
    digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
    if record['cron_digest'] is None or record['cron_digest'] != digest:
        raise IdentityError('Cron publication is missing or changed; rerun install.sh --role server. Collection remains paused.')
    # Persist completion first. The public maintenance marker is always removed
    # last, and the inherited exclusive runtime lock still covers this process.
    atomic_write(state / 'required', 'Local bindings are required.\n', mode=0o644)
    receipt['phase'] = 'ready'
    save_receipt(state / 'receipt.json', receipt)
    record['phase'] = 'complete'
    installation.save_deployment(state, record)
    (state / 'legacy-confirmed').unlink(missing_ok=True)
    (state / 'maintenance').unlink()
    installation.sync_directory(state)


def ssh_settings(project, user):
    options = {}
    path = project / 'config/ssh.env'
    if path.exists() or path.is_symlink():
        text = read_private(path, owner=pwd.getpwnam(user).pw_uid)
        allowed = {'SSH_AUTH_LOGFILE', 'SSH_AUTH_COLLECTOR_ID', 'SSH_BRUTE_FORCE_BATCH_SIZE',
                   'SSH_BRUTE_FORCE_LATE_SECONDS', 'SSH_BRUTE_FORCE_MAX_BUFFER_EVENTS'}
        for line in text.splitlines():
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if not separator or key not in allowed or key in options:
                raise IdentityError('Invalid SSH settings during identity setup.')
            options[key] = value
    return options.get('SSH_AUTH_COLLECTOR_ID') or socket.gethostname(), options.get('SSH_AUTH_LOGFILE', '/var/log/auth.log')


def require_administrator():
    if os.geteuid() != 0:
        raise IdentityError('Local enrollment requires administrator privileges.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Prepare or verify local Server identities.')
    parser.add_argument('action', choices=('begin', 'prepare', 'verify', 'schedule', 'finish'))
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--installed', type=Path, default=Path('/usr/local/lib/mysql_siem'))
    parser.add_argument('--user', default='mysql_siem')
    parser.add_argument('--admin-socket', default='/run/mysqld/mysqld.sock')
    parser.add_argument('--cron-file', type=Path)
    parser.add_argument('--reset', action='store_true', help='Pause for a confirmed fresh-database installation.')
    args = parser.parse_args(argv)
    connection = None
    try:
        if args.action != 'verify':
            require_administrator()
        path = args.project / 'config/identity.env'
        if args.action == 'begin':
            begin_maintenance(STATE_DIR, args.installed, args.user, reset=args.reset)
            return 0
        if args.action != 'verify':
            installation.require_maintenance(STATE_DIR)
            require_stopped_legacy_jobs(args.installed, args.user)
        if args.action == 'schedule':
            if args.cron_file is None:
                raise IdentityError('Cron publication requires --cron-file.')
            schedule_maintenance(STATE_DIR, args.project, args.cron_file, args.user)
            return 0
        if args.action == 'verify':
            from database.connection import get_connection
            connection = get_connection()
            if connection is None:
                raise IdentityError('Cannot verify runtime database connection.')
            with connection.cursor() as cursor:
                validate_bindings(cursor, read_settings(path))
            return 0
        if args.action == 'prepare':
            record = installation.require_stage(STATE_DIR, args.project)
            if record['checkpoint_transition'] is None:
                previous = read_receipt(STATE_DIR / 'receipt.json')
                record['checkpoint_transition'] = previous is None or previous['phase'] != 'ready'
                installation.save_deployment(STATE_DIR, record)
        connection = pymysql.connect(unix_socket=args.admin_socket, user='root',
                                     database=os.environ['DB_NAME'], charset='utf8mb4',
                                     autocommit=False, connect_timeout=5, read_timeout=30,
                                     write_timeout=30, init_command="SET time_zone = '+00:00'")
        from ingestion.auth.collector import get_logfiles
        from ingestion.ufw_to_mysql import get_logfiles as ufw_logfiles
        reader, logfile = ssh_settings(args.project, args.user)
        options = {'auth_reader': reader, 'ufw_paths': ufw_logfiles(), 'auth_paths': get_logfiles(logfile)}
        if args.action == 'finish':
            finish_maintenance(STATE_DIR, path, connection, user=args.user, installed=args.installed, **options)
        else:
            settings = provision(connection, STATE_DIR / 'receipt.json', read_settings(path),
                                 confirmed=(STATE_DIR / 'legacy-confirmed').exists(), **options)
            receipt = read_receipt(STATE_DIR / 'receipt.json')
            if record['checkpoint_transition']:
                verify_pending_checkpoints(connection, receipt, **options)
            write_settings(path, settings, pwd.getpwnam(args.user).pw_gid)
            installation.mark_identity(STATE_DIR, args.project, settings)
        return 0
    except (IdentityError, installation.InstallationStateError, InstallationError) as error:
        print(str(error) + ' Protected jobs remain blocked; stop any unguarded legacy jobs manually. Keep the recovery receipt, deployment journal, '
              'staged settings and backups. Correct the reported conflict, stop legacy jobs gracefully '
              'and rerun sudo bash install.sh --role server; do not restore old cron jobs or delete the maintenance marker.', file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, EOFError, subprocess.SubprocessError, pymysql.MySQLError):
        print('Local identity setup stopped. Keep the maintenance marker, receipt, deployment journal and staged settings. '
              'Resolve the filesystem/database error and rerun sudo bash install.sh --role server. '
              'Do not delete recovery files or enable legacy collection. If retry fails, inspect registry bindings '
              'and checkpoints manually before resuming.', file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
