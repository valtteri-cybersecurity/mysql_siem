"""Root-owned deployment journal and inherited installer lock checks."""

import fcntl
import json
import os
import stat
import tempfile
from pathlib import Path

STATE_DIR = Path('/usr/local/lib/.mysql_siem-local')
INSTALL_LOCK = Path('/usr/local/lib/.mysql_siem-install.lock')
MAINTENANCE_TEXT = 'Local identity setup is incomplete.\n'


class InstallationStateError(RuntimeError):
    """Keep collection paused until deployment can be verified."""


def trusted_state(state):
    from config.service_installation import trusted_directory

    trusted_directory(state)


def read_file(path, *, public=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        mode = 0o644 if public else 0o600
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode):
            raise InstallationStateError('Unsafe deployment state file; keep collection paused.')
        raw = os.read(descriptor, 1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise InstallationStateError('Deployment state file exceeds its size limit.')
        return raw.decode('utf-8')
    finally:
        os.close(descriptor)


def write_file(path, text, *, mode=0o600):
    if len(text.encode('utf-8')) > 1024 * 1024:
        raise InstallationStateError('Deployment state file exceeds its size limit.')
    trusted_state(path.parent)
    if path.exists() or path.is_symlink():
        read_file(path, public=mode == 0o644)
    descriptor, name = tempfile.mkstemp(prefix='.deployment-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            os.fchmod(output.fileno(), mode)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_lock(path, descriptor):
    """Prove the inherited descriptor owns the lock on this exact safe inode.

    A separate open must be blocked, and the inherited open description must
    accept LOCK_EX. An unrelated process holding a lock is not sufficient.
    """
    try:
        info = os.fstat(descriptor)
        named = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o022
                or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
                or not stat.S_ISREG(named.st_mode)):
            raise InstallationStateError('Unsafe or replaced installation lock.')
        probe = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise InstallationStateError('Required installation lock is not held.')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallationStateError('Installation lock belongs to another process.') from None
        finally:
            os.close(probe)
    except OSError:
        raise InstallationStateError('Required inherited installation lock is missing or inaccessible.') from None


def require_install_lock():
    from config.service_installation import trusted_directory

    trusted_directory(INSTALL_LOCK.parent)
    require_lock(INSTALL_LOCK, 9)


def require_maintenance(state):
    require_install_lock()
    trusted_state(state)
    if read_file(state / 'maintenance', public=True) != MAINTENANCE_TEXT:
        raise InstallationStateError('Required maintenance state is missing or invalid.')
    require_lock(state / 'runtime.lock', 8)


def read_deployment(state):
    path = state / 'deployment.json'
    if not path.exists() and not path.is_symlink():
        return None
    record = json.loads(read_file(path))
    fields = {'version', 'stage', 'target', 'stable', 'user', 'candidate', 'phase', 'identity', 'publication', 'database_started', 'cron_digest', 'checkpoint_transition'}
    if not isinstance(record, dict):
        raise InstallationStateError('Invalid deployment recovery journal.')
    # Older journals lack the per-attempt field. Keep their recovery history.
    if set(record) == fields:
        record['database_started_current'] = False
    fields.add('database_started_current')
    if set(record) != fields or type(record['version']) is not int or record['version'] != 1:
        raise InstallationStateError('Invalid deployment recovery journal.')
    if record['phase'] not in ('staged', 'publishing', 'activated', 'complete'):
        raise InstallationStateError('Unknown deployment recovery phase.')
    for name in ('stage', 'target', 'stable'):
        value = record[name]
        if not isinstance(value, str) or not Path(value).is_absolute() or os.path.abspath(value) != value:
            raise InstallationStateError('Invalid deployment recovery path.')
    if (type(record['database_started']) is not bool
            or type(record['database_started_current']) is not bool
            or (record['database_started_current'] and not record['database_started'])
            or record['checkpoint_transition'] is not None and type(record['checkpoint_transition']) is not bool
            or record['cron_digest'] is not None and not isinstance(record['cron_digest'], str)):
        raise InstallationStateError('Invalid deployment progress metadata.')
    candidate = record['candidate']
    if candidate is not None and (not isinstance(candidate, str) or not Path(candidate).is_absolute()
                                  or os.path.abspath(candidate) != candidate):
        raise InstallationStateError('Invalid deployment Python path.')
    if record['phase'] in ('publishing', 'activated', 'complete') and (candidate is None or not isinstance(record['publication'], dict)):
        raise InstallationStateError('Deployment publication metadata is incomplete.')
    if not isinstance(record['identity'], dict) or not isinstance(record['user'], str):
        raise InstallationStateError('Invalid deployment identity metadata.')
    return record


def save_deployment(state, record):
    write_file(state / 'deployment.json', json.dumps(record, sort_keys=True) + '\n')


def require_stage(state, project):
    require_maintenance(state)
    record = read_deployment(state)
    if record is None or record['phase'] != 'staged' or Path(record['stage']) != project:
        raise InstallationStateError('prepare requires the journaled staging directory; rerun the same installation command (keep --upgrade when upgrading).')
    return record


def mark_identity(state, project, settings):
    record = require_stage(state, project)
    record['identity'] = settings
    save_deployment(state, record)
