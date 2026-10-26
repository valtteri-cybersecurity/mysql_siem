"""Prepare and publish a service copy without editing the downloaded checkout."""

import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from config.installation_role import initialize_installation_role
from config.installation_role_setup import read_owned_role


class InstallationError(RuntimeError):
    """An installation cannot be prepared or published safely."""


EXCLUDED = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache', '.ruff_cache',
            '.mypy_cache', '.idea', '.vscode', 'tests', 'docs'}
ENVIRONMENTS = Path('/opt/.mysql_siem-environments')
LOG_PARENT = Path('/var/log')
LOG_COMPONENTS = ('processes', 'services', 'audit')


def trusted_directory(path):
    """Every existing ancestor must be a root-owned, non-writable directory."""
    path = Path(path)
    for directory in [*reversed(path.parents), path]:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallationError('Installation directories must be root-owned without group/other writes.')


def validate_role_sources(source, target, user):
    roles = []
    for directory in (source, target):
        config = directory / 'config'
        if config.is_symlink():
            raise InstallationError('Configuration directory must not be a symbolic link.')
        path = config / 'role.env'
        if path.exists() or path.is_symlink():
            roles.append(read_owned_role(user, path=path))
    if len(set(roles)) > 1:
        raise InstallationError('Installation role conflict; existing roles were not changed.')
    return roles[0] if roles else None


def preserved(path):
    return (path.parent == Path('config') and path.suffix == '.env'
            or path.name.endswith('.log') or '.log.' in path.name)


def raise_walk_error(error):
    raise error


def tree_files(root):
    """Reject included links and special files; do not visit development trees."""
    for directory, names, files in os.walk(root, followlinks=False, onerror=raise_walk_error):
        included_directories = []
        for name in names:
            if name not in EXCLUDED:
                included_directories.append(name)
        names[:] = sorted(included_directories)
        included_files = []
        for name in files:
            if name not in EXCLUDED:
                included_files.append(name)
        files = sorted(included_files)
        for name in names + files:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise InstallationError('Service source contains a symbolic link or special file.')
        for name in sorted(files):
            if name.endswith(('.pyc', '.pyo', '.bak', '.tmp')) or name in {'ruff.toml', 'requirements-dev.txt', 'README.md'}:
                continue
            yield Path(directory) / name


def make_parents(path, root, gid):
    path.mkdir(parents=True, exist_ok=True)
    while path != root.parent:
        os.chown(path, 0, gid)
        path.chmod(0o750)
        if path == root:
            break
        path = path.parent


def stage_service(source, target, uid, gid, role=None, *, settings_source=None):
    trusted_directory(target.parent)
    if target.exists() or target.is_symlink():
        trusted_directory(target)
    stage = Path(tempfile.mkdtemp(prefix='.mysql_siem-stage-', dir=target.parent))
    try:
        for original in tree_files(source):
            relative = original.relative_to(source)
            if preserved(relative):
                continue
            destination = stage / relative
            make_parents(destination.parent, stage, gid)
            shutil.copy2(original, destination)
            os.chown(destination, 0, gid)
            destination.chmod(0o750 if original.stat().st_mode & 0o111 else 0o640)
        # The installed machine configuration wins over downloaded configuration.
        state_root = settings_source if settings_source is not None else (target if target.exists() else source)
        for original in tree_files(state_root):
            relative = original.relative_to(state_root)
            if not preserved(relative):
                continue
            if original.stat().st_nlink != 1:
                raise InstallationError('Machine settings and logs must not have hard links.')
            destination = stage / relative
            make_parents(destination.parent, stage, gid)
            shutil.copy2(original, destination)
            if relative == Path('config/identity.env'):
                os.chown(destination, 0, gid)
                destination.chmod(0o640)
            else:
                os.chown(destination, uid, gid)
                destination.chmod(0o600)
        make_parents(stage / 'config', stage, gid)
        if role is not None and not (stage / 'config/role.env').exists():
            # Keep the code directory root-owned even during first role creation.
            role_path = stage / 'config/role.env'
            initialize_installation_role(role, path=role_path)
            descriptor = os.open(role_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fchown(descriptor, uid, gid)
            finally:
                os.close(descriptor)
        return stage
    except BaseException:
        shutil.rmtree(stage)
        raise


def publish_service(stage, target, *, prepared_identity=False, backup_path=None):
    """Preserve live settings/log inodes; restore the old tree on publish failure."""
    trusted_directory(target.parent)
    backup = None
    moved = []
    try:
        if target.exists():
            backup = backup_path
            if backup is None:
                backup = unused_path(target.parent, '.mysql_siem-previous-')
            os.rename(target, backup)
            for original in tree_files(backup):
                relative = original.relative_to(backup)
                if preserved(relative):
                    if prepared_identity and relative == Path('config/identity.env'):
                        continue
                    destination = stage / relative
                    make_parents(destination.parent, stage, stage.stat().st_gid)
                    descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        info = os.fstat(descriptor)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise InstallationError('Machine settings and logs must be regular files without hard links.')
                        expected = destination.stat() if destination.exists() else info
                        os.fchown(descriptor, expected.st_uid, expected.st_gid)
                        os.fchmod(descriptor, 0o640 if relative == Path('config/identity.env') else 0o600)
                        os.replace(original, destination)
                        moved.append(relative)
                    finally:
                        os.close(descriptor)
        os.rename(stage, target)
        return backup
    except BaseException:
        for relative in reversed(moved):
            os.replace(stage / relative, backup / relative)
        if backup is not None:
            os.rename(backup, target)
        raise


def validate_virtualenv(path, stable=False):
    trusted_directory(path.parent)
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        if not stable or path.lstat().st_uid != 0:
            raise InstallationError('Unsafe virtual environment link.')
        resolved = path.resolve(strict=True)
        trusted_directory(ENVIRONMENTS)
        if resolved.parent != ENVIRONMENTS:
            raise InstallationError('Virtual environment link is outside managed environments.')
        path = resolved
    trusted_directory(path)
    for directory, names, files in os.walk(path, followlinks=False, onerror=raise_walk_error):
        for name in names + files:
            item = Path(directory) / name
            info = item.lstat()
            if info.st_uid != 0:
                raise InstallationError('Virtual environment must be root-owned.')
            if stat.S_ISLNK(info.st_mode):
                if not item.resolve(strict=True).is_relative_to(path):
                    raise InstallationError('Virtual environment has an external symbolic link.')
            elif info.st_mode & 0o022:
                raise InstallationError('Virtual environment must not be group/other writable.')


def new_environment():
    trusted_directory(ENVIRONMENTS.parent)
    if not ENVIRONMENTS.exists():
        ENVIRONMENTS.mkdir(mode=0o755)
        ENVIRONMENTS.chmod(0o755)
    trusted_directory(ENVIRONMENTS)
    path = Path(tempfile.mkdtemp(prefix='python-', dir=ENVIRONMENTS))
    path.chmod(0o755)
    return path


def activate(stage, target, candidate, stable, *, prepared_identity=False, backup_path=None, environment_backup=None):
    if candidate.is_symlink() or not candidate.is_dir() or candidate.parent != ENVIRONMENTS:
        raise InstallationError('Activation requires a complete managed Python environment.')
    validate_virtualenv(candidate)
    if not (candidate / 'bin/python').is_file() or not (candidate / 'pyvenv.cfg').is_file():
        raise InstallationError('Activation requires a complete managed Python environment.')
    validate_virtualenv(stable, stable=True)
    backup = publish_service(stage, target, prepared_identity=prepared_identity, backup_path=backup_path)
    old_environment = None
    link = stable.parent / ('.mysql_siem-link-' + candidate.name)
    try:
        link.symlink_to(candidate)
        if stable.exists() and not stable.is_symlink():
            old_environment = environment_backup
            if old_environment is None:
                old_environment = unused_path(stable.parent, '.mysql_siem-venv-previous-')
            os.rename(stable, old_environment)
        os.replace(link, stable)
    except BaseException:
        if link.is_symlink():
            link.unlink()
        if old_environment is not None:
            os.rename(old_environment, stable)
        # Move the current settings/logs back as part of restoring the old version.
        if backup is not None:
            failed = publish_service(backup, target, prepared_identity=prepared_identity)
            shutil.rmtree(failed)
        else:
            os.rename(target, stage)
        raise
    # Keep the previous program/environment for administrator recovery.
    return backup


def unused_path(parent, prefix):
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    path.rmdir()
    return path


def same_directory(path, identity):
    if identity is None or not path.exists() or path.is_symlink():
        return False
    info = path.lstat()
    return stat.S_ISDIR(info.st_mode) and [info.st_dev, info.st_ino] == identity


def directory_identity(path):
    trusted_directory(path)
    info = path.lstat()
    return [info.st_dev, info.st_ino]


def deployment_paths(record, target, stable, user):
    if (record['target'], record['stable'], record['user']) != (str(target), str(stable), user):
        raise InstallationError('Deployment journal belongs to another installation; keep collection paused.')
    stage = Path(record['stage'])
    if stage.parent != target.parent or not stage.name.startswith('.mysql_siem-stage-'):
        raise InstallationError('Unsafe staging path in recovery journal.')
    if record['candidate'] is not None:
        candidate = Path(record['candidate'])
        if candidate.parent != ENVIRONMENTS or not candidate.name.startswith('python-'):
            raise InstallationError('Unsafe Python path in recovery journal.')


def recover_publication(state, record):
    """Undo an interrupted directory/environment swap using the durable plan.

    Write the plan before the first rename. Inspect inodes on retry, since a
    process can die between a rename and the following journal update.
    """
    from config import installation_state as journal

    journal.require_maintenance(state)
    publication = record['publication']
    fields = {'stage_inode', 'target_inode', 'backup', 'files', 'old_link', 'environment_backup', 'environment_inode'}
    if not isinstance(publication, dict) or set(publication) != fields:
        raise InstallationError('Incomplete publication recovery plan; manual recovery required.')
    stage, target, stable = Path(record['stage']), Path(record['target']), Path(record['stable'])
    backup = Path(publication['backup']) if publication['backup'] is not None else None
    if backup is not None and (backup.parent != target.parent or not backup.name.startswith('.mysql_siem-previous-')):
        raise InstallationError('Unsafe program backup path in recovery journal.')
    environment_backup = publication['environment_backup']
    if environment_backup is not None:
        environment_backup = Path(environment_backup)
        if environment_backup.parent != stable.parent or not environment_backup.name.startswith('.mysql_siem-venv-previous-'):
            raise InstallationError('Unsafe Python backup path in recovery journal.')
    files = publication['files']
    if not isinstance(files, list):
        raise InstallationError('Invalid preserved-file recovery plan.')
    for name in files:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name or not preserved(relative):
            raise InstallationError('Unsafe preserved-file recovery path.')
    # Restore the interpreter first. Never overwrite an unrelated replacement.
    candidate = Path(record['candidate'])
    is_candidate = stable.is_symlink() and os.readlink(stable) == str(candidate)
    if environment_backup is not None and environment_backup.exists():
        trusted_directory(environment_backup)
        if not same_directory(environment_backup, publication['environment_inode']):
            raise InstallationError('Previous Python environment inode changed; manual recovery required.')
        if is_candidate:
            stable.unlink()
        elif stable.exists() or stable.is_symlink():
            raise InstallationError('Python activation conflicts with its backup; manual recovery required.')
        os.rename(environment_backup, stable)
    elif environment_backup is not None:
        if not same_directory(stable, publication['environment_inode']):
            raise InstallationError('Previous Python environment cannot be located; manual recovery required.')
    elif is_candidate:
        old_link = publication['old_link']
        if old_link is None:
            stable.unlink()
        else:
            previous = Path(old_link)
            if not previous.is_absolute():
                previous = stable.parent / previous
            previous = previous.resolve(strict=True)
            validate_virtualenv(previous)
            if previous.parent != ENVIRONMENTS:
                raise InstallationError('Unsafe previous Python environment in recovery journal.')
            link = unused_path(stable.parent, '.mysql_siem-recover-link-')
            try:
                link.symlink_to(previous)
                os.replace(link, stable)
            finally:
                link.unlink(missing_ok=True)
    elif publication['old_link'] is not None:
        previous = Path(publication['old_link'])
        if not previous.is_absolute():
            previous = stable.parent / previous
        if not stable.is_symlink() or stable.resolve(strict=True) != previous.resolve(strict=True):
            raise InstallationError('Python environment changed outside this deployment; manual recovery required.')
    # A published staging inode may still be at the live path after a crash.
    if same_directory(target, publication['stage_inode']):
        if stage.exists() or stage.is_symlink():
            raise InstallationError('Both live and staged program paths exist; manual recovery required.')
        os.rename(target, stage)
    restore = None
    if backup is not None and backup.exists():
        if not same_directory(backup, publication['target_inode']):
            raise InstallationError('Program backup inode changed; manual recovery required.')
        if target.exists() or target.is_symlink():
            raise InstallationError('Live program path conflicts with its backup; manual recovery required.')
        restore = backup
    elif publication['target_inode'] is not None:
        if not same_directory(target, publication['target_inode']):
            raise InstallationError('The previous program cannot be located; manual recovery required.')
        restore = target
    if restore is not None:
        for name in reversed(files):
            original = restore / name
            moved = stage / name
            if original.exists() or original.is_symlink():
                continue
            trusted_directory(stage)
            if not moved.is_file() or moved.is_symlink():
                raise InstallationError('A preserved setting/log is missing; manual recovery required.')
            os.replace(moved, original)
        if restore != target:
            os.rename(restore, target)
    journal.sync_directory(target.parent)
    journal.sync_directory(stable.parent)
    record['phase'] = 'staged'
    record['publication'] = None
    journal.save_deployment(state, record)


def restore_missing_staged_settings(stage, target):
    """Rollback returns original inodes to the live tree; restage their copies."""
    if not target.exists():
        return
    for original in tree_files(target):
        relative = original.relative_to(target)
        destination = stage / relative
        if preserved(relative) and not destination.exists():
            if original.stat().st_nlink != 1:
                raise InstallationError('Recovered settings and logs must not have hard links.')
            make_parents(destination.parent, stage, stage.stat().st_gid)
            shutil.copy2(original, destination)
            info = original.stat()
            os.chown(destination, info.st_uid, info.st_gid)
            destination.chmod(0o640 if relative == Path('config/identity.env') else 0o600)


def check_unpublished_recovery(target, stable, user, state):
    """Read protected recovery metadata before permitting an unpublished upgrade."""
    from config import installation_state as journal

    journal.require_maintenance(state)
    record = journal.read_deployment(state)
    if (record is None or record['phase'] != 'staged' or not record['database_started']
            or target.exists() or target.is_symlink()):
        raise InstallationError('Upgrade recovery requires an unpublished, database-started staging journal.')
    deployment_paths(record, target, stable, user)
    stage = Path(record['stage'])
    trusted_directory(stage / 'config')
    account = pwd.getpwnam(user)
    if account.pw_uid == 0 or account.pw_gid == 0 or read_owned_role(user, path=stage / 'config/role.env') != 'server':
        raise InstallationError('Upgrade recovery requires the existing non-root Server account and role.')
    descriptor = os.open(stage / 'config/mysql.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_uid, info.st_gid) != (account.pw_uid, account.pw_gid)
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise InstallationError('Unsafe staged database settings; preserve the recovery files.')
    finally:
        os.close(descriptor)
    receipt = json.loads(journal.read_file(state / 'receipt.json'))
    if not isinstance(receipt, dict) or receipt.get('phase') not in ('database_ready', 'ready'):
        raise InstallationError('A completed identity receipt is required; preserve incomplete recovery evidence.')
    # Full receipt/binding/DB checks run with the new trusted environment, before
    # maintenance begins or any migration runs. Never execute the old staging code.
    return stage


def prepare_deployment(source, target, user, role, stable, state, *, settings_source=None, reset=False):
    from config import installation_state as journal

    journal.require_install_lock()
    trusted_directory(state.parent)
    if not state.exists() and not state.is_symlink():
        state.mkdir(mode=0o755)
        state.chmod(0o755)
    trusted_directory(state)
    record = journal.read_deployment(state)
    pending_transition = None
    if (not reset and record is None and ((state / 'receipt.json').exists() or (state / 'receipt.json').is_symlink())
            and not (target / 'config/mysql.env').is_file()):
        raise InstallationError('An older identity receipt exists without installed database settings or a deployment journal. '
                                'Keep the receipt and old .mysql_siem-stage-* directories. Recover the original prepared '
                                'service/settings after administrative review before retrying; do not generate a new password.')
    if record is not None:
        if (state / 'maintenance').exists():
            pending_transition = record['checkpoint_transition']
        deployment_paths(record, target, stable, user)
        if record['phase'] == 'publishing':
            recover_publication(state, record)
        if record['phase'] == 'staged' and Path(record['stage']).exists():
            trusted_directory(Path(record['stage']))
            restore_missing_staged_settings(Path(record['stage']), target)
            if not reset:
                account = pwd.getpwnam(user)
                stage = stage_service(source, target, account.pw_uid, account.pw_gid,
                                      role=role, settings_source=Path(record['stage']))
                updated = dict(record, stage=str(stage), candidate=None, cron_digest=None,
                               database_started_current=False)
                # Keep the old directory and durable recovery evidence. Publish
                # the new code/settings reference only after copying succeeds.
                journal.save_deployment(state, updated)
                return stage
            settings_source = Path(record['stage'])
        if record['phase'] == 'staged' and not Path(record['stage']).exists() and not target.exists():
            raise InstallationError('Pending staged settings cannot be located; manual recovery required.')
        if record['phase'] == 'activated':
            verify_publication(state, record)
    account = pwd.getpwnam(user)
    # Keep database history while resuming an unfinished maintenance period,
    # including a failure after publication. Completed upgrades start fresh.
    previous_database_started = bool(record is not None and record['database_started']
                                     and (reset or (state / 'maintenance').exists()))
    if reset and target.exists():
        settings_source = target
    if settings_source is None or (target.exists() and (record is None or record['phase'] != 'staged')):
        settings_source = target if target.exists() else (settings_source or source)
    stage = stage_service(source, target, account.pw_uid, account.pw_gid, role=role, settings_source=settings_source)
    record = {'version': 1, 'stage': str(stage), 'target': str(target), 'stable': str(stable),
              'user': user, 'candidate': None, 'phase': 'staged', 'identity': {}, 'publication': None,
              'database_started': previous_database_started, 'database_started_current': False,
              'cron_digest': None, 'checkpoint_transition': pending_transition}
    journal.save_deployment(state, record)
    return stage


def preflight_deployment(project, target, stable, user, state):
    """Validate the prepared journal/environment without starting maintenance."""
    from config import installation_state as journal

    journal.require_install_lock()
    trusted_directory(state)
    record = journal.read_deployment(state)
    if record is None or record['phase'] != 'staged' or record['stage'] != str(project):
        raise InstallationError('Preflight requires the journaled staging directory; recovery files were retained.')
    deployment_paths(record, target, stable, user)
    trusted_directory(project)
    if record['candidate'] is None:
        raise InstallationError('The prepared Python environment is missing.')
    candidate = Path(record['candidate'])
    validate_virtualenv(candidate)
    if not (candidate / 'bin/python').is_file() or not (candidate / 'pyvenv.cfg').is_file():
        raise InstallationError('The prepared Python environment is incomplete.')
    if (state / 'maintenance').exists() or (state / 'maintenance').is_symlink():
        # A previous maintenance period must already own the inherited locks.
        # Do not create, remove or repair a maintenance marker in this check.
        journal.require_maintenance(state)


def activate_deployment(stage, target, candidate, stable, state):
    from config import installation_state as journal

    record = journal.require_stage(state, stage)
    deployment_paths(record, target, stable, record['user'])
    if record['candidate'] != str(candidate) or not record['identity']:
        raise InstallationError('Python or local identity preparation is incomplete; collection remains paused.')
    validate_virtualenv(candidate)
    validate_virtualenv(stable, stable=True)
    stage_inode = directory_identity(stage)
    target_inode = directory_identity(target) if target.exists() else None
    backup = unused_path(target.parent, '.mysql_siem-previous-') if target_inode is not None else None
    old_environment = None
    old_link = None
    environment_inode = None
    if stable.is_symlink():
        old_link = os.readlink(stable)
    elif stable.exists():
        environment_inode = directory_identity(stable)
        old_environment = unused_path(stable.parent, '.mysql_siem-venv-previous-')
    files = []
    if target_inode is not None:
        for original in tree_files(target):
            relative = original.relative_to(target)
            if preserved(relative) and relative != Path('config/identity.env'):
                files.append(str(relative))
    record['publication'] = {'stage_inode': stage_inode, 'target_inode': target_inode,
                             'backup': str(backup) if backup is not None else None, 'files': files,
                             'old_link': old_link,
                             'environment_backup': str(old_environment) if old_environment is not None else None,
                             'environment_inode': environment_inode}
    record['phase'] = 'publishing'
    journal.save_deployment(state, record)
    # Leave the plan in place even if normal exception handling restores the old
    # program. Retry also handles SIGKILL, which cannot execute Python cleanup.
    activate(stage, target, candidate, stable, prepared_identity=True,
             backup_path=backup, environment_backup=old_environment)
    journal.sync_directory(target.parent)
    journal.sync_directory(stable.parent)
    record['phase'] = 'activated'
    journal.save_deployment(state, record)


def verify_publication(state, record):
    from config import installation_state as journal

    journal.require_maintenance(state)
    if record['phase'] not in ('activated', 'complete') or not isinstance(record['publication'], dict):
        raise InstallationError('Program publication has not completed; collection remains paused.')
    target, stable, candidate = Path(record['target']), Path(record['stable']), Path(record['candidate'])
    trusted_directory(target)
    if not same_directory(target, record['publication']['stage_inode']):
        raise InstallationError('Published program inode does not match the recovery journal.')
    validate_virtualenv(stable, stable=True)
    if not stable.is_symlink() or os.readlink(stable) != str(candidate):
        raise InstallationError('Published Python environment does not match the recovery journal.')


def discard_deployment(state):
    from config import installation_state as journal

    journal.require_install_lock()
    record = journal.read_deployment(state)
    if record is None or record['phase'] != 'staged':
        raise InstallationError('Only an uncommitted staged installation may be discarded.')
    deployment_paths(record, Path(record['target']), Path(record['stable']), record['user'])
    if record['database_started']:
        when = ('during this installation attempt' if record['database_started_current']
                else 'during an earlier interrupted installation attempt')
        print('Database setup was started ' + when +
              '; staged settings and the recovery journal were retained.', file=sys.stderr)
        return
    stable = Path(record['stable'])
    if (record['candidate'] is not None and stable.is_symlink()
            and stable.resolve(strict=True) == Path(record['candidate']).resolve(strict=True)):
        raise InstallationError('Refusing to discard the active Python environment; manual recovery required.')
    shutil.rmtree(record['stage'])
    if record['candidate'] is not None:
        shutil.rmtree(record['candidate'])
    (state / 'deployment.json').unlink()
    journal.sync_directory(state)


def validate_log_parent(info, *, allow_syslog=False):
    """Only the designated log parent may use root:syslog 0775."""
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise InstallationError('Log parent must be a root-owned directory.')
    if info.st_mode & 0o022:
        if not allow_syslog or stat.S_IMODE(info.st_mode) != 0o775:
            raise InstallationError('Unsafe log parent permissions.')
        try:
            syslog_gid = grp.getgrnam('syslog').gr_gid
        except KeyError:
            raise InstallationError('Required syslog group is missing.') from None
        if info.st_gid != syslog_gid or syslog_gid == 0:
            raise InstallationError('Writable log parent must belong to the syslog group.')


def validate_snapshot_entry(info, account, *, shared=False, directory=False):
    """Check ownership, type and write permissions before any mutation."""
    owners = (0,) if shared else (0, account.pw_uid)
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not valid_type or info.st_uid not in owners or info.st_gid not in (0, account.pw_gid)
            or info.st_mode & 0o022 or (not directory and info.st_nlink != 1)):
        raise InstallationError('Unsafe snapshot log owner, permissions, type or hard link.')


def open_snapshot_directory(parent, name, account, *, create=False, shared=False):
    if create:
        try:
            os.mkdir(name, mode=0o750 if shared else 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        info = os.fstat(descriptor)
        validate_snapshot_entry(info, account, shared=shared, directory=True)
        verify_snapshot_name(parent, name, descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def verify_snapshot_name(parent, name, descriptor):
    opened = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise InstallationError('Snapshot log path changed during preparation; retry under maintenance.')


def set_snapshot_permissions(descriptor, uid, gid, mode):
    info = os.fstat(descriptor)
    if (info.st_uid, info.st_gid) != (uid, gid):
        os.fchown(descriptor, uid, gid)
    if stat.S_IMODE(info.st_mode) != mode:
        os.fchmod(descriptor, mode)


def prepare_snapshot_logs(user, root=Path('/var/log/mysql_siem'), *, check_only=False):
    """Check or prepare only our fixed log tree; never change /var/log itself."""
    root = Path(root)
    if root != LOG_PARENT / 'mysql_siem':
        raise InstallationError('Snapshot logs require the dedicated /var/log/mysql_siem layout.')
    account = pwd.getpwnam(user)
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise InstallationError('Snapshot logs require a dedicated non-root account and group.')
    trusted_directory(LOG_PARENT.parent)
    for ancestor in LOG_PARENT.parents:
        info = ancestor.lstat()
        execute = stat.S_IXGRP if info.st_gid == account.pw_gid else stat.S_IXOTH
        if not info.st_mode & execute:
            raise InstallationError('Service group cannot traverse log ancestor: ' + str(ancestor))
    parent = os.open(LOG_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened_parent = os.fstat(parent)
        validate_log_parent(opened_parent, allow_syslog=True)
        execute = stat.S_IXGRP if opened_parent.st_gid == account.pw_gid else stat.S_IXOTH
        if not opened_parent.st_mode & execute:
            raise InstallationError('Service group cannot traverse /var/log; parent permissions were not changed.')
        named_parent = LOG_PARENT.lstat()
        if (named_parent.st_dev, named_parent.st_ino) != (opened_parent.st_dev, opened_parent.st_ino):
            raise InstallationError('Log parent changed during validation.')
        try:
            root_fd = open_snapshot_directory(parent, root.name, account, create=not check_only, shared=True)
        except FileNotFoundError:
            if check_only:
                return
            raise
        try:
            for name in os.listdir(root_fd):
                if name not in LOG_COMPONENTS:
                    raise InstallationError('Unexpected entry in snapshot log root: ' + name)
            if not check_only:
                set_snapshot_permissions(root_fd, 0, account.pw_gid, 0o750)
            for component in LOG_COMPONENTS:
                try:
                    directory = open_snapshot_directory(root_fd, component, account, create=not check_only)
                except FileNotFoundError:
                    if check_only:
                        continue
                    raise
                try:
                    for name in os.listdir(directory):
                        suffix = name.removeprefix('cron.log.')
                        if name != 'cron.log' and not (name.startswith('cron.log.') and suffix.isascii() and suffix.isdigit()):
                            raise InstallationError('Unexpected snapshot log entry: ' + component + '/' + name)
                        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        validate_snapshot_entry(info, account)
                    if not check_only:
                        set_snapshot_permissions(directory, account.pw_uid, account.pw_gid, 0o700)
                    flags = os.O_RDONLY if check_only else os.O_WRONLY | os.O_APPEND | os.O_CREAT
                    try:
                        descriptor = os.open('cron.log', flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                                             0o600, dir_fd=directory)
                    except FileNotFoundError:
                        if check_only:
                            continue
                        raise
                    try:
                        validate_snapshot_entry(os.fstat(descriptor), account)
                        verify_snapshot_name(directory, 'cron.log', descriptor)
                        if not check_only:
                            set_snapshot_permissions(descriptor, account.pw_uid, account.pw_gid, 0o600)
                    finally:
                        os.close(descriptor)
                    verify_snapshot_name(root_fd, component, directory)
                finally:
                    os.close(directory)
            verify_snapshot_name(parent, root.name, root_fd)
        finally:
            os.close(root_fd)
    finally:
        os.close(parent)
    if not check_only:
        for component in LOG_COMPONENTS:
            result = subprocess.run(['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/head', '-c', '0', '--',
                                     str(root / component / 'cron.log')], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=5, check=False)
            if result.returncode != 0:
                raise InstallationError('Service account cannot open snapshot log: ' + component)


def main(arguments):
    try:
        action = arguments[0]
        if action == 'check':
            source = Path(arguments[1])
            target = Path(arguments[2])
            trusted_directory(target.parent)
            if target.exists() or target.is_symlink():
                trusted_directory(target)
            validate_role_sources(source, target, arguments[3])
        elif action == 'recovery-check':
            from config.installation_state import STATE_DIR
            check_unpublished_recovery(Path(arguments[1]), Path('/opt/mysql_siem-venv'), arguments[2], STATE_DIR)
        elif action == 'preflight':
            from config.installation_state import STATE_DIR
            preflight_deployment(Path(arguments[1]), Path(arguments[2]), Path('/opt/mysql_siem-venv'),
                                 arguments[3], STATE_DIR)
        elif action in ('snapshot-logs', 'snapshot-logs-check'):
            prepare_snapshot_logs(arguments[1], check_only=action == 'snapshot-logs-check')
        elif action == 'stage':
            from config.installation_state import STATE_DIR
            print(prepare_deployment(Path(arguments[1]), Path(arguments[2]), arguments[3], arguments[4],
                                     Path('/opt/mysql_siem-venv'), STATE_DIR,
                                     settings_source=Path(arguments[5]) if len(arguments) > 5 else None,
                                     reset=len(arguments) > 6 and arguments[6] == 'reset'))
        elif action == 'environment':
            from config import installation_state as journal
            journal.require_install_lock()
            record = journal.read_deployment(journal.STATE_DIR)
            if record is None or record['phase'] != 'staged':
                raise InstallationError('Prepare the service copy before its Python environment.')
            candidate = new_environment()
            record['candidate'] = str(candidate)
            journal.save_deployment(journal.STATE_DIR, record)
            print(candidate)
        elif action == 'validate-environment':
            validate_virtualenv(Path(arguments[1]), stable=arguments[2] == 'stable')
        elif action == 'activate':
            from config.installation_state import STATE_DIR
            activate_deployment(Path(arguments[1]), Path(arguments[2]), Path(arguments[3]), Path(arguments[4]), STATE_DIR)
        elif action == 'database-started':
            from config import installation_state as journal
            journal.require_maintenance(journal.STATE_DIR)
            record = journal.read_deployment(journal.STATE_DIR)
            if record is None or record['phase'] != 'staged':
                raise InstallationError('Database setup requires a staged deployment.')
            record['database_started'] = True
            record['database_started_current'] = True
            journal.save_deployment(journal.STATE_DIR, record)
        elif action == 'discard':
            from config.installation_state import STATE_DIR
            discard_deployment(STATE_DIR)
        else:
            raise InstallationError('Unknown service installation operation.')
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        raise SystemExit('Service installation failed: ' + str(error)) from None


if __name__ == '__main__':
    main(sys.argv[1:])
