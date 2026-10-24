"""Prepare and publish a service copy without editing the downloaded checkout."""

import os
import pwd
import shutil
import stat
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


def stage_service(source, target, uid, gid, role=None):
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
        state_root = target if target.exists() else source
        for original in tree_files(state_root):
            relative = original.relative_to(state_root)
            if not preserved(relative):
                continue
            if original.stat().st_nlink != 1:
                raise InstallationError('Machine settings and logs must not have hard links.')
            destination = stage / relative
            make_parents(destination.parent, stage, gid)
            shutil.copy2(original, destination)
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


def publish_service(stage, target):
    """Preserve live settings/log inodes; restore the old tree on publish failure."""
    trusted_directory(target.parent)
    backup = None
    moved = []
    try:
        if target.exists():
            backup = Path(tempfile.mkdtemp(prefix='.mysql_siem-previous-', dir=target.parent))
            backup.rmdir()
            os.rename(target, backup)
            for original in tree_files(backup):
                relative = original.relative_to(backup)
                if preserved(relative):
                    destination = stage / relative
                    make_parents(destination.parent, stage, stage.stat().st_gid)
                    descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        info = os.fstat(descriptor)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise InstallationError('Machine settings and logs must be regular files without hard links.')
                        expected = destination.stat() if destination.exists() else info
                        os.fchown(descriptor, expected.st_uid, expected.st_gid)
                        os.fchmod(descriptor, 0o600)
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


def activate(stage, target, candidate, stable):
    if candidate.is_symlink() or not candidate.is_dir() or candidate.parent != ENVIRONMENTS:
        raise InstallationError('Activation requires a complete managed Python environment.')
    validate_virtualenv(candidate)
    if not (candidate / 'bin/python').is_file() or not (candidate / 'pyvenv.cfg').is_file():
        raise InstallationError('Activation requires a complete managed Python environment.')
    validate_virtualenv(stable, stable=True)
    backup = publish_service(stage, target)
    old_environment = None
    link = stable.parent / ('.mysql_siem-link-' + candidate.name)
    try:
        link.symlink_to(candidate)
        if stable.exists() and not stable.is_symlink():
            old_environment = Path(tempfile.mkdtemp(prefix='.mysql_siem-venv-previous-', dir=stable.parent))
            old_environment.rmdir()
            os.rename(stable, old_environment)
        os.replace(link, stable)
    except BaseException:
        if link.is_symlink():
            link.unlink()
        if old_environment is not None:
            os.rename(old_environment, stable)
        # Move the current settings/logs back as part of restoring the old version.
        if backup is not None:
            failed = publish_service(backup, target)
            shutil.rmtree(failed)
        else:
            os.rename(target, stage)
        raise
    # Keep the previous program/environment for administrator recovery.
    return backup


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
        elif action == 'stage':
            account = pwd.getpwnam(arguments[3])
            print(stage_service(Path(arguments[1]), Path(arguments[2]), account.pw_uid, account.pw_gid, role=arguments[4]))
        elif action == 'environment':
            print(new_environment())
        elif action == 'validate-environment':
            validate_virtualenv(Path(arguments[1]), stable=arguments[2] == 'stable')
        elif action == 'activate':
            activate(Path(arguments[1]), Path(arguments[2]), Path(arguments[3]), Path(arguments[4]))
        else:
            raise InstallationError('Unknown service installation operation.')
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        raise SystemExit('Service installation failed: ' + str(error)) from None


if __name__ == '__main__':
    main(sys.argv[1:])
