"""Explicit, persistent installation role; no runtime services are started here."""

import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

ROLE_FILE = Path(__file__).resolve().parent / "role.env"


class RoleConfigurationError(RuntimeError):
    """Missing, unsafe or invalid installation role configuration."""


def _role_path(path):
    target = ROLE_FILE if path is None else Path(path)
    if not target.is_absolute() or ".." in target.parts or not target.name:
        raise RoleConfigurationError("Role configuration requires an absolute file path.")
    return target


@contextmanager
def _role_directory(target):
    # Walk from the root without following symlinks in any directory component.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for part in target.parent.parts[1:]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        yield directory
    finally:
        os.close(directory)


def get_installation_role(*, path=None):
    target = _role_path(path)
    try:
        with _role_directory(target) as directory:
            descriptor = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
                    raise RoleConfigurationError("Role file must be regular with permissions 400 or 600.")
                content = os.read(descriptor, 65)
            finally:
                os.close(descriptor)
    except FileNotFoundError:
        raise RoleConfigurationError("Role file is missing; initialize the role explicitly.") from None
    except OSError:
        raise RoleConfigurationError("Cannot safely read the role file; check paths and permissions.") from None

    for role in ("server", "collector"):
        expected = ("SIEM_ROLE=" + role).encode("ascii")
        if content in (expected, expected + b"\n"):
            return role
    raise RoleConfigurationError("Role file must contain exactly one SIEM_ROLE=server or SIEM_ROLE=collector line.")


def _write_role_contents(descriptor, content):
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written == 0:
            raise OSError("Role file write made no progress.")
        offset += written
    os.fsync(descriptor)


def initialize_installation_role(role, *, path=None):
    if type(role) is not str or role not in ("server", "collector"):
        raise RoleConfigurationError("Installation role must be exactly server or collector.")
    target = _role_path(path)
    content = ("SIEM_ROLE=" + role + "\n").encode("ascii")
    try:
        with _role_directory(target) as directory:
            temporary = ".role-" + secrets.token_hex(16) + ".tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=directory)
            try:
                try:
                    os.fchmod(descriptor, 0o600)
                    _write_role_contents(descriptor, content)
                finally:
                    os.close(descriptor)
                # link() publishes a complete file and fails atomically if the target exists.
                os.link(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory,
                        follow_symlinks=False)
                os.fsync(directory)
            finally:
                os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
    except FileExistsError:
        raise RoleConfigurationError("Role file already exists; initialization never replaces it.") from None
    except OSError:
        raise RoleConfigurationError("Role initialization failed; check the existing configuration before retrying.") from None
    return role
