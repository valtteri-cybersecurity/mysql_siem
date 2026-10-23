"""Small installer adapter; persistent role parsing stays in installation_role."""

import os
import pwd
import sys

from config.installation_role import (
    ROLE_FILE,
    RoleConfigurationError,
    get_installation_role,
    initialize_installation_role,
)


def read_owned_role(user, *, path=ROLE_FILE):
    expected_uid = pwd.getpwnam(user).pw_uid
    if expected_uid == 0 or path.lstat().st_uid != expected_uid:
        raise RoleConfigurationError("Role file must belong to the non-root application user; review ownership manually.")
    return get_installation_role(path=path)


def initialize_owned_role(user, role, *, path=ROLE_FILE):
    expected_uid = pwd.getpwnam(user).pw_uid
    if expected_uid == 0 or os.geteuid() != expected_uid:
        raise RoleConfigurationError("Role initialization must run as the non-root application user.")
    return initialize_installation_role(role, path=path)


def main(arguments):
    try:
        if len(arguments) == 2 and arguments[0] == "read":
            print(read_owned_role(arguments[1]))
        elif len(arguments) == 3 and arguments[0] == "initialize":
            initialize_owned_role(arguments[1], arguments[2])
        else:
            raise RoleConfigurationError("Invalid role setup operation.")
    except (RoleConfigurationError, OSError, KeyError) as error:
        if isinstance(error, RoleConfigurationError):
            message = str(error)
        else:
            message = "Cannot verify role file or application account; review configuration manually."
        raise SystemExit(message) from None


if __name__ == "__main__":
    main(sys.argv[1:])
