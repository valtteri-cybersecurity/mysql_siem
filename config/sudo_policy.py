"""Restrict only Mint's packaged, all-user helpers for the private service user."""

import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from config import installation_state as journal
from config.service_installation import InstallationError, trusted_directory

OWNER = 0
POLICY = Path('/etc/sudoers.d/zz-mysql-siem')
TEXT = '# Managed by mysql_siem: service account must not use sudo.\nmysql_siem ALL=(ALL:ALL) !ALL\n'
MINT_HELPERS = (
    '/usr/bin/mint-refresh-cache',
    '/usr/lib/linuxmint/mintUpdate/dpkg_lock_check.sh',
    '/usr/bin/mintdrivers-remove-live-media',
    '/usr/bin/mintdrivers-load-broadcom-modules',
)


def mint_commands(output, status):
    """Recognize only the packaged root helpers, never general sudo access."""
    if status != 0 or len(output) > 65536:
        raise InstallationError('Cannot verify mysql_siem sudo policy.')
    commands = set()
    header = False
    defaults = False
    denied = False
    for line in output.splitlines():
        if not line.strip():
            continue
        if re.fullmatch(r'User mysql_siem may run the following commands on [A-Za-z0-9_][A-Za-z0-9_.-]*:', line):
            if header:
                raise InstallationError('Duplicate sudo listing header.')
            header = True
            continue
        if not header:
            if re.fullmatch(r'Matching Defaults entries for mysql_siem on [A-Za-z0-9_][A-Za-z0-9_.-]*:', line):
                defaults = True
            elif not defaults or not line.startswith('    '):
                raise InstallationError('Cannot verify mysql_siem sudo policy diagnostics.')
            continue
        value = line.strip()
        if value == '(ALL : ALL) !ALL':
            denied = True
            continue  # Verified below against our own file and native policy queries.
        match = re.fullmatch(r'\(root\) NOPASSWD: (\S+)', value)
        if match is None or match.group(1) not in MINT_HELPERS:
            raise InstallationError('mysql_siem has unexpected sudo privileges; review sudo policy manually.')
        commands.add(match.group(1))
    if not header or not commands and not denied:
        raise InstallationError('Cannot verify Mint helper sudo grants.')
    return commands


def command(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=10, check=False,
                          env=dict(os.environ, LC_ALL='C'))


def check_syntax(path):
    result = command(['/usr/sbin/visudo', '-c', '-f', str(path)])
    if result.returncode != 0 or result.stderr:
        raise InstallationError('Cannot validate sudo policy; no database changes were attempted.')


def restriction_exists():
    try:
        descriptor = os.open(POLICY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != OWNER
                or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o440
                or os.read(descriptor, len(TEXT) + 1) != TEXT.encode()):
            raise InstallationError('Foreign or unsafe mysql_siem sudo restriction; it was not overwritten.')
        named = POLICY.lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise InstallationError('Sudo restriction changed during validation.')
    finally:
        os.close(descriptor)
    return True


def restrict_mint_sudo(output, status, *, confirm=input):
    commands = mint_commands(output, status)
    if os.geteuid() != OWNER:
        raise InstallationError('Sudo restriction requires the installer administrator.')
    journal.require_install_lock()
    trusted_directory(POLICY.parent)
    check_syntax('/etc/sudoers')
    if not restriction_exists():
        print('Mint grants update/driver sudo helpers to every user. The private mysql_siem account '
              'must not inherit these grants. Other users and Mint package files are unchanged.')
        if confirm('Type RESTRICT-SUDO to deny sudo only for mysql_siem: ') != 'RESTRICT-SUDO':
            raise InstallationError('Service sudo restriction declined; sudo policy was not changed.')
        descriptor, name = tempfile.mkstemp(prefix='.mysql-siem-', dir=POLICY.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                os.fchown(stream.fileno(), OWNER, 0)
                os.fchmod(stream.fileno(), 0o440)
                stream.write(TEXT)
                stream.flush()
                os.fsync(stream.fileno())
            check_syntax(temporary)
            # Link publishes atomically without replacing any pre-existing file.
            os.link(temporary, POLICY, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)
        journal.sync_directory(POLICY.parent)
    restriction_exists()
    check_syntax('/etc/sudoers')
    result = command(['/usr/bin/sudo', '-n', '-l', '-U', 'mysql_siem'])
    if result.stderr or mint_commands(result.stdout, result.returncode) != commands:
        raise InstallationError('Sudo policy changed during restriction; keep the deny file and review it.')
    for path in sorted(commands):
        # -l queries policy only: no update/driver helper is ever executed.
        result = command(['/usr/bin/sudo', '-n', '-l', '-U', 'mysql_siem', '-u', 'root', '--', path])
        if result.returncode != 1 or result.stdout or result.stderr:
            raise InstallationError('Service sudo restriction was not verified; deny file retained, installation stopped.')
    print('mysql_siem Mint helper sudo grants are blocked; native policy checks passed.')


def main(arguments):
    try:
        restrict_mint_sudo(arguments[1], int(arguments[0]))
        return 0
    except (OSError, ValueError, RuntimeError, EOFError, subprocess.SubprocessError) as error:
        print('Sudo policy preparation stopped: ' + str(error), file=sys.stderr)
        return 1
