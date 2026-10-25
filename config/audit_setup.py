"""Administrator-only Audit provisioning, executed only by an approved installer.

Importing the module performs no system changes. Tests supply temporary paths
and mock every service, privilege and audit command.
"""

import argparse
import hashlib
import json
import os
import platform
import pwd
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

from config import installation_state
from config.service_installation import trusted_directory
from ingestion.audit.get import source_status
from ingestion.audit.targets import validate_targets

MARKER = '# Managed by mysql_siem Audit; administrator installation only.\n'
RULES_FILE = Path('/etc/audit/rules.d/50-mysql-siem.rules')
CONFIG_FILE = Path('/etc/audit/auditd.conf')
UNIT_DIR = Path('/etc/systemd/system')
UNIT_NAMES = ('mysql-siem-audit.service', 'mysql-siem-audit.timer')


def read_root_text(path, maximum=1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or info.st_size > maximum):
            raise ValueError('Unsafe Audit installation file.')
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum:
            raise ValueError('Audit installation file is too large.')
        return raw.decode('utf-8')
    finally:
        os.close(descriptor)


def write_managed(path, content, *, gid=0):
    """Do not replace another program's file, even with a matching filename."""
    from database.local_identity import atomic_write

    trusted_directory(path.parent)
    if path.exists() or path.is_symlink():
        previous = read_root_text(path)
        if not previous.startswith(MARKER):
            raise ValueError('Audit installation filename belongs to another administrator/program.')
        if previous == content:
            return False
    atomic_write(path, content, gid=gid, mode=0o640)
    return True


def command(arguments):
    # Fixed executables; no argument originates in an audit record.
    result = subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=15,
                            env=dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C'))
    if result.returncode != 0:
        raise RuntimeError('Audit installation command failed: ' + arguments[0])
    return result.stdout


def architectures(machine=None, kernel_config=None):
    machine = platform.machine() if machine is None else machine
    if machine in ('i386', 'i486', 'i586', 'i686', 'armv7l'):
        return ['b32']
    if machine not in ('x86_64', 'aarch64'):
        raise ValueError('Audit rules require a reviewed syscall architecture for this platform.')
    if kernel_config is None:
        kernel_config = read_root_text(Path('/boot/config-' + platform.release()))
    option = 'CONFIG_IA32_EMULATION' if machine == 'x86_64' else 'CONFIG_COMPAT'
    if option + '=y' in kernel_config.splitlines():
        return ['b64', 'b32']
    if '# ' + option + ' is not set' in kernel_config.splitlines():
        return ['b64']
    raise ValueError('Cannot determine kernel compatibility ABI support; review boot kernel configuration.')


def rule_lines(targets, arches):
    validate_targets(targets)
    if not arches or any(arch not in ('b64', 'b32') for arch in arches):
        raise ValueError('Invalid Audit rule architecture.')
    lines = []
    for target in targets:
        for arch in arches:
            for kind, field in (('files', 'path'), ('directories', 'dir'), ('executables', 'exe')):
                for path in target[kind]:
                    syscall_filter = ' -S all' if kind == 'executables' else ''
                    lines.append(f'-a always,exit -F arch={arch}{syscall_filter} '
                                 f'-F {field}={path} -F perm=wa -k ' + target['audit_key'])
    return lines


def rule_signature(line):
    tokens = shlex.split(line)
    fields = {}
    index = 0
    while index < len(tokens):
        option = tokens[index]
        if option not in ('-a', '-F', '-k', '-S') or index + 1 >= len(tokens):
            raise ValueError('Unsupported rule using a mysql_siem Audit key.')
        value = tokens[index + 1]
        if option == '-a':
            fields['action'] = ','.join(sorted(value.split(',')))
        elif option == '-k':
            fields['key'] = value
        elif option == '-S':
            if value != 'all':
                raise ValueError('Unexpected syscall list using a mysql_siem Audit key.')
        else:
            name, separator, setting = value.partition('=')
            if not separator or name in fields:
                raise ValueError('Unsupported or repeated Audit rule field.')
            fields[name] = ''.join(sorted(setting)) if name == 'perm' else setting
        index += 2
    return fields


def verify_rules(expected, output):
    wanted = [rule_signature(line) for line in expected]
    keys = {rule['key'] for rule in wanted}
    found = []
    for line in output.splitlines():
        if line.strip() in ('', 'No rules'):
            continue
        if re.search(r'-a (?:never,(?:task|exit)|(?:task|exit),never)(?:\s|$)', line):
            raise ValueError('A never/task or never/exit rule may suppress Audit events; administrator review required.')
        tokens = shlex.split(line)
        owned = False
        for key in keys:
            if key in tokens or 'key=' + key in tokens:
                owned = True
        if owned:
            signature = rule_signature(line)
            if signature not in wanted:
                raise ValueError('An existing rule conflicts with a mysql_siem Audit key.')
            found.append(signature)
    return [line for line, signature in zip(expected, wanted) if signature not in found]


def audit_configuration(text, group):
    values = {}
    for line in text.splitlines():
        body = line.split('#', 1)[0].strip()
        if not body:
            continue
        key, separator, value = body.partition('=')
        key = key.strip().lower()
        if not separator or key in values:
            raise ValueError('Duplicate or invalid auditd configuration; review manually.')
        values[key] = value.strip()
    if (values.get('write_logs', 'yes').lower() != 'yes'
            or values.get('local_events', 'yes').lower() != 'yes'
            or values.get('log_format', 'raw').lower() not in ('raw', 'enriched')):
        raise ValueError('Audit requires local RAW/ENRICHED disk logging.')
    if values.get('log_group', 'root') not in ('root', '0', group):
        raise ValueError('Existing audit log reader group must be preserved; approve a dedicated read-access plan manually.')
    logfile = values.get('log_file', '/var/log/audit/audit.log')
    if (not re.fullmatch(r'/var/log/[a-zA-Z0-9_./+-]+', logfile)
            or Path(logfile).parent == Path('/var/log') or str(Path(logfile)) != logfile
            or '..' in Path(logfile).parts):
        raise ValueError('Audit log requires a dedicated canonical directory under /var/log.')
    if values.get('log_group') == group:
        return text, Path(logfile)
    lines = []
    for line in text.splitlines():
        if line.split('#', 1)[0].partition('=')[0].strip().lower() == 'log_group':
            lines.append('log_group = ' + group)
        else:
            lines.append(line)
    if 'log_group' not in values:
        lines.append('log_group = ' + group)
    return '\n'.join(lines) + '\n', Path(logfile)


def grant_log_read_access(logfile, account):
    from ingestion.audit.get import log_inventory

    trusted_directory(logfile.parent)
    for path in logfile.parent.iterdir():
        suffix = path.name[len(logfile.name) + 1:] if path.name.startswith(logfile.name + '.') else ''
        if path != logfile and not (suffix.isascii() and suffix.isdigit()):
            raise ValueError('Audit log directory contains unrelated/compressed files; review access manually.')
    directory = os.open(logfile.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchown(directory, 0, account.pw_gid)
        os.fchmod(directory, 0o750)
    finally:
        os.close(directory)
    for item in log_inventory(logfile):
        descriptor = os.open(item['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (item['device'], item['inode'])):
                raise ValueError('Audit log changed during permission preparation.')
            os.fchown(descriptor, 0, account.pw_gid)
            os.fchmod(descriptor, 0o640)
        finally:
            os.close(descriptor)


def install_audit(project, targets):
    from database.local_identity import atomic_write

    account = pwd.getpwnam('mysql_siem')
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise ValueError('Audit requires the non-root mysql_siem account/group.')
    for executable in ('auditd', 'auditctl', 'ausearch', 'augenrules'):
        if not os.access('/usr/sbin/' + executable, os.X_OK):
            raise ValueError('The distribution auditd package is incomplete.')
    command(['/usr/bin/systemctl', 'is-active', '--quiet', 'auditd.service'])
    source_status(time.monotonic() + 5)
    expected = rule_lines(targets, architectures())
    for target in targets:
        for kind in ('files', 'directories', 'executables'):
            for path in target[kind]:
                mode = Path(path).lstat().st_mode
                valid = stat.S_ISDIR(mode) if kind == 'directories' else stat.S_ISREG(mode)
                if not valid:
                    raise ValueError('Audit target has an unsupported file type.')
    missing = verify_rules(expected, command(['/usr/sbin/auditctl', '-l']))
    write_managed(RULES_FILE, MARKER + '\n'.join(expected) + '\n')
    status_text = command(['/usr/sbin/auditctl', '-s'])
    if re.search(r'^enabled\s+2\s*$', status_text, re.MULTILINE) and missing:
        raise ValueError('Audit is immutable. Persistent rules prepared; approved maintenance/reboot required.')
    original = read_root_text(CONFIG_FILE)
    updated, logfile = audit_configuration(original, account.pw_name)
    if updated != original:
        backup = CONFIG_FILE.with_name('.mysql-siem-auditd.conf.original')
        if not backup.exists() and not backup.is_symlink():
            atomic_write(backup, original, mode=0o600)
        else:
            read_root_text(backup)
        atomic_write(CONFIG_FILE, updated, mode=0o640)
        command(['/usr/sbin/auditctl', '--signal', 'reload'])
    grant_log_read_access(logfile, account)
    for line in missing:
        command(['/usr/sbin/auditctl', *shlex.split(line)])
    if verify_rules(expected, command(['/usr/sbin/auditctl', '-l'])):
        raise ValueError('Audit rules did not become active.')
    command(['/usr/sbin/augenrules', '--check'])
    for name in UNIT_NAMES:
        write_managed(UNIT_DIR / name, read_root_text(project / 'config/systemd' / name))
    # Probe OPEN/READ as the service UID; never display/copy raw log data.
    command(['/usr/sbin/runuser', '-u', account.pw_name, '--', '/usr/bin/head', '-c', '1', str(logfile)])
    digest = hashlib.sha256('\n'.join(expected).encode()).hexdigest()
    manifest = {'version': 1, 'logfile': str(logfile), 'rules_sha256': digest}
    atomic_write(project / 'config/audit-runtime.json', json.dumps(manifest) + '\n',
                 gid=account.pw_gid, mode=0o640)


def main(argv=None):
    import pymysql

    parser = argparse.ArgumentParser(description='Prepare protected Linux Audit integration during installation.')
    parser.add_argument('action', choices=('prepare', 'activate'))
    parser.add_argument('--project', type=Path, required=True)
    args = parser.parse_args(argv)
    connection = None
    try:
        if os.geteuid() != 0:
            raise ValueError('Audit installation requires administrator privileges.')
        trusted_directory(args.project)
        if args.action == 'activate':
            if (installation_state.STATE_DIR / 'maintenance').exists():
                raise ValueError('Audit activation is blocked by installation maintenance.')
            read_root_text(args.project / 'config/audit-runtime.json')
            command(['/usr/bin/systemctl', 'daemon-reload'])
            command(['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer'])
        else:
            installation_state.require_maintenance(installation_state.STATE_DIR)
            from ingestion.audit.database import load_targets

            connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                                         database='mysql_siem', autocommit=False, charset='utf8mb4',
                                         connect_timeout=5, read_timeout=15, write_timeout=15)
            with connection.cursor() as cursor:
                targets = load_targets(cursor)
            install_audit(args.project, targets)
            connection.rollback()
        return 0
    except pymysql.MySQLError:
        print('Audit installation database validation failed; keep maintenance and recovery files.', file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        if args.action == 'activate':
            from database.local_identity import atomic_write

            atomic_write(installation_state.STATE_DIR / 'maintenance', installation_state.MAINTENANCE_TEXT, mode=0o644)
        print('Audit installation stopped: ' + str(error)
              + ' Keep maintenance; review Audit configuration and rerun the same installer operation.', file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
