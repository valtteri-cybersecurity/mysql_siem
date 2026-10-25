
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
REQUIRED_TARGET_PATHS = frozenset(('/etc/passwd', '/etc/shadow', '/etc/group'))


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


def command(arguments, *, pass_fds=()):
    # Fixed executables; no argument originates in an audit record.
    result = subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=15,
                            env=dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C'),
                            pass_fds=pass_fds)
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


def inspect_audit_target(path, *, kind, optional=False):
    """Inspect a target without creating it or following the final symlink."""
    if kind not in ('files', 'directories', 'executables'):
        raise ValueError('Unknown Audit target kind.')
    path = Path(path)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        if not optional:
            raise ValueError('Required Audit target is missing: ' + str(path)) from error
        return 'NOT_INSTALLED'
    except OSError as error:
        raise ValueError('Cannot inspect Audit target: ' + str(path)) from error
    valid = stat.S_ISDIR(mode) if kind == 'directories' else stat.S_ISREG(mode)
    if not valid:
        raise ValueError('Audit target has an unsupported file type: ' + str(path))
    return 'PRESENT'


def inspect_audit_targets(targets):
    """Return present paths and explicit presence states for configured targets."""
    validate_targets(targets)
    statuses = {}
    present = set()
    for target in targets:
        for kind in ('files', 'directories', 'executables'):
            for path in target[kind]:
                status = inspect_audit_target(
                    path, kind=kind, optional=path not in REQUIRED_TARGET_PATHS,
                )
                if path in statuses and statuses[path] != status:
                    raise ValueError('Audit target has inconsistent types: ' + path)
                statuses[path] = status
                if status == 'PRESENT':
                    present.add(path)
    return present, statuses


def rule_lines(targets, arches, *, present_paths=None):
    validate_targets(targets)
    if not arches or any(arch not in ('b64', 'b32') for arch in arches):
        raise ValueError('Invalid Audit rule architecture.')
    lines = []
    for target in targets:
        for arch in arches:
            for kind, field in (('files', 'path'), ('directories', 'dir'), ('executables', 'exe')):
                for path in target[kind]:
                    if present_paths is not None and path not in present_paths:
                        continue
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


def verify_rules(expected, output, *, owned_keys=()):
    wanted = [rule_signature(line) for line in expected]
    keys = {rule['key'] for rule in wanted} | set(owned_keys)
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


def parse_audit_configuration(text):
    """Validate syntax and duplicates without changing auditd configuration."""
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
    return values


def validate_audit_log_settings(values):
    if (values.get('write_logs', 'yes').lower() != 'yes'
            or values.get('local_events', 'yes').lower() != 'yes'
            or values.get('log_format', 'raw').lower() not in ('raw', 'enriched')):
        raise ValueError('Audit requires local RAW/ENRICHED disk logging.')


def validate_audit_log_group(values, group):
    """Allow the supported local groups without changing auditd.conf."""
    if values.get('log_group', 'root') not in ('root', '0', 'adm', group):
        raise ValueError('Unknown Audit log reader group; review permissions manually.')


def audit_logfile(values):
    logfile = values.get('log_file', '/var/log/audit/audit.log')
    if (not re.fullmatch(r'/var/log/[a-zA-Z0-9_./+-]+', logfile)
            or Path(logfile).parent == Path('/var/log') or str(Path(logfile)) != logfile
            or '..' in Path(logfile).parts):
        raise ValueError('Audit log requires a dedicated canonical directory under /var/log.')
    return Path(logfile)


def audit_configuration(text, group):
    """Validate and preserve auditd.conf, including its current log_group."""
    values = parse_audit_configuration(text)
    validate_audit_log_settings(values)
    validate_audit_log_group(values, group)
    return text, audit_logfile(values)


def inspect_audit_log_directory(logfile):
    """Read-only check of the prerequisites grant_log_read_access expects."""
    directory = logfile.parent
    info = directory.lstat()  # Does not follow a symlink at the final component.
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise ValueError('Audit log directory is not a trusted root-owned directory.')
    logfile_info = logfile.lstat()
    if (not stat.S_ISREG(logfile_info.st_mode) or logfile_info.st_uid != 0
            or logfile_info.st_nlink != 1):
        raise ValueError('Audit log must be a root-owned regular file with one link.')
    for path in directory.iterdir():
        suffix = path.name[len(logfile.name) + 1:] if path.name.startswith(logfile.name + '.') else ''
        if path != logfile and not (suffix.isascii() and suffix.isdigit()):
            raise ValueError('Audit log directory contains unrelated/compressed files; review access manually.')
    return f'{directory} (root owned; no unrelated files)'


def audit_preflight():
    """Inspect prerequisites. No write, chmod, service change or installation.

    FAIL: prerequisite does not meet the installer's requirements.
    UNKNOWN: observation blocked, e.g. non-root access to protected config.
    """
    results = []

    def record(name, action):
        try:
            detail = action()
        except PermissionError as error:
            results.append(('UNKNOWN', name, f'access denied: {error}'))
            return None
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
                KeyError) as error:
            results.append(('FAIL', name, str(error)))
            return None
        results.append(('PASS', name, str(detail)))
        return detail

    account = record('service account', _preflight_account)
    record('auditd executables', _preflight_executables)
    record('auditd service', _preflight_auditd_active)
    record('kernel ABI configuration', lambda: ', '.join(architectures()))
    record('kernel Audit status', _preflight_kernel_audit_status)

    text = record('auditd.conf integrity', lambda: read_root_text(CONFIG_FILE))
    if text is None:
        for name in ('audit log settings', 'audit log reader group',
                     'audit log path', 'audit log directory'):
            results.append(('UNKNOWN', name, 'auditd.conf cannot be inspected'))
        return results

    values = record('auditd.conf syntax', lambda: parse_audit_configuration(text))
    if values is None:
        for name in ('audit log settings', 'audit log reader group',
                     'audit log path', 'audit log directory'):
            results.append(('UNKNOWN', name, 'auditd.conf syntax invalid'))
        return results

    record('audit log settings', lambda: _preflight_logging(values))
    if account is None:
        results.append(('UNKNOWN', 'audit log reader group', 'service account unavailable'))
    else:
        record('audit log reader group',
               lambda: _preflight_reader_group(values, account.pw_name))
    logfile = record('audit log path', lambda: audit_logfile(values))
    if logfile is None:
        results.append(('UNKNOWN', 'audit log directory', 'log path invalid'))
    else:
        record('audit log directory', lambda: inspect_audit_log_directory(logfile))
    return results


def _preflight_account():
    account = pwd.getpwnam('mysql_siem')
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise ValueError('Audit requires a non-root mysql_siem account/group.')
    return account


def _preflight_executables():
    absent = [name for name in ('auditd', 'auditctl', 'ausearch', 'augenrules')
              if not os.access('/usr/sbin/' + name, os.X_OK)]
    if absent:
        raise ValueError('auditd executables missing or not executable: ' + ', '.join(absent))
    return 'auditd, auditctl, ausearch, augenrules'


def _preflight_auditd_active():
    command(['/usr/bin/systemctl', 'is-active', '--quiet', 'auditd.service'])
    return 'auditd.service active'


def _preflight_kernel_audit_status():
    output = command(['/usr/sbin/auditctl', '-s'])
    match = re.search(r'^enabled\s+([012])\s*$', output, re.MULTILINE)
    if not match:
        raise ValueError('Cannot establish Linux Audit enabled status.')
    if match.group(1) == '0':
        raise ValueError('Linux Audit is disabled in the kernel.')
    return ('Linux Audit active (immutable mode)' if match.group(1) == '2'
            else 'Linux Audit active')


def _preflight_logging(values):
    validate_audit_log_settings(values)
    return 'local disk logging, RAW/ENRICHED'


def _preflight_reader_group(values, group):
    validate_audit_log_group(values, group)
    for executable in ('setfacl', 'setpriv'):
        if not os.access('/usr/bin/' + executable, os.X_OK):
            raise ValueError('Audit ACL tool is missing: ' + executable)
    return f'current log_group={values.get("log_group", "root")}; ACL reader={group}'


def print_audit_preflight(results, *, stream=None):
    if stream is None:
        stream = sys.stdout
    print('mysql_siem Audit environment preflight (read-only)', file=stream)
    for status, name, detail in results:
        if name == 'auditd.conf integrity' and status == 'PASS':
            detail = str(CONFIG_FILE) + ' (safe root-owned file)'
        if name == 'auditd.conf syntax' and status == 'PASS':
            detail = 'valid configuration entries'
        if name == 'service account' and status == 'PASS':
            detail = 'non-root mysql_siem account'
        print(f'[{status}] {name}: {detail}', file=stream)
    ok = bool(results) and all(status == 'PASS' for status, _, _ in results)
    print('Audit environment: ' + ('READY' if ok else 'NOT READY'), file=stream)
    return ok


def set_audit_acl(descriptor, user_id, permissions, *, default=False):
    """Change only mysql_siem's ACL entry on a safely opened object."""
    arguments = ['/usr/bin/setfacl']
    if default:
        arguments.append('-d')
    arguments.extend(['-m', f'u:{user_id}:{permissions}', '--',
                      f'/proc/self/fd/{descriptor}'])
    command(arguments, pass_fds=(descriptor,))


def grant_log_read_access(logfile, account):
    """Preserve root:adm; give the service UID only the needed ACL access."""
    from ingestion.audit.get import log_inventory

    trusted_directory(logfile.parent)
    inventory = log_inventory(logfile)
    if not inventory:
        raise ValueError('Audit log inventory is empty.')
    for path in logfile.parent.iterdir():
        suffix = path.name[len(logfile.name) + 1:] if path.name.startswith(logfile.name + '.') else ''
        if path != logfile and not (suffix.isascii() and suffix.isdigit()):
            raise ValueError('Audit log directory contains unrelated/compressed files; review access manually.')

    directory = os.open(logfile.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Audit log directory changed or has unsafe permissions.')
        set_audit_acl(directory, account.pw_uid, 'r-x')
        set_audit_acl(directory, account.pw_uid, 'r-x', default=True)
    finally:
        os.close(directory)

    for item in inventory:
        descriptor = os.open(item['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or info.st_mode & 0o022
                    or (info.st_dev, info.st_ino) != (item['device'], item['inode'])):
                raise ValueError('Audit log changed during permission preparation.')
            set_audit_acl(descriptor, account.pw_uid, 'r--')
        finally:
            os.close(descriptor)

    # Verify access without the supplementary adm group.
    command(['/usr/bin/setpriv', f'--reuid={account.pw_uid}',
             f'--regid={account.pw_gid}', '--clear-groups', '--',
             '/usr/bin/head', '-c', '1', str(logfile)])


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
    present_paths, target_statuses = inspect_audit_targets(targets)
    expected = rule_lines(targets, architectures(), present_paths=present_paths)
    owned_keys = {target['audit_key'] for target in targets}
    for path, status in sorted(target_statuses.items()):
        if status == 'NOT_INSTALLED':
            print('Audit target NOT_INSTALLED (rule omitted): ' + path, file=sys.stderr)
    missing = verify_rules(expected, command(['/usr/sbin/auditctl', '-l']), owned_keys=owned_keys)
    write_managed(RULES_FILE, MARKER + '\n'.join(expected) + '\n')
    status_text = command(['/usr/sbin/auditctl', '-s'])
    if re.search(r'^enabled\s+2\s*$', status_text, re.MULTILINE) and missing:
        raise ValueError('Audit is immutable. Persistent rules prepared; approved maintenance/reboot required.')
    original = read_root_text(CONFIG_FILE)
    unchanged, logfile = audit_configuration(original, account.pw_name)
    if unchanged != original:
        raise ValueError('Audit configuration must remain unchanged.')
    grant_log_read_access(logfile, account)
    for line in missing:
        command(['/usr/sbin/auditctl', *shlex.split(line)])
    if verify_rules(expected, command(['/usr/sbin/auditctl', '-l']), owned_keys=owned_keys):
        raise ValueError('Audit rules did not become active.')
    command(['/usr/sbin/augenrules', '--check'])
    for name in UNIT_NAMES:
        write_managed(UNIT_DIR / name, read_root_text(project / 'config/systemd' / name))
    digest = hashlib.sha256('\n'.join(expected).encode()).hexdigest()
    manifest = {'version': 1, 'logfile': str(logfile), 'rules_sha256': digest,
                'target_statuses': dict(sorted(target_statuses.items()))}
    atomic_write(project / 'config/audit-runtime.json', json.dumps(manifest) + '\n',
                 gid=account.pw_gid, mode=0o640)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Prepare protected Linux Audit integration during installation.')
    parser.add_argument('action', choices=('check', 'prepare', 'activate'))
    parser.add_argument('--project', type=Path)
    args = parser.parse_args(argv)

    if args.action == 'check':
        return 0 if print_audit_preflight(audit_preflight()) else 1

    if args.project is None:
        parser.error('--project is required for prepare and activate')

    import pymysql

    connection = None
    try:
        if os.geteuid() != 0:
            raise ValueError('Audit installation requires administrator privileges.')
        trusted_directory(args.project)
        if args.action == 'activate':
            from config.audit_launcher import validate_manifest

            if (installation_state.STATE_DIR / 'maintenance').exists():
                raise ValueError('Audit activation is blocked by installation maintenance.')
            manifest = json.loads(read_root_text(args.project / 'config/audit-runtime.json'))
            validate_manifest(manifest)
            command(['/usr/bin/systemctl', 'daemon-reload'])
            command(['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer'])
        else:
            if not print_audit_preflight(audit_preflight()):
                raise ValueError('Audit environment preflight failed; no Audit installation changes were made.')
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
        if args.action == 'activate' and os.geteuid() == 0:
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
