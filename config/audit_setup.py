
import argparse
import grp
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
from config.service_installation import trusted_directory, validate_log_parent
from ingestion.audit.get import source_status
from ingestion.audit.targets import DEFAULT_TARGETS, validate_targets

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

        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > maximum
        ):
            raise ValueError('Unsafe Audit installation file.')

        raw = os.read(descriptor, maximum + 1)

        if len(raw) > maximum:
            raise ValueError('Audit installation file is too large.')

        return raw.decode('utf-8')

    finally:
        os.close(descriptor)


def managed_file_text(path):
    """Check an installation destination without changing it."""
    trusted_directory(path.parent)
    if path.exists() or path.is_symlink():
        previous = read_root_text(path)
        if not previous.startswith(MARKER):
            raise ValueError(
                'Audit installation filename belongs to another administrator/program.'
            )
        return previous
    return None


def write_managed(path, content, *, gid=0):
    """Do not replace another program's file."""
    from database.local_identity import atomic_write

    if managed_file_text(path) == content:
        return False
    atomic_write(path, content, gid=gid, mode=0o640)
    return True


def command(arguments):
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
        env=dict(
            os.environ,
            PATH='/usr/sbin:/usr/bin:/sbin:/bin',
            LC_ALL='C',
        ),
    )

    if result.returncode != 0:
        raise RuntimeError(
            'Audit installation command failed: ' + arguments[0]
        )

    return result.stdout


def architectures(machine=None, kernel_config=None):
    machine = platform.machine() if machine is None else machine

    if machine in ('i386', 'i486', 'i586', 'i686', 'armv7l'):
        return ['b32']

    if machine not in ('x86_64', 'aarch64'):
        raise ValueError(
            'Audit rules require a reviewed syscall architecture for this platform.'
        )

    if kernel_config is None:
        kernel_config = read_root_text(
            Path('/boot/config-' + platform.release())
        )

    option = (
        'CONFIG_IA32_EMULATION'
        if machine == 'x86_64'
        else 'CONFIG_COMPAT'
    )

    if option + '=y' in kernel_config.splitlines():
        return ['b64', 'b32']

    if '# ' + option + ' is not set' in kernel_config.splitlines():
        return ['b64']

    raise ValueError(
        'Cannot determine kernel compatibility ABI support; '
        'review boot kernel configuration.'
    )


def inspect_audit_target(path, *, kind, optional=False):
    """Inspect a target without creating it or following the final symlink."""
    if kind not in ('files', 'directories', 'executables'):
        raise ValueError('Unknown Audit target kind.')

    path = Path(path)

    try:
        mode = path.lstat().st_mode

    except FileNotFoundError as error:
        if not optional:
            raise ValueError(
                'Required Audit target is missing: ' + str(path)
            ) from error

        return 'NOT_INSTALLED'

    except OSError as error:
        raise ValueError(
            'Cannot inspect Audit target: ' + str(path)
        ) from error

    valid = (
        stat.S_ISDIR(mode)
        if kind == 'directories'
        else stat.S_ISREG(mode)
    )

    if not valid:
        raise ValueError(
            'Audit target has an unsupported file type: ' + str(path)
        )

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
                    path,
                    kind=kind,
                    optional=path not in REQUIRED_TARGET_PATHS,
                )

                if path in statuses and statuses[path] != status:
                    raise ValueError(
                        'Audit target has inconsistent types: ' + path
                    )

                statuses[path] = status

                if status == 'PRESENT':
                    present.add(path)

    return present, statuses


def rule_lines(targets, arches, *, present_paths=None):
    validate_targets(targets)

    if not arches or any(
        arch not in ('b64', 'b32')
        for arch in arches
    ):
        raise ValueError('Invalid Audit rule architecture.')

    lines = []

    for target in targets:
        for arch in arches:
            for kind, field in (
                ('files', 'path'),
                ('directories', 'dir'),
                ('executables', 'exe'),
            ):
                for path in target[kind]:
                    if (
                        present_paths is not None
                        and path not in present_paths
                    ):
                        continue

                    syscall_filter = (
                        ' -S all'
                        if kind == 'executables'
                        else ''
                    )

                    lines.append(
                        f'-a always,exit -F arch={arch}{syscall_filter} '
                        f'-F {field}={path} -F perm=wa -k '
                        + target['audit_key']
                    )

    return lines


def rule_signature(line):
    tokens = shlex.split(line)
    fields = {}
    index = 0

    while index < len(tokens):
        option = tokens[index]

        if (
            option not in ('-a', '-F', '-k', '-S')
            or index + 1 >= len(tokens)
        ):
            raise ValueError(
                'Unsupported rule using a mysql_siem Audit key.'
            )

        value = tokens[index + 1]

        if option == '-a':
            fields['action'] = ','.join(sorted(value.split(',')))

        elif option == '-k':
            fields['key'] = value

        elif option == '-S':
            if value != 'all':
                raise ValueError(
                    'Unexpected syscall list using a mysql_siem Audit key.'
                )

        else:
            name, separator, setting = value.partition('=')

            if not separator or name in fields:
                raise ValueError(
                    'Unsupported or repeated Audit rule field.'
                )

            fields[name] = (
                ''.join(sorted(setting))
                if name == 'perm'
                else setting
            )

        index += 2

    return fields



def validate_exclude_rule(tokens):
    """Allow exclusions only when they cannot hide required record types."""
    exclude = False
    for index, token in enumerate(tokens[:-1]):
        if token in ('-a', '-A') and 'exclude' in tokens[index + 1].split(','):
            exclude = True
    if not exclude:
        return
    fields = []
    for index, token in enumerate(tokens[:-1]):
        if token == '-F' and tokens[index + 1].startswith('msgtype'):
            match = re.fullmatch(r'msgtype(!=|=)([A-Z_]+|[0-9]+)', tokens[index + 1])
            if match is None:
                raise ValueError('Unreviewed Audit msgtype exclusion; administrator review required.')
            value = match[2]
            if value.isdigit():
                value = str(int(value))
            fields.append((match[1], value))
    # Linux UAPI audit.h: these are the records consumed by our parser.
    for name, number in (('SYSCALL', '1300'), ('PATH', '1302'), ('CWD', '1307')):
        may_match = True
        for operator, value in fields:
            same = value in (name, number)
            if operator == '=' and not same or operator == '!=' and same:
                may_match = False
        if may_match:
            raise ValueError('An Audit exclude rule may suppress required ' + name
                             + ' records; administrator review required.')


def verify_rules(expected, output, *, owned_keys=()):
    wanted = [rule_signature(line) for line in expected]
    keys = {rule['key'] for rule in wanted} | set(owned_keys)
    found = []

    for line in output.splitlines():
        if line.strip() in ('', 'No rules'):
            continue

        if re.search(
            r'-a (?:never,(?:task|exit)|(?:task|exit),never)(?:\s|$)',
            line,
        ):
            raise ValueError(
                'A never/task or never/exit rule may suppress '
                'Audit events; administrator review required.'
            )

        tokens = shlex.split(line)
        validate_exclude_rule(tokens)
        owned = False

        for key in keys:
            if key in tokens or 'key=' + key in tokens:
                owned = True

        if owned:
            signature = rule_signature(line)

            if signature not in wanted:
                raise ValueError(
                    'An existing rule conflicts with a mysql_siem Audit key.'
                )

            found.append(signature)

    return [
        line
        for line, signature in zip(expected, wanted)
        if signature not in found
    ]


def audit_rule_plan(targets, arches=None):
    """Read and validate the same rule plan used before and after DB setup."""
    if arches is None:
        arches = architectures()
    present, statuses = inspect_audit_targets(targets)
    expected = rule_lines(targets, arches, present_paths=present)
    keys = set()
    for target in targets:
        keys.add(target['audit_key'])
    missing = verify_rules(expected, command(['/usr/sbin/auditctl', '-l']), owned_keys=keys)
    status = command(['/usr/sbin/auditctl', '-s'])
    enabled = re.search(r'^enabled\s+([012])\s*$', status, re.MULTILINE)
    if enabled is None or enabled[1] == '0':
        raise ValueError('Cannot establish an enabled Audit kernel; rules not ready.')
    if enabled[1] == '2' and missing:
        raise ValueError('Audit is immutable and required rules are missing. Administrator rule '
                         'provisioning and an approved reboot are required before database setup.')
    return expected, missing, statuses


def preflight_targets(operation):
    """Predict targets for this operation using only SELECTs on an existing DB."""
    defaults = []
    for target in DEFAULT_TARGETS:
        defaults.append(dict(target, audit_key='siem_' + target['name']))
    if operation == 'reset':
        return validate_targets(defaults)
    if operation != 'upgrade':
        raise ValueError('Unknown Audit preflight operation.')

    import pymysql

    connection = None
    try:
        connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                                     database='mysql_siem', autocommit=True, charset='utf8mb4',
                                     connect_timeout=5, read_timeout=15, write_timeout=15)
        with connection.cursor() as cursor:
            cursor.execute('SELECT table_name FROM information_schema.tables '
                           "WHERE table_schema = DATABASE() AND table_name IN ('audit_targets', 'schema_migrations')")
            tables = set()
            for row in cursor.fetchall():
                tables.add(row[0])
            applied = False
            if 'schema_migrations' in tables:
                cursor.execute("SELECT status FROM schema_migrations WHERE version = '020'")
                row = cursor.fetchone()
                if row is not None and row[0] not in ('APPLIED', 'RUNNING', 'FAILED'):
                    raise ValueError('Unknown Audit migration state; target scope is not verified.')
                applied = row == ('APPLIED',)
            if 'audit_targets' not in tables:
                if applied:
                    raise ValueError('Audit migration 020 is applied but audit_targets is missing.')
                return validate_targets(defaults)
            cursor.execute('SELECT target_name, audit_key, definition, enabled FROM audit_targets ORDER BY target_name')
            rows = cursor.fetchall()
        targets = []
        names = set()
        keys = set()
        for name, key, raw, enabled in rows:
            names.add(name)
            keys.add(key)
            if enabled not in (0, 1):
                raise ValueError('Invalid Audit target enabled status.')
            if enabled:
                definition = json.loads(raw)
                if not isinstance(definition, dict) or set(definition) != {'files', 'directories', 'executables'}:
                    raise ValueError('Invalid stored Audit target definition.')
                targets.append(dict(definition, name=name, audit_key=key))
        if not applied:
            # Migration 020 inserts defaults, preserving existing names/unique keys
            # and disabled rows. Model only that existing seeding behavior.
            for target in defaults:
                if target['name'] not in names and target['audit_key'] not in keys:
                    targets.append(target)
        return validate_targets(targets)
    except pymysql.MySQLError:
        raise ValueError('Cannot read existing Audit targets for upgrade; preflight is not ready. '
                         'No database or rules were changed.') from None
    finally:
        if connection is not None:
            connection.close()


def preflight_rules(targets, arches):
    expected, missing, statuses = audit_rule_plan(targets, arches)
    absent = []
    for path, status in statuses.items():
        if status == 'NOT_INSTALLED':
            absent.append(path)
    detail = f'{len(expected)} expected rules; {len(missing)} missing'
    if missing:
        detail += ' (kernel is mutable; activation still required during preparation)'
    if absent:
        detail += '; optional paths not watched: ' + ', '.join(sorted(absent))
    return detail


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
            raise ValueError(
                'Duplicate or invalid auditd configuration; review manually.'
            )

        values[key] = value.strip()

    return values


def validate_audit_log_settings(values):
    if (
        values.get('write_logs', 'yes').lower() != 'yes'
        or values.get('local_events', 'yes').lower() != 'yes'
        or values.get('log_format', 'raw').lower()
        not in ('raw', 'enriched')
    ):
        raise ValueError(
            'Audit requires local RAW/ENRICHED disk logging.'
        )


def validate_audit_log_group(values, group):
    """Require the private reader group; never rewrite auditd.conf."""
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        raise ValueError('Audit reader group is missing: ' + group) from None
    if gid == 0 or values.get('log_group', 'root') not in (group, str(gid)):
        raise ValueError('Audit requires log_group=mysql_siem. Review docs/audit-permissions.md; '
                         'existing adm readers and permissions were not changed.')


def audit_logfile(values):
    logfile = values.get(
        'log_file',
        '/var/log/audit/audit.log',
    )

    if (
        not re.fullmatch(
            r'/var/log/[a-zA-Z0-9_./+-]+',
            logfile,
        )
        or Path(logfile).parent == Path('/var/log')
        or str(Path(logfile)) != logfile
        or '..' in Path(logfile).parts
    ):
        raise ValueError(
            'Audit log requires a dedicated canonical directory under /var/log.'
        )

    return Path(logfile)


def audit_configuration(text, group):
    """Validate and preserve the existing auditd configuration."""
    values = parse_audit_configuration(text)

    validate_audit_log_settings(values)
    validate_audit_log_group(values, group)

    return text, audit_logfile(values)


def inspect_audit_log_directory(logfile):
    """Validate Audit log directories without changing permissions."""
    logfile = Path(logfile)
    directory = logfile.parent

    # Ordinary installation directories retain the strict policy.
    # Only /var/log has the narrowly defined syslog exception.
    trusted_directory(Path('/var'))

    validate_log_parent(
        Path('/var/log').lstat(),
        allow_syslog=directory == Path('/var/log/audit'),
    )

    info = directory.lstat()

    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        raise ValueError(
            'Audit log directory is not a trusted root-owned directory.'
        )

    logfile_info = logfile.lstat()

    if (
        not stat.S_ISREG(logfile_info.st_mode)
        or logfile_info.st_uid != 0
        or logfile_info.st_nlink != 1
    ):
        raise ValueError(
            'Audit log must be a root-owned regular file with one link.'
        )

    for path in directory.iterdir():
        suffix = (
            path.name[len(logfile.name) + 1:]
            if path.name.startswith(logfile.name + '.')
            else ''
        )

        if path != logfile and not (
            suffix.isascii() and suffix.isdigit()
        ):
            raise ValueError(
                'Audit log directory contains unrelated/compressed files; '
                'review access manually.'
            )

    return f'{directory} (root owned; no unrelated files)'


def preflight_audit_units(project):
    """Read the shipped units and their destinations; never publish them here."""
    directory = Path(project) / 'config/systemd'
    trusted_directory(directory)
    for name in UNIT_NAMES:
        content = read_root_text(directory / name)
        if not content.startswith(MARKER):
            raise ValueError('Shipped Audit unit lacks its management marker: ' + name)
        managed_file_text(UNIT_DIR / name)
    return 'Both Audit units have safe sources and managed destinations'


def audit_preflight(operation='upgrade', project=None):
    """Inspect prerequisites without changing the system."""
    results = []
    if project is None:
        project = Path(__file__).resolve().parents[1]

    def record(name, action):
        try:
            detail = action()

        except PermissionError as error:
            results.append((
                'UNKNOWN',
                name,
                f'access denied: {error}',
            ))
            return None

        except (
            OSError,
            ValueError,
            RuntimeError,
            subprocess.SubprocessError,
            KeyError,
        ) as error:
            results.append(('FAIL', name, str(error)))
            return None

        results.append(('PASS', name, str(detail)))
        return detail

    account = record(
        'service account',
        _preflight_account,
    )

    record(
        'auditd executables',
        _preflight_executables,
    )

    record(
        'auditd service',
        _preflight_auditd_active,
    )

    arches = record('kernel ABI configuration', architectures)

    record(
        'kernel Audit status',
        _preflight_kernel_audit_status,
    )

    record('persistent Audit rules destination',
           lambda: 'managed file' if managed_file_text(RULES_FILE) is not None else 'safe directory; file absent')

    record('Audit systemd files', lambda: preflight_audit_units(project))

    targets = record('Audit target definitions (' + operation + ')', lambda: preflight_targets(operation))
    if targets is None or arches is None:
        results.append(('UNKNOWN', 'Audit watch rules', 'target definitions or kernel ABI could not be verified'))
    else:
        record('Audit watch rules', lambda: preflight_rules(targets, arches))

    text = record(
        'auditd.conf integrity',
        lambda: read_root_text(CONFIG_FILE),
    )

    if text is None:
        for name in (
            'audit log settings',
            'audit log reader group',
            'audit log path',
            'audit log directory',
        ):
            results.append((
                'UNKNOWN',
                name,
                'auditd.conf cannot be inspected',
            ))

        return results

    values = record(
        'auditd.conf syntax',
        lambda: parse_audit_configuration(text),
    )

    if values is None:
        for name in (
            'audit log settings',
            'audit log reader group',
            'audit log path',
            'audit log directory',
        ):
            results.append((
                'UNKNOWN',
                name,
                'auditd.conf syntax invalid',
            ))

        return results

    record(
        'audit log settings',
        lambda: _preflight_logging(values),
    )

    if account is None:
        results.append((
            'UNKNOWN',
            'audit log reader group',
            'service account unavailable',
        ))
    else:
        record(
            'audit log reader group',
            lambda: _preflight_reader_group(
                values,
                account.pw_name,
            ),
        )

    logfile = record(
        'audit log path',
        lambda: audit_logfile(values),
    )

    if logfile is None or account is None:
        results.append((
            'UNKNOWN',
            'audit log directory',
            'log path or reader account unavailable',
        ))
    else:
        record(
            'audit log directory',
            lambda: check_audit_log_access(logfile, account),
        )

    return results


def _preflight_account():
    try:
        account = pwd.getpwnam('mysql_siem')
        group = grp.getgrnam('mysql_siem')
    except KeyError:
        raise ValueError('Audit requires the mysql_siem account and private group.') from None
    if account.pw_uid == 0 or group.gr_gid == 0 or account.pw_gid != group.gr_gid:
        raise ValueError('Audit requires a non-root account with primary group mysql_siem.')
    return account


def _preflight_executables():
    absent = [
        name
        for name in (
            'auditd',
            'auditctl',
            'ausearch',
            'augenrules',
        )
        if not os.access('/usr/sbin/' + name, os.X_OK)
    ]

    if absent:
        raise ValueError(
            'auditd executables missing or not executable: '
            + ', '.join(absent)
        )

    return 'auditd, auditctl, ausearch, augenrules'


def _preflight_auditd_active():
    command([
        '/usr/bin/systemctl',
        'is-active',
        '--quiet',
        'auditd.service',
    ])

    return 'auditd.service active'


def _preflight_kernel_audit_status():
    # Use the installer's existing full health check: auditd PID, enabled kernel,
    # lost records and backlog. This only reads status and the boot ID.
    source_status(time.monotonic() + 5)
    return 'Audit enabled, auditd running, no reported loss or queued records'


def _preflight_logging(values):
    validate_audit_log_settings(values)

    return 'local disk logging, RAW/ENRICHED'


def _preflight_reader_group(values, group):
    validate_audit_log_group(values, group)
    if not os.access('/usr/bin/setpriv', os.X_OK):
        raise ValueError('Audit read verification requires /usr/bin/setpriv.')
    return 'auditd log_group=mysql_siem; no supplementary groups required'


def print_audit_preflight(results, *, stream=None):
    if stream is None:
        stream = sys.stdout

    print(
        'mysql_siem Audit environment preflight (read-only)',
        file=stream,
    )

    for status, name, detail in results:
        if (
            name == 'auditd.conf integrity'
            and status == 'PASS'
        ):
            detail = (
                str(CONFIG_FILE)
                + ' (safe root-owned file)'
            )

        if (
            name == 'auditd.conf syntax'
            and status == 'PASS'
        ):
            detail = 'valid configuration entries'

        if (
            name == 'service account'
            and status == 'PASS'
        ):
            detail = 'non-root mysql_siem account'

        print(
            f'[{status}] {name}: {detail}',
            file=stream,
        )

    ok = bool(results) and all(
        status == 'PASS'
        for status, _, _ in results
    )

    print(
        'Audit environment: '
        + ('READY FOR PREPARATION' if ok else 'NOT READY'),
        file=stream,
    )

    return ok


# This small program runs AFTER setpriv has dropped every root ID and group.
# It opens the same inode independently; it never inherits a root-opened log FD.
READ_PROBE = """import os
import stat
import sys
uid = int(sys.argv[2])
gid = int(sys.argv[3])
device = int(sys.argv[4])
inode = int(sys.argv[5])
if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or os.getgroups():
    raise SystemExit(1)
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
        raise SystemExit(1)
    os.read(fd, 1)
finally:
    os.close(fd)
"""


def validate_audit_log_permissions(info, gid, *, directory=False):
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    modes = (0o750,) if directory else (0o640, 0o440)
    if (not valid_type or info.st_uid != 0 or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) not in modes or (not directory and info.st_nlink != 1)):
        raise ValueError('Audit requires root:mysql_siem, directory 0750 and logs 0640/0440. '
                         'Check old rotations separately; no permissions were changed.')


def audit_group_files(logfile, account, *, read=False):
    """Validate every retained log, optionally reading as the already dropped UID."""
    from ingestion.audit.get import log_inventory, open_log_source

    if read and (os.getresuid() != (account.pw_uid,) * 3
                 or os.getresgid() != (account.pw_gid,) * 3 or os.getgroups()):
        raise ValueError('Audit log reads require permanently dropped IDs and no supplementary groups.')
    inspect_audit_log_directory(logfile)
    logfile = Path(logfile)
    descriptor = os.open(logfile.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        validate_audit_log_permissions(info, account.pw_gid, directory=True)
        named = logfile.parent.lstat()
        if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError('Audit log directory changed during validation; retry.')
        inventory = log_inventory(logfile)
        for item in inventory:
            with open_log_source(item) as source:
                validate_audit_log_permissions(os.fstat(source.fileno()), account.pw_gid)
                if read:
                    source.read(1)
        current = logfile.parent.lstat()
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('Audit log directory changed during validation; retry.')
        return inventory
    finally:
        os.close(descriptor)


def check_audit_log_access(logfile, account):
    """Read-only preflight: prove actual access without root or adm groups."""
    if os.geteuid() != 0:
        raise PermissionError('Run the Audit preflight as root to verify a complete privilege drop.')
    inventory = audit_group_files(logfile, account)
    for item in inventory:
        arguments = ['/usr/bin/setpriv', f'--reuid={account.pw_uid}', f'--regid={account.pw_gid}',
                     '--clear-groups', '--', '/usr/bin/python3', '-I', '-B', '-c', READ_PROBE,
                     str(item['path']), str(account.pw_uid), str(account.pw_gid),
                     str(item['device']), str(item['inode'])]
        try:
            command(arguments)
        except RuntimeError:
            raise ValueError('mysql_siem cannot read Audit log without supplementary groups: '
                             + str(item['path']) + '. No permissions were changed.') from None
    return f'{len(inventory)} Audit logs readable with primary group mysql_siem only'


def install_audit(project, targets):
    from database.local_identity import atomic_write

    account = _preflight_account()

    for executable in (
        'auditd',
        'auditctl',
        'ausearch',
        'augenrules',
    ):
        if not os.access(
            '/usr/sbin/' + executable,
            os.X_OK,
        ):
            raise ValueError(
                'The distribution auditd package is incomplete.'
            )

    command([
        '/usr/bin/systemctl',
        'is-active',
        '--quiet',
        'auditd.service',
    ])

    source_status(time.monotonic() + 5)

    expected, missing, target_statuses = audit_rule_plan(targets)

    for path, status in sorted(target_statuses.items()):
        if status == 'NOT_INSTALLED':
            print(
                'Audit target NOT_INSTALLED (rule omitted): ' + path,
                file=sys.stderr,
            )

    original = read_root_text(CONFIG_FILE)

    unchanged, logfile = audit_configuration(
        original,
        account.pw_name,
    )

    if unchanged != original:
        raise ValueError(
            'Audit configuration must remain unchanged.'
        )

    check_audit_log_access(logfile, account)

    write_managed(
        RULES_FILE,
        MARKER + '\n'.join(expected) + '\n',
    )

    for line in missing:
        command([
            '/usr/sbin/auditctl',
            *shlex.split(line),
        ])

    owned_keys = set()
    for target in targets:
        owned_keys.add(target['audit_key'])
    if verify_rules(
        expected,
        command(['/usr/sbin/auditctl', '-l']),
        owned_keys=owned_keys,
    ):
        raise ValueError(
            'Audit rules did not become active.'
        )

    command([
        '/usr/sbin/augenrules',
        '--check',
    ])

    for name in UNIT_NAMES:
        write_managed(
            UNIT_DIR / name,
            read_root_text(
                project / 'config/systemd' / name
            ),
        )

    digest = hashlib.sha256(
        '\n'.join(expected).encode()
    ).hexdigest()

    manifest = {
        'version': 1,
        'logfile': str(logfile),
        'rules_sha256': digest,
        'target_statuses': dict(
            sorted(target_statuses.items())
        ),
    }

    atomic_write(
        project / 'config/audit-runtime.json',
        json.dumps(manifest) + '\n',
        gid=account.pw_gid,
        mode=0o640,
    )



def verify_audit_units(project):
    """Read back the protected files and their loaded systemd definitions."""
    from config.audit_launcher import validate_manifest

    validate_manifest(json.loads(read_root_text(project / 'config/audit-runtime.json')))
    for name in UNIT_NAMES:
        if managed_file_text(UNIT_DIR / name) != read_root_text(project / 'config/systemd' / name):
            raise ValueError('Installed Audit unit differs from the published service copy.')
        output = command(['/usr/bin/systemctl', 'show', '--all',
                          '--property=LoadState,FragmentPath,DropInPaths', name])
        properties = {}
        for line in output.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key in properties:
                raise ValueError('Cannot verify the loaded Audit unit.')
            properties[key] = value
        if properties != {'LoadState': 'loaded', 'FragmentPath': str(UNIT_DIR / name), 'DropInPaths': ''}:
            raise ValueError('Audit unit is not loaded from the managed file or has unreviewed overrides.')


def verify_audit_activation(project):
    """Verify loaded units and persistent timer activation before release."""
    verify_audit_units(project)
    if command(['/usr/bin/systemctl', 'is-enabled', 'mysql-siem-audit.timer']).strip() != 'enabled':
        raise ValueError('Audit timer must be persistently enabled.')
    command(['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql-siem-audit.timer'])


def activate_audit(project):
    """Activate only the journaled publication while all collectors stay paused."""
    from config.audit_launcher import validate_manifest
    from config.service_installation import verify_publication

    installation_state.require_maintenance(installation_state.STATE_DIR)
    record = installation_state.read_deployment(installation_state.STATE_DIR)
    if record is None or record['target'] != str(project):
        raise ValueError('Audit activation requires the journaled published installation.')
    verify_publication(installation_state.STATE_DIR, record)
    validate_manifest(json.loads(read_root_text(project / 'config/audit-runtime.json')))
    # Check disk files before reloading, then loaded definitions before starting.
    for name in UNIT_NAMES:
        if managed_file_text(UNIT_DIR / name) != read_root_text(project / 'config/systemd' / name):
            raise ValueError('Installed Audit unit differs from the published service copy.')
    command(['/usr/bin/systemctl', 'daemon-reload'])
    verify_audit_units(project)
    command(['/usr/bin/systemctl', 'enable', '--now', 'mysql-siem-audit.timer'])
    verify_audit_activation(project)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Prepare protected Linux Audit integration during installation.'
    )

    parser.add_argument(
        'action',
        choices=('check', 'prepare', 'activate'),
    )

    parser.add_argument('--operation', choices=('reset', 'upgrade'), default='upgrade',
                        help='Target scope for the read-only check; defaults to an existing installation.')

    parser.add_argument(
        '--project',
        type=Path,
    )

    args = parser.parse_args(argv)

    if args.action == 'check':
        return (
            0
            if print_audit_preflight(audit_preflight(operation=args.operation, project=args.project))
            else 1
        )

    if args.project is None:
        parser.error(
            '--project is required for prepare and activate'
        )

    import pymysql

    connection = None

    try:
        if os.geteuid() != 0:
            raise ValueError(
                'Audit installation requires administrator privileges.'
            )

        trusted_directory(args.project)

        if args.action == 'activate':
            activate_audit(args.project)

        else:
            if not print_audit_preflight(
                audit_preflight(operation='upgrade', project=args.project)
            ):
                raise ValueError(
                    'Audit environment preflight failed; '
                    'no Audit installation changes were made.'
                )

            installation_state.require_maintenance(
                installation_state.STATE_DIR
            )

            from ingestion.audit.database import load_targets

            connection = pymysql.connect(
                unix_socket='/run/mysqld/mysqld.sock',
                user='root',
                database='mysql_siem',
                autocommit=False,
                charset='utf8mb4',
                connect_timeout=5,
                read_timeout=15,
                write_timeout=15,
            )

            with connection.cursor() as cursor:
                targets = load_targets(cursor)

            install_audit(
                args.project,
                targets,
            )

            connection.rollback()

        return 0

    except pymysql.MySQLError:
        print(
            'Audit installation database validation failed; '
            'keep maintenance and recovery files.',
            file=sys.stderr,
        )
        return 1

    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:

        print(
            'Audit installation stopped: ' + str(error)
            + ' Keep maintenance; review Audit configuration '
            'and rerun the same installer operation.',
            file=sys.stderr,
        )

        return 1

    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())

