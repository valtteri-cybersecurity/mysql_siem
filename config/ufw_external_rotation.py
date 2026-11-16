"""Read-only checks for supported external, uncompressed UFW rotation policies."""

import fnmatch
import grp
import os
import pwd
import re
import shlex
import stat
import subprocess
from pathlib import Path

from config.service_installation import trusted_directory
from ingestion.ufw_validation import convert_timestamp

LOGROTATE_DEFAULTS = Path('/etc/logrotate.conf')
UFW_RULE = Path('/etc/rsyslog.d/20-ufw.conf')
LOG = Path('/var/log/ufw.log')
POSTROTATE = Path('/usr/lib/rsyslog/rsyslog-rotate')
READER = 'mysql_siem'
RSYSLOG_RULE = ':msg,contains,"[UFW " /var/log/ufw.log'
SCRIPTS = ('firstaction', 'lastaction', 'prerotate', 'postrotate', 'preremove')
MAX_ROTATIONS = 255  # The collector can verify at most 256 plain files including the active log.
FREQUENCIES = ('hourly', 'daily', 'weekly', 'monthly', 'yearly')
SAFE_SU = ('su root adm', 'su root syslog')


def supports_external_policy(lines, postrotate):
    if lines[:2] != ['/var/log/ufw.log', '{'] or lines[-4:] != ['postrotate', postrotate, 'endscript', '}']:
        return False
    required = {'missingok', 'notifempty', 'nocompress', 'sharedscripts', 'rotate', 'frequency'}
    seen = set()
    for option in lines[2:-4]:
        kind = option
        if option in FREQUENCIES:
            kind = 'frequency'
        elif re.fullmatch(r'rotate [1-9][0-9]{0,2}', option):
            if not 2 <= int(option.split()[1]) <= MAX_ROTATIONS:
                return False
            kind = 'rotate'
        elif option in SAFE_SU:
            kind = 'su'
        elif option in ('create', 'create 0640 syslog adm'):
            kind = 'create'
        elif option not in ('missingok', 'notifempty', 'nocompress', 'sharedscripts'):
            return False
        if kind in seen:
            return False
        seen.add(kind)
    return required <= seen


def effective_lines(text):
    lines = []
    if text is not None:
        for character in ('\r', '\x00', '\v', '\f'):
            if character in text:
                raise RuntimeError('Unverified control character in external UFW configuration.')
        for raw in text.split('\n'):
            line = raw.strip(' \t')
            if line and not line.startswith('#'):
                lines.append(line)
    return lines


def check_sibling(text, name, logfile):
    """Require other drop-ins to contain only scoped stanzas."""
    if text is None:
        raise RuntimeError(f'Logrotate drop-in disappeared: {name}.')
    header = []
    inside = script = False
    protected = [str(logfile)]
    for number in range(1, MAX_ROTATIONS + 1):
        rotation = str(logfile) + '.' + str(number)
        protected.extend((rotation, rotation + '.gz'))
    for line in effective_lines(text):
        if script:
            if line == 'endscript':
                script = False
            continue
        if inside:
            if line in SCRIPTS:
                script = True
            elif line == '}':
                inside = False
            elif '{' in line or '}' in line or re.match(r'include(?:[ \t=]|$)', line):
                raise RuntimeError(f'Unverified logrotate stanza in {name}.')
            continue
        paths, brace, rest = line.partition('{')
        for pattern in shlex.split(paths, comments=False):
            if not pattern.startswith('/') or '..' in Path(pattern).parts:
                raise RuntimeError(f'Unverified logrotate defaults in {name}; external UFW rotation was refused.')
            pattern = os.path.normpath(pattern)
            for target in protected:
                if fnmatch.fnmatchcase(target, pattern):
                    raise RuntimeError(f'Conflicting UFW logrotate stanza in {name}.')
            header.append(pattern)
        if brace:
            if not header or rest.strip():
                raise RuntimeError(f'Unverified logrotate stanza in {name}.')
            inside = True
            header.clear()
    if header or inside:
        raise RuntimeError(f'Incomplete logrotate stanza in {name}.')


def check_external_source(config, read_config):
    defaults = read_config(LOGROTATE_DEFAULTS)
    lines = []
    for line in effective_lines(defaults[0]):
        lines.append(re.sub(r'[ \t]+', ' ', line))
    include = 'include ' + str(config.parent)
    if not lines or lines.pop() != include or 'create' not in lines:
        raise RuntimeError('Unverified global logrotate settings for external UFW rotation.')
    seen = set()
    for option in lines:
        kind = option
        if option in FREQUENCIES:
            kind = 'frequency'
        elif re.fullmatch(r'rotate [0-9]{1,9}', option):
            kind = 'rotate'
        elif option in SAFE_SU:
            kind = 'su'
        elif option in ('compress', 'nocompress'):
            kind = 'compression'
        elif option != 'create':
            raise RuntimeError('Unverified global logrotate settings for external UFW rotation.')
        if kind in seen:
            raise RuntimeError('Conflicting global logrotate settings for external UFW rotation.')
        seen.add(kind)
    drop_ins = []
    entries = sorted(config.parent.iterdir())
    if len(entries) > 128:
        raise RuntimeError('Too many logrotate drop-ins to verify external UFW rotation.')
    for entry in entries:
        if entry == config or entry.name.startswith('.'):
            continue
        sibling = read_config(entry)
        check_sibling(sibling[0], entry.name, LOG)
        drop_ins.append((entry.name, sibling))
    rule = read_config(UFW_RULE)
    rule_lines = effective_lines(rule[0])
    if not rule_lines or not re.fullmatch(r':msg,contains,"\[UFW "[ \t]+/var/log/ufw\.log', rule_lines[0]):
        raise RuntimeError('Unverified rsyslog UFW rule; check the configured log destination and format.')
    if len(rule_lines) != 1 and (len(rule_lines) != 2 or not re.fullmatch(r'&[ \t]+stop', rule_lines[1])):
        raise RuntimeError('Unverified additional rsyslog UFW directives.')
    helper = read_config(POSTROTATE)
    if helper[0] is None or not helper[1] & 0o100:
        raise RuntimeError('Unsafe rsyslog rotation helper.')
    check_logs(LOG)
    return defaults, drop_ins, rule, helper


def check_logs(logfile):
    owners = {os.geteuid()}
    writer_groups = {0}
    try:
        writer = pwd.getpwnam('syslog')
    except KeyError:
        pass
    else:
        owners.add(writer.pw_uid)
        writer_groups.add(writer.pw_gid)
    reader_groups = writer_groups | {grp.getgrnam('adm').gr_gid}
    trusted_directory(logfile.parent.parent)
    parent = logfile.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o7002
            or parent.st_mode & 0o020 and parent.st_gid not in writer_groups):
        raise RuntimeError('Unsafe external UFW log directory.')
    files = [logfile]
    for path in logfile.parent.glob(logfile.name + '.*'):
        suffix = path.name[len(logfile.name) + 1:]
        if not suffix.isascii() or not suffix.isdigit():
            continue
        number = int(suffix)
        if not 1 <= number <= MAX_ROTATIONS or suffix != str(number):
            raise RuntimeError('Unexpected numbered rotation for external UFW; check the retained logs.')
        files.append(path)
    for path in files:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in owners
                    or info.st_gid not in reader_groups or info.st_mode & 0o7022):
                raise RuntimeError('Unsafe external UFW log ownership or permissions.')
            check_timestamp_sample(fd, info.st_size)
        finally:
            os.close(fd)
    try:
        subprocess.run(['/usr/sbin/runuser', '-u', READER, '--', '/usr/bin/head', '-c', '0', '--', *files],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
    except subprocess.SubprocessError:
        raise RuntimeError('The mysql_siem service account could not verify read access to external UFW logs.') from None


def check_timestamp_sample(fd, size):
    offset = max(0, size - 65536)
    lines = os.pread(fd, size - offset, offset).split(b'\n')
    if offset:
        lines = lines[1:]
    checked = False
    for line in lines[:-1]:
        if not line.strip():
            continue
        if b'[UFW ' not in line:
            raise RuntimeError('Unexpected records in the configured UFW log.')
        try:
            convert_timestamp(line.split(None, 1)[0].decode('ascii'))
        except ValueError:
            raise RuntimeError('External UFW log does not use timestamps with a verified UTC offset.') from None
        checked = True
    if offset and not checked:
        raise RuntimeError('External UFW timestamp sample contains no complete records.')
