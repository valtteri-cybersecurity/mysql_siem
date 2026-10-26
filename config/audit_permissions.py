"""Installer-only Audit permission migration; never called by the runtime worker."""

import errno
import fcntl
import grp
import json
import os
import pwd
import re
import signal
import stat
import struct
import tempfile
import time
import uuid
from pathlib import Path

from config import audit_setup as audit
from config import installation_state as state

OWNER = 0
ACCESS = 'system.posix_acl_access'
DEFAULT = 'system.posix_acl_default'
TAGS = {1: 'user:', 2: 'user:', 4: 'group:', 8: 'group:', 16: 'mask:', 32: 'other:'}
BACKUP = 'audit-permissions.json'
PENDING = 'audit-permissions.pending'

READER_PROBE = """import os
import stat
import sys
uid, gid = int(sys.argv[2]), int(sys.argv[3])
groups = list(map(int, sys.argv[6].split(',')))
if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or sorted(os.getgroups()) != sorted(groups):
    raise SystemExit(1)
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (int(sys.argv[4]), int(sys.argv[5])):
        raise SystemExit(1)
    os.read(fd, 1)
finally:
    os.close(fd)
"""


def read_acl(descriptor, *, default=False):
    """Linux POSIX ACL xattrs: version 2, followed by tag/permissions/numeric ID."""
    try:
        raw = os.getxattr(descriptor, DEFAULT if default else ACCESS)
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise
        if default:
            return {}
        mode = os.fstat(descriptor).st_mode
        return {'user:': (mode >> 6) & 7, 'group:': (mode >> 3) & 7,
                'mask:': (mode >> 3) & 7, 'other:': mode & 7}
    if len(raw) < 4 or struct.unpack_from('<I', raw)[0] != 2 or (len(raw) - 4) % 8:
        raise ValueError('Unsupported POSIX ACL encoding.')
    result = {}
    for offset in range(4, len(raw), 8):
        tag, permissions, identifier = struct.unpack_from('<HHI', raw, offset)
        if tag not in TAGS or permissions > 7:
            raise ValueError('Invalid POSIX ACL entry.')
        key = TAGS[tag] + (str(identifier) if tag in (2, 8) else '')
        if key in result or (tag not in (2, 8) and identifier != 0xffffffff):
            raise ValueError('Invalid or duplicate POSIX ACL entry.')
        result[key] = permissions
    if not {'user:', 'group:', 'other:'} <= set(result) or len(result) > 128:
        raise ValueError('Incomplete or oversized POSIX ACL.')
    result.setdefault('mask:', result['group:'])
    return result


def write_acl(descriptor, acl, *, default=False):
    entries = []
    for tag, prefix in ((1, 'user:'), (2, 'user:'), (4, 'group:'), (8, 'group:'), (16, 'mask:'), (32, 'other:')):
        selected = []
        for key in acl:
            qualifier = key[len(prefix):] if key.startswith(prefix) else None
            if qualifier is not None and bool(qualifier) == (tag in (2, 8)):
                identifier = int(qualifier) if qualifier else 0xffffffff
                selected.append((identifier, key))
        for identifier, key in sorted(selected):
            entries.append(struct.pack('<HHI', tag, acl[key], identifier))
    os.setxattr(descriptor, DEFAULT if default else ACCESS, struct.pack('<I', 2) + b''.join(entries))


def effective_acl(acl):
    result = dict(acl)
    for key in result:
        if key not in ('user:', 'other:', 'mask:'):
            result[key] &= acl['mask:']
    return result


def migrated_acl(original, old_gid, account, *, directory=False, owner=6):
    """Keep effective rights, replacing the owning group's implicit grant by ID."""
    result = effective_acl(original)
    if result['other:'] or result['group:'] & 2:
        raise ValueError('World access or non-root Audit writers need separate review.')
    for key, permissions in result.items():
        if key not in ('user:', 'mask:') and permissions & 2:
            raise ValueError('An existing non-root ACL writer needs separate review.')
        if not directory and key != 'user:' and permissions & 1:
            raise ValueError('Executable Audit log ACLs need separate review.')
    if old_gid != account.pw_gid:
        key = 'group:' + str(old_gid)
        result[key] = result.get(key, 0) | result['group:']
    result['user:'] = 7 if directory else owner
    result['group:'] = 5 if directory else 4
    result['mask:'] = result['group:']
    # A named user entry takes precedence over its primary group, including denial.
    user_key = 'user:' + str(account.pw_uid)
    if user_key in result:
        result[user_key] = result['group:']
    return result


def future_acl(original, old_gid, account):
    # auditd creates group-readable files only when log_group is non-root.
    had_default = bool(original)
    old_mask = 4 if old_gid else 0
    if not original:
        original = {'user:': 7, 'group:': old_mask, 'mask:': old_mask, 'other:': 0}
    acl = effective_acl(original)
    for key in acl:
        if key not in ('user:', 'other:', 'mask:'):
            acl[key] &= old_mask
    acl['other:'] = 0
    result = migrated_acl(acl, old_gid, account, directory=True)
    # With no previous readers, auditd's own chown/chmod is sufficient.
    readers = False
    for key, permissions in result.items():
        if key not in ('user:', 'group:', 'mask:', 'other:') and permissions:
            readers = True
    return result if had_default or readers else {}



def future_bridge(original, old_gid, account):
    final = future_acl(original, old_gid, account)
    if not final:
        return {}
    result = dict(final)
    old_permissions = original.get('group:', 4) & original.get('mask:', 4) if old_gid else 0
    result['group:'] = old_permissions & 4
    result['group:' + str(account.pw_gid)] = 4
    return result


def permission_for(acl, uid, groups, owner, gid):
    if uid == owner:
        return acl['user:']
    key = 'user:' + str(uid)
    if key in acl:
        return acl[key] & acl['mask:']
    matched = False
    permissions = 0
    if gid in groups:
        matched = True
        permissions |= acl['group:']
    for group in groups:
        key = 'group:' + str(group)
        if key in acl:
            matched = True
            permissions |= acl[key]
    return permissions & acl['mask:'] if matched else acl['other:']


def configuration_text(original):
    values = audit.parse_audit_configuration(original)
    audit.validate_audit_log_settings(values)
    if values.get('log_group') == 'mysql_siem':
        return original
    lines = original.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if re.match(r'^[ \t]*log_group[ \t]*=', line, re.IGNORECASE):
            lines[index] = re.sub(r'^([ \t]*log_group[ \t]*=[ \t]*)[^ \t#\r\n]+',
                                  r'\g<1>mysql_siem', line, flags=re.IGNORECASE)
            return ''.join(lines)
    return original + ('' if original.endswith('\n') else '\n') + 'log_group = mysql_siem\n'


def account_and_group():
    account = audit._preflight_account()
    group = grp.getgrnam('mysql_siem')
    if set(group.gr_mem) - {account.pw_name}:
        raise ValueError('mysql_siem must be a private group; no membership was changed.')
    for candidate in grp.getgrall():
        if candidate.gr_gid == account.pw_gid and candidate.gr_name != 'mysql_siem':
            raise ValueError('An alias shares the private mysql_siem group ID.')
    for user in pwd.getpwall():
        if user.pw_uid == account.pw_uid and user.pw_name != account.pw_name:
            raise ValueError('Another account shares the mysql_siem UID.')
        if user.pw_uid != account.pw_uid and account.pw_gid in os.getgrouplist(user.pw_name, user.pw_gid):
            raise ValueError('Another account uses the private mysql_siem group.')
    return account


def metadata(descriptor):
    info = os.fstat(descriptor)
    return {'device': info.st_dev, 'inode': info.st_ino, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'access': read_acl(descriptor)}



def check_parents(logfile):
    for directory in reversed(logfile.parent.parents):
        if directory == Path('/var/log'):
            audit.validate_log_parent(directory.lstat(), allow_syslog=logfile.parent == Path('/var/log/audit'))
        else:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
                raise ValueError('Unsafe or linked Audit parent directory.')


def pin_logs(logfile):
    check_parents(logfile)
    audit.inspect_audit_log_directory(logfile)
    descriptors = {}
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptors[str(logfile.parent)] = os.open(logfile.parent, flags | os.O_DIRECTORY)
        directory = descriptors[str(logfile.parent)]
        names = os.listdir(directory)
        if len(names) > 257 or logfile.name not in names:
            raise ValueError('Incomplete or oversized Audit log inventory.')
        for name in sorted(names):
            suffix = name.removeprefix(logfile.name + '.')
            if name != logfile.name and not (name.startswith(logfile.name + '.') and suffix.isascii() and suffix.isdigit()):
                raise ValueError('Unexpected Audit directory entry; no permissions were changed.')
            descriptors[str(logfile.parent / name)] = os.open(name, flags, dir_fd=directory)
        for name, descriptor in descriptors.items():
            info = os.fstat(descriptor)
            directory_entry = name == str(logfile.parent)
            correct_type = stat.S_ISDIR(info.st_mode) if directory_entry else stat.S_ISREG(info.st_mode)
            if (not correct_type or info.st_uid != OWNER or info.st_mode & 0o7022
                    or not directory_entry and (info.st_nlink != 1 or info.st_mode & 0o111)):
                raise ValueError('Unsafe Audit inode, ownership, mode or hard link.')
        verify_inventory(descriptors, logfile)
        return descriptors
    except (OSError, ValueError):
        for descriptor in descriptors.values():
            os.close(descriptor)
        raise


def verify_inventory(descriptors, logfile):
    names = set()
    for name, descriptor in descriptors.items():
        opened = os.fstat(descriptor)
        current = Path(name).lstat()
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('Audit rotation/path changed; retained backup requires review before retry.')
        if name != str(logfile.parent):
            names.add(Path(name).name)
    if set(os.listdir(descriptors[str(logfile.parent)])) != names:
        raise ValueError('Audit inventory changed; collection remains paused for recovery review.')


def plan_permissions(account, original, descriptors, logfile):
    values = audit.parse_audit_configuration(original)
    group = values.get('log_group', 'root')
    old_gid = account.pw_gid if group == 'mysql_siem' else (grp.getgrgid(int(group)).gr_gid if group.isdigit() else grp.getgrnam(group).gr_gid)
    entries = {}
    for name, descriptor in descriptors.items():
        entry = metadata(descriptor)
        directory = name == str(logfile.parent)
        entry['default'] = read_acl(descriptor, default=True) if directory else {}
        owner = 7 if directory else (6 if name == str(logfile) else 4)
        entry['new'] = migrated_acl(entry['access'], entry['gid'], account, directory=directory, owner=owner)
        entry['bridge'] = dict(entry['new'])
        entry['bridge']['group:'] = entry['access']['group:'] & entry['access']['mask:']
        if entry['gid'] != account.pw_gid:
            entry['bridge']['group:' + str(account.pw_gid)] = 5 if directory else 4
        entry['future'] = future_acl(entry['default'], old_gid, account) if directory else {}
        entry['future_bridge'] = future_bridge(entry['default'], old_gid, account) if directory else {}
        entries[name] = entry
    config_fd = os.open(audit.CONFIG_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        config_meta = metadata(config_fd)
        attributes = {}
        for key in os.listxattr(config_fd):
            attributes[key] = os.getxattr(config_fd, key).hex()
    finally:
        os.close(config_fd)
    return {'version': 1, 'phase': 'prepared', 'uid': account.pw_uid, 'gid': account.pw_gid,
            'maintenance_owned': not ((state.STATE_DIR / 'maintenance').exists() or (state.STATE_DIR / 'maintenance').is_symlink()),
            'config': str(audit.CONFIG_FILE), 'config_metadata': config_meta, 'attributes': attributes, 'original': original, 'desired': configuration_text(original),
            'logfile': str(logfile), 'entries': entries}



def validate_record(record, account, logfile, descriptors):
    fields = {'version', 'phase', 'uid', 'gid', 'maintenance_owned', 'config', 'config_metadata', 'attributes',
              'original', 'desired', 'logfile', 'entries'}
    if (not isinstance(record, dict) or set(record) != fields or type(record['version']) is not int
            or record['version'] != 1 or type(record['maintenance_owned']) is not bool or record['phase'] not in ('prepared', 'complete')
            or (record['uid'], record['gid'], record['config'], record['logfile']) != (
                account.pw_uid, account.pw_gid, str(audit.CONFIG_FILE), str(logfile))):
        raise ValueError('Invalid or conflicting Audit permission backup; preserve recovery evidence.')
    if not isinstance(record['original'], str) or configuration_text(record['original']) != record['desired']:
        raise ValueError('Invalid saved Audit configuration transition.')
    if not isinstance(record['entries'], dict) or set(record['entries']) != set(descriptors):
        raise ValueError('Audit rotation inventory changed during migration; recovery review required.')
    metadata_fields = {'device', 'inode', 'gid', 'mode', 'access'}
    config_meta = record['config_metadata']
    if not isinstance(config_meta, dict) or set(config_meta) != metadata_fields:
        raise ValueError('Invalid saved Audit configuration metadata.')
    for key in ('device', 'inode', 'gid', 'mode'):
        if type(config_meta[key]) is not int or config_meta[key] < 0:
            raise ValueError('Invalid saved configuration identity.')
    if not isinstance(record['attributes'], dict):
        raise TypeError('Invalid saved configuration attributes.')
    for key, value in record['attributes'].items():
        if not isinstance(key, str) or not isinstance(value, str) or len(value) > 262144:
            raise ValueError('Invalid saved configuration attribute.')
        bytes.fromhex(value)
    old_group = audit.parse_audit_configuration(record['original']).get('log_group', 'root')
    old_gid = account.pw_gid if old_group == 'mysql_siem' else (
        grp.getgrgid(int(old_group)).gr_gid if old_group.isdigit() else grp.getgrnam(old_group).gr_gid)
    for name, entry in record['entries'].items():
        expected = {'device', 'inode', 'gid', 'mode', 'access', 'default', 'new', 'bridge', 'future', 'future_bridge'}
        if not isinstance(entry, dict) or set(entry) != expected:
            raise ValueError('Invalid saved Audit inode metadata.')
        for key in ('device', 'inode', 'gid', 'mode'):
            if type(entry[key]) is not int or entry[key] < 0:
                raise ValueError('Invalid saved Audit inode identity.')
        for key in ('access', 'default', 'new', 'bridge', 'future', 'future_bridge'):
            acl = entry[key]
            if not isinstance(acl, dict) or len(acl) > 128:
                raise ValueError('Invalid saved ACL.')
            for field, value in acl.items():
                if (not re.fullmatch(r'(?:user|group):[0-9]*|mask:|other:', field)
                        or type(value) is not int or not 0 <= value <= 7):
                    raise ValueError('Invalid saved ACL entry.')
            if acl and not {'user:', 'group:', 'mask:', 'other:'} <= set(acl):
                raise ValueError('Incomplete saved ACL.')
        directory = name == str(logfile.parent)
        owner = 7 if directory else (6 if name == str(logfile) else 4)
        wanted = migrated_acl(entry['access'], entry['gid'], account, directory=directory, owner=owner)
        bridge = dict(wanted)
        bridge['group:'] = entry['access']['group:'] & entry['access']['mask:']
        if entry['gid'] != account.pw_gid:
            bridge['group:' + str(account.pw_gid)] = 5 if directory else 4
        future = future_acl(entry['default'], old_gid, account) if directory else {}
        transitional = future_bridge(entry['default'], old_gid, account) if directory else {}
        if (entry['new'], entry['bridge'], entry['future'], entry['future_bridge']) != (wanted, bridge, future, transitional):
            raise ValueError('Saved Audit ACL plan conflicts with its original reader policy.')


def verify_entry(descriptor, entry, gid, *, final=False):
    info = os.fstat(descriptor)
    if info.st_uid != OWNER or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1) or info.st_mode & 0o7022:
        raise ValueError('Audit inode became unsafe during preparation.')
    actual = metadata(descriptor)
    if (actual['device'], actual['inode']) != (entry['device'], entry['inode']):
        raise ValueError('Audit inode changed; refusing to restore or overwrite permissions.')
    allowed = (entry['new'],) if final else (entry['access'], entry['bridge'], entry['new'])
    if stat.S_ISDIR(info.st_mode) and read_acl(descriptor, default=True) not in (entry['default'], entry['future_bridge'], entry['future']):
        raise ValueError('Concurrent default ACL change; no overwrite allowed.')
    if actual['access'] not in allowed or actual['gid'] not in ((gid,) if final else (entry['gid'], gid)):
        raise ValueError('Concurrent Audit permission change; preserve the recovery backup.')


def probe_readers(entries, logfile, account):
    """Verify known local readers; group-ID ACL preservation also covers NSS readers."""
    directory = entries[str(logfile.parent)]
    readers = []
    for user in pwd.getpwall():
        if user.pw_uid in (OWNER, account.pw_uid):
            continue
        groups = os.getgrouplist(user.pw_name, user.pw_gid)
        for name, entry in entries.items():
            if name == str(logfile.parent):
                continue
            traverse = permission_for(directory['access'], user.pw_uid, groups, OWNER, directory['gid']) & 1
            readable = permission_for(entry['access'], user.pw_uid, groups, OWNER, entry['gid']) & 4
            if traverse and readable:
                readers.append((user, groups, name))
    if len(readers) > 2048:
        raise ValueError('Too many reader probes; reviewed migration required.')
    for user, groups, name in readers:
        entry = entries[name]
        audit.command(['/usr/bin/setpriv', '--reuid=' + str(user.pw_uid), '--regid=' + str(user.pw_gid),
                       '--groups=' + ','.join(str(group) for group in groups), '--', '/usr/bin/python3', '-I', '-B',
                       '-c', READER_PROBE, name, str(user.pw_uid), str(user.pw_gid),
                       str(entry['device']), str(entry['inode']), ','.join(str(group) for group in groups)])
    return len(readers)


def replace_configuration(record):
    path = Path(record['config'])
    current = audit.read_root_text(path)
    if current not in (record['original'], record['desired']):
        raise ValueError('auditd.conf changed concurrently; backup retained, no overwrite allowed.')
    if current == record['desired']:
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    temporary = None
    try:
        info = os.fstat(descriptor)
        current_meta = metadata(descriptor)
        if current_meta != record['config_metadata']:
            raise ValueError('Audit configuration metadata changed before replacement.')
        attributes = record['attributes']
        output, filename = tempfile.mkstemp(prefix='.mysql-siem-audit-', dir=path.parent)
        temporary = Path(filename)
        try:
            os.fchown(output, info.st_uid, info.st_gid)
            for name, value in attributes.items():
                os.setxattr(output, name, bytes.fromhex(value))
            os.fchmod(output, stat.S_IMODE(info.st_mode))
            with os.fdopen(os.dup(output), 'wb') as stream:
                stream.write(record['desired'].encode())
                stream.flush()
            os.fsync(output)
        finally:
            os.close(output)
        if audit.read_root_text(path) != current or path.lstat().st_ino != info.st_ino:
            raise ValueError('auditd.conf changed before atomic replacement.')
        os.replace(temporary, path)
        state.sync_directory(path.parent)
    finally:
        os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)



def verify_configuration(record):
    path = Path(record['config'])
    if audit.read_root_text(path) != record['desired']:
        raise ValueError('Audit configuration changed; collection remains paused.')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        current = metadata(descriptor)
        for key in ('gid', 'mode', 'access'):
            if current[key] != record['config_metadata'][key]:
                raise ValueError('Audit configuration permissions changed concurrently.')
        attributes = {}
        for key in os.listxattr(descriptor):
            attributes[key] = os.getxattr(descriptor, key).hex()
        if attributes != record['attributes']:
            raise ValueError('Audit configuration attributes changed concurrently.')
    finally:
        os.close(descriptor)


def reload_auditd(descriptor):
    health = audit.source_status(time.monotonic() + 5)
    pid = health['daemon_pid']
    position = os.fstat(descriptor).st_size
    process = os.pidfd_open(pid)
    try:
        running = os.stat('/proc/' + str(pid) + '/exe')
        expected = os.stat('/usr/sbin/auditd')
        if (running.st_dev, running.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError('Kernel Audit PID does not refer to the installed auditd executable.')
        signal.pidfd_send_signal(process, signal.SIGHUP)
        deadline = time.monotonic() + 15
        content = b''
        while time.monotonic() < deadline:
            chunk = os.pread(descriptor, 65536, position)
            position += len(chunk)
            content += chunk
            if len(content) > 4 * 1024 * 1024:
                raise ValueError('Audit reload acknowledgement exceeded its read budget.')
            for line in content.splitlines():
                if (b'type=DAEMON_CONFIG ' in line and b'op=reconfigure state=changed ' in line
                        and (' pid=' + str(os.getpid()) + ' ').encode() in line and b'res=success' in line):
                    verified = audit.source_status(time.monotonic() + 5)
                    if verified['daemon_pid'] != pid:
                        raise ValueError('auditd restarted during reload verification.')
                    return
            time.sleep(0.05)
        raise ValueError('auditd did not acknowledge configuration reload; backup and collection barrier retained.')
    finally:
        os.close(process)


def runtime_lock(directory):
    path = directory / 'runtime.lock'
    marker = directory / 'maintenance'
    if marker.exists() or marker.is_symlink():
        if state.read_file(marker, public=True) != state.MAINTENANCE_TEXT:
            raise ValueError('Unrecognized maintenance marker; no changes allowed.')
        if not path.exists():
            raise ValueError('Maintenance runtime lock is missing; manual recovery review required.')
        try:
            state.require_lock(path, 8)
        except state.InstallationStateError:
            pass  # A standalone retry may safely acquire the lock itself below.
        else:
            return os.dup(8)
    if not path.exists() and not path.is_symlink():
        state.write_file(path, '', mode=0o644)
    state.read_file(path, public=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('Collectors did not stop; Audit permissions were not changed.') from None
                time.sleep(0.05)
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def prepare_permissions(project, operation, *, confirm=input):
    if os.geteuid() != OWNER:
        raise PermissionError('Audit permission preparation requires the installer administrator.')
    state.require_install_lock()
    audit.trusted_directory(state.STATE_DIR)
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('Audit preparation requires Linux pidfd signal support.')
    account = account_and_group()
    deployment = state.read_deployment(state.STATE_DIR)
    if (deployment is None or deployment['phase'] != 'staged' or deployment['stage'] != str(project)
            or deployment['user'] != account.pw_name):
        raise ValueError('Audit permission preparation requires the protected installer staging journal.')
    audit.trusted_directory(project)
    original = audit.read_root_text(audit.CONFIG_FILE, maximum=128 * 1024)
    values = audit.parse_audit_configuration(original)
    logfile = audit.audit_logfile(values)
    descriptors = pin_logs(logfile)
    locked = None
    backup = state.STATE_DIR / BACKUP
    pending = state.STATE_DIR / PENDING
    try:
        record = plan_permissions(account, original, descriptors, logfile)
        previous = json.loads(state.read_file(backup)) if backup.exists() or backup.is_symlink() else None
        if (pending.exists() or pending.is_symlink()) and previous is None:
            raise ValueError('Audit permission backup is missing; preserve the pending marker and request recovery review.')
        if previous is not None:
            if not isinstance(previous, dict):
                raise ValueError('Invalid Audit permission backup; no overwrite allowed.')
            inventory = descriptors if previous.get('phase') != 'complete' or pending.exists() else previous.get('entries', {})
            validate_record(previous, account, logfile, inventory)
        resume = previous is not None and (previous.get('phase') != 'complete' or pending.exists())
        if resume:
            if (previous.get('version'), previous.get('uid'), previous.get('gid'), previous.get('logfile'), previous.get('config')) != (
                    1, account.pw_uid, account.pw_gid, str(logfile), str(audit.CONFIG_FILE)):
                raise ValueError('Audit permission recovery belongs to another configuration; preserve backup.')
            if set(previous.get('entries', {})) != set(descriptors):
                raise ValueError('Audit rotation inventory changed during migration; recovery review required.')
            record = previous
        results = audit.audit_preflight(operation=operation, project=project)
        for status, name, _detail in results:
            if status != 'PASS' and name not in ('audit log reader group', 'audit log directory'):
                audit.print_audit_preflight(results)
                raise ValueError('Audit safety preflight failed before permission changes.')
        changed = record['original'] != record['desired']
        for name, entry in record['entries'].items():
            verify_entry(descriptors[name], entry, account.pw_gid)
            if entry['gid'] != account.pw_gid or entry['access'] != entry['new']:
                changed = True
            if name == str(logfile.parent) and entry['default'] != entry['future']:
                changed = True
        if not changed and not pending.exists() and not pending.is_symlink() and previous is not None:
            if not audit.print_audit_preflight(results):
                raise ValueError('Audit environment is not ready.')
            return False
        if not resume:
            print('Audit preparation will update log_group, per-inode permissions and existing reader ACLs. '
                  'A private backup is retained; database RESET is a separate approval.')
            if confirm('Type AUDIT to approve these Audit system changes: ') != 'AUDIT':
                raise ValueError('Audit changes declined; no Audit configuration or permissions were changed.')
        probe_readers(record['entries'], logfile, account)
        locked = runtime_lock(state.STATE_DIR)
        verify_inventory(descriptors, logfile)
        for name, entry in record['entries'].items():
            verify_entry(descriptors[name], entry, account.pw_gid)
        if not resume:
            if previous is not None:
                archive = state.STATE_DIR / ('audit-permissions-backup-' + uuid.uuid4().hex + '.json')
                state.write_file(archive, state.read_file(backup))
            state.write_file(backup, json.dumps(record, sort_keys=True) + '\n')
        state.write_file(pending, 'Audit permission preparation is incomplete.\n', mode=0o644)
        if record['maintenance_owned']:
            state.write_file(state.STATE_DIR / 'maintenance', state.MAINTENANCE_TEXT, mode=0o644)
        for name, entry in record['entries'].items():
            descriptor = descriptors[name]
            verify_inventory(descriptors, logfile)
            verify_entry(descriptor, entry, account.pw_gid)
            if read_acl(descriptor) != entry['bridge']:
                write_acl(descriptor, entry['bridge'])
            if os.fstat(descriptor).st_gid != account.pw_gid:
                os.fchown(descriptor, OWNER, account.pw_gid)
            if read_acl(descriptor) != entry['new']:
                write_acl(descriptor, entry['new'])
            os.fsync(descriptor)
        directory = descriptors[str(logfile.parent)]
        transitional = record['entries'][str(logfile.parent)]['future_bridge']
        if transitional and read_acl(directory, default=True) != transitional:
            write_acl(directory, transitional, default=True)
            os.fsync(directory)
        replace_configuration(record)
        verify_configuration(record)
        reload_auditd(descriptors[str(logfile)])
        directory = descriptors[str(logfile.parent)]
        wanted = record['entries'][str(logfile.parent)]['future']
        if wanted and read_acl(directory, default=True) != wanted:
            write_acl(directory, wanted, default=True)
            os.fsync(directory)
        verify_inventory(descriptors, logfile)
        for name, entry in record['entries'].items():
            verify_entry(descriptors[name], entry, account.pw_gid, final=True)
        probe_readers(record['entries'], logfile, account)
        verify_configuration(record)
        current_account = account_and_group()
        if (current_account.pw_uid, current_account.pw_gid) != (account.pw_uid, account.pw_gid):
            raise ValueError('Audit service account changed during preparation.')
        if not audit.print_audit_preflight(audit.audit_preflight(operation=operation, project=project)):
            raise ValueError('Audit postflight failed; backup and collection barrier retained.')
        if read_acl(directory, default=True) != wanted:
            raise ValueError('Default Audit ACL did not reach the verified future-reader policy.')
        record['phase'] = 'complete'
        state.write_file(backup, json.dumps(record, sort_keys=True) + '\n')
        # Old installed wrappers know the maintenance marker, not our new marker.
        # Remove our marker only after durable, verified completion, under the lock.
        if record['maintenance_owned']:
            (state.STATE_DIR / 'maintenance').unlink()
            state.sync_directory(state.STATE_DIR)
        pending.unlink()
        state.sync_directory(state.STATE_DIR)
        return True
    finally:
        if locked is not None:
            os.close(locked)
        for descriptor in descriptors.values():
            os.close(descriptor)
