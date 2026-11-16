"""Journaled installation of the managed UFW compression command; no log rotation."""
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from config import installation_state as journal
from config.service_installation import trusted_directory
from config.ufw_external_rotation import check_external_source, supports_external_policy

CONFIG = Path('/etc/logrotate.d/ufw')
RECEIPT = 'ufw-rotation.json'
MAX_CONFIG = 65536
MANAGED_GZIP = 'managed gzip'
EXTERNAL_PLAIN = 'external uncompressed'
STOCK = '''/var/log/ufw.log
{
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -x /usr/lib/rsyslog/rsyslog-rotate ] && /usr/lib/rsyslog/rsyslog-rotate || true
    endscript
}
'''
COMPRESSOR_OPTIONS = (
    'compresscmd /usr/local/lib/mysql_siem/config/ufw-compress.sh',
    'compressoptions -6',
    'compressext .gz',
    'uncompresscmd /usr/bin/gunzip',
)
CUSTOM = ('Custom UFW logrotate configuration was preserved. Compare /etc/logrotate.d/ufw with the packaged ufw '
          'configuration and review the differences before retrying. Keep any custom file and recovery receipt.')


def configuration_lines(text):
    """Recognize one packaged stanza without joining directives or script lines."""
    for character in ('\r', '\x00', '\v', '\f'):
        if character in text:
            raise RuntimeError(CUSTOM)
    lines = []
    in_script = False
    compress_line = None
    for index, line in enumerate(text.split('\n')):
        content = line.strip(' \t')
        if not content or content.startswith('#'):
            continue
        if not in_script:
            content = re.sub(r'[ \t]+', ' ', content)
            if content == 'compress':
                compress_line = index
            if content == 'postrotate':
                in_script = True
        elif content == 'endscript':
            in_script = False
        if not lines and content == '/var/log/ufw.log {':
            lines.extend(('/var/log/ufw.log', '{'))
        else:
            lines.append(content)
    return lines, compress_line


def add_compressor(text):
    lines, index = configuration_lines(text)
    if lines != STOCK_LINES:
        raise RuntimeError(CUSTOM)
    original = text.split('\n')
    line = original[index]
    indent = line[:len(line) - len(line.lstrip(' \t'))]
    additions = []
    for option in COMPRESSOR_OPTIONS:
        additions.append(indent + option)
    original[index + 1:index + 1] = additions
    result = '\n'.join(original)
    if len(result.encode()) > MAX_CONFIG:
        raise RuntimeError('Managed UFW logrotate configuration exceeds its limit.')
    return result


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


STOCK_LINES, _ = configuration_lines(STOCK)
MANAGED = add_compressor(STOCK)
MANAGED_LINES, _ = configuration_lines(MANAGED)
# The original receipt format used this fixed digest regardless of the original formatting.
LEGACY_MANAGED_SHA = '526f5b69351a9db656f4d4ffdcb173db1a156bed4c6c09d2f2fe96cde71a6c15'


def read_config(path):
    trusted_directory(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, None, None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o7022:
            raise RuntimeError('Unsafe UFW logrotate configuration.')
        raw = os.read(descriptor, MAX_CONFIG + 1)
        if len(raw) > MAX_CONFIG:
            raise RuntimeError('UFW logrotate configuration exceeds its limit.')
        after = os.fstat(descriptor)
        named = path.lstat()
        if (len(raw) != info.st_size or info.st_ctime_ns != after.st_ctime_ns
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError('UFW logrotate configuration changed while being read.')
        return raw.decode('utf-8'), stat.S_IMODE(info.st_mode), info.st_gid
    finally:
        os.close(descriptor)


def check(path=CONFIG, *, state=None):
    current = read_config(path)
    saved = None
    if state is not None:
        saved = receipt(state)
    mode, _managed = rotation_plan(current, saved)
    return fingerprint(current, saved, source_snapshot(mode, path))


def write_config(path, text, mode, gid, previous):
    trusted_directory(path.parent)
    descriptor, name = tempfile.mkstemp(prefix='.ufw-config-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w') as output:
            os.fchown(output.fileno(), os.geteuid(), gid)
            os.fchmod(output.fileno(), mode)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        if read_config(path) != previous:
            raise RuntimeError('UFW configuration changed before publication; the changes were preserved.')
        os.replace(temporary, path)
        journal.sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def receipt(state):
    journal.trusted_state(state)
    path = state / RECEIPT
    if not path.exists() and not path.is_symlink():
        return None
    record = json.loads(journal.read_file(path))
    fields = {'original', 'mode', 'gid', 'managed_sha', 'phase'}
    if not isinstance(record, dict) or set(record) not in (fields, fields | {'version'}):
        raise RuntimeError('Invalid UFW rotation recovery receipt; configuration was preserved.')
    if 'version' in record and (type(record['version']) is not int or record['version'] != 2):
        raise RuntimeError('Unsupported UFW rotation recovery receipt version.')
    if record['phase'] not in ('pending', 'committed', 'restored'):
        raise RuntimeError('Invalid UFW rotation recovery receipt phase.')
    if record['original'] is not None and not isinstance(record['original'], str):
        raise RuntimeError('Invalid original UFW configuration.')
    if record['original'] is not None:
        mode = record['mode']
        gid = record['gid']
        if type(mode) is not int or not 0 <= mode <= 0o777 or mode & 0o022:
            raise RuntimeError('Invalid original UFW configuration permissions.')
        if type(gid) is not int or not 0 <= gid < 0xFFFFFFFF:
            raise RuntimeError('Invalid original UFW configuration group.')
    elif record['mode'] is not None or record['gid'] is not None:
        raise RuntimeError('Invalid absent UFW configuration metadata.')
    if record['original'] is not None and configuration_lines(record['original'])[0] != STOCK_LINES:
        raise RuntimeError('Unverified original UFW rotation configuration; files were preserved.')
    expected = LEGACY_MANAGED_SHA
    if 'version' in record:
        expected = digest(managed_config(record)[0])
    if record['managed_sha'] != expected:
        raise RuntimeError('Invalid UFW rotation recovery receipt digest; files were preserved.')
    return record


def original_config(saved):
    return saved['original'], saved['mode'], saved['gid']


def managed_config(saved):
    if 'version' not in saved or saved['original'] is None:
        return MANAGED, 0o644, os.getegid()
    return add_compressor(saved['original']), saved['mode'], saved['gid']


def fingerprint(current, saved, source):
    return digest(json.dumps([current, saved, source], sort_keys=True))


def source_snapshot(mode, path):
    if mode == EXTERNAL_PLAIN:
        return check_external_source(path, read_config)
    return None


def rotation_plan(current, saved):
    if saved is not None and saved['phase'] == 'pending':
        managed = managed_config(saved)
        if current == managed or current == original_config(saved):
            return MANAGED_GZIP, managed
        raise RuntimeError('UFW configuration changed during interrupted installation; files were preserved.')
    text, mode, gid = current
    if text is None:
        return MANAGED_GZIP, (MANAGED, 0o644, os.getegid())
    lines, _ = configuration_lines(text)
    if supports_external_policy(lines, STOCK_LINES[-3]):
        return EXTERNAL_PLAIN, None
    if lines == MANAGED_LINES:
        if saved is None or saved['phase'] != 'committed':
            raise RuntimeError('Managed UFW configuration has no matching committed receipt; preserve the file and review recovery.')
        return MANAGED_GZIP, None
    return MANAGED_GZIP, (add_compressor(text), mode, gid)


def apply(state, path=CONFIG, *, expected=None):
    current = read_config(path)
    saved = receipt(state)
    # Preserve the preflight drift diagnostic before classifying an edited stanza.
    source = None
    if current[0] is not None:
        lines, _ = configuration_lines(current[0])
        if supports_external_policy(lines, STOCK_LINES[-3]):
            source = source_snapshot(EXTERNAL_PLAIN, path)
    if expected is not None and fingerprint(current, saved, source) != expected:
        raise RuntimeError('UFW configuration or recovery receipt changed after preflight; files were preserved.')
    _mode, managed = rotation_plan(current, saved)
    if managed is None:
        return False
    if current == managed:
        return True
    if saved is None or saved['phase'] != 'pending':
        text, mode, gid = current
        saved = {'version': 2, 'original': text, 'mode': mode, 'gid': gid, 'phase': 'pending',
                 'managed_sha': digest(managed[0])}
        journal.write_file(state / RECEIPT, json.dumps(saved))
    try:
        write_config(path, *managed, current)
    except BaseException:
        try:
            rollback(state, path)
        except (OSError, RuntimeError):
            print('UFW configuration recovery is incomplete; recovery receipt was retained.', file=sys.stderr)
        raise
    return True


def rollback(state, path=CONFIG):
    saved = receipt(state)
    if saved is None or saved['phase'] == 'restored':
        return
    current = read_config(path)
    original = original_config(saved)
    if current != original:
        if current != managed_config(saved):
            raise RuntimeError('UFW configuration changed; automatic restore was refused.')
        if saved['original'] is None:
            if read_config(path) != current:
                raise RuntimeError('UFW configuration changed; automatic restore was refused.')
            path.unlink()
            journal.sync_directory(path.parent)
        else:
            write_config(path, *original, current)
    saved['phase'] = 'restored'
    journal.write_file(state / RECEIPT, json.dumps(saved))


def commit(state):
    saved = receipt(state)
    if saved is not None and saved['phase'] == 'pending':
        if read_config(CONFIG) != managed_config(saved):
            raise RuntimeError('UFW configuration changed before commit.')
        saved['phase'] = 'committed'
        journal.write_file(state / RECEIPT, json.dumps(saved))


def verify_active(state, *, during_maintenance=False):
    current = read_config(CONFIG)
    saved = receipt(state)
    mode, planned = rotation_plan(current, saved)
    if planned is not None and (current != planned or not during_maintenance):
        raise RuntimeError('UFW rotation publication is incomplete; preserve the recovery receipt.')
    source_snapshot(mode, CONFIG)
    return mode


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        if os.geteuid() != 0 or not argv:
            raise RuntimeError('UFW rotation setup requires the root installer.')
        journal.require_install_lock()
        if argv == ['check']:
            print(check(CONFIG, state=journal.STATE_DIR))
        elif len(argv) == 2 and argv[0] == 'apply':
            journal.require_maintenance(journal.STATE_DIR)
            print(int(apply(journal.STATE_DIR, CONFIG, expected=argv[1])))
        elif argv == ['rollback']:
            rollback(journal.STATE_DIR, CONFIG)
        elif argv == ['commit']:
            commit(journal.STATE_DIR)
        else:
            raise RuntimeError('Unknown UFW rotation operation.')
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
