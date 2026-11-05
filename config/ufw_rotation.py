"""Journaled installation of the managed UFW compression command; no log rotation."""
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

from config import installation_state as journal
from config.service_installation import trusted_directory

CONFIG = Path('/etc/logrotate.d/ufw')
RECEIPT = 'ufw-rotation.json'
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
MANAGED = STOCK.replace('    compress\n', '''    compress
    compresscmd /usr/local/lib/mysql_siem/config/ufw-compress.sh
    compressoptions -6
    compressext .gz
    uncompresscmd /usr/bin/gunzip
''')


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
        raw = os.read(descriptor, 65537)
        if len(raw) > 65536:
            raise RuntimeError('UFW logrotate configuration exceeds its limit.')
        return raw.decode('utf-8'), stat.S_IMODE(info.st_mode), info.st_gid
    finally:
        os.close(descriptor)


def check(path=CONFIG):
    text, _mode, _gid = read_config(path)
    if text is not None and text.split() not in (STOCK.split(), MANAGED.split()):
        raise RuntimeError('Custom UFW logrotate configuration was preserved; configure the managed compressor explicitly.')


def write_config(path, text, mode, gid):
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
        os.replace(temporary, path)
        journal.sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def receipt(state):
    path = state / RECEIPT
    if not path.exists() and not path.is_symlink():
        return None
    record = json.loads(journal.read_file(path))
    if (not isinstance(record, dict) or set(record) != {'original', 'mode', 'gid', 'managed_sha', 'phase'}
            or record['phase'] not in ('pending', 'committed', 'restored')
            or record['managed_sha'] != hashlib.sha256(MANAGED.encode()).hexdigest()):
        raise RuntimeError('Invalid UFW rotation recovery receipt; configuration was preserved.')
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
    return record


def apply(state, path=CONFIG):
    check(path)
    text, mode, gid = read_config(path)
    saved = receipt(state)
    if text is not None and text.split() == MANAGED.split():
        if saved is None or saved['phase'] == 'committed':
            return False
        if saved['phase'] != 'pending':
            raise RuntimeError('UFW configuration conflicts with its recovery receipt.')
        return True
    if saved is not None and saved['phase'] == 'pending' and text != saved['original']:
        raise RuntimeError('UFW configuration changed during interrupted installation.')
    record = {'original': text, 'mode': mode, 'gid': gid, 'phase': 'pending',
              'managed_sha': hashlib.sha256(MANAGED.encode()).hexdigest()}
    journal.write_file(state / RECEIPT, json.dumps(record))
    try:
        write_config(path, MANAGED, 0o644, os.getegid())
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
    text, _mode, _gid = read_config(path)
    if text != saved['original']:
        if text is None or hashlib.sha256(text.encode()).hexdigest() != saved['managed_sha']:
            raise RuntimeError('UFW configuration changed; automatic restore was refused.')
        if saved['original'] is None:
            path.unlink()
            journal.sync_directory(path.parent)
        else:
            write_config(path, saved['original'], saved['mode'], saved['gid'])
    saved['phase'] = 'restored'
    journal.write_file(state / RECEIPT, json.dumps(saved))


def commit(state):
    saved = receipt(state)
    if saved is not None and saved['phase'] == 'pending':
        text, _mode, _gid = read_config(CONFIG)
        if text is None or hashlib.sha256(text.encode()).hexdigest() != saved['managed_sha']:
            raise RuntimeError('UFW configuration changed before commit.')
        saved['phase'] = 'committed'
        journal.write_file(state / RECEIPT, json.dumps(saved))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        if os.geteuid() != 0 or len(argv) != 1:
            raise RuntimeError('UFW rotation setup requires the root installer.')
        if argv[0] == 'check':
            check()
        else:
            journal.require_install_lock()
            if argv[0] == 'apply':
                journal.require_maintenance(journal.STATE_DIR)
                print(int(apply(journal.STATE_DIR)))
            elif argv[0] == 'rollback':
                rollback(journal.STATE_DIR)
            elif argv[0] == 'commit':
                commit(journal.STATE_DIR)
            else:
                raise RuntimeError('Unknown UFW rotation operation.')
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
