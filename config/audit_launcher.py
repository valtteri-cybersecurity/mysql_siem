import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

PROJECT = Path('/usr/local/lib/mysql_siem')
PYTHON = '/opt/mysql_siem-venv/bin/python'


def validate_manifest(manifest):
    """Accept installed version-1 manifests, including optional target statuses."""
    required = {'version', 'logfile', 'rules_sha256'}
    allowed = required | {'target_statuses'}
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('Invalid Audit installation manifest.')
    if not required <= set(manifest) or not set(manifest) <= allowed:
        raise ValueError('Invalid Audit installation manifest fields.')
    if type(manifest['version']) is not int or manifest['version'] != 1:
        raise ValueError('Unsupported Audit installation manifest version.')
    logfile = manifest['logfile']
    if not isinstance(logfile, str) or not logfile:
        raise ValueError('Invalid Audit log path.')
    from config.audit_setup import audit_logfile

    audit_logfile({'log_file': logfile})
    digest = manifest['rules_sha256']
    if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
        raise ValueError('Invalid Audit rule digest.')
    if 'target_statuses' in manifest:
        statuses = manifest['target_statuses']
        if not isinstance(statuses, dict) or len(statuses) > 128:
            raise ValueError('Invalid Audit target statuses.')
        for path, status in statuses.items():
            if not isinstance(path, str) or len(path) > 4096 or not path.startswith('/'):
                raise ValueError('Invalid Audit target status path.')
            if status not in ('PRESENT', 'NOT_INSTALLED'):
                raise ValueError('Invalid Audit target status.')
    return manifest


def launch():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError('Only the fixed root-owned systemd entrypoint may launch Audit.')
    for directory in [*reversed(PROJECT.parents), PROJECT]:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe Audit launcher source directory.')
    sys.path.insert(0, str(PROJECT))
    from config.audit_setup import (
        CONFIG_FILE,
        MARKER,
        RULES_FILE,
        _preflight_account,
        audit_configuration,
        audit_group_files,
        command,
        read_root_text,
        verify_rules,
    )
    from ingestion.audit.get import source_status

    manifest = json.loads(read_root_text(PROJECT / 'config/audit-runtime.json'))
    validate_manifest(manifest)
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    rules = read_root_text(RULES_FILE)
    if not rules.startswith(MARKER):
        raise ValueError('Unmanaged Audit rules file.')
    expected = rules.splitlines()[1:]
    digest = hashlib.sha256('\n'.join(expected).encode()).hexdigest()
    if digest != manifest['rules_sha256'] or verify_rules(expected, command(['/usr/sbin/auditctl', '-l'])):
        raise ValueError('Audit watch rules changed or are not active.')
    original = read_root_text(CONFIG_FILE)
    validated, logfile = audit_configuration(original, 'mysql_siem')
    if original != validated or str(logfile) != manifest['logfile']:
        raise ValueError('Audit disk logging configuration changed; maintenance required.')
    health = source_status(time.monotonic() + 5)
    health['observed_at'] = time.time()
    account = _preflight_account()

    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': account.pw_dir,
                   'USER': account.pw_name, 'LOGNAME': account.pw_name, 'LANG': 'C.UTF-8',
                   'PYTHONPATH': str(PROJECT), 'PYTHONDONTWRITEBYTECODE': '1',
                   'SIEM_AUDIT_HEALTH': json.dumps(health), 'SIEM_AUDIT_LOGFILE': manifest['logfile']}
    os.umask(0o077)
    os.chdir(PROJECT)
    os.setgroups([])
    os.setresgid(account.pw_gid, account.pw_gid, account.pw_gid)
    os.setresuid(account.pw_uid, account.pw_uid, account.pw_uid)
    if os.getresuid() != (account.pw_uid,) * 3 or os.getresgid() != (account.pw_gid,) * 3 or os.getgroups():
        raise ValueError('Audit privilege drop failed.')

    # The active file AND every retained rotation must be readable without adm.
    audit_group_files(Path(manifest['logfile']), account, read=True)

    wrapper = str(PROJECT / 'config/run_with_env.sh')
    os.execve(wrapper, [wrapper, PYTHON, '-m', 'ingestion.audit.main', '--automatic',
                        '--log-file', '/var/log/mysql_siem/audit/cron.log'], environment)


if __name__ == '__main__':
    try:
        launch()
    except (OSError, ValueError, RuntimeError):
        print('Audit launcher failed before database collection; check protected configuration, auditd and privileges.', file=sys.stderr)
        raise SystemExit(1) from None
