"""Exercise GitHub handoff with fake git and harmless downloaded installers."""

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'config/install_bootstrap.sh'
REVISION = 'a' * 40


@pytest.fixture
def download(tmp_path):
    original = tmp_path / 'private home' / 'mysql_siem'
    original.mkdir(parents=True)
    (original / 'local-change.py').write_text('uncommitted local work\n')
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    git = binaries / 'git'
    git.write_text('''#!/usr/bin/python3
import json
import os
import shutil
import sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['TEST_LOG'], 'a') as out:
    out.write(json.dumps(args) + '\\n')
if 'clone' in args:
    if os.environ.get('TEST_FAILURE') == 'download':
        sys.exit(42)
    target = Path(args[-1])
    (target / 'config').mkdir(parents=True)
    shutil.copyfile(os.environ['TEST_HELPER'], target / 'config/install_bootstrap.sh')
    child = """#!/bin/bash
set -euo pipefail
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
log() { echo "$*"; }
die() { echo "$*" >&2; exit 1; }
stat() { echo 0:700; }
. "$SOURCE_DIR/config/install_bootstrap.sh"
bootstrap_latest_release
printf 'NEW_INSTALLER:%s:%s\\n' "$SIEM_BOOTSTRAP_COMMIT" "$SIEM_BOOTSTRAP_SETTINGS"
exit "${TEST_CHILD_STATUS:-0}"
"""
    (target / 'install.sh').write_text(child)
    if os.environ.get('TEST_FAILURE') == 'symlink':
        (target / 'install.sh').rename(target / 'other.sh')
        (target / 'install.sh').symlink_to('other.sh')
elif 'get-url' in args:
    if os.environ.get('TEST_FAILURE') == 'origin':
        print('https://github.com/untrusted/other.git')
    else:
        print('https://github.com/valtteri-cybersecurity/mysql_siem.git')
elif 'rev-parse' in args:
    print('invalid-revision' if os.environ.get('TEST_FAILURE') == 'revision' else 'a' * 40)
elif 'checkout' not in args:
    sys.exit(99)
''')
    git.chmod(0o755)
    log = tmp_path / 'git-calls'
    env = dict(os.environ, PATH=str(binaries) + ':/usr/bin:/bin', TEST_LOG=str(log),
               TEST_HELPER=str(HELPER), TEST_ROOT=str(tmp_path))
    for name in ('SIEM_BOOTSTRAP_CHECKOUT', 'SIEM_BOOTSTRAP_COMMIT', 'SIEM_BOOTSTRAP_SETTINGS'):
        env.pop(name, None)
    script = '''set -euo pipefail
SOURCE_DIR="$TEST_SOURCE"
log() { echo "$*"; }
die() { echo "$*" >&2; exit 1; }
mktemp() { /usr/bin/mktemp -d "$TEST_ROOT/download-XXXXXXXX"; }
. "$TEST_HELPER"
bootstrap_latest_release
'''
    env['TEST_SOURCE'] = str(original)
    return script, env, log, original


def execute(download, **extra):
    script, env, _log, _source = download
    return subprocess.run(['/bin/bash', '-c', script], env=dict(env, **extra), capture_output=True,
                          text=True, check=False, timeout=10)


def test_latest_installer_is_executed_once_and_local_changes_survive(download):
    _script, _env, log, source = download
    before = (source / 'local-change.py').read_bytes()
    result = execute(download)
    assert result.returncode == 0, result.stderr
    assert 'NEW_INSTALLER:' + REVISION + ':' + str(source) in result.stdout
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    clones = [call for call in calls if 'clone' in call]
    assert len(clones) == 1
    assert clones[0][-2] == 'https://github.com/valtteri-cybersecurity/mysql_siem.git'
    assert '--branch' in clones[0] and 'main' in clones[0]
    assert (source / 'local-change.py').read_bytes() == before
    assert not list(source.parent.parent.glob('download-*'))


@pytest.mark.parametrize('failure', ['download', 'origin', 'revision', 'symlink'])
def test_download_or_origin_failure_never_executes_installer(download, failure):
    result = execute(download, TEST_FAILURE=failure)
    assert result.returncode != 0
    assert 'NEW_INSTALLER:' not in result.stdout
    assert result.stderr.strip()


def test_downloaded_installer_failure_is_not_reported_as_success(download):
    result = execute(download, TEST_CHILD_STATUS='23')
    assert result.returncode == 23
