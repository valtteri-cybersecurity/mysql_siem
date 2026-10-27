"""Exercise approved GitHub handoff with fake git and harmless installers."""

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
failure = os.environ.get('TEST_FAILURE')
for name in ('GIT_EXEC_PATH', 'GIT_SSL_NO_VERIFY', 'GIT_SSL_CAINFO', 'GIT_SSL_CAPATH'):
    if name in os.environ:
        sys.exit(91)
if os.environ.get('GIT_TERMINAL_PROMPT') != '0' or os.environ.get('GIT_ASKPASS') != '/bin/false':
    sys.exit(92)
with open(os.environ['TEST_LOG'], 'a') as out:
    out.write(json.dumps(args) + '\\n')
if 'init' in args:
    target = Path(args[-1])
    (target / 'config').mkdir(parents=True)
    shutil.copyfile(os.environ['TEST_HELPER'], target / 'config/install_bootstrap.sh')
    child = """#!/bin/bash
set -euo pipefail
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_REVISION=""
INSTALL_OPERATION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --revision) INSTALL_REVISION="$2"; shift 2 ;;
        --role) shift 2 ;;
        --upgrade) INSTALL_OPERATION=upgrade; shift ;;
        --reset) INSTALL_OPERATION=reset; shift ;;
        *) exit 83 ;;
    esac
done
log() { echo "$*"; }
die() { echo "$*" >&2; exit 1; }
stat() {
    if [[ "${TEST_FAILURE:-}" == unsafe-parent ]]; then
        echo 1000:777
    else
        echo 0:700
    fi
}
if [[ "${TEST_FAILURE:-}" == handoff-approval ]]; then
    SIEM_BOOTSTRAP_COMMIT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
fi
. "$SOURCE_DIR/config/install_bootstrap.sh"
bootstrap_latest_release
printf 'NEW_INSTALLER:%s:%s:%s:%s\\n' "$SIEM_BOOTSTRAP_COMMIT" "$SIEM_BOOTSTRAP_SETTINGS" "$INSTALL_OPERATION" "$INSTALL_REVISION"
exit "${TEST_CHILD_STATUS:-0}"
"""
    (target / 'install.sh').write_text(child)
    if failure == 'symlink':
        (target / 'install.sh').rename(target / 'other.sh')
        (target / 'install.sh').symlink_to('other.sh')
elif 'fetch' in args:
    if failure == 'download':
        sys.exit(42)
elif 'get-url' in args:
    if failure == 'origin':
        print('https://github.com/untrusted/other.git')
    else:
        print('https://github.com/valtteri-cybersecurity/mysql_siem.git')
elif 'rev-parse' in args:
    revision = 'a' * 40
    if failure == 'revision':
        revision = 'invalid-revision'
    elif failure == 'wrong-head' and 'HEAD^{commit}' in args:
        revision = 'b' * 40
    elif failure == 'child-tamper' and os.environ.get('SIEM_BOOTSTRAP_CHECKOUT'):
        revision = 'b' * 40
    print(revision)
elif 'status' in args:
    if failure == 'dirty' or failure == 'child-dirty' and os.environ.get('SIEM_BOOTSTRAP_CHECKOUT'):
        print(' M install.sh')
elif 'checkout' not in args and 'add' not in args:
    sys.exit(99)
''')
    git.chmod(0o755)
    log = tmp_path / 'git-calls'
    env = dict(os.environ, PATH=str(binaries) + ':/usr/bin:/bin', TEST_LOG=str(log),
               TEST_HELPER=str(HELPER), TEST_ROOT=str(tmp_path), INSTALL_REVISION=REVISION)
    for name in ('SIEM_BOOTSTRAP_CHECKOUT', 'SIEM_BOOTSTRAP_COMMIT', 'SIEM_BOOTSTRAP_SETTINGS',
                 'SIEM_BOOTSTRAP_CONFIRMED'):
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


def git_calls(log):
    calls = []
    for line in log.read_text().splitlines():
        calls.append(json.loads(line))
    return calls


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
def test_approved_installer_executes_once_and_preserves_local_changes(download, operation):
    _script, _env, log, source = download
    before = (source / 'local-change.py').read_bytes()
    result = execute(download, INSTALL_OPERATION=operation)
    assert result.returncode == 0, result.stderr
    assert 'NEW_INSTALLER:' + REVISION + ':' + str(source) + ':' + operation + ':' + REVISION in result.stdout
    assert result.stdout.index('Approved official commit: ' + REVISION) < result.stdout.index('NEW_INSTALLER:')
    calls = git_calls(log)
    initialized = fetched = 0
    for call in calls:
        if 'init' in call:
            initialized += 1
            assert '--template=' in call
        if 'fetch' in call:
            fetched += 1
            assert call[-2:] == ['origin', REVISION]
        if 'add' in call:
            assert call[-1] == 'https://github.com/valtteri-cybersecurity/mysql_siem.git'
        assert 'core.hooksPath=/dev/null' in call
        assert 'protocol.allow=never' in call
        assert 'protocol.https.allow=always' in call
        assert 'http.sslVerify=true' in call
        assert 'main' not in call
    assert initialized == 1
    assert fetched == 1
    assert (source / 'local-change.py').read_bytes() == before
    assert not list(source.parent.parent.glob('download-*'))


@pytest.mark.parametrize('revision', ['', 'main', 'a' * 39, 'a' * 41, 'A' * 40, 'x' * 40,
                                      'a' * 40 + ';touch marker'])
def test_missing_or_invalid_approval_never_downloads(download, revision):
    _script, _env, log, _source = download
    result = execute(download, INSTALL_REVISION=revision)
    assert result.returncode != 0
    assert '--revision' in result.stderr
    assert not log.exists()


def test_absent_approval_never_downloads(download):
    script, env, log, _source = download
    env = dict(env)
    env.pop('INSTALL_REVISION')
    result = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True,
                            text=True, check=False, timeout=10)
    assert result.returncode != 0
    assert not log.exists()


@pytest.mark.parametrize('failure', ['download', 'origin', 'revision', 'wrong-head', 'dirty',
                                     'symlink', 'child-tamper', 'child-dirty',
                                     'handoff-approval', 'unsafe-parent'])
def test_failed_verification_never_executes_installation_body(download, failure):
    result = execute(download, TEST_FAILURE=failure)
    assert result.returncode != 0
    assert 'NEW_INSTALLER:' not in result.stdout
    assert result.stderr.strip()


def test_downloaded_installer_failure_is_not_reported_as_success(download):
    result = execute(download, TEST_CHILD_STATUS='23')
    assert result.returncode == 23


def test_git_transport_cannot_inherit_disabled_tls_or_external_helpers(download):
    result = execute(download, GIT_SSL_NO_VERIFY='1', GIT_SSL_CAINFO='/untrusted/ca.pem',
                     GIT_SSL_CAPATH='/untrusted', GIT_EXEC_PATH='/untrusted/bin',
                     GIT_ASKPASS='/untrusted/askpass', GIT_TERMINAL_PROMPT='1')
    assert result.returncode == 0, result.stderr
    assert 'NEW_INSTALLER:' in result.stdout
