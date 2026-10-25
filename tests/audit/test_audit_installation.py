"""Installer boundaries: no auditctl, systemctl or database is used here."""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / 'install.sh').read_text()


@pytest.mark.parametrize('action', ['prepare', 'activate'])
@pytest.mark.parametrize('exit_code', [0, 7])
def test_audit_installer_bridge_preserves_arguments_and_failure(tmp_path, action, exit_code):
    start = INSTALLER.index('audit_installation() {')
    end = INSTALLER.index('\n}', start) + 2
    script = '''set -euo pipefail
PROJECT_DIR=$1
APP_PYTHON=record_python
TEST_EXIT=$3
record_python() { printf '%s\\n' "$PYTHONPATH" "$@"; return "$TEST_EXIT"; }
''' + INSTALLER[start:end] + '\naudit_installation "$2"\n'
    project = str(tmp_path / 'project with spaces')
    result = subprocess.run(['bash', '-c', script, 'test', project, action, str(exit_code)],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == exit_code, result.stderr
    assert result.stdout.splitlines() == [project, '-m', 'config.audit_setup', action,
                                          '--project', project]


def test_audit_preparation_and_activation_follow_maintenance_lifecycle():
    prepare = INSTALLER.index('\naudit_installation prepare\n')
    publish = INSTALLER.index('\nlocal_identity_setup finish\n')
    activate = INSTALLER.index('\naudit_installation activate\n')
    complete = INSTALLER.index('log "Installation steps completed.')
    assert INSTALLER.index('\nlocal_identity_setup prepare\n') < prepare < publish
    assert publish < activate < complete
