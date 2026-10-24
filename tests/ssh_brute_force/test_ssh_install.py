"""Execute isolated installer sections with fake cron/DB commands, never install.sh."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project with spaces"
    (root / "config").mkdir(parents=True)
    for name in ("run_with_env.sh", "ssh.env.example"):
        shutil.copy(ROOT / "config" / name, root / "config" / name)
    (root / "config/mysql.env").write_text(
        "DB_HOST=localhost\nDB_USER=test\nDB_PASSWORD=test-only\nDB_NAME=test\n"
    )
    return root


def ssh_cron(project, *, ready="1", source=None):
    if source is not None:
        (project / "config/ssh.env").write_text(f"SSH_AUTH_LOGFILE={source}\n")

    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# Schedule the SSH jobs independently;")
    end = installer.index("# Schedule UFW Analysis;", start)

    log_helper = "prepare_runtime_log() {" + installer.split(
        "prepare_runtime_log() {", 1
    )[1].split("# Use file-descriptor operations", 1)[0]

    script = (
        "set -euo pipefail\n"
        "warn() { printf '%s\\n' \"$*\" >&2; }\n"
        "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
        "chown() { :; }\n"
        "id() { printf 'test-group\\n'; }\n"
        "runuser() { return 0; }\n"
        + log_helper
        + installer[start:end]
        + '\nprintf "%s\\n%s\\n" "$SSH_AUTH_CRON" "$SSH_DETECTION_CRON"'
    )

    return subprocess.run(
        ["bash", "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PROJECT_DIR": str(project),
            "INSTALL_USER": "test-user",
            "SSH_READY": ready,
            "APP_PYTHON": sys.executable,
        },
    )


def test_cron_paths_environment_and_rotation(project):
    result = ssh_cron(project, source=project / "not-yet-created.log")
    jobs = result.stdout.strip().splitlines()

    assert len(jobs) == 2
    assert "absent" in result.stderr

    for job in jobs:
        assert job.startswith("* * * * * ")
        assert f'cd "{project}"' in job and f'PYTHONPATH="{project}"' in job
        assert 'umask 077' in job and f'--ssh "{sys.executable}" -m ' in job
        assert '--log-file ' in job and '>>' not in job

    assert "ingestion.auth.main --allow-missing-source" in jobs[0]
    assert "detection.ssh_brute_force.main --automatic" in jobs[1]

    for name in (
        "ingestion/auth/cron.log",
        "detection/ssh_brute_force/cron.log",
        "config/ssh.env",
    ):
        assert (project / name).stat().st_mode & 0o777 == 0o600


def test_no_ssh_schema_no_jobs_or_log_files(project):
    assert not ssh_cron(project, ready="0").stdout.strip()
    assert not (project / "ingestion/auth/cron.log").exists()


def test_existing_config_is_not_overwritten(project):
    settings = project / "config/ssh.env"
    settings.write_text("SSH_BRUTE_FORCE_BATCH_SIZE=42\n")

    ssh_cron(project)

    assert settings.read_text() == "SSH_BRUTE_FORCE_BATCH_SIZE=42\n"


def test_ssh_settings_are_literal_and_do_not_affect_other_jobs(project):
    settings = project / "config/ssh.env"
    settings.write_text("SSH_AUTH_LOGFILE=$(touch must-not-exist)\n")

    result = subprocess.run(
        [
            "bash",
            str(project / "config/run_with_env.sh"),
            "--ssh",
            "bash",
            "-c",
            'printf "%s\\n" "$SSH_AUTH_LOGFILE"',
        ],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "$(touch must-not-exist)"
    assert not (project / "must-not-exist").exists()

    settings.write_text("UNKNOWN=bad\n")

    result = subprocess.run(
        ["bash", str(project / "config/run_with_env.sh"), "true"],
        check=False,
        capture_output=True,
    )

    assert result.returncode == 0


@pytest.mark.parametrize("ready", [False, True])
def test_only_new_database_provisions_ssh_schema(ready):
    installer = (ROOT / "install.sh").read_text()

    start = installer.index("# SSH schema: provision new databases only;")
    end = installer.index("# Grant privileges only after", start)

    block = installer[start:end].replace("/usr/bin/mysql", "fake_mysql")

    script = (
        "set -euo pipefail\n"
        "log() { :; }\n"
        "warn() { :; }\n"
        "ensure_schema() { printf 'CURRENT_SCHEMA:%s\\n' \"$1\"; }\n"
        "fake_mysql() { if [[ \"$*\" == *'SELECT COUNT'* ]]; then echo 0; else echo MIGRATION; cat; fi; }\n"
        + block
        + '\nprintf "READY:%s\\n" "$SSH_READY"'
    )

    result = subprocess.run(
        ["bash", "-c", script],
        check=True,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "PROJECT_DIR": str(ROOT),
            "TABLE_COUNT": "0" if ready else "8",
            "DETECTION_READY": "1",
            "EXPECTED_DB_NAME": "test",
        },
    )

    assert ("CURRENT_SCHEMA:auth" in result.stdout) == ready
    assert "MIGRATION" not in result.stdout
    assert f"READY:{int(ready)}" in result.stdout


def test_managed_cron_is_repeatable_and_preserves_existing_jobs(project, tmp_path):
    auth, detection = ssh_cron(project).stdout.strip().splitlines()

    installer = (ROOT / "install.sh").read_text()

    start = installer.index("# Update only this installation's marked cron block.")
    end = installer.index('log "Installation steps completed.', start)

    script = (
        '''set -euo pipefail
local_identity_setup() { :; }
crontab() {
    if [[ "$*" == *" -l" ]]; then cat "$TEST_CRONTAB"; else cp "${@: -1}" "$TEST_CRONTAB"; fi
}
'''
        + installer[start:end]
    )

    cron_file = tmp_path / "fake-cron"
    cron_file.write_text("MAILTO=test\n17 * * * * echo external-job\n")

    env = {
        **os.environ,
        "PROJECT_DIR": str(project),
        "INSTALL_USER": "test",
        "TEST_CRONTAB": str(cron_file),
        "CRON_BEGIN": "# BEGIN mysql_siem managed jobs",
        "CRON_END": "# END mysql_siem managed jobs",
        "APP_PYTHON": sys.executable,
        "SSH_AUTH_CRON": auth,
        "SSH_DETECTION_CRON": detection,
        "PORT_SCAN_CRON": "* * * * * echo port-scan-kept",
        "DNS_CRON": "*/5 * * * * echo dns-kept",
    }

    for attempt in range(2):
        subprocess.run(
            ["bash", "-c", script],
            env=env,
            check=True,
            capture_output=True,
        )

        current = cron_file.read_text()

        if attempt == 0:
            first = current
        else:
            assert current == first

    assert current.count("-m ingestion.auth.main") == 1
    assert current.count("-m detection.ssh_brute_force.main") == 1

    for job in (
        "external-job",
        "port-scan-kept",
        "dns-kept",
        "ufw_to_mysql.py",
        "metrics.security.main",
    ):
        assert job in current


def test_embedded_installer_python_is_valid_and_no_ssh_server_changes():
    installer = (ROOT / "install.sh").read_text()

    for source in re.findall(r"<<'PY'\n(.*?)\nPY", installer, re.DOTALL):
        compile(source, "install.sh embedded Python", "exec")

    assert "ALTER USER" not in installer
    assert 'usermod -aG adm "$INSTALL_USER"' in installer
    assert installer.count("usermod ") == 1
    assert "systemctl enable --now ssh" not in installer
    assert '"auth_events": "SELECT, INSERT"' in installer


@pytest.mark.parametrize(
    "tables,rule,ready",
    [
        ("2", "1", "1"),
        ("2", "0", "0"),
        ("0", "1", "0"),
    ],
)
def test_existing_installation_requires_both_auth_schema_and_rule(
    tables, rule, ready
):
    installer = (ROOT / "install.sh").read_text()

    start = installer.index("# SSH schema: provision new databases only;")
    end = installer.index("# Grant privileges only after", start)

    block = installer[start:end].replace("/usr/bin/mysql", "fake_mysql")

    script = (
        '''set -euo pipefail
log() { :; }
warn() { :; }
fake_mysql() {
    if [[ "$*" == *information_schema.tables* ]]; then echo "$TEST_TABLES";
    elif [[ "$*" == *detection_rules* ]]; then echo "$TEST_RULE";
    else echo UNEXPECTED_WRITE; return 1; fi
}
'''
        + block
        + '\nprintf "READY:%s\\n" "$SSH_READY"'
    )

    result = subprocess.run(
        ["bash", "-c", script],
        check=True,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "PROJECT_DIR": str(ROOT),
            "TABLE_COUNT": "30",
            "DETECTION_READY": "1",
            "EXPECTED_DB_NAME": "test",
            "TEST_TABLES": tables,
            "TEST_RULE": rule,
        },
    )

    assert f"READY:{ready}" in result.stdout
    assert "UNEXPECTED_WRITE" not in result.stdout
