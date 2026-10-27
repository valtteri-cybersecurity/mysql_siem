"""Execute isolated installer sections with fake cron/DB commands, never install.sh."""

import os
import re
import shlex
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
    runtime = root / "config/run_with_env.sh"
    runtime.write_text(runtime.read_text().replace(
        "LOCAL_STATE_DIR=/usr/local/lib/.mysql_siem-local",
        "LOCAL_STATE_DIR=" + shlex.quote(str(root / "local-state")),
    ))
    (root / "config/mysql.env").write_text(
        "DB_HOST=localhost\nDB_USER=test\nDB_PASSWORD=test-only\nDB_NAME=test\n"
    )
    return root


def ssh_cron(project, *, ready="1", source=None, preflight_result="0"):
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
        "runuser() { if [[ \"$*\" == *--check-source* ]]; then return \"$SSH_PREFLIGHT_RESULT\"; fi; return 0; }\n"
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
            "SSH_PREFLIGHT_RESULT": preflight_result,
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
    assert "/usr/bin/timeout --verbose --signal=TERM --kill-after=5s 50s " in jobs[0]
    assert jobs[0].index("/usr/bin/timeout") < jobs[0].index("config/run_with_env.sh")
    assert "/usr/bin/timeout" not in jobs[1]
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


def test_fresh_database_enables_ssh_after_single_initialization():
    installer = (ROOT / "install.sh").read_text()
    assert installer.index('config.reset_installation reset') < installer.index('SSH_READY=1')
    assert 'TABLE_COUNT' not in installer


def test_managed_cron_is_repeatable_and_preserves_existing_jobs(project, tmp_path):
    auth, detection = ssh_cron(project).stdout.strip().splitlines()

    installer = (ROOT / "install.sh").read_text()

    start = installer.index("# Update only this installation's marked cron block.")
    end = installer.index('log "Installation steps completed.', start)

    script = (
        '''set -euo pipefail
local_identity_setup() { :; }
audit_installation() { :; }
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


def test_ssh_fresh_setup_has_no_legacy_opt_in_branch():
    installer = (ROOT / 'install.sh').read_text()
    block = installer.split('# SSH schema:', 1)[1].split('# Grant privileges only after', 1)[0]
    assert 'SSH_READY=1' in block
    assert 'SSH_TABLE_COUNT' not in block
    assert 'SSH_RULE_COUNT' not in block


def test_auth_source_context_and_budget_are_loaded_literally(project):
    settings = project / "config/ssh.env"
    settings.write_text(
        "SSH_AUTH_MAX_SECONDS=30\n"
        "SSH_AUTH_SYSLOG_START=2026-01-01T00:00:00+02:00\n"
        "SSH_AUTH_SYSLOG_END=2027-01-01T00:00:00+02:00\n"
        "SSH_AUTH_SYSLOG_TIMEZONE=Europe/Helsinki\n"
    )
    command = (
        'printf "%s\\n" "$SSH_AUTH_MAX_SECONDS" "$SSH_AUTH_SYSLOG_START" '
        '"$SSH_AUTH_SYSLOG_END" "$SSH_AUTH_SYSLOG_TIMEZONE"'
    )
    result = subprocess.run(
        ["bash", str(project / "config/run_with_env.sh"), "--ssh", "bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == [
        "30", "2026-01-01T00:00:00+02:00", "2027-01-01T00:00:00+02:00", "Europe/Helsinki",
    ]


def test_absent_ssh_config_clears_inherited_source_context(project):
    environment = dict(os.environ)
    for key in ("SSH_AUTH_MAX_SECONDS", "SSH_AUTH_SYSLOG_START", "SSH_AUTH_SYSLOG_END", "SSH_AUTH_SYSLOG_TIMEZONE"):
        environment[key] = "untrusted inherited value"
    command = (
        'printf "%s\\n" "${SSH_AUTH_MAX_SECONDS-unset}" "${SSH_AUTH_SYSLOG_START-unset}" '
        '"${SSH_AUTH_SYSLOG_END-unset}" "${SSH_AUTH_SYSLOG_TIMEZONE-unset}"'
    )
    result = subprocess.run(
        ["bash", str(project / "config/run_with_env.sh"), "--ssh", "bash", "-c", command],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == ["unset", "unset", "unset", "unset"]


def test_auth_login_migration_is_required_before_installation():
    installer = (ROOT / "install.sh").read_text()
    preflight = installer.split("for path in ", 1)[1].split("done", 1)[0]
    assert "database/auth_migrations.py" in preflight
    assert "database/migrations/021_auth_logins.sql" in preflight


def test_installer_checks_source_timestamp_without_reconfiguring_rsyslog():
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# Schedule the SSH jobs independently;")
    end = installer.index("# Schedule UFW Analysis;", start)
    section = installer[start:end]
    assert '-m ingestion.auth.main --check-source --logfile "$SSH_LOG_SOURCE"' in section
    assert "runuser -u" in section
    assert "SSH_AUTH_SYSLOG_START/END/TIMEZONE" in section
    assert "/etc/rsyslog" not in section


def test_failed_timestamp_preflight_warns_without_changing_source(project):
    source = project / "auth.log"
    original = "Oct 22 12:00:00 host CRON[1]: session opened\n"
    source.write_text(original)
    result = ssh_cron(project, source=source, preflight_result="1")
    assert "Auth timestamp preflight failed or was inconclusive" in result.stderr
    assert "SSH_AUTH_SYSLOG_START/END/TIMEZONE" in result.stderr
    assert source.read_text() == original
    assert "-m ingestion.auth.main --allow-missing-source" in result.stdout
