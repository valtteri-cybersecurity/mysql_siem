import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project with spaces"
    (root / "config").mkdir(parents=True)
    (root / "detection/port_scan").mkdir(parents=True)
    shutil.copy(
        ROOT / "config/port_scan.env.example", root / "config/port_scan.env.example"
    )
    shutil.copy(ROOT / "config/run_with_env.sh", root / "config/run_with_env.sh")
    (root / "config/mysql.env").write_text(
        "DB_HOST=localhost\nDB_USER=test-user\nDB_PASSWORD=test-only\nDB_NAME=mysql_siem\n"
    )
    return root


def detection_cron(project, ready="1"):
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# Schedule one bounded detection pass;")
    end = installer.index("# DNS is optional:", start)
    result = subprocess.run(
        [
            "bash",
            "-c",
            "set -euo pipefail\n"
            + installer[start:end]
            + '\nprintf "%s\\n" "$PORT_SCAN_CRON"',
        ],
        env={**os.environ, "PROJECT_DIR": str(project), "DETECTION_READY": ready},
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def test_cron_uses_system_python_environment_cwd_and_bounded_log(project):
    command = detection_cron(project)
    assert command.startswith("* * * * * ")
    assert f'cd "{project}"' in command
    assert f'PYTHONPATH="{project}"' in command
    assert (
        'config/run_with_env.sh" --port-scan /usr/bin/python3 -m detection.port_scan.main'
        in command
    )
    assert f'--log-file "{project}/detection/port_scan/cron.log"' in command
    assert ">>" not in command
    assert (project / "config/port_scan.env").exists()
    assert (project / "detection/port_scan/cron.log").stat().st_mode & 0o777 == 0o600


def test_no_automatic_job_until_schema_is_ready(project):
    assert detection_cron(project, ready="0") == ""
    assert not (project / "detection/port_scan/cron.log").exists()


def test_detection_configuration_is_preserved(project):
    settings = project / "config/port_scan.env"
    settings.write_text("PORT_SCAN_BATCH_SIZE=42\n")
    detection_cron(project)
    assert settings.read_text() == "PORT_SCAN_BATCH_SIZE=42\n"


def test_managed_cron_is_repeatable_and_preserves_other_jobs(project, tmp_path):
    command = detection_cron(project)
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# Update only this installation's marked cron block.")
    end = installer.index('log "Installation steps completed.', start)
    block = installer[start:end]
    cron_file = tmp_path / "fake-crontab.txt"
    cron_file.write_text(
        "MAILTO=local-user\n17 * * * * echo keep-existing\n"
        "# BEGIN mysql_siem managed jobs\nold managed job\n# END mysql_siem managed jobs\n"
    )
    script = (
        r"""set -euo pipefail
crontab() {
    if [[ "$*" == *" -l" ]]; then
        cat "$TEST_CRONTAB"
    else
        cp "${@: -1}" "$TEST_CRONTAB"
    fi
}
"""
        + block
    )
    env = {
        **os.environ,
        "PROJECT_DIR": str(project),
        "INSTALL_USER": "test-user",
        "CRON_BEGIN": "# BEGIN mysql_siem managed jobs",
        "CRON_END": "# END mysql_siem managed jobs",
        "PORT_SCAN_CRON": command,
        "DNS_CRON": "*/5 * * * * echo existing-dns",
        "UFW_ANALYSIS_CRON": "*/5 * * * * /usr/bin/python3 -m analysis.ufw.main --all --recent-hours 3",
        "TEST_CRONTAB": str(cron_file),
    }
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    first = cron_file.read_text()
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    assert cron_file.read_text() == first
    assert first.count("-m detection.port_scan.main") == 1
    assert "17 * * * * echo keep-existing" in first
    assert "MAILTO=local-user" in first
    for job in (
        "ingestion/ufw_to_mysql.py",
        "metrics/system/main.py",
        "metrics/filesystem/main.py",
        "metrics.security.main",
        "analysis.ufw.main",
        "analysis/daily_counts/daily_counts.py",
        "existing-dns",
    ):
        assert job in first
    assert "old managed job" not in first


@pytest.mark.parametrize("new_database", [False, True])
def test_only_new_database_gets_automatic_detection_migrations(tmp_path, new_database):
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# Detection schema:")
    end = installer.index("# Verify tables and migrate", start)
    block = installer[start:end].replace("/usr/bin/mysql", "mock_mysql")
    script = (
        r"""set -euo pipefail
log() { :; }
warn() { :; }
mock_mysql() {
    if [[ "$*" == *"SELECT COUNT"* ]]; then
        printf '0\n'
    else
        printf 'MIGRATION\n'
        cat
    fi
}
"""
        + block
        + '\nprintf "READY:%s\\n" "$DETECTION_READY"'
    )
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **os.environ,
            "TABLE_COUNT": "0" if new_database else "8",
            "PROJECT_DIR": str(ROOT),
            "EXPECTED_DB_NAME": "mysql_siem",
        },
        text=True,
        capture_output=True,
        check=True,
    )
    assert (
        "CREATE TABLE IF NOT EXISTS detection_state" in result.stdout
    ) is new_database
    assert result.stdout.count("MIGRATION") == (2 if new_database else 0)
    assert f"READY:{int(new_database)}" in result.stdout


def test_installer_keeps_existing_passwords():
    installer = (ROOT / "install.sh").read_text()
    assert "CREATE USER IF NOT EXISTS" in installer
    assert "ALTER USER" not in installer


def test_port_scan_settings_are_literal_and_optional_for_other_jobs(project):
    settings = project / "config/port_scan.env"
    settings.write_text("PORT_SCAN_BATCH_SIZE=$(touch should-not-exist)\n")
    command = 'printf "%s\\n" "${PORT_SCAN_BATCH_SIZE:-unset}"'
    result = subprocess.run(
        [
            "bash",
            str(project / "config/run_with_env.sh"),
            "--port-scan",
            "bash",
            "-c",
            command,
        ],
        cwd=project,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == "$(touch should-not-exist)"
    assert not (project / "should-not-exist").exists()
    result = subprocess.run(
        ["bash", str(project / "config/run_with_env.sh"), "true"],
        check=False,
        cwd=project,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
