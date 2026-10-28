"""Exercise role dispatch without installing packages or changing real accounts."""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / "install.sh").read_text()
SERVER_ENTRY = '[[ $EUID -eq 0 ]] || die "Run: sudo bash install.sh"'


@pytest.fixture
def isolated_installer(tmp_path):
    project = tmp_path / "existing project with spaces"
    project.mkdir()
    installer = project / "install.sh"
    installer.write_text(INSTALLER.replace('readonly SERVICE_DIR="/usr/local/lib/mysql_siem"', 'readonly SERVICE_DIR="$PROJECT_DIR"'))
    config = project / "config"
    config.mkdir()
    for filename in ("mysql.env", "identity.env", "ssh.env", "adguard.env"):
        settings = config / filename
        settings.write_text("EXISTING_SETTING=keep-this-value\n")
        settings.chmod(0o600)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    # The real installer only needs dirname before its role selection gate.
    (binaries / "dirname").symlink_to("/usr/bin/dirname")
    calls = tmp_path / "unexpected-commands"
    for command in (
        "apt-get", "systemctl", "getent", "useradd", "groupadd", "passwd",
        "id", "sudo", "runuser", "install", "chown", "chmod", "crontab",
        "openssl", "mysql", "mysqld", "mariadbd", "python3", "ufw", "nft",
        "iptables", "mkdir", "touch", "rm",
    ):
        binary = binaries / command
        binary.write_text(
            '#!/bin/bash\nprintf "%s\\n" "${0##*/}" >> "$TEST_CALL_LOG"\nexit 99\n'
        )
        binary.chmod(0o755)
    env = {"PATH": str(binaries), "LC_ALL": "C", "TEST_CALL_LOG": str(calls)}
    return installer, env, calls


def run_installer(setup, arguments, selection=""):
    installer, env, _calls = setup
    return subprocess.run(
        ["/bin/bash", str(installer), *arguments], input=selection, env=env,
        text=True, capture_output=True, check=False, timeout=5,
    )


def project_snapshot(project):
    snapshot = {}
    for path in sorted(project.rglob("*")):
        relative = str(path.relative_to(project))
        contents = None
        if path.is_file():
            contents = path.read_bytes()
        metadata = path.stat()
        snapshot[relative] = (
            contents, metadata.st_mode, metadata.st_uid, metadata.st_gid,
            metadata.st_mtime_ns,
        )
    return snapshot


@pytest.mark.parametrize("arguments,selection", [
    (["--role", "collector"], ""),
    ([], "2\n2\n"),
])
def test_collector_refuses_before_any_installation_work(isolated_installer, arguments, selection):
    installer, _env, calls = isolated_installer
    before = project_snapshot(installer.parent)
    result = run_installer(isolated_installer, arguments, selection)
    assert result.returncode == 1
    assert "SIEM Collector is not available yet" in result.stderr
    assert "Current collectors require MySQL" in result.stderr
    assert "HTTPS registration and event delivery are not implemented" in result.stderr
    assert "No installation changes were made" in result.stderr
    assert "Required file is missing" not in result.stderr
    assert "Run: sudo" not in result.stderr
    assert "Installation steps completed" not in result.stdout
    assert "registration token" not in result.stdout.lower()
    assert "https://" not in result.stdout.lower()
    assert not calls.exists()
    assert project_snapshot(installer.parent) == before


def test_repeated_collector_attempt_preserves_existing_installation(isolated_installer):
    installer, _env, calls = isolated_installer
    before = project_snapshot(installer.parent)
    for _attempt in range(2):
        result = run_installer(isolated_installer, ["--role", "collector"])
        assert result.returncode == 1
        assert "not available yet" in result.stderr
        assert project_snapshot(installer.parent) == before
    assert not calls.exists()


@pytest.mark.parametrize("arguments,selection,message", [
    (["--role", "invalid"], "", "Invalid installation role"),
    (["--role", "Server"], "", "Invalid installation role"),
    (["--role", ""], "", "Invalid installation role"),
    (["--role"], "", "Specify --role"),
    (["server"], "", "Usage:"),
    (["--unknown", "server"], "", "Usage:"),
    (["--role", "server", "--role", "collector"], "", "Specify --role"),
    (["--role", "collector", "--token", "secret-test-value"], "", "Usage:"),
    ([], "0\n", "Invalid installation operation"),
    ([], "server\n", "Invalid installation operation"),
    ([], "\n", "Invalid installation operation"),
    ([], "", "No installation operation selected"),
])
def test_invalid_selection_fails_without_changes(isolated_installer, arguments, selection, message):
    installer, _env, calls = isolated_installer
    before = project_snapshot(installer.parent)
    result = run_installer(isolated_installer, arguments, selection)
    assert result.returncode == 1
    assert message in result.stderr
    assert "secret-test-value" not in result.stdout + result.stderr
    assert "Installation steps completed" not in result.stdout
    assert not calls.exists()
    assert project_snapshot(installer.parent) == before


@pytest.mark.parametrize("arguments,selection", [
    (["--role", "server"], ""),
    ([], "2\n1\n"),
])
def test_server_reaches_existing_installation_path(isolated_installer, arguments, selection):
    installer, _env, calls = isolated_installer
    # Replace the start of the existing server path with a harmless stop. No
    # packages, users, services or database commands can run in this test.
    assert INSTALLER.count(SERVER_ENTRY) == 1
    installer.write_text(INSTALLER.replace(SERVER_ENTRY, "printf 'SERVER_ENTRY\\n'\nexit 0", 1).replace('readonly SERVICE_DIR="/usr/local/lib/mysql_siem"', 'readonly SERVICE_DIR="$PROJECT_DIR"'))
    for _attempt in range(2):
        result = run_installer(isolated_installer, arguments, selection + "yes\n")
        assert result.returncode == 0, result.stderr
        assert "SERVER_ENTRY" in result.stdout
        assert "not available yet" not in result.stderr
    assert not calls.exists()
    if not arguments:
        assert "mysql_siem Installation" in result.stdout
        assert "1. SIEM Server" in result.stdout
        assert "detection and local collectors." in result.stdout
        assert "2. SIEM Collector" in result.stdout
        assert "Select installation type [1-2]:" in result.stdout
