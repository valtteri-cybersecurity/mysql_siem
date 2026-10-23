"""Run dependency selection with fake OS files and commands, never a real install."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / "install.sh").read_text()


def dependency_setup(tmp_path, distribution, version="8.4.13", *, client=True, maria=False):
    release = tmp_path / "os-release"
    release.write_text(distribution)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    if version is not None:
        server = binaries / "mysqld"
        server.write_text('#!/bin/bash\nprintf "%s\\n" "$TEST_MYSQL_VERSION"\n')
        server.chmod(0o755)
    if client:
        mysql = binaries / "mysql"
        mysql.write_text("#!/bin/bash\nexit 0\n")
        mysql.chmod(0o755)
    if maria:
        daemon = binaries / "mariadbd"
        daemon.write_text("#!/bin/bash\nexit 0\n")
        daemon.chmod(0o755)

    start = INSTALLER.index("# Platform and dependency checks")
    end = INSTALLER.index("# End platform and dependency checks.", start)
    functions = INSTALLER[start:end]
    # Remove all host filesystem/binary fallbacks from this isolated test.
    functions = functions.replace("/etc/os-release", str(release))
    functions = functions.replace("/usr/sbin/mysqld", str(binaries / "mysqld"))
    functions = functions.replace("/usr/sbin/mariadbd", str(binaries / "mariadbd"))
    functions = functions.replace("/usr/bin/mysql", str(binaries / "mysql"))
    start = INSTALLER.index("\ndetect_distribution\n")
    end = INSTALLER.index('log "Starting services."', start)
    script = '''set -Eeuo pipefail
log() { printf 'LOG:%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }
ensure_application_user() { INSTALL_USER=mysql_siem; printf 'ACCOUNT_CHECK\n'; }
runuser() { printf 'RUNUSER:%s\n' "$*"; }
apt-get() { printf 'APT'; printf ' <%s>' "$@"; printf '\n'; }
''' + functions + INSTALLER[start:end]
    env = dict(os.environ)
    env["PATH"] = str(binaries)
    env["PROJECT_DIR"] = str(tmp_path / "project with spaces")
    env["TEST_MYSQL_VERSION"] = f"mysqld Ver {version} for Linux on x86_64 (MySQL Community Server - GPL)"
    return subprocess.run(["/bin/bash", "-c", script], env=env, text=True,
                          capture_output=True, check=False, timeout=5)


@pytest.mark.parametrize("distribution", [
    'ID=debian\nVERSION_ID="13"\n',
    'ID=debian\nVERSION_ID="13.1"\n',
    'ID=ubuntu\nVERSION_ID="24.04"\n',
    'ID=linuxmint\nVERSION_ID="22.3"\nID_LIKE="ubuntu debian"\n',
])
@pytest.mark.parametrize("version", ["8.0.46", "8.4.13"])
def test_existing_mysql_is_kept_on_all_supported_distributions(tmp_path, distribution, version):
    result = dependency_setup(tmp_path, distribution, version)
    assert result.returncode == 0, result.stderr
    assert "APT <update>" in result.stdout
    assert "<python3-pymysql>" in result.stdout
    assert "<python3-cryptography>" in result.stdout
    assert "<rsyslog>" in result.stdout and "<cron>" in result.stdout
    assert "<mysql-server>" not in result.stdout
    assert "mariadb-server" not in result.stdout
    assert "default-mysql-server" not in result.stdout
    assert "Keeping the installed MySQL server" in result.stdout
    assert "ACCOUNT_CHECK" in result.stdout
    assert "RUNUSER:-u mysql_siem -- test -r" in result.stdout


@pytest.mark.parametrize("distribution", ["ubuntu", "linuxmint"])
def test_fresh_ubuntu_and_mint_keep_mysql_installation(tmp_path, distribution):
    result = dependency_setup(tmp_path, f"ID={distribution}\nVERSION_ID=24.04\n", None)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("<mysql-server>") == 1


def test_debian_without_mysql_stops_before_package_changes(tmp_path):
    result = dependency_setup(tmp_path, "ID=debian\nVERSION_ID=13\n", None)
    assert result.returncode != 0
    assert "preinstalled Oracle MySQL" in result.stderr
    assert "APT" not in result.stdout


@pytest.mark.parametrize("distribution", [
    "ID=debian\nVERSION_ID=12\n", "ID=debian\nVERSION_ID=14\n",
    "ID=fedora\nVERSION_ID=43\nID_LIKE=debian\n", "VERSION_ID=13\n",
])
def test_unknown_or_unsupported_distribution_stops_before_changes(tmp_path, distribution):
    result = dependency_setup(tmp_path, distribution)
    assert result.returncode != 0
    assert "APT" not in result.stdout


@pytest.mark.parametrize("version", ["5.5.5-10.11-MariaDB", "9.7.0"])
def test_incompatible_server_is_never_replaced(tmp_path, version):
    result = dependency_setup(tmp_path, "ID=debian\nVERSION_ID=13\n", version)
    assert result.returncode != 0
    assert "APT" not in result.stdout


@pytest.mark.parametrize("distribution", ["debian", "ubuntu", "linuxmint"])
def test_mariadb_without_mysql_alias_is_never_replaced(tmp_path, distribution):
    result = dependency_setup(tmp_path, f"ID={distribution}\nVERSION_ID=13\n", None, maria=True)
    assert result.returncode != 0
    assert "MariaDB" in result.stderr
    assert "APT" not in result.stdout


def test_missing_mysql_client_stops_before_package_changes(tmp_path):
    result = dependency_setup(tmp_path, "ID=debian\nVERSION_ID=13\n", client=False)
    assert result.returncode != 0
    assert "client" in result.stderr
    assert "APT" not in result.stdout
