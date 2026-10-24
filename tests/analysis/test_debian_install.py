"""Test dependency selection with fake OS files and commands, never a real install."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / "install.sh").read_text(encoding="utf-8")


def dependency_setup(tmp_path, distribution, version="8.4.13", *, client=True, maria=False):
    release = tmp_path / "os-release"
    release.write_text(distribution, encoding="utf-8")

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

    # Replace host binary paths and OS metadata with isolated test stand-ins.
    functions = functions.replace("/etc/os-release", str(release))
    functions = functions.replace("/usr/sbin/mysqld", str(binaries / "mysqld"))
    functions = functions.replace("/usr/sbin/mariadbd", str(binaries / "mariadbd"))
    functions = functions.replace("/usr/bin/mysql", str(binaries / "mysql"))

    start = INSTALLER.index("\ndetect_distribution\n")
    end = INSTALLER.index("\nprintf '%s\\n' \"$SIEM_BOOTSTRAP_COMMIT\"", start)

    # Stub every privilege-changing, filesystem-changing and package-installing
    # operation except the package SELECTION itself. The virtualenv installer is
    # redefined after sourcing the dependency functions, so pip is never run.
    script = r'''set -Eeuo pipefail
log() { printf 'LOG:%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }
ensure_application_user() { INSTALL_USER=mysql_siem; printf 'ACCOUNT_CHECK\n'; }
ensure_log_access() { printf 'LOG_ACCESS_CHECK\n'; }
secure_project_sources() { printf 'SOURCE_PROTECTION_CHECK\n'; }
runuser() { printf 'RUNUSER:%s\n' "$*"; }
id() { printf 'mysql_siem\n'; }
install() { :; }
persist_installation_role() { :; }
prepare_service_installation() { printf 'SERVICE_COPY_CHECK\n'; }
apt-get() { printf 'APT'; printf ' <%s>' "$@"; printf '\n'; }
''' + functions + r'''
install_virtualenv() { printf 'VENV_CHECK\n'; }
''' + INSTALLER[start:end]

    env = dict(os.environ)
    env["PATH"] = str(binaries)
    env["PROJECT_DIR"] = str(tmp_path / "project with spaces")
    env["TEST_MYSQL_VERSION"] = (
        f"mysqld Ver {version} for Linux on x86_64 "
        "(MySQL Community Server - GPL)"
    )

    return subprocess.run(
        ["/bin/bash", "-c", script],
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )


@pytest.mark.parametrize("distribution", [
    'ID=debian\nVERSION_ID="13"\n',
    'ID=debian\nVERSION_ID="13.1"\n',
    'ID=ubuntu\nVERSION_ID="24.04"\n',
    'ID=linuxmint\nVERSION_ID="22.3"\nID_LIKE="ubuntu debian"\n',
])
@pytest.mark.parametrize("version", ["8.0.46", "8.4.13"])
def test_existing_mysql_is_kept_on_all_supported_distributions(
    tmp_path, distribution, version
):
    result = dependency_setup(tmp_path, distribution, version)

    assert result.returncode == 0, result.stderr

    assert "APT <update>" in result.stdout

    assert "<python3>" in result.stdout
    assert "<python3-venv>" in result.stdout

    assert "<rsyslog>" in result.stdout
    assert "<cron>" in result.stdout

    assert "<mysql-server>" not in result.stdout
    assert "<python3-pymysql>" not in result.stdout
    assert "<python3-cryptography>" not in result.stdout

    assert "mariadb-server" not in result.stdout
    assert "default-mysql-server" not in result.stdout

    assert "Keeping the installed MySQL server" in result.stdout

    assert "ACCOUNT_CHECK" in result.stdout
    assert "LOG_ACCESS_CHECK" in result.stdout
    assert "SOURCE_PROTECTION_CHECK" in result.stdout
    assert "VENV_CHECK" in result.stdout

    assert "RUNUSER:-u mysql_siem -- test -r" in result.stdout


@pytest.mark.parametrize("distribution", ["ubuntu", "linuxmint"])
def test_fresh_ubuntu_and_mint_keep_mysql_installation(
    tmp_path, distribution
):
    result = dependency_setup(
        tmp_path,
        f"ID={distribution}\nVERSION_ID=24.04\n",
        None,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.count("<mysql-server>") == 1


def test_debian_without_mysql_stops_before_package_changes(tmp_path):
    result = dependency_setup(
        tmp_path,
        "ID=debian\nVERSION_ID=13\n",
        None,
    )

    assert result.returncode != 0
    assert "preinstalled Oracle MySQL" in result.stderr
    assert "APT" not in result.stdout


@pytest.mark.parametrize("distribution", [
    "ID=debian\nVERSION_ID=12\n",
    "ID=debian\nVERSION_ID=14\n",
    "ID=fedora\nVERSION_ID=43\nID_LIKE=debian\n",
    "VERSION_ID=13\n",
])
def test_unknown_or_unsupported_distribution_stops_before_changes(
    tmp_path, distribution
):
    result = dependency_setup(tmp_path, distribution)

    assert result.returncode != 0
    assert "APT" not in result.stdout


@pytest.mark.parametrize("version", [
    "5.5.5-10.11-MariaDB",
    "9.7.0",
])
def test_incompatible_server_is_never_replaced(tmp_path, version):
    result = dependency_setup(
        tmp_path,
        "ID=debian\nVERSION_ID=13\n",
        version,
    )

    assert result.returncode != 0
    assert "APT" not in result.stdout


@pytest.mark.parametrize("distribution", [
    "debian",
    "ubuntu",
    "linuxmint",
])
def test_mariadb_without_mysql_alias_is_never_replaced(
    tmp_path, distribution
):
    result = dependency_setup(
        tmp_path,
        f"ID={distribution}\nVERSION_ID=13\n",
        None,
        maria=True,
    )

    assert result.returncode != 0
    assert "MariaDB" in result.stderr
    assert "APT" not in result.stdout


def test_missing_mysql_client_stops_before_package_changes(tmp_path):
    result = dependency_setup(
        tmp_path,
        "ID=debian\nVERSION_ID=13\n",
        client=False,
    )

    assert result.returncode != 0
    assert "client" in result.stderr
    assert "APT" not in result.stdout


def test_private_runtime_environment_uses_project_requirements():
    assert 'readonly VENV_DIR="/opt/mysql_siem-venv"' in INSTALLER

    assert "python3 python3-venv" in INSTALLER
    assert "python3-pymysql" not in INSTALLER

    assert '-m venv --copies "$VENV_BUILD_DIR"' in INSTALLER

    assert (
        '-m pip install -r "$PROJECT_DIR/requirements-runtime.txt"'
        in INSTALLER
    )

    assert "--break-system-packages" not in INSTALLER

    requirements = (ROOT / "requirements-dns.txt").read_text()
    assert "PyMySQL[rsa]>=1.2,<2" in requirements


def test_runtime_and_cron_use_absolute_virtualenv_python():
    runtime = INSTALLER.split(
        'log "Starting services."', 1
    )[1]

    assert "/usr/bin/python3" not in runtime

    cron = runtime.split(
        'cat >> "$CRON_TMP" <<CRON', 1
    )[1].split("\nCRON", 1)[0]

    assert cron.count('"$APP_PYTHON"') == 6

    assert (
        'runuser -u "$INSTALL_USER" -- /usr/bin/python3 -B'
        in INSTALLER
    )


def test_virtualenv_is_protected_from_application_ownership_changes():
    setup = INSTALLER.split(
        "validate_virtualenv_location() {", 1
    )[1].split("# End platform", 1)[0]

    helper = (ROOT / 'config/service_installation.py').read_text()
    assert 'info.st_uid != 0' in helper
    assert 'info.st_mode & 0o022' in helper
    assert 'item.resolve(strict=True).is_relative_to(path)' in helper
    assert 'resolved.parent != ENVIRONMENTS' in helper
    assert 'validate_virtualenv_location "$VENV_BUILD_DIR" candidate' in setup

    assert "cd /" in setup
    assert '"$APP_PYTHON" -I -m pip' in setup


def test_log_access_and_source_protection_before_package_changes():
    steps = INSTALLER.split(
        "\ndetect_distribution\n", 1
    )[1].split('log "Starting services."', 1)[0]

    assert (
        steps.index("ensure_application_user\n")
        < steps.index("ensure_log_access\n")
    )

    assert (
        steps.index("persist_installation_role\n")
        < steps.index("secure_project_sources\n")
    )

    assert (
        steps.index("secure_project_sources\n")
        < steps.index("install_dependencies\n")
    )

    assert 'usermod -aG adm "$INSTALL_USER"' in INSTALLER

    assert "validate_application_user\n" in INSTALLER


def test_secrets_file_rejects_symlinks_and_hardlinks():
    secure = INSTALLER.split(
        "prepare_mysql_env() {", 1
    )[1].split(
        "# End application account management.", 1
    )[0]

    assert "os.O_NOFOLLOW" in secure
    assert "stat.S_ISREG(info.st_mode)" in secure
    assert "info.st_nlink != 1" in secure

    assert "os.fchown(fd," in secure
    assert "os.fchmod(fd," in secure


def test_project_source_and_cron_log_permissions_are_separate():
    secure = INSTALLER.split(
        "secure_project_sources() {", 1
    )[1].split(
        "prepare_runtime_log() {", 1
    )[0]

    assert 'chown "root:$INSTALL_USER"' in secure
    assert 'chmod 750 "$PROJECT_DIR/config"' in secure

    assert "prepare_runtime_log() {" in INSTALLER

    assert (
        'chown "$INSTALL_USER:$INSTALL_USER" "$path"'
        in INSTALLER
    )
