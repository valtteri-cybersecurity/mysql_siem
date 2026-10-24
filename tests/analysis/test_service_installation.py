"""Service-copy updates use temporary trees, never real installation paths."""

import os

import pytest

from config import service_installation as service


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    # System parent ownership is tested by the installer. Unit-test trees are
    # intentionally owned by the developer account rather than root.
    monkeypatch.setattr(service, "trusted_directory", lambda path: None)
    actual_chown = os.chown

    def test_chown(path, uid, gid):
        actual_chown(path, os.getuid() if uid == 0 else uid, gid)

    monkeypatch.setattr(service.os, "chown", test_chown)
    home = tmp_path / "private home"
    home.mkdir(mode=0o700)
    source = home / "mysql_siem"
    source.mkdir(mode=0o700)
    (source / "config").mkdir()
    (source / "ingestion").mkdir()
    (source / "install.sh").write_text("new installer\n")
    (source / "ingestion" / "main.py").write_text("print('new collector')\n")
    (source / "requirements-dns.txt").write_text("project requirements\n")
    parent = tmp_path / "service"
    parent.mkdir()
    target = parent / "mysql_siem"
    return source, target


def stage(source, target):
    return service.stage_service(source, target, os.getuid(), os.getgid())


def test_private_home_source_is_untouched_and_service_copy_is_separate(deployment):
    source, target = deployment
    paths = [source.parent, source, source / "install.sh"]
    before = [(p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in paths]
    pending = stage(source, target)
    assert pending.parent == target.parent
    assert pending != target
    assert not target.exists()
    service.publish_service(pending, target)
    assert (target / "ingestion/main.py").read_bytes() == (source / "ingestion/main.py").read_bytes()
    assert (target / "requirements-dns.txt").read_bytes() == (source / "requirements-dns.txt").read_bytes()
    assert [(p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in paths] == before
    assert not pending.exists()


@pytest.mark.parametrize("name", [".git", ".venv", "venv", "__pycache__", "tests", "docs"])
def test_development_directories_are_not_copied(deployment, name):
    source, target = deployment
    (source / name).mkdir()
    (source / name / "development-only").write_text("unused\n")
    pending = stage(source, target)
    assert not (pending / name).exists()
    assert (source / name / "development-only").exists()


def test_excluded_development_virtualenv_link_is_ignored(deployment):
    source, target = deployment
    (source / ".venv").symlink_to("/outside-development-environment")
    pending = stage(source, target)
    assert not (pending / ".venv").exists()
    assert not (pending / ".venv").is_symlink()
    assert (source / ".venv").is_symlink()


def test_included_symbolic_link_is_rejected_without_publishing(deployment):
    source, target = deployment
    (source / "ingestion" / "danger.py").symlink_to("/etc/passwd")
    with pytest.raises(service.InstallationError):
        stage(source, target)
    assert not target.exists()
    assert list(target.parent.iterdir()) == []


def test_reinstallation_preserves_settings_roles_and_runtime_logs(deployment):
    source, target = deployment
    (target / "config").mkdir(parents=True)
    (target / "ingestion").mkdir()
    preserved = {
        "config/mysql.env": "DB_PASSWORD=keep-local-password\n",
        "config/role.env": "SIEM_ROLE=server\n",
        "config/identity.env": "HOST_ID=keep-local-identity\n",
        "ingestion/cron.log": "keep runtime history\n",
        "ingestion/cron.log.1": "keep rotated history\n",
    }
    for name, text in preserved.items():
        destination = target / name
        destination.write_text(text)
        destination.chmod(0o600)
    # Machine configuration in the downloaded clone must not replace the
    # installed credentials or role.
    (source / "config/mysql.env").write_text("DB_PASSWORD=wrong-source-password\n")
    (source / "config/role.env").write_text("SIEM_ROLE=server\n")
    pending = stage(source, target)
    assert (target / "config/mysql.env").read_text() == preserved["config/mysql.env"]
    service.publish_service(pending, target)
    for name, text in preserved.items():
        assert (target / name).read_text() == text
        assert (target / name).stat().st_mode & 0o777 == 0o600
    assert (target / "ingestion/main.py").read_text() == "print('new collector')\n"


def test_copy_failure_preserves_live_installation_and_cleans_stage(deployment, monkeypatch):
    source, target = deployment
    target.mkdir()
    (target / "install.sh").write_text("working installer\n")

    def fail_copy(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(service.shutil, "copy2", fail_copy)
    with pytest.raises(OSError, match="simulated disk failure"):
        stage(source, target)
    assert (target / "install.sh").read_text() == "working installer\n"
    assert list(target.parent.iterdir()) == [target]


def test_role_conflict_is_rejected_without_creating_stage(deployment):
    import pwd

    source, target = deployment
    (target / "config").mkdir(parents=True)
    for root, role in [(source, "server"), (target, "collector")]:
        role_file = root / "config/role.env"
        role_file.write_text(f"SIEM_ROLE={role}\n")
        role_file.chmod(0o600)
    user = pwd.getpwuid(os.getuid()).pw_name
    with pytest.raises(service.InstallationError):
        service.validate_role_sources(source, target, user)
    assert list(target.parent.iterdir()) == [target]
    assert (source / "config/role.env").read_text() == "SIEM_ROLE=server\n"
    assert (target / "config/role.env").read_text() == "SIEM_ROLE=collector\n"


def test_publish_failure_restores_live_files_and_configuration(deployment, monkeypatch):
    source, target = deployment
    (target / "config").mkdir(parents=True)
    (target / "install.sh").write_text("working installer\n")
    settings = target / "config/mysql.env"
    settings.write_text("DB_PASSWORD=keep\n")
    settings.chmod(0o600)
    original_inode = settings.stat().st_ino
    pending = stage(source, target)
    actual_rename = service.os.rename

    def failing_publish(old, new):
        if old == pending and new == target:
            raise OSError("simulated publish failure")
        return actual_rename(old, new)

    monkeypatch.setattr(service.os, "rename", failing_publish)
    with pytest.raises(OSError, match="simulated publish failure"):
        service.publish_service(pending, target)
    assert (target / "install.sh").read_text() == "working installer\n"
    assert settings.read_text() == "DB_PASSWORD=keep\n"
    assert settings.stat().st_ino == original_inode


def test_environment_activation_failure_restores_program_and_old_environment(
    deployment, monkeypatch
):
    source, target = deployment
    (target / "config").mkdir(parents=True)
    (target / "install.sh").write_text("working installer\n")
    settings = target / "config/mysql.env"
    settings.write_text("DB_PASSWORD=keep\n")
    settings.chmod(0o600)
    pending = stage(source, target)
    candidate = target.parent / "candidate-python"
    (candidate / "bin").mkdir(parents=True)
    (candidate / "bin/python").write_text("fake environment Python\n")
    (candidate / "pyvenv.cfg").write_text("fake environment metadata\n")
    monkeypatch.setattr(service, "ENVIRONMENTS", candidate.parent)
    stable = target.parent / "stable-python"
    stable.mkdir()
    (stable / "existing-environment").write_text("working packages\n")
    monkeypatch.setattr(service, "validate_virtualenv", lambda *args, **kwargs: None)
    actual_replace = service.os.replace

    def failing_link_publish(old, new):
        if new == stable:
            raise OSError("simulated environment activation failure")
        return actual_replace(old, new)

    monkeypatch.setattr(service.os, "replace", failing_link_publish)
    with pytest.raises(OSError, match="simulated environment activation failure"):
        service.activate(pending, target, candidate, stable)
    assert (target / "install.sh").read_text() == "working installer\n"
    assert settings.read_text() == "DB_PASSWORD=keep\n"
    assert (stable / "existing-environment").read_text() == "working packages\n"
    assert not stable.is_symlink()


def test_pip_failure_keeps_live_program_environment_and_cron(deployment):
    import shlex
    import subprocess

    source, target = deployment
    target.mkdir()
    (target / "install.sh").write_text("working installer\n")
    stable = target.parent / "existing-python"
    stable.mkdir()
    (stable / "packages").write_text("working dependencies\n")
    cron = target.parent / "crontab"
    cron.write_text("existing cron jobs\n")
    pending = stage(source, target)
    candidate = target.parent / "candidate-python"
    (candidate / "bin").mkdir(parents=True)
    fake_candidate = candidate / "bin/python"
    fake_candidate.write_text("#!/bin/sh\nprintf 'simulated pip failure\\n' >&2\nexit 42\n")
    fake_candidate.chmod(0o700)
    fake_system = target.parent / "system-python"
    fake_system.write_text("#!/bin/sh\nexit 0\n")
    fake_system.chmod(0o700)
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "install.sh").read_text()
    copy_functions = text.split("# Service copy operations", 1)[1].split("# Platform and dependency checks", 1)[0]
    platform_functions = text.split("# Platform and dependency checks", 1)[1].split("# End platform and dependency checks.", 1)[0]
    # Keep marker comments out of the extracted shell source.
    copy_functions = copy_functions[copy_functions.index("\n") :]
    platform_functions = platform_functions[platform_functions.index("\n") :]
    platform_functions = platform_functions.replace("/usr/bin/python3", shlex.quote(str(fake_system)))
    values = {
        "SOURCE_DIR": source,
        "SERVICE_DIR": target,
        "PROJECT_DIR": pending,
        "STAGED_PROJECT_DIR": pending,
        "VENV_DIR": stable,
        "TEST_CANDIDATE": candidate,
    }
    script = "set -eu\n" + "\n".join(f"{name}={shlex.quote(str(value))}" for name, value in values.items())
    script += "\n" + copy_functions + "\n" + platform_functions + '''
service_installation() { printf '%s\\n' "$TEST_CANDIDATE"; }
validate_virtualenv_location() { :; }
log() { :; }
die() { echo "$*" >&2; exit 1; }
runuser() { echo 'Unexpected runtime execution' >&2; exit 99; }
trap cleanup_prepared_installation EXIT
install_virtualenv
'''
    result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 42, result.stderr
    assert "simulated pip failure" in result.stderr
    assert (target / "install.sh").read_text() == "working installer\n"
    assert (stable / "packages").read_text() == "working dependencies\n"
    assert cron.read_text() == "existing cron jobs\n"
    assert not candidate.exists()
    assert not pending.exists()


def test_new_environment_is_traversable_with_installer_private_umask(deployment, monkeypatch):
    _source, target = deployment
    parent = target.parent / "managed-environments"
    monkeypatch.setattr(service, "ENVIRONMENTS", parent)
    previous = os.umask(0o077)
    try:
        candidate = service.new_environment()
    finally:
        os.umask(previous)
    assert parent.stat().st_mode & 0o777 == 0o755
    assert candidate.stat().st_mode & 0o777 == 0o755
    assert candidate.parent == parent


def test_missing_environment_is_rejected_before_program_publication(deployment, monkeypatch):
    source, target = deployment
    target.mkdir()
    (target / "install.sh").write_text("working installer\n")
    pending = stage(source, target)
    missing = target.parent / "missing-environment"
    stable = target.parent / "existing-environment"
    stable.mkdir()
    monkeypatch.setattr(service, "ENVIRONMENTS", target.parent)
    with pytest.raises(service.InstallationError, match="complete managed Python environment"):
        service.activate(pending, target, missing, stable)
    assert (target / "install.sh").read_text() == "working installer\n"
    assert pending.exists()
    assert stable.is_dir()


def test_first_role_is_initialized_with_service_owner_and_private_permissions(deployment):
    source, target = deployment
    pending = service.stage_service(source, target, os.getuid(), os.getgid(), role="server")
    role = pending / "config/role.env"
    assert role.read_text() == "SIEM_ROLE=server\n"
    assert role.stat().st_uid == os.getuid()
    assert role.stat().st_gid == os.getgid()
    assert role.stat().st_mode & 0o777 == 0o600
    assert not (pending / "config").stat().st_mode & 0o022
    assert not (source / "config/role.env").exists()


@pytest.mark.parametrize("stored,arguments,accepted", [
    ("server", [], True),
    ("server", ["--role", "collector"], False),
    ("collector", ["--role", "server"], False),
])
def test_installed_role_is_authoritative_before_service_staging(
    deployment, stored, arguments, accepted
):
    import pwd
    import shlex
    import subprocess
    from pathlib import Path

    source, target = deployment
    root = Path(__file__).resolve().parents[2]
    for name in ("installation_role.py", "installation_role_setup.py"):
        (source / "config" / name).write_bytes((root / "config" / name).read_bytes())
    (target / "config").mkdir(parents=True)
    role = target / "config/role.env"
    role.write_text(f"SIEM_ROLE={stored}\n")
    role.chmod(0o600)
    installer = (root / "install.sh").read_text()
    functions = installer.split("# Installation role selection", 1)[1].split(
        "# End installation role selection.", 1
    )[0]
    functions = functions[functions.index("\n") :]
    values = {
        "PROJECT_DIR": source,
        "SERVICE_DIR": target,
        "INSTALL_USER": pwd.getpwuid(os.getuid()).pw_name,
    }
    script = "set -eu\n" + "\n".join(
        f"{key}={shlex.quote(str(value))}" for key, value in values.items()
    )
    script += '\ndie() { echo "$*" >&2; exit 1; }\n' + functions
    script += "\nselect_installation_role " + shlex.join(arguments)
    script += '\nprintf "ROLE:%s\\n" "$INSTALL_ROLE"\n'
    result = subprocess.run(
        ["/bin/bash", "-c", script], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert (result.returncode == 0) == accepted, result.stderr
    assert "Confirm Server" not in result.stdout
    assert "Select installation type" not in result.stdout
    if accepted:
        assert "ROLE:server" in result.stdout
    else:
        assert "role conflict" in result.stderr
    assert role.read_text() == f"SIEM_ROLE={stored}\n"
    assert not (source / "config/role.env").exists()


@pytest.mark.parametrize("condition,accepted", [
    ("managed", True), ("external", False), ("writable-package", False),
])
def test_stable_environment_link_and_package_permissions(
    deployment, monkeypatch, condition, accepted
):
    from pathlib import Path
    from types import SimpleNamespace

    _source, target = deployment
    managed = target.parent / "managed-python"
    managed.mkdir()
    environment = managed / "python-one"
    environment.mkdir()
    package = environment / "package.py"
    package.write_text("package contents\n")
    package.chmod(0o664 if condition == "writable-package" else 0o644)
    stable = target.parent / "stable-python"
    if condition == "external":
        outside = target.parent / "unmanaged-python"
        outside.mkdir()
        stable.symlink_to(outside)
    else:
        stable.symlink_to(environment)
    monkeypatch.setattr(service, "ENVIRONMENTS", managed)
    original_lstat = Path.lstat

    def root_owned_test_path(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if path == target.parent or target.parent in path.parents:
            return SimpleNamespace(st_uid=0, st_mode=metadata.st_mode)
        return metadata

    monkeypatch.setattr(Path, "lstat", root_owned_test_path)
    if accepted:
        service.validate_virtualenv(stable, stable=True)
    else:
        with pytest.raises(service.InstallationError):
            service.validate_virtualenv(stable, stable=True)


def test_publication_keeps_live_secret_inode_and_restricts_existing_permissions(deployment):
    source, target = deployment
    (target / "config").mkdir(parents=True)
    secret = target / "config/mysql.env"
    secret.write_text("DB_PASSWORD=keep-existing-value\n")
    secret.chmod(0o644)
    inode = secret.stat().st_ino
    pending = stage(source, target)
    assert (pending / "config/mysql.env").stat().st_mode & 0o777 == 0o600
    service.publish_service(pending, target)
    assert secret.read_text() == "DB_PASSWORD=keep-existing-value\n"
    assert secret.stat().st_ino == inode
    assert secret.stat().st_mode & 0o777 == 0o600


def test_failed_database_setup_retains_prepared_credentials_without_publication(deployment):
    import shlex
    import subprocess
    from pathlib import Path

    source, target = deployment
    target.mkdir()
    (target / "install.sh").write_text("working installer\n")
    pending = stage(source, target)
    secret = pending / "config/mysql.env"
    secret.write_text("DB_PASSWORD=prepared-credential\n")
    secret.chmod(0o600)
    candidate = target.parent / "candidate-environment"
    candidate.mkdir()
    cron = target.parent / "crontab"
    cron.write_text("existing cron jobs\n")
    text = (Path(__file__).resolve().parents[2] / "install.sh").read_text()
    functions = text.split("# Service copy operations", 1)[1].split(
        "# Platform and dependency checks", 1
    )[0]
    functions = functions[functions.index("\n") :]
    script = "set -eu\n" + functions
    script += "\n" + "\n".join(
        f"{key}={shlex.quote(str(value))}" for key, value in {
            "STAGED_PROJECT_DIR": pending,
            "VENV_BUILD_DIR": candidate,
            "DATABASE_SETUP_STARTED": 1,
            "SERVICE_PUBLISHED": 0,
        }.items()
    )
    script += '\nwarn() { echo "$*" >&2; }\ncleanup_prepared_installation\n'
    result = subprocess.run(
        ["/bin/bash", "-c", script], capture_output=True,
        text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert secret.read_text() == "DB_PASSWORD=prepared-credential\n"
    assert secret.stat().st_mode & 0o777 == 0o600
    assert candidate.is_dir()
    assert (target / "install.sh").read_text() == "working installer\n"
    assert cron.read_text() == "existing cron jobs\n"
