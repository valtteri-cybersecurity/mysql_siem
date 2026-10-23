"""Installation role tests use temporary configuration files exclusively."""

import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from config import installation_role as roles


@pytest.fixture
def role_file(tmp_path, monkeypatch):
    target = tmp_path / "config" / "role.env"
    target.parent.mkdir()
    monkeypatch.setattr(roles, "ROLE_FILE", target)
    return target


@pytest.mark.parametrize("role", ["server", "collector"])
def test_first_initialization_and_repeated_reads(role_file, role):
    assert roles.initialize_installation_role(role) == role
    assert role_file.read_bytes() == ("SIEM_ROLE=" + role + "\n").encode()
    assert stat.S_IMODE(role_file.stat().st_mode) == 0o600
    for _attempt in range(2):
        assert roles.get_installation_role() == role
    assert list(role_file.parent.iterdir()) == [role_file]


@pytest.mark.parametrize("role", ["server", "collector"])
@pytest.mark.parametrize("ending", ["", "\n"])
def test_exact_valid_contents(role_file, role, ending):
    role_file.write_text("SIEM_ROLE=" + role + ending)
    role_file.chmod(0o600)
    assert roles.get_installation_role() == role


@pytest.mark.parametrize("content", [
    b'', b'SIEM_ROLE=', b'SIEM_ROLE=unknown\n', b'SIEM_ROLE=SERVER\n', b'SIEM_ROLE= server \n',
    b' SIEM_ROLE=server\n', b'SIEM_ROLE =server\n', b'SIEM_ROLE=server\r\n',
    b'SIEM_ROLE=server\nSIEM_ROLE=server\n', b'SIEM_ROLE=server\nSIEM_ROLE=collector\n',
    b'OTHER=server\n', b'SIEM_ROLE=server\nOTHER=value\n', b'export SIEM_ROLE=server\n',
    b'# comment\nSIEM_ROLE=server\n', b'SIEM_ROLE=server\n\n', b'\xff',
    b'SIEM_ROLE="server"\n', b'SIEM_ROLE=server\x00', b'x'*100000,
])
def test_invalid_configuration_is_rejected_without_changes(role_file, content):
    role_file.write_bytes(content)
    role_file.chmod(0o600)
    before = role_file.stat()
    with pytest.raises(roles.RoleConfigurationError):
        roles.get_installation_role()
    assert role_file.read_bytes() == content
    assert role_file.stat().st_mtime_ns == before.st_mtime_ns


def test_missing_role_has_no_default_or_environment_fallback(role_file, monkeypatch):
    monkeypatch.setenv("SIEM_ROLE", "server")
    with pytest.raises(roles.RoleConfigurationError, match="missing"):
        roles.get_installation_role()
    assert not role_file.exists()


def test_shell_content_is_data_and_never_executed(role_file, tmp_path):
    marker = tmp_path / "should-not-exist"
    role_file.write_text('SIEM_ROLE=$(touch "' + str(marker) + '")\n')
    role_file.chmod(0o600)
    with pytest.raises(roles.RoleConfigurationError):
        roles.get_installation_role()
    assert not marker.exists()


@pytest.mark.parametrize("role", [None, "", "SERVER", " server ", "other", 1, True, []])
def test_invalid_initial_role_leaves_no_file(role_file, role):
    with pytest.raises(roles.RoleConfigurationError):
        roles.initialize_installation_role(role)
    assert list(role_file.parent.iterdir()) == []


@pytest.mark.parametrize("second", ["server", "collector"])
def test_existing_role_is_never_overwritten_even_by_same_role(role_file, second):
    roles.initialize_installation_role("server")
    before = role_file.stat()
    with pytest.raises(roles.RoleConfigurationError, match="already exists"):
        roles.initialize_installation_role(second)
    assert role_file.read_bytes() == b'SIEM_ROLE=server\n'
    assert role_file.stat().st_ino == before.st_ino
    assert role_file.stat().st_mtime_ns == before.st_mtime_ns
    assert list(role_file.parent.iterdir()) == [role_file]


def test_invalid_existing_file_is_not_repaired(role_file):
    role_file.write_text("INVALID=value\n")
    role_file.chmod(0o600)
    with pytest.raises(roles.RoleConfigurationError):
        roles.initialize_installation_role("server")
    assert role_file.read_text() == "INVALID=value\n"


@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_target_is_neither_read_nor_overwritten(role_file, tmp_path, dangling):
    destination = tmp_path / "other"
    if not dangling:
        destination.write_text("SIEM_ROLE=server\n")
        destination.chmod(0o600)
    role_file.symlink_to(destination)
    for operation in (roles.get_installation_role, lambda: roles.initialize_installation_role("collector")):
        with pytest.raises(roles.RoleConfigurationError):
            operation()
    assert role_file.is_symlink()
    if dangling:
        assert not destination.exists()
    else:
        assert destination.read_text() == "SIEM_ROLE=server\n"


def test_symlink_in_directory_path_is_rejected(role_file, tmp_path):
    link = tmp_path / "linked"
    link.symlink_to(role_file.parent, target_is_directory=True)
    with pytest.raises(roles.RoleConfigurationError):
        roles.initialize_installation_role("server", path=link / "role.env")
    roles.initialize_installation_role("server")
    with pytest.raises(roles.RoleConfigurationError):
        roles.get_installation_role(path=link / "role.env")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o700, 0o000])
def test_unsafe_permissions_are_rejected(role_file, mode):
    role_file.write_text("SIEM_ROLE=server\n")
    role_file.chmod(mode)
    with pytest.raises(roles.RoleConfigurationError):
        roles.get_installation_role()


def test_owner_read_only_file_is_supported(role_file):
    role_file.write_text("SIEM_ROLE=collector\n")
    role_file.chmod(0o400)
    assert roles.get_installation_role() == "collector"


def test_fifo_is_rejected_without_blocking(role_file):
    os.mkfifo(role_file, 0o600)
    with pytest.raises(roles.RoleConfigurationError):
        roles.get_installation_role()


def test_failed_partial_write_leaves_no_active_or_temporary_file(role_file, monkeypatch):
    original_write = roles.os.write

    def fail_write(descriptor, content):
        original_write(descriptor, content[:3])
        raise OSError("Simulated write failure")

    monkeypatch.setattr(roles.os, "write", fail_write)
    with pytest.raises(roles.RoleConfigurationError, match="initialization failed"):
        roles.initialize_installation_role("server")
    assert list(role_file.parent.iterdir()) == []


def test_short_writes_are_completed_before_publication(role_file, monkeypatch):
    original_write = roles.os.write
    monkeypatch.setattr(roles.os, "write", lambda descriptor, content: original_write(descriptor, content[:2]))
    roles.initialize_installation_role("server")
    assert roles.get_installation_role() == "server"


def test_failed_file_sync_does_not_publish(role_file, monkeypatch):
    def fail_sync(descriptor):
        raise OSError("Simulated sync failure")

    monkeypatch.setattr(roles.os, "fsync", fail_sync)
    with pytest.raises(roles.RoleConfigurationError):
        roles.initialize_installation_role("server")
    assert list(role_file.parent.iterdir()) == []


def test_publication_failure_removes_temporary_file(role_file, monkeypatch):
    def fail_link(*args, **kwargs):
        raise OSError("Simulated link failure")

    monkeypatch.setattr(roles.os, "link", fail_link)
    with pytest.raises(roles.RoleConfigurationError):
        roles.initialize_installation_role("server")
    assert list(role_file.parent.iterdir()) == []


def test_concurrent_initializers_publish_exactly_one_complete_role(role_file):
    barrier = Barrier(8)

    def initialize(index):
        role = "server" if index % 2 == 0 else "collector"
        barrier.wait(timeout=10)
        try:
            return roles.initialize_installation_role(role)
        except roles.RoleConfigurationError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(initialize, range(8)))
    successes = []
    for result in results:
        if result is not None:
            successes.append(result)
    assert len(successes) == 1
    assert roles.get_installation_role() == successes[0]
    assert list(role_file.parent.iterdir()) == [role_file]


def test_default_path_is_stable_and_environment_cannot_change_role(role_file, tmp_path, monkeypatch):
    roles.initialize_installation_role("collector")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SIEM_ROLE", "server")
    assert roles.get_installation_role() == "collector"


def test_role_survives_fresh_process_with_no_cached_state(role_file):
    roles.initialize_installation_role("collector")
    script = 'from config.installation_role import get_installation_role; import sys; print(get_installation_role(path=sys.argv[1]))'
    result = subprocess.run([sys.executable, "-B", "-c", script, str(role_file)], check=False,
                            cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "collector\n"


def test_read_and_import_have_no_runtime_or_write_side_effects(role_file):
    roles.initialize_installation_role("server")
    script = '''
import sys

def audit(event, args):
    if event in ("socket.connect", "socket.bind", "subprocess.Popen", "os.system", "os.link", "os.remove", "os.mkdir"):
        raise RuntimeError("Unexpected side effect")
    if event == "open":
        mode, flags = args[1:3]
        if (isinstance(mode, str) and any(char in mode for char in "wax+")) or flags & 67:
            raise RuntimeError("Unexpected file write")
    if event == "import" and args[0].split(".")[0] in ("pymysql", "requests", "database", "ingestion", "metrics"):
        raise RuntimeError("Unexpected runtime dependency")

sys.addaudithook(audit)
from config.installation_role import get_installation_role
assert get_installation_role(path=sys.argv[1]) == "server"
'''
    before = role_file.stat()
    result = subprocess.run([sys.executable, "-B", "-c", script, str(role_file)], check=False,
                            cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert role_file.stat().st_mtime_ns == before.st_mtime_ns


def test_machine_role_file_is_git_ignored():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["git", "check-ignore", "config/role.env"], cwd=root,
                            capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0
    assert result.stdout.strip() == "config/role.env"
