"""Application account checks with fake commands; never edit real accounts."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / "install.sh").read_text()


def account_setup(tmp_path, *, exists=False, group=False, repeat=1, **settings):
    state = tmp_path / "user"
    group_state = tmp_path / "group"
    if exists:
        state.touch()
        group_state.touch()
    if group:
        group_state.touch()
    account_home = tmp_path / "home"
    if exists:
        account_home.mkdir()
    if settings.get("HOME_MISSING") == "1":
        account_home.rmdir()
    if settings.get("SYMLINK") == "1":
        account_home.rmdir()
        account_home.symlink_to(tmp_path / "elsewhere")
    log = tmp_path / "calls"
    start = INSTALLER.index("# Application account management")
    end = INSTALLER.index("# End application account management.", start)
    functions = INSTALLER[start:end]
    assignment = ''
    for line in INSTALLER.splitlines():
        if line.startswith("readonly INSTALL_USER="):
            assignment = line
    assert assignment
    mocks = r'''
log() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
getent() {
    if [[ "$1" == passwd ]]; then
        if [[ -z "${2:-}" ]]; then
            printf 'root:x:0:0:root:/root:/bin/bash\n'
            if [[ "${SHARED_UID:-0}" == 1 ]]; then
                printf 'other:x:111:333::/other:/usr/sbin/nologin\n'
            fi
            if [[ "${SHARED_GROUP:-0}" == 1 ]]; then
                printf 'other:x:123:222::/other:/usr/sbin/nologin\n'
            fi
            return 0
        fi
        [[ "${LOOKUP_ERROR:-0}" == 0 ]] || return 3
        [[ -f "$STATE" ]] || return 2
        printf 'mysql_siem:x:%s:%s::%s:%s\n' "${ACCOUNT_UID:-111}" "${ACCOUNT_GID:-222}" "${ACCOUNT_HOME:-$APP_HOME}" "${ACCOUNT_SHELL:-/usr/sbin/nologin}"
    elif [[ "$1" == group ]]; then
        if [[ "${2:-}" == adm ]]; then
            [[ -n "${ADM_GID:-}" ]] || return 2
            printf 'adm:x:%s:\n' "$ADM_GID"
            return 0
        fi
        [[ -f "$GROUP_STATE" ]] || return 2
        printf 'mysql_siem:x:%s:%s\n' "${GROUP_GID:-222}" "${GROUP_MEMBERS:-}"
    else
        return 3
    fi
}
id() { printf '%s\n' "${ACCOUNT_GROUPS:-222}"; }
passwd() { printf 'passwd %s\n' "$*" >> "$CALLS"; printf 'mysql_siem %s 2026-10-23 0 99999 7 -1\n' "${PASSWORD_STATE:-L}"; }
sudo() {
    [[ "${HAS_SUDO:-0}" != 1 ]] || return 0
    [[ "${SUDO_ERROR:-0}" != 1 ]] || { printf 'policy failed\n' >&2; return 1; }
    printf 'User mysql_siem is not allowed to run sudo on test-host.\n' >&2
    return 1
}
groupadd() {
    printf 'groupadd %s\n' "$*" >> "$CALLS"
    [[ "${GROUPADD_FAIL:-0}" != 1 ]] || return 1
    : > "$GROUP_STATE"
}
useradd() {
    printf 'useradd %s\n' "$*" >> "$CALLS"
    [[ "${USERADD_FAIL:-0}" != 1 ]] || return 1
    : > "$STATE"
}
install() {
    printf 'install %s\n' "$*" >> "$CALLS"
    /bin/mkdir -p "$APP_HOME"
}
stat() { printf '%s\n' "${HOME_METADATA:-mysql_siem:mysql_siem:750}"; }
'''
    script = 'set -Eeuo pipefail\nAPP_NAME=mysql_siem\n' + assignment + '\n' + mocks + functions
    for _ in range(repeat):
        script += '\nensure_application_user\n'
    binaries = tmp_path / "empty-bin"
    binaries.mkdir()
    env = dict(os.environ)
    env["PATH"] = str(binaries)
    env.update({"STATE": str(state), "GROUP_STATE": str(group_state), "APP_HOME": str(account_home),
                "CALLS": str(log), "SUDO_USER": "root"})
    env.update(settings)
    result = subprocess.run(["/bin/bash", "-c", script], env=env, text=True,
                            capture_output=True, check=False, timeout=5)
    calls = ""
    if log.exists():
        calls = log.read_text()
    return result, calls


def test_missing_account_creates_locked_system_user_and_private_home(tmp_path):
    result, calls = account_setup(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "groupadd --system mysql_siem" in calls
    assert "useradd --system --gid mysql_siem --home-dir" in calls
    assert "--no-create-home --shell /usr/sbin/nologin --password ! mysql_siem" in calls
    assert "install -d -m 750 -o mysql_siem -g mysql_siem" in calls
    assert "passwd -S mysql_siem" in calls
    assert "usermod" not in calls


@pytest.mark.parametrize("uid", ["111", "2222"])
def test_existing_safe_account_is_not_modified(tmp_path, uid):
    result, calls = account_setup(tmp_path, exists=True, ACCOUNT_UID=uid)
    assert result.returncode == 0, result.stderr
    assert calls == "passwd -S mysql_siem\n"


@pytest.mark.parametrize("settings,message", [
    ({"ACCOUNT_UID": "0"}, "non-root"),
    ({"SHARED_UID": "1"}, "shares the mysql_siem UID"),
    ({"ACCOUNT_GID": "0"}, "primary group"),
    ({"GROUP_GID": "0"}, "primary group"),
    ({"ACCOUNT_HOME": "/unexpected"}, "requires home"),
    ({"ACCOUNT_SHELL": "/bin/bash"}, "requires home"),
    ({"PASSWORD_STATE": "P"}, "locked password"),
    ({"PASSWORD_STATE": "NP"}, "locked password"),
    ({"ACCOUNT_GROUPS": "222 27"}, "supplementary groups"),
    ({"HAS_SUDO": "1"}, "sudo privileges"),
    ({"SUDO_ERROR": "1"}, "sudo policy"),
    ({"GROUP_MEMBERS": "other"}, "shared"),
    ({"SHARED_GROUP": "1"}, "Another account"),
    ({"HOME_METADATA": "root:root:750"}, "owner"),
    ({"HOME_METADATA": "mysql_siem:mysql_siem:777"}, "mode 750"),
    ({"SYMLINK": "1"}, "symbolic link"),
])
def test_conflicting_account_stops_without_rewriting_it(tmp_path, settings, message):
    result, calls = account_setup(tmp_path, exists=True, **settings)
    assert result.returncode != 0
    assert message in result.stderr
    assert "useradd" not in calls and "groupadd" not in calls and "install" not in calls


@pytest.mark.parametrize("failure", ["USERADD_FAIL", "GROUPADD_FAIL"])
def test_creation_failure_stops_with_clear_message(tmp_path, failure):
    result, calls = account_setup(tmp_path, **{failure: "1"})
    assert result.returncode != 0
    assert "Failed to create" in result.stderr
    assert "install" not in calls


def test_repeated_install_creates_account_and_home_only_once(tmp_path):
    result, calls = account_setup(tmp_path, repeat=2)
    assert result.returncode == 0, result.stderr
    assert calls.count("useradd ") == 1
    assert calls.count("groupadd ") == 1
    assert calls.count("install ") == 1


def test_unused_existing_group_is_reused_without_changing_gid(tmp_path):
    result, calls = account_setup(tmp_path, group=True)
    assert result.returncode == 0, result.stderr
    assert "groupadd" not in calls
    assert "useradd --system --gid mysql_siem" in calls


@pytest.mark.parametrize("settings", [{"GROUP_GID": "0"}, {"GROUP_MEMBERS": "other"}, {"SHARED_GROUP": "1"}])
def test_group_conflict_stops_before_creating_user(tmp_path, settings):
    result, calls = account_setup(tmp_path, group=True, **settings)
    assert result.returncode != 0
    assert "useradd" not in calls


def test_account_lookup_error_does_not_create_user(tmp_path):
    result, calls = account_setup(tmp_path, LOOKUP_ERROR="1")
    assert result.returncode != 0
    assert "lookup failed" in result.stderr
    assert calls == ""


def test_existing_account_gets_only_its_missing_home(tmp_path):
    result, calls = account_setup(tmp_path, exists=True, HOME_MISSING="1")
    assert result.returncode == 0, result.stderr
    assert "useradd" not in calls and "groupadd" not in calls
    assert "install -d -m 750 -o mysql_siem -g mysql_siem" in calls


@pytest.mark.parametrize("groups,adm_gid,accepted", [
    ("222", "", True),
    ("222 4567", "4567", True),
    ("222 4567 9876", "4567", False),
])
def test_only_primary_and_optional_adm_groups_are_allowed(tmp_path, groups, adm_gid, accepted):
    result, calls = account_setup(tmp_path, exists=True, ACCOUNT_GROUPS=groups, ADM_GID=adm_gid)
    assert (result.returncode == 0) == accepted, result.stderr
    if not accepted:
        assert "supplementary groups" in result.stderr
    assert "useradd" not in calls and "groupadd" not in calls and "install" not in calls
