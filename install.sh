#!/usr/bin/env bash
# mysql_siem - Debian 13, Ubuntu and Linux Mint installation
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP_NAME="mysql_siem"
readonly EXPECTED_DB_NAME="mysql_siem"
readonly EXPECTED_DB_USER="pythonuser"
readonly CRON_BEGIN="# BEGIN mysql_siem managed jobs"
readonly CRON_END="# END mysql_siem managed jobs"

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE_DIR="$PROJECT_DIR"
SETTINGS_SOURCE_DIR="$SOURCE_DIR"
if [[ "${SIEM_BOOTSTRAP_CHECKOUT:-}" == "$SOURCE_DIR" ]]; then
    SETTINGS_SOURCE_DIR="${SIEM_BOOTSTRAP_SETTINGS:?Missing original settings directory}"
fi
SIEM_DATABASE_RESET_APPROVED=0
export SIEM_DATABASE_RESET_APPROVED
readonly SERVICE_DIR="/usr/local/lib/mysql_siem"
readonly INSTALL_USER="$APP_NAME"
readonly APP_HOME="/var/lib/mysql_siem"
readonly VENV_DIR="/opt/mysql_siem-venv"
APP_PYTHON="$VENV_DIR/bin/python"
ENV_FILE="$PROJECT_DIR/config/mysql.env"
STAGED_PROJECT_DIR=""
VENV_BUILD_DIR=""
SERVICE_PUBLISHED=0
DATABASE_SETUP_STARTED=0
LOCAL_DEPLOYMENT_STARTED=0
STAGING_RECOVERY=0

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Installation role selection (before any installation changes).
select_installation_role() {
    local selection stored_role="" role_directory found_role argument
    local -a role_arguments=()
    INSTALL_OPERATION=reset
    for argument in "$@"; do
        if [[ "$argument" == --upgrade ]]; then
            [[ "$INSTALL_OPERATION" == reset ]] || die "Duplicate --upgrade option."
            INSTALL_OPERATION=upgrade
        else
            role_arguments+=("$argument")
        fi
    done
    set -- "${role_arguments[@]}"
    for role_directory in "${SETTINGS_SOURCE_DIR:-$PROJECT_DIR}" "${SERVICE_DIR:-$PROJECT_DIR}"; do
        [[ ! -L "$role_directory/config" ]] || die "Configuration directory must not be a symbolic link."
        if [[ -e "$role_directory/config/role.env" || -L "$role_directory/config/role.env" ]]; then
            found_role="$(role_configuration read "$role_directory")" || die "Cannot validate the stored installation role; no installation changes were made."
            [[ -z "$stored_role" || "$found_role" == "$stored_role" ]] || die "Installation role conflict; existing roles were not changed."
            stored_role="$found_role"
        fi
    done
    if [[ $# -eq 0 && -n "$stored_role" ]]; then
        INSTALL_ROLE="$stored_role"
    elif [[ $# -eq 0 ]]; then
        printf '%s\n' 'mysql_siem Installation

1. SIEM Server
   Central server with MySQL, analysis,
   detection and local collectors.

2. SIEM Collector
   Lightweight Linux collector that sends
   events to a central SIEM server.
'
        printf 'Select installation type [1-2]: '
        IFS= read -r selection || die "No installation type selected; use --role server or --role collector."
        case "$selection" in
            1) INSTALL_ROLE=server ;;
            2) INSTALL_ROLE=collector ;;
            *) die "Invalid installation selection; enter 1 or 2." ;;
        esac
    elif [[ $# -eq 2 && "$1" == --role ]]; then
        INSTALL_ROLE="$2"
    else
        die "Usage: sudo bash install.sh [--role server|collector] [--upgrade]"
    fi

    case "$INSTALL_ROLE" in
        server|collector) ;;
        *) die "Invalid installation role; use server or collector." ;;
    esac
    if [[ -n "$stored_role" && "$INSTALL_ROLE" != "$stored_role" ]]; then
        die "Installation role conflict; the stored role will not be changed."
    fi
    if [[ -z "$stored_role" && "$INSTALL_ROLE" == server && "${SIEM_BOOTSTRAP_CONFIRMED:-}" != "${SOURCE_DIR:-$PROJECT_DIR}" ]]; then
        printf 'No persistent role exists. Confirm Server role for this new or existing installation [yes]: '
        IFS= read -r selection || die "Server role confirmation required; no changes were made."
        [[ "$selection" == yes ]] || die "Server role not confirmed; no changes were made."
    fi
}

role_configuration() {
    local action="$1"
    if [[ "$action" == initialize ]]; then
        runuser -u "$INSTALL_USER" -- /usr/bin/python3 -B - "$PROJECT_DIR" "$action" "$INSTALL_USER" "$INSTALL_ROLE" <<'PY_ROLE'
import sys
sys.path.insert(0, sys.argv[1])
from config.installation_role_setup import main
main(sys.argv[2:])
PY_ROLE
    else
        /usr/bin/python3 -B - "$PROJECT_DIR" "$INSTALL_USER" "${2:-$PROJECT_DIR}" <<'PY_ROLE'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from config.installation_role_setup import read_owned_role
print(read_owned_role(sys.argv[2], path=Path(sys.argv[3]) / "config/role.env"))
PY_ROLE
    fi
}

persist_installation_role() {
    if [[ -e "$PROJECT_DIR/config/role.env" || -L "$PROJECT_DIR/config/role.env" ]]; then
        local stored_role
        stored_role="$(role_configuration read)" || die "Cannot validate role ownership or permissions."
        [[ "$stored_role" == "$INSTALL_ROLE" ]] || die "Installation role conflict."
    else
        role_configuration initialize || die "Role initialization failed. Check config/role.env before retrying; a complete file may exist. Installation stopped."
    fi
    runuser -u "$INSTALL_USER" -- test -r "$PROJECT_DIR/config/role.env" || die "Application user cannot read role.env; ownership was not changed."
}

select_role_cron_jobs() {
    case "$INSTALL_ROLE" in
        server) ;;
        collector)
            UFW_ANALYSIS_CRON=""
            PORT_SCAN_CRON=""
            SSH_DETECTION_CRON=""
            ;;
        *) die "Invalid cron installation role." ;;
    esac
}
# End installation role selection.

# Service copy operations use only the standard library before dependencies exist.
service_installation() {
    /usr/bin/python3 -I -B - "$SOURCE_DIR" "$@" <<'PY_SERVICE'
import sys
sys.path.insert(0, sys.argv[1])
from config.service_installation import main
main(sys.argv[2:])
PY_SERVICE
}

prepare_service_installation() {
    STAGED_PROJECT_DIR="$(service_installation stage "$SOURCE_DIR" "$SERVICE_DIR" "$INSTALL_USER" "$INSTALL_ROLE" "$SETTINGS_SOURCE_DIR" "${INSTALL_OPERATION:-reset}")"
    LOCAL_DEPLOYMENT_STARTED=1
    PROJECT_DIR="$STAGED_PROJECT_DIR"
    ENV_FILE="$PROJECT_DIR/config/mysql.env"
    cd -- "$PROJECT_DIR"
}

activate_service_installation() {
    service_installation activate "$STAGED_PROJECT_DIR" "$SERVICE_DIR" "$VENV_BUILD_DIR" "$VENV_DIR" prepared-identity
    SERVICE_PUBLISHED=1
    PROJECT_DIR="$SERVICE_DIR"
    ENV_FILE="$PROJECT_DIR/config/mysql.env"
    APP_PYTHON="$VENV_DIR/bin/python"
    cd -- "$PROJECT_DIR"
}

cleanup_prepared_installation() {
    if [[ "${SNAPSHOT_LOGS_SETUP_STARTED:-0}" == 1 && "${SERVICE_PUBLISHED:-0}" != 1 ]]; then
        warn "Snapshot log preparation began under maintenance; staged settings and recovery journal were retained. Rerun the same installation command."
        return
    fi
    if [[ "${LOCAL_DEPLOYMENT_STARTED:-0}" == 1 && "${SERVICE_PUBLISHED:-0}" != 1 ]]; then
        service_installation discard || warn "Prepared deployment retained; keep maintenance and recovery files and rerun the same installation command (keep --upgrade when upgrading)."
        return
    fi
    if [[ "${SERVICE_PUBLISHED:-0}" != 1 ]]; then
        if [[ "${DATABASE_SETUP_STARTED:-0}" == 1 ]]; then
            warn "Database setup was started; retained prepared settings at $STAGED_PROJECT_DIR and Python at $VENV_BUILD_DIR for manual recovery."
            return
        fi
        if [[ -n "${STAGED_PROJECT_DIR:-}" ]]; then rm -rf -- "$STAGED_PROJECT_DIR"; fi
        if [[ -n "${VENV_BUILD_DIR:-}" ]]; then rm -rf -- "$VENV_BUILD_DIR"; fi
    fi
}

# The root-owned maintenance barrier blocks new jobs; old jobs need a one-time
# administrator confirmation. Keep the runtime lock through config and cron publication.
local_identity_setup() {
    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m database.local_identity "$@" \
        --project "$PROJECT_DIR" --installed "$SERVICE_DIR" --user "$INSTALL_USER" --operation "${INSTALL_OPERATION:-reset}"
}
audit_installation() {
    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m config.audit_setup "$@" --project "$PROJECT_DIR"
}
verify_local_identity() {
    runuser -u "$INSTALL_USER" -- env PYTHONPATH="$PROJECT_DIR" \
        "$APP_PYTHON" -m database.local_identity verify --project "$PROJECT_DIR" --operation "${INSTALL_OPERATION:-reset}"
}

# Platform and dependency checks (no database writes).
detect_distribution() {
    local release_file="${1:-/etc/os-release}"
    local ID="" VERSION_ID=""
    [[ -r "$release_file" ]] || die "Cannot read operating system information."
    . "$release_file"

    REQUIRE_EXISTING_MYSQL=0
    case "$ID" in
        debian)
            [[ "${VERSION_ID%%.*}" == "13" ]] || die "Debian 13 is required for the Debian installation path."
            REQUIRE_EXISTING_MYSQL=1
            ;;
        ubuntu|linuxmint)
            ;;
        *)
            die "Supported systems: Debian 13, Ubuntu and Linux Mint."
            ;;
    esac
    log "Detected $ID $VERSION_ID."
}

select_mysql_package() {
    local daemon version
    MYSQL_PACKAGE=""
    daemon="$(command -v mysqld || true)"
    if [[ -z "$daemon" && -x /usr/sbin/mysqld ]]; then
        daemon=/usr/sbin/mysqld
    fi

    if [[ -n "$daemon" ]]; then
        version="$("$daemon" --version)" || die "Cannot determine the installed MySQL version."
        case "$version" in
            *MariaDB*) die "MariaDB is not supported; the installer will not replace it." ;;
            *"Ver 8.0."*|*"Ver 8.4."*) ;;
            *) die "Expected an existing MySQL 8.0 or 8.4 server; no server packages were changed." ;;
        esac
        [[ -x /usr/bin/mysql ]] || die "The installed MySQL server requires its /usr/bin/mysql client."
        log "Keeping the installed MySQL server; no MySQL server package will be requested."
    elif command -v mariadbd >/dev/null 2>&1 || [[ -x /usr/sbin/mariadbd ]]; then
        die "MariaDB is installed; the installer will not replace it."
    elif [[ "$REQUIRE_EXISTING_MYSQL" == "1" ]]; then
        die "Debian 13 requires a preinstalled Oracle MySQL 8.0 or 8.4 server and client."
    else
        MYSQL_PACKAGE=mysql-server
    fi
}

install_dependencies() {
    local packages=(
        python3 python3-venv
        rsyslog cron ca-certificates openssl coreutils
    )
    if [[ -n "$MYSQL_PACKAGE" ]]; then
        packages+=("$MYSQL_PACKAGE")
    fi
    # auditd includes auditctl, ausearch and augenrules on Debian/Ubuntu/Mint.
    # apt does not reinstall an already installed package; do not request it twice.
    if [[ "$(dpkg-query -W -f='${Status}' auditd 2>/dev/null || true)" != 'install ok installed' ]]; then
        packages+=(auditd)
    fi
    export DEBIAN_FRONTEND=noninteractive
    log "Updating package lists."
    apt-get update
    log "Installing dependencies."
    apt-get install -y "${packages[@]}"
}
# Keep packages outside the application-owned project tree.
validate_virtualenv_location() {
    service_installation validate-environment "${1:-$VENV_DIR}" "${2:-stable}"
}

install_virtualenv() {
    local system_version candidate_version
    /usr/bin/python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10 or newer is required."
    validate_virtualenv_location
    VENV_BUILD_DIR="$(service_installation environment)"
    APP_PYTHON="$VENV_BUILD_DIR/bin/python"
    # This is the environment's final physical location; never relocate a venv.
    (
        umask 022
        cd /
        /usr/bin/python3 -I -m venv --copies "$VENV_BUILD_DIR"
        "$APP_PYTHON" -I -m pip install -r "$PROJECT_DIR/requirements-runtime.txt"
        "$APP_PYTHON" -I -m pip check
    )
    validate_virtualenv_location "$VENV_BUILD_DIR" candidate
    system_version="$(/usr/bin/python3 -I -c 'import sys; print(sys.version_info[:2])')"
    candidate_version="$("$APP_PYTHON" -I -c 'import sys; print(sys.version_info[:2])')"
    [[ "$system_version" == "$candidate_version" ]] || die "Virtual environment Python version mismatch."
    runuser -u "$INSTALL_USER" -- "$APP_PYTHON" -I -c 'import pymysql, requests, cryptography, psutil'
}
# End platform and dependency checks.


# Application account management (shared by Debian, Ubuntu and Linux Mint).
validate_application_user() {
    local record name password account_uid account_gid description account_home account_shell
    local group_record group_name group_password group_gid group_members
    local status status_name password_state rest groups group_id accounts sudo_output expected_uid

    record="$(getent passwd "$INSTALL_USER")" || die "Cannot read the mysql_siem account."
    IFS=: read -r name password account_uid account_gid description account_home account_shell <<< "$record"
    [[ "$name" == "$INSTALL_USER" && "$account_uid" =~ ^[0-9]+$ && "$account_uid" != 0 ]] ||
        die "mysql_siem must be a non-root account; existing UID was not changed."
    [[ "$account_home" == "$APP_HOME" && "$account_shell" == /usr/sbin/nologin ]] ||
        die "mysql_siem requires home $APP_HOME and shell /usr/sbin/nologin; existing account was not changed."
    group_record="$(getent group "$INSTALL_USER")" || die "mysql_siem requires its own primary group."
    IFS=: read -r group_name group_password group_gid group_members <<< "$group_record"
    [[ "$group_name" == "$INSTALL_USER" && "$group_gid" =~ ^[0-9]+$ && "$group_gid" != 0 && "$account_gid" == "$group_gid" ]] ||
        die "mysql_siem has a conflicting primary group; existing GID was not changed."
    [[ -z "$group_members" || "$group_members" == "$INSTALL_USER" ]] ||
        die "The mysql_siem group is shared with other users; review it manually."

    expected_uid="$account_uid"
    accounts="$(getent passwd)" || die "Cannot check mysql_siem UID/group ownership."
    while IFS=: read -r name password account_uid account_gid description account_home account_shell; do
        if [[ "$name" != "$INSTALL_USER" && "$account_uid" == "$expected_uid" ]]; then
            die "Another account shares the mysql_siem UID; review it manually."
        fi
        if [[ "$name" != "$INSTALL_USER" && "$account_gid" == "$group_gid" ]]; then
            die "Another account uses the mysql_siem primary group; review it manually."
        fi
    done <<< "$accounts"
    groups="$(id -G "$INSTALL_USER")" || die "Cannot check mysql_siem groups."
    local adm_record adm_name adm_password adm_gid="" adm_members
    if adm_record="$(getent group adm)"; then
        IFS=: read -r adm_name adm_password adm_gid adm_members <<< "$adm_record"
        [[ "$adm_name" == adm && "$adm_gid" =~ ^[0-9]+$ && "$adm_gid" != 0 ]] ||
            die "Cannot validate the optional adm group."
    else
        status=$?
        [[ "$status" == 2 ]] || die "Cannot look up the optional adm group."
    fi
    local -a account_groups
    IFS=' ' read -r -a account_groups <<< "$groups"
    for group_id in "${account_groups[@]}"; do
        [[ "$group_id" == "$group_gid" || ( -n "$adm_gid" && "$group_id" == "$adm_gid" ) ]] ||
            die "mysql_siem has supplementary groups; review them manually instead of granting broad access."
    done
    status="$(LC_ALL=C passwd -S "$INSTALL_USER")" || die "Cannot verify mysql_siem password status."
    IFS=' ' read -r status_name password_state rest <<< "$status"
    [[ "$status_name" == "$INSTALL_USER" && "$password_state" == L ]] ||
        die "mysql_siem must have a locked password; existing password was not changed."
    if command -v sudo >/dev/null 2>&1; then
        local sudo_status=0 sudo_denial_prefix sudo_denial_host
        sudo_output="$(LC_ALL=C sudo -n -l -U "$INSTALL_USER" 2>&1)" || sudo_status=$?
        sudo_denial_prefix="User $INSTALL_USER is not allowed to run sudo on "
        sudo_denial_host="${sudo_output#"$sudo_denial_prefix"}"
        # Root's listing can succeed even when the listed user has no grants.
        if [[ ( "$sudo_status" == 0 || "$sudo_status" == 1 ) &&
              "$sudo_output" == "$sudo_denial_prefix"* &&
              "$sudo_denial_host" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*\.$ ]]; then
            :
        elif [[ "$sudo_output" == *"User $INSTALL_USER may run the following commands on "* ]]; then
            die "mysql_siem has sudo privileges; remove them manually before installing."
        else
            die "Cannot verify that mysql_siem has no sudo privileges; review sudo policy."
        fi
    fi
}

ensure_application_user() {
    local record group_record group_name group_password group_gid group_members status accounts
    local name password account_uid account_gid description account_home account_shell
    local created=0

    [[ -x /usr/sbin/nologin ]] || die "/usr/sbin/nologin is required."
    if record="$(getent passwd "$INSTALL_USER")"; then
        validate_application_user
    else
        status=$?
        [[ "$status" == 2 ]] || die "Account lookup failed; no account was created."
        [[ ! -e "$APP_HOME" && ! -L "$APP_HOME" ]] ||
            die "$APP_HOME exists without mysql_siem; review its ownership before creating the account."
        if group_record="$(getent group "$INSTALL_USER")"; then
            IFS=: read -r group_name group_password group_gid group_members <<< "$group_record"
            [[ "$group_name" == "$INSTALL_USER" && "$group_gid" =~ ^[0-9]+$ && "$group_gid" != 0 && -z "$group_members" ]] ||
                die "The existing mysql_siem group conflicts with account creation."
            accounts="$(getent passwd)" || die "Cannot check the existing mysql_siem group."
            while IFS=: read -r name password account_uid account_gid description account_home account_shell; do
                [[ "$account_gid" != "$group_gid" ]] || die "Another account uses the mysql_siem group."
            done <<< "$accounts"
        else
            status=$?
            [[ "$status" == 2 ]] || die "Group lookup failed; no group was created."
            groupadd --system "$INSTALL_USER" || die "Failed to create the mysql_siem system group."
        fi
        useradd --system --gid "$INSTALL_USER" --home-dir "$APP_HOME" \
            --no-create-home --shell /usr/sbin/nologin --password '!' "$INSTALL_USER" ||
            die "Failed to create mysql_siem; inspect the group/account before retrying."
        created=1
        validate_application_user
    fi

    [[ ! -L "$APP_HOME" ]] || die "mysql_siem home must not be a symbolic link."
    if [[ ! -e "$APP_HOME" ]]; then
        install -d -m 750 -o "$INSTALL_USER" -g "$INSTALL_USER" "$APP_HOME" ||
            die "Failed to create the mysql_siem home directory."
    fi
    [[ -d "$APP_HOME" ]] || die "mysql_siem home must be a directory."
    [[ "$(stat -c '%U:%G:%a' "$APP_HOME")" == "$INSTALL_USER:$INSTALL_USER:750" ]] ||
        die "mysql_siem home requires owner mysql_siem:mysql_siem and mode 750; review it manually."
    log "mysql_siem account verified (created=$created)."
}

# Grant the service account access to system logs. SSH is an optional source
# and its configured path is checked when the SSH cron jobs are prepared.
ensure_log_access() {
    local adm_record adm_name adm_password adm_gid adm_members account_groups source
    adm_record="$(getent group adm)" || die "The adm log-reader group is required."
    IFS=: read -r adm_name adm_password adm_gid adm_members <<< "$adm_record"
    [[ "$adm_name" == adm && "$adm_gid" =~ ^[0-9]+$ && "$adm_gid" != 0 ]] ||
        die "Invalid adm group; log access was not changed."

    account_groups="$(id -G "$INSTALL_USER")" || die "Cannot inspect application groups."
    if [[ " $account_groups " != *" $adm_gid "* ]]; then
        usermod -aG adm "$INSTALL_USER" || die "Could not grant mysql_siem adm log access."
    fi
    validate_application_user

    # UFW is a core log source; do not silently install an unusable UFW collector.
    # /var/log/auth.log is optional. Check the ability to open UFW log data,
    # not the preflight test -r result, which may disagree with open(2).
    # Never loosen system log permissions to make an installation pass.
    source=/var/log/ufw.log
    if [[ -e "$source" ]]; then
        runuser -u "$INSTALL_USER" -- /usr/bin/head -c 1 "$source" >/dev/null ||
            die "mysql_siem cannot read $source even with adm membership."
    else
        warn "Log source does not exist yet: $source"
    fi
}

# Keep executable source files out of the service account's control.
# The config directory is locked only AFTER the initial role has been written.
secure_project_sources() {
    local link
    link="$(find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o -type l -print -quit)"
    [[ -z "$link" ]] || die "Project contains an unsafe symbolic link: $link"
    find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o \
        -type f ! -path "$PROJECT_DIR/config/*.env" ! -name '*.log' ! -name '*.log.*' \
        -exec chown "root:$INSTALL_USER" {} + \
        -exec chmod 'g+rX,go-w' {} +
    find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o \
        -type d -exec chown "root:$INSTALL_USER" {} + \
        -exec chmod 'g+rX,go-w' {} +
    # root owns the directory: mysql_siem may read config, but cannot
    # replace trusted scripts by renaming files in their parent directory.
    chown "root:$INSTALL_USER" "$PROJECT_DIR/config"
    chmod 750 "$PROJECT_DIR/config"
}

# Writable logs are individual files, never writable source directories.
prepare_runtime_log() {
    local path="$1"
    [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] ||
        die "Invalid application log path: $path"
    touch -- "$path" || die "Cannot create application log: $path"
    chown "$INSTALL_USER:$INSTALL_USER" "$path"
    chmod 600 "$path"
}

# Use file-descriptor operations so chmod/chown never follow mysql.env links.
prepare_mysql_env() {
    local action=existing password=""
    if [[ ! -e "$ENV_FILE" && ! -L "$ENV_FILE" ]]; then
        action=create
        password="$(openssl rand -hex 32)" || die "Could not generate database password."
    fi
    if ! DB_PASSWORD="$password" /usr/bin/python3 -I - "$ENV_FILE" "$INSTALL_USER" "$action" <<'PY_SECURE_ENV'
import os
import pwd
import stat
import sys

path, username, action = sys.argv[1:]
account = pwd.getpwnam(username)
if action == "create":
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
else:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("mysql.env must be a regular file with one hard link")
    os.fchown(fd, account.pw_uid, account.pw_gid)
    os.fchmod(fd, 0o600)
    if action == "create":
        with os.fdopen(os.dup(fd), "w") as output:
            output.write(
                "DB_HOST=localhost\n"
                "DB_USER=pythonuser\n"
                f"DB_PASSWORD={os.environ['DB_PASSWORD']}\n"
                "DB_NAME=mysql_siem\n"
            )
            output.flush()
            os.fsync(output.fileno())
finally:
    os.close(fd)
PY_SECURE_ENV
    then
        die "Could not securely prepare mysql.env; inspect it before retrying."
    fi
    unset DB_PASSWORD
    if [[ "$action" == create ]]; then
        log "Created a new database environment file."
    else
        log "Keeping the existing mysql.env file."
    fi
}

# End application account management.

load_mysql_env() {
    local env_file="$1"
    local line
    local key
    local value

    if [[ ! -r "$env_file" ]]; then
        printf 'Cannot read configuration file.\n' >&2
        return 1
    fi

    unset DB_HOST DB_USER DB_PASSWORD DB_NAME
    unset DB_PORT DB_CONNECT_TIMEOUT DB_READ_TIMEOUT DB_WRITE_TIMEOUT DB_SSL_CA

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" || "$line" == \#* ]]; then
            continue
        fi

        if [[ "$line" != *=* ]]; then
            printf 'Invalid configuration line.\n' >&2
            return 1
        fi

        key="${line%%=*}"
        value="${line#*=}"

        case "$key" in
            DB_HOST)
                export DB_HOST="$value"
                ;;
            DB_USER)
                export DB_USER="$value"
                ;;
            DB_PASSWORD)
                export DB_PASSWORD="$value"
                ;;
            DB_NAME)
                export DB_NAME="$value"
                ;;
            DB_PORT|DB_CONNECT_TIMEOUT|DB_READ_TIMEOUT|DB_WRITE_TIMEOUT|DB_SSL_CA)
                export "$key=$value"
                ;;
            *)
                printf 'Unknown configuration key.\n' >&2
                return 1
                ;;
        esac
    done < "$env_file"

    if [[ -z "${DB_HOST:-}" ||
          -z "${DB_USER:-}" ||
          -z "${DB_PASSWORD:-}" ||
          -z "${DB_NAME:-}" ]]; then
        printf 'Required database setting is missing.\n' >&2
        return 1
    fi
}

trap 'rc=$?; printf "[ERROR] Installation failed (exit %s, line %s). Keep maintenance/recovery files and rerun the same installation command (keep --upgrade when upgrading) after correcting the error.\n" "$rc" "${BASH_LINENO[0]:-?}" >&2; exit "$rc"' ERR

select_installation_role "$@"
if [[ "$INSTALL_ROLE" == collector ]]; then
    die "SIEM Collector is not available yet. Current collectors require MySQL; HTTPS registration and event delivery are not implemented. No installation changes were made."
fi

[[ $EUID -eq 0 ]] || die "Run: sudo bash install.sh"

# The first invocation downloads; the verified invocation continues without a loop.
. "$SOURCE_DIR/config/install_bootstrap.sh"
bootstrap_latest_release


for path in \
    requirements-dns.txt \
    requirements-runtime.txt \
    config/service_installation.py \
    config/reset_installation.py \
    config/install_bootstrap.sh \
    config/installation_state.py \
    database/local_identity.py \
    database/schema.sql \
    database/schema.py \
    database/migrate.py \
    database/migration_steps.py \
    database/migrations/014_host_registry.sql \
    database/migrations/017_ufw_datetime_precision.sql \
    database/migrations/018_processes.sql \
    database/migrations/019_services.sql \
    database/snapshot_migrations.py \
    database/audit_migrations.py \
    database/migrations/020_audit.sql \
    ingestion/audit/main.py \
    ingestion/audit/get.py \
    ingestion/audit/parser.py \
    ingestion/audit/database.py \
    ingestion/audit/targets.py \
    config/audit_setup.py \
    config/audit_permissions.py \
    config/audit_launcher.py \
    config/systemd/mysql-siem-audit.service \
    config/systemd/mysql-siem-audit.timer \
    metrics/snapshot.py \
    config/run_with_env.sh \
    config/installation_role.py \
    config/installation_role_setup.py \
    config/ssh.env.example \
    ingestion/auth/main.py \
    detection/ssh_brute_force/main.py \
    config/port_scan.env.example \
    detection/port_scan/main.py \
    ingestion/dns/main.py \
    ingestion/ufw_to_mysql.py \
    metrics/system/main.py \
    metrics/filesystem/main.py \
    metrics/security/main.py \
    metrics/processes/main.py \
    metrics/processes/get.py \
    metrics/processes/database.py \
    metrics/services/main.py \
    metrics/services/get.py \
    metrics/services/database.py \
    analysis/ufw/__init__.py \
    analysis/ufw/source_ips.py \
    analysis/ufw/ports.py \
    analysis/ufw/main.py \
    analysis/ufw/traffic.py
do
    [[ -f "$PROJECT_DIR/$path" ]] || die "Required file is missing: $path"
done

# Inspect the database without requesting destructive approval yet.
if [[ -x /usr/bin/mysql ]]; then
    EXISTING_DATABASE="$(/usr/bin/mysql --no-defaults --protocol=socket --socket=/run/mysqld/mysqld.sock \
        --user=root --connect-timeout=5 --batch --skip-column-names \
        -e "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='mysql_siem'")" ||
        die "Cannot inspect local MySQL. Start/check the installed server before retrying; no reset was performed."
    if [[ "$EXISTING_DATABASE" == 1 && "${INSTALL_OPERATION:-reset}" == upgrade ]]; then
        : # Validate published or staging recovery state under the installation lock below.
    elif [[ "$EXISTING_DATABASE" == 1 ]]; then
        : # Request final RESET approval only after all preflights.
    elif [[ "$EXISTING_DATABASE" != 0 ]]; then
        die "Unexpected database inspection result; reset was not attempted."
    fi
fi
if [[ "${INSTALL_OPERATION:-reset}" == upgrade && "${EXISTING_DATABASE:-0}" != 1 ]]; then
    die "Upgrade requires an existing MySQL database; no installation changes were made."
fi

# Recheck persistent roles before creating even the installation lock.
service_installation check "$SETTINGS_SOURCE_DIR" "$SERVICE_DIR" "$INSTALL_USER"
[[ ! -L /usr/local/lib/.mysql_siem-install.lock ]] || die "Unsafe installation lock link."
exec 9>> /usr/local/lib/.mysql_siem-install.lock
flock -n 9 || die "Another mysql_siem installation is running."
# A pending publication may need rollback before a new service copy is staged.
if [[ -e /usr/local/lib/.mysql_siem-local/maintenance ]]; then
    [[ ! -L /usr/local/lib/.mysql_siem-local/runtime.lock ]] || die "Unsafe runtime lock link."
    exec 8< /usr/local/lib/.mysql_siem-local/runtime.lock
    flock -x -w 30 8 || die "Runtime jobs did not stop; collection remains paused."
fi
service_installation check "$SETTINGS_SOURCE_DIR" "$SERVICE_DIR" "$INSTALL_USER"
if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then
    if [[ -f "$SERVICE_DIR/config/mysql.env" && -f "$SERVICE_DIR/config/identity.env" &&
          -f /usr/local/lib/.mysql_siem-local/receipt.json ]]; then
        log "Preserving the existing database and local identities."
    elif [[ ! -e /usr/local/lib/.mysql_siem-local && ! -L /usr/local/lib/.mysql_siem-local ]]; then
        die "Cannot use --upgrade: protected local installation state is missing. An existing mysql_siem database alone is not an installed instance. The database was preserved. If its data must be kept, recover this machine's own installation/settings or arrange a reviewed legacy migration. A fresh installation without --upgrade requires an explicit RESET confirmation before replacing an existing database. Do not create recovery files manually or copy them from another host."
    else
        service_installation recovery-check "$SERVICE_DIR" "$INSTALL_USER"
        STAGING_RECOVERY=1
        log "Using protected unpublished staging recovery; database bindings will be checked before upgrade."
    fi
fi
trap cleanup_prepared_installation EXIT

detect_distribution
select_mysql_package
ensure_application_user
ensure_log_access
prepare_service_installation
runuser -u "$INSTALL_USER" -- test -r "$PROJECT_DIR/install.sh" || die "mysql_siem cannot read the prepared service copy."
persist_installation_role
secure_project_sources
install_dependencies
install_virtualenv
printf '%s\n' "$SIEM_BOOTSTRAP_COMMIT" > "$PROJECT_DIR/config/installed-version"
chown root:"$INSTALL_USER" "$PROJECT_DIR/config/installed-version"
chmod 640 "$PROJECT_DIR/config/installed-version"

# Create or validate the database secrets file without following symbolic links.
prepare_mysql_env

# Read configuration as data without executing its contents.
load_mysql_env "$ENV_FILE"

[[ "${DB_NAME:-}" == "$EXPECTED_DB_NAME" ]] ||
    die "mysql.env: DB_NAME must be $EXPECTED_DB_NAME."
[[ "${DB_USER:-}" == "$EXPECTED_DB_USER" ]] ||
    die "mysql.env: DB_USER must be $EXPECTED_DB_USER."
[[ -n "${DB_PASSWORD:-}" ]] || die "DB_PASSWORD is missing from mysql.env."
[[ "${DB_HOST:-}" == "localhost" ]] ||
    die "This installer requires DB_HOST=localhost."

# These checks only read prepared state, MySQL and log prerequisites.
# They must pass before starting a new maintenance period or database operation.
service_installation preflight "$PROJECT_DIR" "$SERVICE_DIR" "$INSTALL_USER"
PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m config.reset_installation check --operation "$INSTALL_OPERATION" --project "$PROJECT_DIR"
if [[ "$STAGING_RECOVERY" == 1 ]]; then
    local_identity_setup check-recovery
fi
service_installation snapshot-logs-check "$INSTALL_USER"
audit_installation permissions --operation "$INSTALL_OPERATION"
audit_installation check --operation "$INSTALL_OPERATION"

# Final database reset approval follows successful Audit preparation and all preflights.
if [[ "${INSTALL_OPERATION:-reset}" == reset && "${EXISTING_DATABASE:-0}" == 1 ]]; then
        printf '%s\n' 'Existing local mysql_siem database detected.' \
            'Reinstallation permanently deletes all events, metrics, alerts and database records.'
        printf 'Type RESET to continue: '
        IFS= read -r reset_answer || die "Reset cancelled; Audit preparation may already have completed; no database reset was performed."
        [[ "$reset_answer" == RESET ]] || die "Reset cancelled; Audit preparation may already have completed; no database reset was performed."
        SIEM_DATABASE_RESET_APPROVED=1
fi

if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then
    local_identity_setup begin
else
    local_identity_setup begin --reset
fi
exec 8< /usr/local/lib/.mysql_siem-local/runtime.lock
flock -x -w 30 8 || die "Runtime jobs did not stop; collection remains paused."
export SIEM_INSTALL_MAINTENANCE=1

# Prepare and verify snapshot logs under both inherited locks, before database changes.
SNAPSHOT_LOGS_SETUP_STARTED=1
service_installation snapshot-logs "$INSTALL_USER"

# Normal service enablement follows successful checks; never use it to pass them.
log "Starting services."
systemctl enable --now mysql
systemctl enable --now cron
systemctl enable --now rsyslog

# Upgrade preserves history; the original reset path still requires explicit consent.
DATABASE_SETUP_STARTED=1
service_installation database-started
if [[ "${INSTALL_OPERATION:-reset}" == upgrade ]]; then
    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m config.reset_installation upgrade --project "$PROJECT_DIR"
else
    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m config.reset_installation reset --project "$PROJECT_DIR"
fi

# Both schema paths have installed or verified every current table and rule.
DETECTION_READY=1

# Source IP Analysis schema: validate the fresh migrated structure.
PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" - <<'PY_CHECK_SOURCES'
import os
import pymysql
from database.schema import validate_source_ips_schema

conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database=os.environ["DB_NAME"])
try:
    validate_source_ips_schema(conn)
finally:
    conn.close()
PY_CHECK_SOURCES
SOURCE_IP_ANALYSIS_READY=1

# Port Activity Analysis schema: validate before grants and scheduling.
PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" - <<'PY_CHECK_PORTS'
import os
import pymysql
from analysis.ufw.ports import PortAnalysisError, validate_ports_schema

conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database=os.environ["DB_NAME"])
try:
    validate_ports_schema(conn)
except PortAnalysisError as error:
    raise SystemExit(str(error))
finally:
    conn.close()
PY_CHECK_PORTS
PORT_ANALYSIS_READY=1

# Traffic tables are already provisioned from the current schema.
PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" - <<'PY_CHECK_TRAFFIC'
import os
import pymysql
from analysis.ufw.traffic import TrafficAnalysisError, validate_traffic_schema

conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database=os.environ["DB_NAME"])
try:
    validate_traffic_schema(conn)
except TrafficAnalysisError as error:
    raise SystemExit(str(error))
finally:
    conn.close()
PY_CHECK_TRAFFIC
TRAFFIC_ANALYSIS_READY=1

# SSH schema: the fresh initializer has also installed both detection rules.
SSH_READY=1

# Grant privileges only after the tables have been created.
# Do not grant global privileges to the database user.
"$APP_PYTHON" - <<'PY'
import os
import pymysql

db_name = os.environ["DB_NAME"]
db_user = os.environ["DB_USER"]

grants = {
    "filesystem_metrics": "SELECT, INSERT, UPDATE",
    "security_metrics": "SELECT, INSERT, UPDATE",
    "system_metrics": "SELECT, INSERT",
    "process_events": "SELECT, INSERT",
    "service_events": "SELECT, INSERT",
    "process_state": "SELECT, INSERT, DELETE",
    "service_state": "SELECT, INSERT, DELETE",
    "collector_snapshots": "SELECT, INSERT, UPDATE",
    "audit_events": "SELECT, INSERT",
    "audit_checkpoints": "SELECT, INSERT, UPDATE",
    "audit_targets": "SELECT",
    "analysis_ufw_ports": "SELECT, INSERT, DELETE",
    "analysis_ufw_traffic": "SELECT, INSERT, UPDATE",
    "analysis_ufw_traffic_daily": "SELECT, INSERT, UPDATE",
    "ufw_log": "SELECT, INSERT",
    "ufw_state": "SELECT, INSERT, UPDATE",
}

conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root")
try:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s",
            (db_name,),
        )
        actual = {row[0] for row in cur.fetchall()}
        # Runtime jobs can resolve approved bindings but cannot enroll hosts,
        # approve collectors, edit sender identities or manage certificates.
        for table in ("schema_migrations", "hosts", "log_sources", "collectors", "collector_sources", "sender_identities", "sender_sources"):
            if table in actual:
                grants[table] = "SELECT"
        if "alert_hosts" in actual:
            grants["alert_hosts"] = "SELECT, INSERT"
        dns_tables = {"dns_sources", "dns_events", "dns_collection_state"}
        if dns_tables <= actual:
            grants.update({
                "dns_sources": "SELECT, INSERT, UPDATE",
                "dns_events": "SELECT, INSERT, DELETE",
                "dns_collection_state": "SELECT, INSERT, UPDATE",
            })
        if dns_tables <= actual and "dns_client_filters" in actual:
            grants["dns_client_filters"] = "SELECT, INSERT, UPDATE, DELETE"
        if dns_tables <= actual and "dns_domain_filters" in actual:
            grants["dns_domain_filters"] = "SELECT, INSERT, UPDATE, DELETE"
        detection_tables = {"detection_rules", "detection_alerts", "alert_evidence", "detection_state"}
        if detection_tables <= actual:
            grants.update({
                "detection_rules": "SELECT",
                "detection_alerts": "SELECT, INSERT, UPDATE",
                "alert_evidence": "SELECT, INSERT",
                "detection_state": "SELECT, INSERT, UPDATE",
            })
        if {"auth_events", "auth_ingestion_state"} <= actual:
            grants.update({
                "auth_events": "SELECT, INSERT",
                "auth_ingestion_state": "SELECT, INSERT, UPDATE",
            })
        if "analysis_source_ips" in actual:
            grants["analysis_source_ips"] = "SELECT, INSERT, DELETE"
        for table, privileges in grants.items():
            cur.execute(
                f"GRANT {privileges} ON `{db_name}`.`{table}` "
                f"TO '{db_user}'@'localhost'"
            )
finally:
    conn.close()
PY

log "Preparing local identities; collection remains paused until installation completes."
local_identity_setup prepare
verify_local_identity

# Only the approved installer performs privileged Audit preparation, while all
# runtime jobs are behind the existing maintenance barrier. Never reload all
# audit rules or erase other programs' rules. Conflicts leave maintenance intact.
audit_installation prepare

# Publish only after copying, dependencies, database and identity checks succeeded.
activate_service_installation
verify_local_identity

# Use the shipped environment loader; keep one implementation of DNS loading.

chmod 750 "$PROJECT_DIR/config/run_with_env.sh"

# Schedule one bounded detection pass; the application holds a database lock.
PORT_SCAN_CRON=""
if [[ "$DETECTION_READY" == "1" ]]; then
    if [[ ! -f "$PROJECT_DIR/config/port_scan.env" ]]; then
        cp "$PROJECT_DIR/config/port_scan.env.example" "$PROJECT_DIR/config/port_scan.env"
    fi
    chmod 600 "$PROJECT_DIR/config/port_scan.env"
    chown "$INSTALL_USER:$INSTALL_USER" "$PROJECT_DIR/config/port_scan.env"
    prepare_runtime_log "$PROJECT_DIR/detection/port_scan/cron.log"
    PORT_SCAN_CRON="* * * * * cd \"$PROJECT_DIR\" && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --port-scan \"$APP_PYTHON\" -m detection.port_scan.main --log-file \"$PROJECT_DIR/detection/port_scan/cron.log\""
fi

# DNS is optional: configured installations use the same interpreter and cron block.
DNS_CRON=""
if [[ -f "$PROJECT_DIR/config/adguard.env" ]]; then
    chmod 600 "$PROJECT_DIR/config/adguard.env"
    chown "$INSTALL_USER:$INSTALL_USER" "$PROJECT_DIR/config/adguard.env"
    log "Validating DNS settings and registering the configured source."
    "$PROJECT_DIR/config/run_with_env.sh" --dns "$APP_PYTHON" -m ingestion.dns.main --register-source
    DNS_CRON="*/5 * * * * cd \"$PROJECT_DIR\" && PYTHONPATH=\"$PROJECT_DIR\" /usr/bin/timeout --signal=TERM 270s \"$PROJECT_DIR/config/run_with_env.sh\" --dns \"$APP_PYTHON\" -m ingestion.dns.main >> \"$PROJECT_DIR/ingestion/dns/cron.log\" 2>&1"
    prepare_runtime_log "$PROJECT_DIR/ingestion/dns/cron.log"
    log "DNS cron configured; new sources must be explicitly enabled before collection."
else
    log "DNS cron skipped: configure config/adguard.env to enable integration."
fi

# Schedule the SSH jobs independently; missing auth.log is a logged skip.
SSH_AUTH_CRON=""
SSH_DETECTION_CRON=""
if [[ "${SSH_READY:-0}" == "1" ]]; then
    if [[ ! -f "$PROJECT_DIR/config/ssh.env" ]]; then
        cp "$PROJECT_DIR/config/ssh.env.example" "$PROJECT_DIR/config/ssh.env"
    fi
    chmod 600 "$PROJECT_DIR/config/ssh.env"
    chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" "$PROJECT_DIR/config/ssh.env"
    SSH_LOG_SOURCE="$("$PROJECT_DIR/config/run_with_env.sh" --ssh "$APP_PYTHON" -c 'import os; print(os.getenv("SSH_AUTH_LOGFILE", "/var/log/auth.log"))')"
    SSH_LOG_READABLE=1
    if [[ ! -e "$SSH_LOG_SOURCE" ]]; then
        warn "SSH log source absent: $SSH_LOG_SOURCE; the SSH collector will report SKIPPED until it appears."
    elif ! runuser -u "$INSTALL_USER" -- /usr/bin/head -c 1 "$SSH_LOG_SOURCE" >/dev/null; then
        SSH_LOG_READABLE=0
        warn "SSH log source is unreadable by mysql_siem: $SSH_LOG_SOURCE. SSH collection and detection will NOT be scheduled."
        warn "Check log ACLs, directory permissions and any access controls separately; do not loosen log permissions."
    fi
    if [[ "$SSH_LOG_READABLE" == 1 ]]; then
        mkdir -p "$PROJECT_DIR/ingestion/auth" "$PROJECT_DIR/detection/ssh_brute_force"
        prepare_runtime_log "$PROJECT_DIR/ingestion/auth/cron.log"
        prepare_runtime_log "$PROJECT_DIR/detection/ssh_brute_force/cron.log"
        SSH_AUTH_CRON="* * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --ssh \"$APP_PYTHON\" -m ingestion.auth.main --allow-missing-source --log-file \"$PROJECT_DIR/ingestion/auth/cron.log\""
        SSH_DETECTION_CRON="* * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --ssh \"$APP_PYTHON\" -m detection.ssh_brute_force.main --automatic --log-file \"$PROJECT_DIR/detection/ssh_brute_force/cron.log\""
    fi
fi

# Schedule UFW Analysis; a single job runs the ready analyses with bounded logs.
UFW_ANALYSIS_CRON=""
UFW_ANALYSIS_OPTIONS=""
if [[ "${SOURCE_IP_ANALYSIS_READY:-0}" == "1" && "${PORT_ANALYSIS_READY:-0}" == "1" ]]; then
    UFW_ANALYSIS_OPTIONS="--all --recent-hours 3"
elif [[ "${PORT_ANALYSIS_READY:-0}" == "1" ]]; then
    UFW_ANALYSIS_OPTIONS="--ports --recent-hours 3"
elif [[ "${SOURCE_IP_ANALYSIS_READY:-0}" == "1" ]]; then
    UFW_ANALYSIS_OPTIONS="--recent-hours 2"
fi

if [[ "${TRAFFIC_ANALYSIS_READY:-0}" == "1" ]]; then
    if [[ "$UFW_ANALYSIS_OPTIONS" != "--all --recent-hours 3" ]]; then
        # --traffic combines with an explicitly selected legacy-compatible analysis.
        if [[ "$UFW_ANALYSIS_OPTIONS" == "--recent-hours 2" ]]; then
            UFW_ANALYSIS_OPTIONS="--source-ips --recent-hours 3"
        fi
        UFW_ANALYSIS_OPTIONS="${UFW_ANALYSIS_OPTIONS:+$UFW_ANALYSIS_OPTIONS }--traffic"
    fi
fi

if [[ -n "$UFW_ANALYSIS_OPTIONS" ]]; then
    mkdir -p "$PROJECT_DIR/analysis/ufw"
    prepare_runtime_log "$PROJECT_DIR/analysis/ufw/cron.log"
    UFW_ANALYSIS_CRON="*/5 * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" \"$APP_PYTHON\" -m analysis.ufw.main $UFW_ANALYSIS_OPTIONS --log-file \"$PROJECT_DIR/analysis/ufw/cron.log\""
fi

# Cron output files must remain writable after the source tree is locked down.
prepare_runtime_log "$PROJECT_DIR/ingestion/cron.log"
prepare_runtime_log "$PROJECT_DIR/metrics/system/cron.log"
prepare_runtime_log "$PROJECT_DIR/metrics/filesystem/cron.log"
prepare_runtime_log "$PROJECT_DIR/metrics/security/cron.log"
log "Checking Python syntax."
while IFS= read -r -d '' pyfile; do
    "$APP_PYTHON" -m py_compile "$pyfile"
done < <(find "$PROJECT_DIR" -type f -name '*.py' \
    -not -path '*/.git/*' -not -path '*/__pycache__/*' \
    -not -path '*/.venv/*' -not -path '*/venv/*' -print0)

log "Testing the application database connection."
"$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" - <<'PY'
import os
import pymysql

conn = pymysql.connect(
    host=os.environ["DB_HOST"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    database=os.environ["DB_NAME"],
    connect_timeout=5,
)
try:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_schema = DATABASE()")
        print("Database tables:", cur.fetchone()[0])
finally:
    conn.close()
PY

select_role_cron_jobs

# Update only this installation's marked cron block.
CRON_TMP="$(mktemp)"
trap 'rm -f "$CRON_TMP"' EXIT

if ! CRON_EXISTING="$(LC_ALL=C crontab -u "$INSTALL_USER" -l 2>"$CRON_TMP")"; then
    [[ "$(<"$CRON_TMP")" == "no crontab for $INSTALL_USER" ]] ||
        die "Cannot read the existing crontab; no cron changes were made."
    CRON_EXISTING=""
fi

printf '%s\n' "$CRON_EXISTING" |
    awk -v begin="$CRON_BEGIN" -v end="$CRON_END" -v project="$PROJECT_DIR" '
        $0 == begin { skip=1; next }
        $0 == end   { skip=0; next }
        !skip && index($0, project "/analysis/daily_counts/") && $0 !~ /^[[:space:]]*#/ { next }
        !skip && index($0, "cd \"" project "\"") && $0 ~ /analysis\/daily_counts\// && $0 !~ /^[[:space:]]*#/ { next }
        !skip { print }
    ' > "$CRON_TMP"

cat >> "$CRON_TMP" <<CRON
$CRON_BEGIN
* * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" "$PROJECT_DIR/ingestion/ufw_to_mysql.py" >> "$PROJECT_DIR/ingestion/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" "$PROJECT_DIR/metrics/system/main.py" >> "$PROJECT_DIR/metrics/system/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" "$PROJECT_DIR/metrics/filesystem/main.py" >> "$PROJECT_DIR/metrics/filesystem/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" -m metrics.security.main >> "$PROJECT_DIR/metrics/security/cron.log" 2>&1
* * * * * cd "$PROJECT_DIR" && umask 077 && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" -m metrics.processes.main --log-file "/var/log/mysql_siem/processes/cron.log"
* * * * * cd "$PROJECT_DIR" && umask 077 && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" "$APP_PYTHON" -m metrics.services.main --log-file "/var/log/mysql_siem/services/cron.log"
${UFW_ANALYSIS_CRON:-}
$PORT_SCAN_CRON
${SSH_AUTH_CRON:-}
${SSH_DETECTION_CRON:-}
$DNS_CRON
$CRON_END
CRON

local_identity_setup schedule --cron-file "$CRON_TMP"
crontab -u "$INSTALL_USER" "$CRON_TMP"
# Audit uses a fixed status preflight then permanently drops root. The service
# account receives no sudo/capabilities and all DB work uses run_with_env.sh.
audit_installation activate
local_identity_setup finish
unset SIEM_INSTALL_MAINTENANCE
rm -f "$CRON_TMP"
trap - EXIT

log "Installation steps completed. Installed official commit $SIEM_BOOTSTRAP_COMMIT."
log "Cron: sudo crontab -u $INSTALL_USER -l"
if [[ "${SSH_LOG_READABLE:-1}" == 0 ]]; then
    warn "SSH ingestion and SSH detection were not enabled: unreadable SSH log source."
fi
log "Check the UFW log source and permissions before production use."
log "Audit: systemctl status mysql-siem-audit.timer; validate live auditd/service-user/MySQL behavior before production."
