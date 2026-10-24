#!/usr/bin/env bash
# mysql_siem - Debian 13, Ubuntu and Linux Mint installation
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP_NAME="mysql_siem"
readonly EXPECTED_DB_NAME="mysql_siem"
readonly EXPECTED_DB_USER="pythonuser"
readonly SCHEMA_REL="database/schema.sql"
readonly CRON_BEGIN="# BEGIN mysql_siem managed jobs"
readonly CRON_END="# END mysql_siem managed jobs"

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE_DIR="$PROJECT_DIR"
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

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Installation role selection (before any installation changes).
select_installation_role() {
    local selection stored_role="" role_directory found_role
    for role_directory in "$PROJECT_DIR" "${SERVICE_DIR:-$PROJECT_DIR}"; do
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
        die "Usage: sudo bash install.sh [--role server|collector]"
    fi

    case "$INSTALL_ROLE" in
        server|collector) ;;
        *) die "Invalid installation role; use server or collector." ;;
    esac
    if [[ -n "$stored_role" && "$INSTALL_ROLE" != "$stored_role" ]]; then
        die "Installation role conflict; the stored role will not be changed."
    fi
    if [[ -z "$stored_role" && "$INSTALL_ROLE" == server ]]; then
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
    STAGED_PROJECT_DIR="$(service_installation stage "$SOURCE_DIR" "$SERVICE_DIR" "$INSTALL_USER" "$INSTALL_ROLE")"
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
    if [[ "${LOCAL_DEPLOYMENT_STARTED:-0}" == 1 && "${SERVICE_PUBLISHED:-0}" != 1 ]]; then
        service_installation discard || warn "Prepared deployment retained; keep maintenance and recovery files and rerun install.sh --role server."
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
        --project "$PROJECT_DIR" --installed "$SERVICE_DIR" --user "$INSTALL_USER"
}
verify_local_identity() {
    runuser -u "$INSTALL_USER" -- env PYTHONPATH="$PROJECT_DIR" \
        "$APP_PYTHON" -m database.local_identity verify --project "$PROJECT_DIR"
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
    validate_virtualenv_location
    VENV_BUILD_DIR="$(service_installation environment)"
    APP_PYTHON="$VENV_BUILD_DIR/bin/python"
    # This is the environment's final physical location; never relocate a venv.
    (
        umask 022
        cd /
        /usr/bin/python3 -I -m venv --copies "$VENV_BUILD_DIR"
        "$APP_PYTHON" -I -m pip install -r "$PROJECT_DIR/requirements-dns.txt"
        "$APP_PYTHON" -I -m pip check
    )
    validate_virtualenv_location "$VENV_BUILD_DIR" candidate
    system_version="$(/usr/bin/python3 -I -c 'import sys; print(sys.version_info[:2])')"
    candidate_version="$("$APP_PYTHON" -I -c 'import sys; print(sys.version_info[:2])')"
    [[ "$system_version" == "$candidate_version" ]] || die "Virtual environment Python version mismatch."
    runuser -u "$INSTALL_USER" -- "$APP_PYTHON" -I -c 'import pymysql, requests, cryptography'
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
# Grant the service account read access to Debian/Ubuntu system logs.
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

    for source in /var/log/auth.log /var/log/ufw.log; do
        if [[ -e "$source" ]]; then
            runuser -u "$INSTALL_USER" -- test -r "$source" ||
                die "mysql_siem cannot read $source even with adm membership."
        else
            warn "Log source does not exist yet: $source"
        fi
    done
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

trap 'rc=$?; printf "[ERROR] Installation failed (exit %s, line %s). Keep maintenance/recovery files and rerun install.sh --role server after correcting the error.\n" "$rc" "${BASH_LINENO[0]:-?}" >&2; exit "$rc"' ERR

select_installation_role "$@"
if [[ "$INSTALL_ROLE" == collector ]]; then
    die "SIEM Collector is not available yet. Current collectors require MySQL; HTTPS registration and event delivery are not implemented. No installation changes were made."
fi

[[ $EUID -eq 0 ]] || die "Run: sudo bash install.sh"

for path in \
    requirements-dns.txt \
    config/service_installation.py \
    config/installation_state.py \
    database/local_identity.py \
    database/schema.sql \
    database/schema.py \
    database/migrate.py \
    database/migration_steps.py \
    database/migrations/014_host_registry.sql \
    database/migrations/017_ufw_datetime_precision.sql \
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
    analysis/ufw/__init__.py \
    analysis/ufw/source_ips.py \
    analysis/ufw/ports.py \
    analysis/ufw/main.py \
    analysis/ufw/traffic.py
do
    [[ -f "$PROJECT_DIR/$path" ]] || die "Required file is missing: $path"
done

# Recheck persistent roles before creating even the installation lock.
service_installation check "$SOURCE_DIR" "$SERVICE_DIR" "$INSTALL_USER"
[[ ! -L /usr/local/lib/.mysql_siem-install.lock ]] || die "Unsafe installation lock link."
exec 9>> /usr/local/lib/.mysql_siem-install.lock
flock -n 9 || die "Another mysql_siem installation is running."
# A pending publication may need rollback before a new service copy is staged.
if [[ -e /usr/local/lib/.mysql_siem-local/maintenance ]]; then
    [[ ! -L /usr/local/lib/.mysql_siem-local/runtime.lock ]] || die "Unsafe runtime lock link."
    exec 8< /usr/local/lib/.mysql_siem-local/runtime.lock
    flock -x -w 30 8 || die "Runtime jobs did not stop; collection remains paused."
fi
service_installation check "$SOURCE_DIR" "$SERVICE_DIR" "$INSTALL_USER"
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

local_identity_setup begin
exec 8< /usr/local/lib/.mysql_siem-local/runtime.lock
flock -x -w 30 8 || die "Runtime jobs did not stop; collection remains paused."
export SIEM_INSTALL_MAINTENANCE=1

log "Starting services."
systemctl enable --now mysql
systemctl enable --now cron
systemctl enable --now rsyslog

"$APP_PYTHON" -c 'import pymysql; print("PyMySQL OK")'

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

# Prepare tables before granting table-specific privileges.
# Do not reimport existing tables when rerunning the installer.
log "Checking database and schema."

# Keep generated credentials recoverable if database provisioning fails midway.
DATABASE_SETUP_STARTED=1
service_installation database-started
DB_SETUP_RESULT="$("$APP_PYTHON" - "$ENV_FILE" "$PROJECT_DIR/$SCHEMA_REL" <<'PY'
import os
import sys
import pymysql

env_file, schema_file = sys.argv[1:3]

# Read mysql.env as key-value pairs without executing its contents.
# Credentials are exported by the load_mysql_env function in install.sh.
password = os.environ["DB_PASSWORD"]
db_name = os.environ["DB_NAME"]
db_user = os.environ["DB_USER"]

conn = pymysql.connect(
    unix_socket="/run/mysqld/mysqld.sock",
    user="root",
    charset="utf8mb4",
    autocommit=True,
)
try:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=%s", (db_name,))
        if cur.fetchone()[0] == 0:
            # No IF NOT EXISTS: a concurrent creator must make this attempt fail.
            cur.execute(
                f"CREATE DATABASE `{db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            print("DATABASE_CREATED_THIS_RUN")
        cur.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema=%s",
            (db_name,),
        )
        table_count = cur.fetchone()[0]

        if table_count == 0:
            # The new database needs its table definitions.
            # Use the mysql CLI to import the schema in a separate step.
            print("SCHEMA_EMPTY")
        else:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=%s",
                (db_name,),
            )
            existing = {row[0] for row in cur.fetchall()}
            existing -= {"schema_migrations", "hosts", "host_groups", "host_group_members", "log_sources",
                         "collectors", "collector_sources", "sender_identities", "sender_sources",
                         "sender_certificates", "alert_hosts"}
            expected = {
                "filesystem_metrics", "security_metrics", "system_metrics",
                "ufw_log", "ufw_state",
            }
            dns_tables = {"dns_sources", "dns_events", "dns_collection_state"}
            detection_tables = {"detection_rules", "detection_alerts", "alert_evidence"}
            state_tables = {"detection_state"}
            client_filter_tables = {"dns_client_filters"}
            domain_filter_tables = {"dns_domain_filters"}
            auth_tables = {"auth_events", "auth_ingestion_state"}
            if existing & auth_tables not in (set(), auth_tables):
                raise SystemExit("The auth schema is incomplete; inspect it manually.")
            existing -= auth_tables
            existing.discard("analysis_source_ips")
            existing -= {"analysis_ufw_ports", "analysis_ufw_traffic", "analysis_ufw_traffic_daily"}
            existing -= {"ufw_daily_actions_counts", "top_attacking_ips", "top_targeted_ports"}
            if existing not in (
                expected, expected | dns_tables,
                expected | detection_tables, expected | dns_tables | detection_tables,
                expected | detection_tables | state_tables,
                expected | dns_tables | detection_tables | state_tables,
                expected | dns_tables | client_filter_tables,
                expected | dns_tables | detection_tables | client_filter_tables,
                expected | dns_tables | detection_tables | state_tables | client_filter_tables,
                expected | dns_tables | domain_filter_tables,
                expected | dns_tables | detection_tables | domain_filter_tables,
                expected | dns_tables | detection_tables | state_tables | domain_filter_tables,
                expected | dns_tables | client_filter_tables | domain_filter_tables,
                expected | dns_tables | detection_tables | client_filter_tables | domain_filter_tables,
                expected | dns_tables | detection_tables | state_tables | client_filter_tables | domain_filter_tables,
            ):
                raise SystemExit(
                    "The database has a partial or unexpected schema. "
                    f"Tables: {sorted(existing)}. Correct the schema manually before continuing. "
                    "Inspect the current definitions in database/schema.sql; existing legacy tables may remain."
                )
            print("SCHEMA_EXISTS")

        # Escape the SQL string using the connection's encoder.
        escaped_password = conn.escape(password)
        cur.execute(
            f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' "
            f"IDENTIFIED BY {escaped_password}"
        )
finally:
    conn.close()
PY
)"
printf '%s\n' "$DB_SETUP_RESULT"

# Import the DDL schema if the database is new.
TABLE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}'")"

if [[ "$TABLE_COUNT" == "0" ]]; then
    log "Importing database schema."
    /usr/bin/mysql --protocol=socket "$EXPECTED_DB_NAME" < "$PROJECT_DIR/$SCHEMA_REL"
fi

# Provision current UFW summaries before checking or scheduling them.
ensure_schema() {
    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m database.schema "$1"
}

# Only a database exclusively created by this attempt may migrate automatically.
# An existing empty or partially initialized database never enters this branch.
if [[ "$DB_SETUP_RESULT" == *$'DATABASE_CREATED_THIS_RUN\n'* && "$TABLE_COUNT" == "0" ]]; then
    log "Initializing migrations in the database created by this installation."
    PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m database.migrate apply --admin-socket /run/mysqld/mysqld.sock
fi

# Final preflight: all migrations, including 017, must be applied.
# The administrator uses database.migrate to make changes during maintenance.
PYTHONPATH="$PROJECT_DIR" "$APP_PYTHON" -m database.migrate check --admin-socket /run/mysqld/mysqld.sock || \
    die "Database migration 013-017 required. Stop jobs, back up, and apply the versioned migrations through database.migrate before retrying."

log "Checking and creating missing UFW Analysis tables."
ensure_schema analysis

# Create DNS tables once; preserve existing telemetry and reject partial schemas.
DNS_TABLE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}' AND table_name IN ('dns_sources', 'dns_events', 'dns_collection_state')")"

case "$DNS_TABLE_COUNT" in
    0)
        log "Creating DNS telemetry tables."
        ensure_schema dns
        ;;
    3)
        log "Keeping existing DNS telemetry tables."
        ;;
    *)
        die "The DNS schema is incomplete. Inspect it manually before retrying."
        ;;
esac

# DNS client filters: create once after the source tables exist.
DNS_CLIENT_FILTER_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}' AND table_name='dns_client_filters'")"

case "$DNS_CLIENT_FILTER_COUNT" in
    0)
        log "Creating DNS client filter table."
        ensure_schema dns-client-filters
        ;;
    1)
        log "Keeping existing DNS client filters."
        ;;
    *)
        die "Cannot verify the DNS client filter table. Inspect the schema before retrying."
        ;;
esac

# DNS domain filters: exact-name exclusions, independent of client rules.
DNS_DOMAIN_FILTER_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}' AND table_name='dns_domain_filters'")"

case "$DNS_DOMAIN_FILTER_COUNT" in
    0)
        log "Creating DNS domain filter table."
        ensure_schema dns-domain-filters
        ;;
    1)
        log "Keeping existing DNS domain filters."
        ;;
    *)
        die "Cannot verify the DNS domain filter table. Inspect the schema before retrying."
        ;;
esac

# Detection schema: automatic provisioning is restricted to a new database.
# Existing installations retain their current detection activation policy.
DETECTION_READY=0
if [[ "$TABLE_COUNT" == "0" ]]; then
    log "Creating detection tables in the new database."
    ensure_schema detection
    DETECTION_READY=1
else
    DETECTION_TABLE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
        -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}' AND table_name IN ('detection_rules', 'detection_alerts', 'alert_evidence', 'detection_state')")"
    if [[ "$DETECTION_TABLE_COUNT" == "4" ]]; then
        DETECTION_READY=1
    else
        warn "Detection not scheduled: its current tables are incomplete; inspect database/schema.sql."
    fi
fi

# Verify tables and migrate the existing ufw_state tracking columns.
"$APP_PYTHON" - <<'PY'
import os
import sys
import pymysql

expected = {
    "filesystem_metrics", "security_metrics", "system_metrics",
    "ufw_log", "ufw_state",
}
conn = pymysql.connect(
    unix_socket="/run/mysqld/mysqld.sock",
    user="root",
    database=os.environ["DB_NAME"],
)
try:
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES")
        actual = {row[0] for row in cur.fetchall()}
    actual -= {"schema_migrations", "hosts", "host_groups", "host_group_members", "log_sources",
               "collectors", "collector_sources", "sender_identities", "sender_sources",
               "sender_certificates", "alert_hosts"}
    dns_tables = {"dns_sources", "dns_events", "dns_collection_state"}
    detection_tables = {"detection_rules", "detection_alerts", "alert_evidence"}
    state_tables = {"detection_state"}
    client_filter_tables = {"dns_client_filters"}
    domain_filter_tables = {"dns_domain_filters"}
    auth_tables = {"auth_events", "auth_ingestion_state"}
    if actual & auth_tables not in (set(), auth_tables):
        raise SystemExit("The auth schema is incomplete; inspect it manually.")
    actual -= auth_tables
    actual.discard("analysis_source_ips")
    actual -= {"analysis_ufw_ports", "analysis_ufw_traffic", "analysis_ufw_traffic_daily"}
    actual -= {"ufw_daily_actions_counts", "top_attacking_ips", "top_targeted_ports"}
    if actual not in (
        expected, expected | dns_tables,
        expected | detection_tables, expected | dns_tables | detection_tables,
        expected | detection_tables | state_tables,
        expected | dns_tables | detection_tables | state_tables,
        expected | dns_tables | client_filter_tables,
        expected | dns_tables | detection_tables | client_filter_tables,
        expected | dns_tables | detection_tables | state_tables | client_filter_tables,
        expected | dns_tables | domain_filter_tables,
        expected | dns_tables | detection_tables | domain_filter_tables,
        expected | dns_tables | detection_tables | state_tables | domain_filter_tables,
        expected | dns_tables | client_filter_tables | domain_filter_tables,
        expected | dns_tables | detection_tables | client_filter_tables | domain_filter_tables,
        expected | dns_tables | detection_tables | state_tables | client_filter_tables | domain_filter_tables,
    ):
        raise SystemExit(
            f"Schema tables do not match. Missing: {sorted(expected-actual)}; "
            f"extra: {sorted(actual-expected)}. "
            "Inspect the current definitions in database/schema.sql; existing legacy tables may remain."
        )
    with conn.cursor() as cur:
        cur.execute("SHOW COLUMNS FROM ufw_state")
        columns = {}

        for row in cur.fetchall():
            columns[row[0]] = row

        if "file_device" not in columns and "file_inode" not in columns:
            cur.execute("""ALTER TABLE ufw_state
                MODIFY COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                ADD COLUMN file_device BIGINT UNSIGNED NULL,
                ADD COLUMN file_inode BIGINT UNSIGNED NULL,
                ADD UNIQUE KEY uq_ufw_state_file (file_device, file_inode)""")
            print("UFW_STATE_MIGRATED")
        elif "file_device" not in columns or "file_inode" not in columns:
            raise SystemExit("ufw_state: the file-identity schema is incomplete.")

        cur.execute("SHOW COLUMNS FROM ufw_state")
        columns = {}

        for row in cur.fetchall():
            columns[row[0]] = row

        for name in ("id", "file_device", "file_inode"):
            if columns[name][1].lower() != "bigint unsigned":
                raise SystemExit(f"ufw_state: column {name} must be BIGINT UNSIGNED.")

        if "auto_increment" not in columns["id"][5].lower():
            raise SystemExit("ufw_state: the id column is missing AUTO_INCREMENT.")

        cur.execute("SHOW INDEX FROM ufw_state WHERE Key_name = 'uq_ufw_state_file'")
        index_columns = {}

        for row in cur.fetchall():
            if row[1] != 0:
                raise SystemExit("ufw_state: the file-identity index must be unique.")
            index_columns[row[3]] = row[4]

        if index_columns not in ({1: "file_device", 2: "file_inode"},
                                 {1: "file_device", 2: "file_inode", 3: "source_scope"}):
            raise SystemExit("ufw_state: the file-identity index is missing or invalid.")
finally:
    conn.close()
PY

# Source IP Analysis schema: created and validated before the strict guard.
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

# SSH schema: provision new databases only; existing installations opt in manually.
SSH_READY=0
if [[ "$TABLE_COUNT" == "0" && "$DETECTION_READY" == "1" ]]; then
    log "Creating SSH telemetry and rule in the new database."
    ensure_schema auth
    SSH_READY=1
elif [[ "$DETECTION_READY" == "1" ]]; then
    SSH_TABLE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
        -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}' AND table_name IN ('auth_events', 'auth_ingestion_state')")"
    SSH_RULE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names "$EXPECTED_DB_NAME" \
        -e "SELECT COUNT(*) FROM detection_rules WHERE rule_key='SSH_BRUTE_FORCE_001'")"
    if [[ "$SSH_TABLE_COUNT" == "2" && "$SSH_RULE_COUNT" == "1" ]]; then
        SSH_READY=1
    else
        warn "SSH jobs not scheduled: its auth tables or rule are missing; inspect database/schema.sql."
    fi
else
    warn "SSH jobs not scheduled: the shared detection schema is required."
fi

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
    if [[ ! -e "$SSH_LOG_SOURCE" ]]; then
        warn "SSH log source absent; collection will report SKIPPED until it appears."
    elif ! runuser -u "$INSTALL_USER" -- test -r "$SSH_LOG_SOURCE"; then
        warn "SSH log source is not readable by the application user. Review log-group access separately."
    fi
    mkdir -p "$PROJECT_DIR/ingestion/auth" "$PROJECT_DIR/detection/ssh_brute_force"
    prepare_runtime_log "$PROJECT_DIR/ingestion/auth/cron.log"
    prepare_runtime_log "$PROJECT_DIR/detection/ssh_brute_force/cron.log"
    SSH_AUTH_CRON="* * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --ssh \"$APP_PYTHON\" -m ingestion.auth.main --allow-missing-source --log-file \"$PROJECT_DIR/ingestion/auth/cron.log\""
    SSH_DETECTION_CRON="* * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --ssh \"$APP_PYTHON\" -m detection.ssh_brute_force.main --automatic --log-file \"$PROJECT_DIR/detection/ssh_brute_force/cron.log\""
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
${UFW_ANALYSIS_CRON:-}
$PORT_SCAN_CRON
${SSH_AUTH_CRON:-}
${SSH_DETECTION_CRON:-}
$DNS_CRON
$CRON_END
CRON

local_identity_setup schedule --cron-file "$CRON_TMP"
crontab -u "$INSTALL_USER" "$CRON_TMP"
local_identity_setup finish
unset SIEM_INSTALL_MAINTENANCE
rm -f "$CRON_TMP"
trap - EXIT

log "Installation steps completed."
log "Cron: sudo crontab -u $INSTALL_USER -l"
log "Check the UFW log source and permissions before production use."
