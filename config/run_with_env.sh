#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

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

load_adguard_env() {
    local env_file="$PROJECT_DIR/config/adguard.env"
    local line key value

    if [[ ! -r "$env_file" ]]; then
        printf 'Cannot read DNS configuration file.\n' >&2
        return 1
    fi
    unset ADGUARD_URL ADGUARD_USERNAME ADGUARD_PASSWORD ADGUARD_SOURCE_NAME
    unset ADGUARD_CONNECT_TIMEOUT ADGUARD_READ_TIMEOUT ADGUARD_PAGE_SIZE
    unset ADGUARD_CA_BUNDLE
    unset DNS_MAX_PAGES DNS_MAX_SECONDS DNS_OVERLAP_SECONDS DNS_SETTLE_SECONDS
    unset DNS_RETENTION_DAYS DNS_MAX_GROUP_EVENTS
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" || "$line" == \#* ]]; then
            continue
        fi
        if [[ "$line" != *=* ]]; then
            printf 'Invalid DNS configuration line.\n' >&2
            return 1
        fi
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            ADGUARD_URL|ADGUARD_USERNAME|ADGUARD_PASSWORD|ADGUARD_SOURCE_NAME|\
            ADGUARD_CONNECT_TIMEOUT|ADGUARD_READ_TIMEOUT|ADGUARD_PAGE_SIZE|\
            ADGUARD_CA_BUNDLE|DNS_MAX_PAGES|DNS_MAX_SECONDS|DNS_OVERLAP_SECONDS|\
            DNS_SETTLE_SECONDS|DNS_RETENTION_DAYS|DNS_MAX_GROUP_EVENTS)
                export "$key=$value"
                ;;
            *)
                printf 'Unknown DNS configuration key.\n' >&2
                return 1
                ;;
        esac
    done < "$env_file"
    if [[ -z "${ADGUARD_URL:-}" || -z "${ADGUARD_USERNAME:-}" ||
          -z "${ADGUARD_PASSWORD:-}" ]]; then
        printf 'Required DNS setting is missing.\n' >&2
        return 1
    fi
}

# Local identity maintenance barrier. The descriptor survives exec of every job.
LOCAL_STATE_DIR=/usr/local/lib/.mysql_siem-local
if [[ "$EUID" == 0 && "${SIEM_INSTALL_MAINTENANCE:-}" == 1 ]]; then
    /usr/bin/python3 -I -B - "$PROJECT_DIR" "$LOCAL_STATE_DIR" <<'PY_MAINTENANCE'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from config.installation_state import require_maintenance
require_maintenance(Path(sys.argv[2]))
PY_MAINTENANCE
else
    if [[ -e "$LOCAL_STATE_DIR/required" || -e "$LOCAL_STATE_DIR/deployment.json" || -e "$LOCAL_STATE_DIR/maintenance" ]]; then
        [[ -f "$LOCAL_STATE_DIR/runtime.lock" && ! -L "$LOCAL_STATE_DIR/runtime.lock" ]] || {
            printf 'Required runtime lock is missing; job skipped.\n' >&2; exit 75;
        }
    fi
    if [[ -e "$LOCAL_STATE_DIR/runtime.lock" ]]; then
        [[ ! -L "$LOCAL_STATE_DIR/runtime.lock" ]] || exit 1
        exec 8< "$LOCAL_STATE_DIR/runtime.lock"
        flock -s -n 8 || { printf 'Local identity maintenance: job skipped.\n' >&2; exit 75; }
    fi
    [[ ! -e "$LOCAL_STATE_DIR/maintenance" ]] || { printf 'Local identity setup is incomplete; job skipped.\n' >&2; exit 75; }
fi

load_mysql_env "$PROJECT_DIR/config/mysql.env"

load_identity_env() {
    local env_file="$PROJECT_DIR/config/identity.env"
    local line key value required=0
    local -A identity_keys=()
    unset SIEM_COLLECTOR_ID SIEM_UFW_SOURCE_ID SIEM_AUTH_SOURCE_ID SIEM_DNS_SOURCE_ID
    unset SIEM_PROCESSES_SOURCE_ID SIEM_SERVICES_SOURCE_ID SIEM_AUDIT_SOURCE_ID
    unset SIEM_SYSTEM_SOURCE_ID SIEM_FILESYSTEM_SOURCE_ID SIEM_SECURITY_SOURCE_ID SIEM_LOCAL_IDENTITY_REQUIRED
    [[ ! -e "$LOCAL_STATE_DIR/required" ]] || required=1
    [[ ! -L "$env_file" ]] || { printf 'Unsafe identity configuration link.\n' >&2; return 1; }
    if [[ ! -f "$env_file" ]]; then
        [[ "$required" == 0 ]] || { printf 'Required local identity configuration is missing.\n' >&2; return 1; }
        return 0
    fi
    if [[ "$required" == 1 ]]; then
        [[ "$(stat -c '%u:%a' "$env_file")" == 0:640 ]] || { printf 'Unsafe identity configuration permissions.\n' >&2; return 1; }
        export SIEM_LOCAL_IDENTITY_REQUIRED=1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || { printf 'Invalid identity configuration.\n' >&2; return 1; }
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            SIEM_COLLECTOR_ID|SIEM_UFW_SOURCE_ID|SIEM_AUTH_SOURCE_ID|SIEM_DNS_SOURCE_ID|\
            SIEM_SYSTEM_SOURCE_ID|SIEM_FILESYSTEM_SOURCE_ID|SIEM_SECURITY_SOURCE_ID|SIEM_PROCESSES_SOURCE_ID|SIEM_SERVICES_SOURCE_ID|SIEM_AUDIT_SOURCE_ID)
                [[ -z "${identity_keys[$key]:-}" && "$value" =~ ^[1-9][0-9]*$ ]] || { printf 'Invalid or duplicate identity setting.\n' >&2; return 1; }
                identity_keys[$key]=1
                export "$key=$value" ;;
            *) printf 'Unknown identity configuration key.\n' >&2; return 1 ;;
        esac
    done < "$env_file"
    if [[ "$required" == 1 ]]; then
        for key in SIEM_COLLECTOR_ID SIEM_UFW_SOURCE_ID SIEM_AUTH_SOURCE_ID SIEM_SYSTEM_SOURCE_ID SIEM_FILESYSTEM_SOURCE_ID SIEM_SECURITY_SOURCE_ID SIEM_PROCESSES_SOURCE_ID SIEM_SERVICES_SOURCE_ID SIEM_AUDIT_SOURCE_ID; do
            [[ -n "${!key:-}" ]] || { printf 'A required local identity binding is missing.\n' >&2; return 1; }
        done
    fi
}
load_identity_env

load_port_scan_env() {
    local env_file="$PROJECT_DIR/config/port_scan.env"
    local line key value
    [[ -f "$env_file" ]] || return 0
    unset PORT_SCAN_BATCH_SIZE PORT_SCAN_LATE_SECONDS PORT_SCAN_MAX_BUFFER_EVENTS
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || { printf 'Invalid port-scan configuration.\n' >&2; return 1; }
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            PORT_SCAN_BATCH_SIZE|PORT_SCAN_LATE_SECONDS|PORT_SCAN_MAX_BUFFER_EVENTS)
                export "$key=$value" ;;
            *) printf 'Unknown port-scan configuration key.\n' >&2; return 1 ;;
        esac
    done < "$env_file"
}

load_ssh_env() {
    local env_file="$PROJECT_DIR/config/ssh.env"
    local line key value
    unset SSH_AUTH_LOGFILE SSH_AUTH_COLLECTOR_ID
    unset SSH_BRUTE_FORCE_BATCH_SIZE SSH_BRUTE_FORCE_LATE_SECONDS SSH_BRUTE_FORCE_MAX_BUFFER_EVENTS
    [[ -f "$env_file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || { printf 'Invalid SSH configuration.\n' >&2; return 1; }
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            SSH_AUTH_LOGFILE|SSH_AUTH_COLLECTOR_ID|SSH_BRUTE_FORCE_BATCH_SIZE|SSH_BRUTE_FORCE_LATE_SECONDS|SSH_BRUTE_FORCE_MAX_BUFFER_EVENTS)
                export "$key=$value" ;;
            *) printf 'Unknown SSH configuration key.\n' >&2; return 1 ;;
        esac
    done < "$env_file"
}

# Explicit opt-in keeps unrelated collectors independent of DNS configuration.
if [[ "${1:-}" == "--dns" ]]; then
    shift
    load_adguard_env
fi
if [[ "${1:-}" == "--port-scan" ]]; then
    shift
    load_port_scan_env
fi
if [[ "${1:-}" == "--ssh" ]]; then
    shift
    load_ssh_env
fi
if [[ "$#" == "0" ]]; then
    printf 'A command is required.\n' >&2
    exit 1
fi
exec "$@"
