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

load_mysql_env "$PROJECT_DIR/config/mysql.env"

# Explicit opt-in keeps unrelated collectors independent of DNS configuration.
if [[ "${1:-}" == "--dns" ]]; then
    shift
    load_adguard_env
fi
if [[ "$#" == "0" ]]; then
    printf 'A command is required.\n' >&2
    exit 1
fi
exec "$@"
