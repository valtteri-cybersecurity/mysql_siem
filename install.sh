
#!/usr/bin/env bash
# mysql_siem - Ubuntu installation and deployment
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
INSTALL_USER="${SUDO_USER:-${USER}}"
ENV_FILE="$PROJECT_DIR/config/mysql.env"

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

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

trap 'rc=$?; printf "[ERROR] Installation failed (exit %s, line %s).\n" "$rc" "${BASH_LINENO[0]:-?}" >&2; exit "$rc"' ERR

[[ $EUID -eq 0 ]] || die "Run: sudo bash install.sh"
id "$INSTALL_USER" >/dev/null 2>&1 || die "User not found: $INSTALL_USER"

for path in \
    database/schema.sql \
    database/schema.py \
    database/migrate.py \
    database/migration_steps.py \
    database/migrations/014_host_registry.sql \
    database/migrations/017_ufw_datetime_precision.sql \
    config/run_with_env.sh \
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

export DEBIAN_FRONTEND=noninteractive
log "Updating package lists."
apt-get update

log "Installing dependencies."
apt-get install -y \
    python3 python3-pymysql python3-requests mysql-server rsyslog cron \
    ca-certificates openssl coreutils

log "Starting services."
systemctl enable --now mysql
systemctl enable --now cron
systemctl enable --now rsyslog

/usr/bin/python3 -c 'import pymysql; print("PyMySQL OK")'

install -d -o "$INSTALL_USER" -g "$(id -gn "$INSTALL_USER")" \
    "$PROJECT_DIR/config"

# Create the secrets file only if it does not exist.
if [[ ! -f "$ENV_FILE" ]]; then
    DB_PASSWORD="$(openssl rand -hex 32)"
    {
        printf 'DB_HOST=localhost\n'
        printf 'DB_USER=%s\n' "$EXPECTED_DB_USER"
        printf 'DB_PASSWORD=%s\n' "$DB_PASSWORD"
        printf 'DB_NAME=%s\n' "$EXPECTED_DB_NAME"
    } > "$ENV_FILE"
    unset DB_PASSWORD
    log "Created a new database environment file."
else
    log "Keeping the existing mysql.env file."
fi

chmod 600 "$ENV_FILE"
chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" "$ENV_FILE"

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

/usr/bin/python3 - "$ENV_FILE" "$PROJECT_DIR/$SCHEMA_REL" <<'PY'
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
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
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

# Import the DDL schema if the database is new.
TABLE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}'")"

if [[ "$TABLE_COUNT" == "0" ]]; then
    log "Importing database schema."
    /usr/bin/mysql --protocol=socket "$EXPECTED_DB_NAME" < "$PROJECT_DIR/$SCHEMA_REL"
fi

# Provision current UFW summaries before checking or scheduling them.
ensure_schema() {
    PYTHONPATH="$PROJECT_DIR" /usr/bin/python3 -m database.schema "$1"
}

# Read-only preflight: all migrations, including 017, must already be applied.
# The administrator uses database.migrate to make changes during maintenance.
PYTHONPATH="$PROJECT_DIR" /usr/bin/python3 -m database.migrate check --admin-socket /run/mysqld/mysqld.sock || \
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
/usr/bin/python3 - <<'PY'
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
PYTHONPATH="$PROJECT_DIR" /usr/bin/python3 - <<'PY_CHECK_PORTS'
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
PYTHONPATH="$PROJECT_DIR" /usr/bin/python3 - <<'PY_CHECK_TRAFFIC'
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
/usr/bin/python3 - <<'PY'
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

# Use the shipped environment loader; keep one implementation of DNS loading.

chmod 750 "$PROJECT_DIR/config/run_with_env.sh"
chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" \
    "$PROJECT_DIR/config/run_with_env.sh"

# Schedule one bounded detection pass; the application holds a database lock.
PORT_SCAN_CRON=""
if [[ "$DETECTION_READY" == "1" ]]; then
    if [[ ! -f "$PROJECT_DIR/config/port_scan.env" ]]; then
        cp "$PROJECT_DIR/config/port_scan.env.example" "$PROJECT_DIR/config/port_scan.env"
    fi
    chmod 600 "$PROJECT_DIR/config/port_scan.env"
    touch "$PROJECT_DIR/detection/port_scan/cron.log"
    chmod 600 "$PROJECT_DIR/detection/port_scan/cron.log"
    PORT_SCAN_CRON="* * * * * cd \"$PROJECT_DIR\" && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --port-scan /usr/bin/python3 -m detection.port_scan.main --log-file \"$PROJECT_DIR/detection/port_scan/cron.log\""
fi

# DNS is optional: configured installations use the same interpreter and cron block.
DNS_CRON=""
if [[ -f "$PROJECT_DIR/config/adguard.env" ]]; then
    chmod 600 "$PROJECT_DIR/config/adguard.env"
    log "Validating DNS settings and registering the configured source."
    "$PROJECT_DIR/config/run_with_env.sh" --dns /usr/bin/python3 -m ingestion.dns.main --register-source
    DNS_CRON="*/5 * * * * cd \"$PROJECT_DIR\" && PYTHONPATH=\"$PROJECT_DIR\" /usr/bin/timeout --signal=TERM 270s \"$PROJECT_DIR/config/run_with_env.sh\" --dns /usr/bin/python3 -m ingestion.dns.main >> \"$PROJECT_DIR/ingestion/dns/cron.log\" 2>&1"
    touch "$PROJECT_DIR/ingestion/dns/cron.log"
    chmod 600 "$PROJECT_DIR/ingestion/dns/cron.log"
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
    SSH_LOG_SOURCE="$("$PROJECT_DIR/config/run_with_env.sh" --ssh /usr/bin/python3 -c 'import os; print(os.getenv("SSH_AUTH_LOGFILE", "/var/log/auth.log"))')"
    if [[ ! -e "$SSH_LOG_SOURCE" ]]; then
        warn "SSH log source absent; collection will report SKIPPED until it appears."
    elif ! runuser -u "$INSTALL_USER" -- test -r "$SSH_LOG_SOURCE"; then
        warn "SSH log source is not readable by the application user. Review log-group access separately."
    fi
    mkdir -p "$PROJECT_DIR/ingestion/auth" "$PROJECT_DIR/detection/ssh_brute_force"
    touch "$PROJECT_DIR/ingestion/auth/cron.log" "$PROJECT_DIR/detection/ssh_brute_force/cron.log"
    chmod 600 "$PROJECT_DIR/ingestion/auth/cron.log" "$PROJECT_DIR/detection/ssh_brute_force/cron.log"
    SSH_AUTH_CRON="* * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --ssh /usr/bin/python3 -m ingestion.auth.main --allow-missing-source --log-file \"$PROJECT_DIR/ingestion/auth/cron.log\""
    SSH_DETECTION_CRON="* * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" --ssh /usr/bin/python3 -m detection.ssh_brute_force.main --automatic --log-file \"$PROJECT_DIR/detection/ssh_brute_force/cron.log\""
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
    touch "$PROJECT_DIR/analysis/ufw/cron.log"
    chmod 600 "$PROJECT_DIR/analysis/ufw/cron.log"
    UFW_ANALYSIS_CRON="*/5 * * * * cd \"$PROJECT_DIR\" && umask 077 && PYTHONPATH=\"$PROJECT_DIR\" \"$PROJECT_DIR/config/run_with_env.sh\" /usr/bin/python3 -m analysis.ufw.main $UFW_ANALYSIS_OPTIONS --log-file \"$PROJECT_DIR/analysis/ufw/cron.log\""
fi

# Set application ownership without changing ownership of .git.
find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o \
    -type f ! -path "$ENV_FILE" -exec chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" {} +
find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o \
    -type d ! -path "$PROJECT_DIR/config" -exec chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" {} +

log "Checking Python syntax."
while IFS= read -r -d '' pyfile; do
    /usr/bin/python3 -m py_compile "$pyfile"
done < <(find "$PROJECT_DIR" -type f -name '*.py' \
    -not -path '*/.git/*' -not -path '*/__pycache__/*' \
    -not -path '*/.venv/*' -not -path '*/venv/*' -print0)

log "Testing the application database connection."
"$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 - <<'PY'
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

# Update only this installation's marked cron block.
CRON_TMP="$(mktemp)"
trap 'rm -f "$CRON_TMP"' EXIT

(crontab -u "$INSTALL_USER" -l 2>/dev/null || true) |
    awk -v begin="$CRON_BEGIN" -v end="$CRON_END" -v project="$PROJECT_DIR" '
        $0 == begin { skip=1; next }
        $0 == end   { skip=0; next }
        !skip && index($0, project "/analysis/daily_counts/") && $0 !~ /^[[:space:]]*#/ { next }
        !skip && index($0, "cd \"" project "\"") && $0 ~ /analysis\/daily_counts\// && $0 !~ /^[[:space:]]*#/ { next }
        !skip { print }
    ' > "$CRON_TMP"

cat >> "$CRON_TMP" <<CRON
$CRON_BEGIN
* * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/ingestion/ufw_to_mysql.py" >> "$PROJECT_DIR/ingestion/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/metrics/system/main.py" >> "$PROJECT_DIR/metrics/system/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/metrics/filesystem/main.py" >> "$PROJECT_DIR/metrics/filesystem/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 -m metrics.security.main >> "$PROJECT_DIR/metrics/security/cron.log" 2>&1
${UFW_ANALYSIS_CRON:-}
$PORT_SCAN_CRON
${SSH_AUTH_CRON:-}
${SSH_DETECTION_CRON:-}
$DNS_CRON
$CRON_END
CRON

crontab -u "$INSTALL_USER" "$CRON_TMP"
rm -f "$CRON_TMP"
trap - EXIT

log "Installation steps completed."
log "Cron: sudo crontab -u $INSTALL_USER -l"
log "Check the UFW log source and permissions before production use."
