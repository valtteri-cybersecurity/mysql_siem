
#!/usr/bin/env bash
# mysql_siem - Ubuntu installation and deployment
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP_NAME="mysql_siem"
readonly EXPECTED_DB_NAME="ufw_monitor"
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

trap 'rc=$?; printf "[ERROR] Asennus epäonnistui (exit %s, rivi %s).\n" "$rc" "${BASH_LINENO[0]:-?}" >&2; exit "$rc"' ERR

[[ $EUID -eq 0 ]] || die "Suorita: sudo bash install.sh"
id "$INSTALL_USER" >/dev/null 2>&1 || die "Käyttäjää ei löydy: $INSTALL_USER"

for path in \
    database/schema.sql \
    ingestion/ufw_to_mysql.py \
    metrics/system/main.py \
    metrics/filesystem/main.py \
    metrics/security/main.py \
    analysis/attacking_ips/main.py \
    analysis/daily_counts/daily_counts.py \
    analysis/targeted_ports/main.py
do
    [[ -f "$PROJECT_DIR/$path" ]] || die "Pakollinen tiedosto puuttuu: $path"
done

export DEBIAN_FRONTEND=noninteractive
log "Päivitetään pakettiluettelo."
apt-get update

log "Asennetaan riippuvuudet."
apt-get install -y \
    python3 python3-pymysql mysql-server rsyslog cron \
    ca-certificates openssl

log "Käynnistetään palvelut."
systemctl enable --now mysql
systemctl enable --now cron
systemctl enable --now rsyslog

/usr/bin/python3 -c 'import pymysql; print("PyMySQL OK")'

install -d -o "$INSTALL_USER" -g "$(id -gn "$INSTALL_USER")" \
    "$PROJECT_DIR/config"

# Luo salaisuustiedosto vain, jos sitä ei ole.
if [[ ! -f "$ENV_FILE" ]]; then
    DB_PASSWORD="$(openssl rand -hex 32)"
    {
        printf 'DB_HOST=localhost\n'
        printf 'DB_USER=%s\n' "$EXPECTED_DB_USER"
        printf 'DB_PASSWORD=%s\n' "$DB_PASSWORD"
        printf 'DB_NAME=%s\n' "$EXPECTED_DB_NAME"
    } > "$ENV_FILE"
    unset DB_PASSWORD
    log "Luotiin uusi tietokannan ympäristötiedosto."
else
    log "Säilytetään olemassa oleva mysql.env."
fi

chmod 600 "$ENV_FILE"
chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" "$ENV_FILE"

# Lataa asetukset vasta erillisten vakioiden määrittelyn jälkeen.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

[[ "${DB_NAME:-}" == "$EXPECTED_DB_NAME" ]] ||
    die "mysql.env: DB_NAME-arvon pitää olla $EXPECTED_DB_NAME."
[[ "${DB_USER:-}" == "$EXPECTED_DB_USER" ]] ||
    die "mysql.env: DB_USER-arvon pitää olla $EXPECTED_DB_USER."
[[ -n "${DB_PASSWORD:-}" ]] || die "DB_PASSWORD puuttuu mysql.env-tiedostosta."
[[ "${DB_HOST:-}" == "localhost" ]] ||
    die "Tämä asennusversio edellyttää DB_HOST=localhost."

# Valmistellaan taulut ennen taulukohtaisten oikeuksien myöntämistä.
# Toistuvalla asennuksella olemassa olevia tauluja ei tuoda uudelleen.
log "Tarkistetaan tietokanta ja skeema."

/usr/bin/python3 - "$ENV_FILE" "$PROJECT_DIR/$SCHEMA_REL" <<'PY'
import os
import sys
import pymysql

env_file, schema_file = sys.argv[1:3]

# mysql.env on ylläpitäjän hallitsema shell-muotoinen tiedosto.
# Tunnukset tuodaan ympäristöstä install.sh:n source-komennolla.
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
            # Skeema sisältää vain CREATE TABLE -määritykset.
            # Käytetään mysql CLI:tä skeeman tuontiin erillisessä vaiheessa.
            print("SCHEMA_EMPTY")
        else:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=%s",
                (db_name,),
            )
            existing = {row[0] for row in cur.fetchall()}
            expected = {
                "filesystem_metrics", "security_metrics", "system_metrics",
                "top_attacking_ips", "top_targeted_ports",
                "ufw_daily_actions_counts", "ufw_log", "ufw_state",
            }
            if existing != expected:
                raise SystemExit(
                    "Tietokannassa on osittainen tai odottamaton skeema. "
                    f"Taulut: {sorted(existing)}. Korjaa käsin ennen jatkoa."
                )
            print("SCHEMA_EXISTS")

        # Turvallinen SQL-merkkijonon escape yhteyden omalla encoderilla.
        escaped_password = conn.escape(password)
        cur.execute(
            f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' "
            f"IDENTIFIED BY {escaped_password}"
        )
        cur.execute(
            f"ALTER USER '{db_user}'@'localhost' "
            f"IDENTIFIED BY {escaped_password}"
        )
finally:
    conn.close()
PY

# Jos tietokanta on uusi, tuo DDL-skeema.
TABLE_COUNT="$(/usr/bin/mysql --protocol=socket --batch --skip-column-names \
    -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${EXPECTED_DB_NAME}'")"

if [[ "$TABLE_COUNT" == "0" ]]; then
    log "Tuodaan tietokantaskeema."
    /usr/bin/mysql --protocol=socket "$EXPECTED_DB_NAME" < "$PROJECT_DIR/$SCHEMA_REL"
fi

# Varmista täsmälleen odotetut taulut.
/usr/bin/python3 - <<'PY'
import pymysql

expected = {
    "filesystem_metrics", "security_metrics", "system_metrics",
    "top_attacking_ips", "top_targeted_ports",
    "ufw_daily_actions_counts", "ufw_log", "ufw_state",
}
conn = pymysql.connect(
    unix_socket="/run/mysqld/mysqld.sock",
    user="root",
    database="ufw_monitor",
)
try:
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES")
        actual = {row[0] for row in cur.fetchall()}
    if actual != expected:
        raise SystemExit(
            f"Skeeman taulut eivät täsmää. Puuttuvat: {sorted(expected-actual)}; "
            f"ylimääräiset: {sorted(actual-expected)}"
        )
finally:
    conn.close()
PY

# Myönnä käyttöoikeudet vasta taulujen luonnin jälkeen.
# Tietokantakäyttäjälle ei myönnetä globaaleja oikeuksia.
/usr/bin/python3 - <<'PY'
import pymysql

grants = {
    "filesystem_metrics": "SELECT, INSERT, UPDATE",
    "security_metrics": "SELECT, INSERT, UPDATE",
    "system_metrics": "SELECT, INSERT",
    "top_attacking_ips": "SELECT, INSERT, UPDATE",
    "top_targeted_ports": "SELECT, INSERT, UPDATE",
    "ufw_daily_actions_counts": "SELECT, INSERT, UPDATE",
    "ufw_log": "SELECT, INSERT",
    "ufw_state": "SELECT, INSERT, UPDATE",
}
conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root")
try:
    with conn.cursor() as cur:
        for table, privileges in grants.items():
            cur.execute(
                f"GRANT {privileges} ON `ufw_monitor`.`{table}` "
                "TO 'pythonuser'@'localhost'"
            )
finally:
    conn.close()
PY

# Luo ympäristömuuttujat lataava wrapper.
cat > "$PROJECT_DIR/config/run_with_env.sh" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
source "$PROJECT_DIR/config/mysql.env"
set +a
exec "$@"
WRAPPER

chmod 750 "$PROJECT_DIR/config/run_with_env.sh"
chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" \
    "$PROJECT_DIR/config/run_with_env.sh"

# Omistajuus sovelluksen käyttöön; älä muuta .git-hakemiston omistajuutta.
find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o \
    -type f ! -path "$ENV_FILE" -exec chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" {} +
find "$PROJECT_DIR" -path "$PROJECT_DIR/.git" -prune -o \
    -type d ! -path "$PROJECT_DIR/config" -exec chown "$INSTALL_USER:$(id -gn "$INSTALL_USER")" {} +

log "Tarkistetaan Python-syntaksi."
while IFS= read -r -d '' pyfile; do
    /usr/bin/python3 -m py_compile "$pyfile"
done < <(find "$PROJECT_DIR" -type f -name '*.py' \
    -not -path '*/.git/*' -not -path '*/__pycache__/*' -print0)

# Päivitä vain tämän asennuksen merkitty cron-lohko.
CRON_TMP="$(mktemp)"
trap 'rm -f "$CRON_TMP"' EXIT

(crontab -u "$INSTALL_USER" -l 2>/dev/null || true) |
    awk -v begin="$CRON_BEGIN" -v end="$CRON_END" '
        $0 == begin { skip=1; next }
        $0 == end   { skip=0; next }
        !skip { print }
    ' > "$CRON_TMP"

cat >> "$CRON_TMP" <<CRON
$CRON_BEGIN
* * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/ingestion/ufw_to_mysql.py" >> "$PROJECT_DIR/ingestion/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/metrics/system/main.py" >> "$PROJECT_DIR/metrics/system/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/metrics/filesystem/main.py" >> "$PROJECT_DIR/metrics/filesystem/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 -m metrics.security.main >> "$PROJECT_DIR/metrics/security/cron.log" 2>&1
*/5 * * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/analysis/attacking_ips/main.py" >> "$PROJECT_DIR/analysis/attacking_ips/cron.log" 2>&1
2 13 * * * cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 "$PROJECT_DIR/analysis/daily_counts/daily_counts.py" >> "$PROJECT_DIR/analysis/daily_counts/cron.log" 2>&1
3 13 * * * cd "$PROJECT_DIR/analysis/targeted_ports" && PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/config/run_with_env.sh" /usr/bin/python3 main.py >> "$PROJECT_DIR/analysis/targeted_ports/cron.log" 2>&1
$CRON_END
CRON

crontab -u "$INSTALL_USER" "$CRON_TMP"
rm -f "$CRON_TMP"
trap - EXIT

log "Testataan sovelluskäyttäjän tietokantayhteys."
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
        print("Tietokantatauluja:", cur.fetchone()[0])
finally:
    conn.close()
PY

log "Asennusvaiheet suoritettu."
log "Cron: sudo crontab -u $INSTALL_USER -l"
log "Tarkista UFW-lokin lähde ja oikeudet ennen tuotantokäyttöä."
