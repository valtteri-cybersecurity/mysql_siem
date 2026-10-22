"""Installer-only provisioning from the current schema, without migration history.

Existing tables are never replaced. DDL commits implicitly, so a partial failure
can leave newly created tables; a rerun safely resumes creation. Runtime
collectors/analyses never provision schemas and require no DDL privileges.
"""

import argparse
import os
import re
from pathlib import Path

import pymysql

from analysis.ufw.ports import PortAnalysisError, validate_ports_schema
from analysis.ufw.traffic import TrafficAnalysisError, validate_traffic_schema

SCHEMA_FILE = Path(__file__).with_name("schema.sql")
GROUPS = {
    "analysis": (("analysis_source_ips", "analysis_ufw_ports", "analysis_ufw_traffic", "analysis_ufw_traffic_daily"), ()),
    "dns": (("dns_sources", "dns_events", "dns_collection_state"), ()),
    "dns-client-filters": (("dns_client_filters",), ()),
    "dns-domain-filters": (("dns_domain_filters",), ()),
    "detection": (("detection_rules", "detection_alerts", "alert_evidence", "detection_state"), ("PORT_SCAN_001",)),
    "auth": (("auth_events", "auth_ingestion_state"), ("SSH_BRUTE_FORCE_001",)),
}


class SchemaError(RuntimeError):
    """Current definitions or an existing analysis schema need manual inspection."""


def read_schema(path=SCHEMA_FILE):
    """Read only the CREATE/seed statements allowed in our current schema file.

    This intentionally supports ordinary table DDL and the two simple rule
    seeds, not arbitrary SQL dumps, stored routines or migration scripts.
    Validate the entire file before executing any statement.
    """
    sql = "\n".join(line for line in Path(path).read_text().splitlines() if not line.lstrip().startswith("--"))
    tables, rules = {}, {}
    for part in sql.split(";"):
        statement = part.strip()
        if not statement:
            continue
        table = re.fullmatch(r"CREATE TABLE (?:IF NOT EXISTS )?`?(\w+)`? \(.*\) ENGINE=InnoDB.*", statement, re.DOTALL)
        rule = re.fullmatch(
            r"INSERT INTO detection_rules \(rule_key, name, severity, enabled\)\s*"
            r"VALUES \('([A-Z0-9_]+)', '[^']*', '[A-Z]+', TRUE\)\s*"
            r"ON DUPLICATE KEY UPDATE rule_key = detection_rules.rule_key", statement)
        if table and statement.count("CREATE TABLE ") == 1 and table[1] not in tables:
            tables[table[1]] = statement
        elif rule and rule[1] in {"PORT_SCAN_001", "SSH_BRUTE_FORCE_001"} and rule[1] not in rules:
            rules[rule[1]] = statement
        else:
            raise SchemaError("Unsupported or duplicate statement in database/schema.sql; no SQL was executed.")
    return tables, rules


def ensure_tables(connection, table_names, *, rule_keys=(), schema_file=SCHEMA_FILE):
    """Create only requested missing tables; retain all existing rows and settings."""
    definitions, rules = read_schema(schema_file)
    if set(table_names) - definitions.keys() or set(rule_keys) - rules.keys():
        raise SchemaError("Requested definitions are missing from database/schema.sql.")
    created = []
    with connection.cursor() as cursor:
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
        existing = {row[0] for row in cursor.fetchall()}
        for name in table_names:
            if name not in existing:
                # A concurrent installer may create it after our inventory.
                statement = re.sub(r"^CREATE TABLE (?:IF NOT EXISTS )?", "CREATE TABLE IF NOT EXISTS ", definitions[name])
                cursor.execute(statement)
                created.append(name)
        for key in rule_keys:
            cursor.execute(rules[key])
    connection.commit()
    return created


def validate_source_ips_schema(connection):
    """Check the Source IP table without altering data or its analysis algorithm."""
    table = "analysis_source_ips"
    with connection.cursor() as cursor:
        cursor.execute("""SELECT engine, table_type, table_collation FROM information_schema.tables
                       WHERE table_schema = DATABASE() AND table_name = %s""", (table,))
        if cursor.fetchone() != ("InnoDB", "BASE TABLE", "utf8mb4_bin"):
            raise SchemaError("analysis_source_ips: incompatible table; inspect database/schema.sql.")
        cursor.execute("""SELECT column_name, column_type, is_nullable, collation_name, column_default, extra
                       FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = %s""", (table,))
        actual = {name: (kind.lower(), nullable, collation, default.lower() if isinstance(default, str) else default, extra.lower())
                  for name, kind, nullable, collation, default, extra in cursor.fetchall()}
        expected = {name: ("datetime(6)", "NO", None, None, "")
                    for name in ("period_start", "period_end", "first_seen", "last_seen")}
        expected.update({name: ("bigint unsigned", "NO", None, None, "") for name in (
            "total_events", "blocked_events", "allowed_events", "audited_events", "unique_destination_ports",
            "unique_destination_ips", "tcp_events", "udp_events")})
        expected.update({"source_ip": ("varchar(45)", "NO", "ascii_bin", None, ""),
                         "analyzed_at": ("timestamp(6)", "NO", None, "current_timestamp(6)", "default_generated")})
        if actual != expected:
            raise SchemaError("analysis_source_ips: incompatible columns; inspect database/schema.sql.")
        cursor.execute("""SELECT index_name, non_unique, column_name, sub_part, is_visible
                       FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = %s
                       ORDER BY index_name, seq_in_index""", (table,))
        indexes = {}
        for name, non_unique, column, prefix, visible in cursor.fetchall():
            if prefix is not None or visible != "YES":
                raise SchemaError("analysis_source_ips: incompatible index; inspect database/schema.sql.")
            indexes.setdefault(name, (non_unique, []))[1].append(column)
        if indexes != {"PRIMARY": (0, ["period_start", "period_end", "source_ip"]),
                       "idx_analysis_source_history": (1, ["source_ip", "period_start", "period_end"])}:
            raise SchemaError("analysis_source_ips: incompatible keys; inspect database/schema.sql.")


def prepare_schema(connection, group, *, schema_file=SCHEMA_FILE):
    """Provision one supported group, preserving optional-job activation policy."""
    tables, rules = GROUPS[group]
    try:
        created = ensure_tables(connection, tables, rule_keys=rules, schema_file=schema_file)
        if group == "analysis":
            validate_source_ips_schema(connection)
            validate_ports_schema(connection)
            validate_traffic_schema(connection)
        return created
    except Exception:
        connection.rollback()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Installer-only creation of missing current tables.")
    parser.add_argument("group", choices=GROUPS)
    args = parser.parse_args(argv)
    connection = None
    try:
        connection = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root",
                                     database=os.environ["DB_NAME"], charset="utf8mb4", autocommit=False)
        created = prepare_schema(connection, args.group)
        print("Created tables: " + (", ".join(created) if created else "none; existing tables retained"))
        return 0
    except (SchemaError, PortAnalysisError, TrafficAnalysisError) as error:
        print(str(error))
        return 1
    except (pymysql.MySQLError, OSError, KeyError):
        print("Schema setup failed; inspect database/schema.sql and administrator permissions. Existing tables were not replaced.")
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
