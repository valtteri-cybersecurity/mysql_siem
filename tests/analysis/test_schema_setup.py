"""Current-schema provisioning, including the reported installer upgrade failure."""

import re
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from analysis.ufw.ports import PortAnalysisError, run_port_analysis
from analysis.ufw.source_ips import run_source_ip_analysis
from analysis.ufw.traffic import TrafficAnalysisError, run_traffic_analysis
from database import schema

ROOT = Path(__file__).resolve().parents[2]
TABLES = {
    "filesystem_metrics", "security_metrics", "system_metrics", "ufw_log", "ufw_state",
    "analysis_source_ips", "analysis_ufw_ports", "analysis_ufw_traffic", "analysis_ufw_traffic_daily",
    "dns_sources", "dns_events", "dns_collection_state", "dns_client_filters", "dns_domain_filters",
    "detection_rules", "detection_alerts", "alert_evidence", "detection_state", "auth_events", "auth_ingestion_state",
}


def test_current_schema_is_complete_and_contains_no_destructive_dump_statements():
    tables, rules = schema.read_schema()
    assert set(tables) == TABLES
    assert set(rules) == {"PORT_SCAN_001", "SSH_BRUTE_FORCE_001"}
    text = "\n".join(line for line in schema.SCHEMA_FILE.read_text().splitlines() if not line.lstrip().startswith("--"))
    assert not re.search(r"(?m)^\s*(DROP|TRUNCATE|DELETE|REPLACE|ALTER)\s", text)
    assert "idx_evidence_event (event_type, event_id)" in tables["alert_evidence"]


@pytest.mark.parametrize("suffix", ["DROP TABLE ufw_log;", "DELETE FROM ufw_log;", "SET FOREIGN_KEY_CHECKS=0;",
    "CREATE TABLE broken (id INT);", "CREATE TABLE x (id INT) ENGINE=InnoDB; CREATE TABLE x (id INT) ENGINE=InnoDB;"])
def test_invalid_schema_file_rejected_before_any_database_access(tmp_path, suffix):
    path = tmp_path / "schema.sql"
    path.write_text(schema.SCHEMA_FILE.read_text() + "\n" + suffix)
    connection = MagicMock()
    with pytest.raises(schema.SchemaError):
        schema.ensure_tables(connection, ("analysis_ufw_traffic",), schema_file=path)
    connection.cursor.assert_not_called()


def test_missing_definition_fails_before_any_database_access():
    connection = MagicMock()
    with pytest.raises(schema.SchemaError, match="missing"):
        schema.ensure_tables(connection, ("not_a_current_table",))
    connection.cursor.assert_not_called()


@pytest.mark.parametrize("failure", [pymysql.OperationalError(1142, "private-payload"), schema.SchemaError("wrong schema")])
def test_setup_cli_returns_failure_closes_connection_and_does_not_expose_driver_payload(monkeypatch, capsys, failure):
    connection = MagicMock()
    monkeypatch.setenv("DB_NAME", "private-test")
    monkeypatch.setattr(schema.pymysql, "connect", Mock(return_value=connection))
    monkeypatch.setattr(schema, "prepare_schema", Mock(side_effect=failure))
    assert schema.main(["analysis"]) == 1
    assert "private-payload" not in capsys.readouterr().out
    connection.close.assert_called_once()


def test_setup_failure_rolls_back(monkeypatch):
    connection = MagicMock()
    monkeypatch.setattr(schema, "ensure_tables", Mock(side_effect=pymysql.OperationalError(1142, "synthetic")))
    with pytest.raises(pymysql.MySQLError):
        schema.prepare_schema(connection, "analysis")
    connection.rollback.assert_called_once()


@pytest.fixture
def setup_mysql(analysis_private_server):
    connection = pymysql.connect(unix_socket=analysis_private_server, user="root", charset="utf8mb4", autocommit=False)
    try:
        name = f"setup_test_{time.monotonic_ns()}"
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
        connection.select_db(name)
        yield connection
    finally:
        connection.close()


def current_tables(connection):
    with connection.cursor() as cursor:
        cursor.execute("SHOW TABLES")
        return {row[0] for row in cursor.fetchall()}


def snapshot(connection, names):
    with connection.cursor() as cursor:
        result = {}
        for name in sorted(names):
            cursor.execute(f"SELECT * FROM `{name}`")
            result[name] = cursor.fetchall()
        return result


def execute_guard(monkeypatch, connection, index):
    """Execute the installer's real embedded guard on this private database."""
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY", (ROOT / "install.sh").read_text(), re.DOTALL)
    guards = [block for block in blocks if '"expected"' not in block and "expected = {" in block]
    assert len(guards) == 2
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        name = cursor.fetchone()[0]
    proxy = MagicMock(wraps=connection)
    proxy.close = Mock()
    monkeypatch.setenv("DB_NAME", name)
    monkeypatch.setenv("DB_USER", "schema_test_user")
    monkeypatch.setenv("DB_PASSWORD", "synthetic-only")
    monkeypatch.setattr(sys, "argv", ["installer", "unused.env", str(schema.SCHEMA_FILE)])
    monkeypatch.setattr(pymysql, "connect", Mock(return_value=proxy))
    exec(compile(guards[index], "private-db-installer-guard", "exec"), {})  # noqa: S102
    proxy.close.assert_called_once()


def seed_history(connection, *, auth):
    with connection.cursor() as cursor:
        cursor.execute("""INSERT INTO ufw_log (event_time, action, src_ip, dst_ip, protocol, dst_port, raw_line, event_hash)
            VALUES ('2026-10-22 12:05:00', 'BLOCK', '192.0.2.1', '198.51.100.1', 'TCP', 22, 'synthetic', %s)""", ("a" * 64,))
        cursor.execute("""INSERT INTO ufw_state (logfile, last_position, file_device, file_inode)
            VALUES ('synthetic.log', 777, 1, 2)""")
        cursor.execute("""INSERT INTO dns_sources (source_name, source_type, base_url, enabled)
            VALUES ('synthetic', 'adguard', 'https://dns.example.test', FALSE)""")
        source = cursor.lastrowid
        cursor.execute("""INSERT INTO dns_events
            (source_id, event_time, raw_timestamp, domain, query_type, filtering_result)
            VALUES (%s, '2026-10-22 12:05:00', '2026-10-22T12:05:00Z', 'example.test', 'A', 'allowed')""", (source,))
        cursor.execute("INSERT INTO dns_collection_state VALUES (%s, '{}', '2026-10-22 12:05:00')", (source,))
        cursor.execute("""INSERT INTO dns_client_filters (source_id, client_ip, exclude_from_collection)
            VALUES (%s, '192.0.2.10', TRUE)""", (source,))
        cursor.execute("INSERT INTO dns_domain_filters (source_id, domain) VALUES (%s, 'example.test')", (source,))
        cursor.execute("""INSERT INTO detection_rules (rule_key, name, severity, enabled)
            VALUES ('PORT_SCAN_001', 'Operator setting', 'LOW', FALSE)""")
        rule = cursor.lastrowid
        cursor.execute("""INSERT INTO detection_alerts
            (rule_id, severity, title, description, first_seen, last_seen, alert_fingerprint, details)
            VALUES (%s, 'LOW', 'synthetic', 'synthetic', '2026-10-22 12:05:00', '2026-10-22 12:05:00', %s, '{}')""", (rule, "b" * 64))
        alert = cursor.lastrowid
        cursor.execute("INSERT INTO alert_evidence (alert_id, event_type, event_id) VALUES (%s, 'UFW', 1)", (alert,))
        cursor.execute("INSERT INTO detection_state (rule_id, last_event_id, state_data) VALUES (%s, 888, '{}')", (rule,))
        if auth:
            cursor.execute("""INSERT INTO auth_events
                (event_time, hostname, source_ip, event_type, service, raw_message, event_hash)
                VALUES ('2026-10-22 12:05:00', 'synthetic', '192.0.2.10', 'password_failure', 'sshd', 'synthetic', %s)""", ("c" * 64,))
            cursor.execute("INSERT INTO auth_ingestion_state VALUES ('synthetic', 1, 2, 'synthetic.log', 999, %s)", ("d" * 64,))
    connection.commit()


@pytest.mark.parametrize("has_source", [False, True])
@pytest.mark.parametrize("auth", [False, True])
def test_reported_upgrade_creates_missing_analysis_and_preserves_every_existing_row(
        setup_mysql, tmp_path, monkeypatch, has_source, auth):
    connection = setup_mysql
    definitions, _ = schema.read_schema()
    missing = {"analysis_ufw_traffic", "analysis_ufw_traffic_daily"}
    if not has_source:
        missing.add("analysis_source_ips")
    if not auth:
        missing |= {"auth_events", "auth_ingestion_state"}
    existing = [name for name in definitions if name not in missing]
    schema.ensure_tables(connection, existing)
    seed_history(connection, auth=auth)
    from datetime import datetime
    start, end = datetime(2026, 10, 22, 12), datetime(2026, 10, 22, 13)
    assert run_port_analysis(connection, start, end)["total_events"] == 1
    if has_source:
        assert run_source_ip_analysis(connection, start, end)["total_events"] == 1
    before = snapshot(connection, existing)
    # The exact first guard previously rejected this layout before setup ran.
    execute_guard(monkeypatch, connection, 0)
    isolated_schema = tmp_path / "deployment without migrations" / "schema.sql"
    isolated_schema.parent.mkdir()
    isolated_schema.write_text(schema.SCHEMA_FILE.read_text())
    assert not (isolated_schema.parent / "migrations").exists()
    created = schema.prepare_schema(connection, "analysis", schema_file=isolated_schema)
    assert set(created) == missing & set(schema.GROUPS["analysis"][0])
    execute_guard(monkeypatch, connection, 1)
    assert snapshot(connection, existing) == before
    assert schema.prepare_schema(connection, "analysis", schema_file=isolated_schema) == []
    assert snapshot(connection, existing) == before
    assert run_source_ip_analysis(connection, start, end)["total_events"] == 1
    assert run_port_analysis(connection, start, end)["total_events"] == 1
    assert run_traffic_analysis(connection, start, end, now=end)["total_events"] == 1


def test_fresh_install_import_and_repeatable_current_setup(setup_mysql):
    connection = setup_mysql
    # Exactly the fresh installer import, without using any migration file.
    text = "\n".join(line for line in schema.SCHEMA_FILE.read_text().splitlines() if not line.lstrip().startswith("--"))
    with connection.cursor() as cursor:
        for statement in text.split(";"):
            if statement.strip():
                cursor.execute(statement)
    connection.commit()
    assert current_tables(connection) == TABLES
    before = snapshot(connection, TABLES)
    for _ in range(2):
        for group in schema.GROUPS:
            assert schema.prepare_schema(connection, group) == []
    assert snapshot(connection, TABLES) == before


@pytest.mark.parametrize("present", ["analysis_ufw_traffic", "analysis_ufw_traffic_daily"])
def test_partial_traffic_setup_is_completed_without_replacing_existing_results(setup_mysql, present):
    connection = setup_mysql
    schema.ensure_tables(connection, (present,))
    schema.prepare_schema(connection, "analysis")
    assert current_tables(connection) == set(schema.GROUPS["analysis"][0])
    assert schema.prepare_schema(connection, "analysis") == []


@pytest.mark.parametrize("table,alter", [
    ("analysis_source_ips", "MODIFY total_events BIGINT NULL"),
    ("analysis_source_ips", "DROP PRIMARY KEY"),
    ("analysis_ufw_ports", "MODIFY protocol VARCHAR(8) NOT NULL"),
    ("analysis_ufw_traffic", "MODIFY total_events BIGINT NOT NULL"),
    ("analysis_ufw_traffic_daily", "DROP INDEX uq_traffic_period"),
])
def test_incompatible_analysis_is_reported_and_never_replaced(setup_mysql, table, alter):
    connection = setup_mysql
    schema.prepare_schema(connection, "analysis")
    with connection.cursor() as cursor:
        cursor.execute(f"ALTER TABLE {table} {alter}")
        cursor.execute(f"SHOW CREATE TABLE {table}")
        before = cursor.fetchone()
    with pytest.raises((schema.SchemaError, PortAnalysisError, TrafficAnalysisError)):
        schema.prepare_schema(connection, "analysis")
    with connection.cursor() as cursor:
        cursor.execute(f"SHOW CREATE TABLE {table}")
        assert cursor.fetchone() == before


def test_old_ufw_file_identity_upgrade_preserves_positions_without_migration_file(setup_mysql, monkeypatch):
    connection = setup_mysql
    definitions, _ = schema.read_schema()
    schema.ensure_tables(connection, tuple(definitions))
    with connection.cursor() as cursor:
        cursor.execute("ALTER TABLE ufw_state DROP INDEX uq_ufw_state_file, DROP COLUMN file_device, DROP COLUMN file_inode")
        cursor.execute("INSERT INTO ufw_state (logfile, last_position) VALUES ('synthetic.log', 123)")
    connection.commit()
    execute_guard(monkeypatch, connection, 1)
    execute_guard(monkeypatch, connection, 1)
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, logfile, last_position, file_device, file_inode FROM ufw_state")
        assert cursor.fetchone() == (1, "synthetic.log", 123, None, None)


def test_current_rule_registration_preserves_operator_settings(setup_mysql):
    connection = setup_mysql
    definitions, _ = schema.read_schema()
    schema.ensure_tables(connection, tuple(definitions))
    with connection.cursor() as cursor:
        cursor.executemany("""INSERT INTO detection_rules (id, rule_key, name, severity, enabled)
            VALUES (%s, %s, 'Operator name', 'LOW', FALSE)""",
            [(17, "PORT_SCAN_001"), (23, "SSH_BRUTE_FORCE_001")])
    connection.commit()
    before = snapshot(connection, {"detection_rules"})
    for _ in range(2):
        schema.prepare_schema(connection, "detection")
        schema.prepare_schema(connection, "auth")
    assert snapshot(connection, {"detection_rules"}) == before


@pytest.mark.parametrize("operation", ["reset", "upgrade"])
def test_fresh_initializer_failure_stops_installer_before_publication(tmp_path, operation):
    import subprocess
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("DATABASE_SETUP_STARTED=1\nservice_installation database-started")
    end = installer.index("DETECTION_READY=1", start)
    block = installer[start:end]
    script = ('set -euo pipefail\nservice_installation() { :; }\n'
              'failed_schema_setup() { return 1; }\n' + block + '\nprintf "UNREACHABLE\n"')
    result = subprocess.run(['bash', '-c', script],
                            env={'PROJECT_DIR': str(tmp_path), 'APP_PYTHON': 'failed_schema_setup', 'INSTALL_OPERATION': operation},
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0 and 'UNREACHABLE' not in result.stdout
