
"""Integration proof for registry isolation, migration recovery and old history."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pymysql
import pytest

from analysis.ufw.ports import run_port_analysis
from analysis.ufw.source_ips import run_source_ip_analysis
from analysis.ufw.traffic import analyze_traffic, run_traffic_analysis
from database import migrate as migrations
from database import migration_steps
from database.identity import (
    IdentityError,
    register_host,
    resolve_identity,
    update_host,
)
from database.schema import ensure_tables, read_schema
from detection.common.alerts import link_alert_hosts, save_alert
from detection.port_scan.db import get_db_data
from detection.port_scan.detector import detect_port_scans
from detection.port_scan.formatting import build_alert
from detection.ssh_brute_force.db import get_db_data as get_auth_data
from detection.ssh_brute_force.detector import detect_ssh_brute_force
from ingestion.auth.db import save_event as save_auth
from ingestion.auth.parser import parse_auth_line
from ingestion.dns.db import register_source, save_events
from ingestion.dns.models import DNSEvent
from ingestion.ufw_to_mysql import process_file, save_event

START = datetime(2026, 10, 22, 12)
END = START + timedelta(hours=1)


def enroll(connection, *, source_type="ufw", collector_id=None, name="same-name"):
    with connection.cursor() as cursor:
        host_id = register_host(cursor, name, reported_hostname="same-name", current_ip="192.0.2.10")
        cursor.execute("UPDATE hosts SET enrollment_status = 'ACTIVE' WHERE host_id = %s", (host_id,))
        if collector_id is None:
            cursor.execute("INSERT INTO collectors (collector_name, enabled) VALUES (%s, TRUE)", (f"collector-{host_id}",))
            collector_id = cursor.lastrowid
        cursor.execute("INSERT INTO log_sources (host_id, source_name, source_type, enabled) VALUES (%s, %s, %s, TRUE)",
                       (host_id, source_type, source_type))
        source_id = cursor.lastrowid
        cursor.execute("INSERT INTO collector_sources VALUES (%s, %s, TRUE)", (collector_id, source_id))
        identity = resolve_identity(cursor, source_id, collector_id, source_type=source_type)
    connection.commit()
    return identity


def ufw_line(index=0):
    return (f"2026-10-22T12:00:{index:02d}.123456+00:00 reported-other-name kernel: [UFW BLOCK] "
            f"SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT={1000 + index}\n")


def test_empty_database_and_repeat_run(empty_mysql):
    assert migrations.migrate(empty_mysql) == ["013", "014", "015", "016", "017", "018", "019", "020", "021"]
    assert migrations.migrate(empty_mysql) == []
    assert {state for _, state in migrations.migration_status(empty_mysql).values()} == {"APPLIED"}


def snapshot(connection, table, fields):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {', '.join(fields)} FROM `{table}` ORDER BY {', '.join(fields[:1])}")
        return cursor.fetchall()


def test_all_legacy_rows_ids_timestamps_hashes_and_counts_survive(empty_mysql):
    connection = empty_mysql
    tables, rules = read_schema()
    ensure_tables(connection, tuple(tables), rule_keys=tuple(rules))
    with connection.cursor() as cursor:
        save_event(cursor, ufw_line())
        event = parse_auth_line("2026-10-22T12:00:00+00:00 same-name sshd[1]: Failed password for alice from 192.0.2.1 port 123 ssh2")
        assert event is not None
        # This fixture represents history from before the Auth metadata migration.
        fields = ("event_time", "hostname", "source_ip", "username", "event_type",
                  "service", "raw_message", "event_hash")
        values = []
        for field in fields:
            values.append(event[field])
        cursor.execute(
            "INSERT INTO auth_events (event_time, hostname, source_ip, username, "
            "event_type, service, raw_message, event_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", values,
        )
        cursor.execute("INSERT INTO system_metrics (id, timestamp) VALUES (71, %s)", (START,))
        cursor.execute("INSERT INTO filesystem_metrics VALUES (%s, 3, 17)", (START.date(),))
        cursor.execute("INSERT INTO security_metrics VALUES (%s, 1, 2, 3, 4)", (START,))
        cursor.execute("INSERT INTO ufw_state (id, logfile, last_position, file_device, file_inode) VALUES (41, 'old.log', 99, 1, 2)")
        cursor.execute("INSERT INTO auth_ingestion_state VALUES ('legacy-reader', 1, 2, 'old.log', 99, %s)", ("a" * 64,))
        cursor.execute("INSERT INTO dns_sources (id, source_name, source_type, base_url, enabled) "
                       "VALUES (13, 'old-dns', 'adguard', 'https://dns.example.test', TRUE)")
        cursor.execute("INSERT INTO dns_events (id, source_id, event_time, raw_timestamp, client_ip, domain, query_type, filtering_result) "
                       "VALUES (19, 13, %s, '2026-10-22T12:00:00Z', '192.0.2.10', 'example.test', 'A', 'allowed')", (START,))
    connection.commit()

    # Run the original baseline analyses before upgrading.
    with connection.cursor() as cursor:
        cursor.execute("""INSERT INTO analysis_ufw_traffic (id, period_start, period_end,
            total_events, blocked_events, allowed_events, audited_events, other_events,
            tcp_events, udp_events, unique_source_ips, unique_destination_ips, unique_destination_ports,
            first_seen, last_seen, period_status) VALUES
            (23, %s, %s, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, %s, %s, 'CLOSED')""", (START, END, START, START))
        cursor.execute("""INSERT INTO analysis_source_ips
            (period_start, period_end, source_ip, total_events, blocked_events, allowed_events,
             audited_events, unique_destination_ports, unique_destination_ips,
             first_seen, last_seen, tcp_events, udp_events)
            VALUES (%s, %s, '192.0.2.1', 1, 1, 0, 0, 1, 1, %s, %s, 1, 0)""", (START, END, START, START))
        cursor.execute("""INSERT INTO analysis_ufw_ports
            (id, period_start, period_end, destination_ip, destination_port, protocol,
             total_events, blocked_events, allowed_events, audited_events,
             unique_source_ips, first_seen, last_seen)
            VALUES (29, %s, %s, '198.51.100.1', 22, 'TCP', 1, 1, 0, 0, 1, %s, %s)""", (START, END, START, START))
        cursor.execute("""INSERT INTO analysis_ufw_traffic_daily
            (id, analysis_date, total_events, blocked_events, allowed_events, audited_events,
             other_events, tcp_events, udp_events, unique_source_ips, unique_destination_ips,
             unique_destination_ports, period_status)
            VALUES (31, %s, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 'CLOSED')""", (START.date(),))
        cursor.execute("INSERT INTO dns_collection_state VALUES (13, '{\"version\": 1}', %s)", (START,))
        cursor.execute("INSERT INTO dns_client_filters (id, source_id, client_ip) VALUES (37, 13, '192.0.2.10')")
        cursor.execute("INSERT INTO dns_domain_filters (id, source_id, domain) VALUES (43, 13, 'example.test')")
        cursor.execute("UPDATE detection_rules SET name = 'Operator setting', severity = 'LOW', enabled = FALSE "
                       "WHERE rule_key = 'PORT_SCAN_001'")
        cursor.execute("SELECT id FROM detection_rules WHERE rule_key = 'PORT_SCAN_001'")
        rule_id = cursor.fetchone()[0]
        cursor.execute("""INSERT INTO detection_alerts
            (id, rule_id, severity, title, description, first_seen, last_seen, alert_fingerprint, details)
            VALUES (47, %s, 'LOW', 'Historical alert', 'Keep original', %s, %s, %s, '{}')""",
                       (rule_id, START, START, "d" * 64))
        cursor.execute("INSERT INTO alert_evidence (id, alert_id, event_type, event_id) VALUES (53, 47, 'UFW', 1)")
        cursor.execute("INSERT INTO detection_state (rule_id, last_event_id, state_data) "
                       "VALUES (%s, 77, '{\"version\": 1, \"events\": []}')", (rule_id,))
    connection.commit()

    old_columns = {}
    with connection.cursor() as cursor:
        for table in tables:
            cursor.execute("SELECT column_name FROM information_schema.columns "
                           "WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ordinal_position", (table,))
            old_columns[table] = tuple(row[0] for row in cursor.fetchall())

    before = {table: snapshot(connection, table, fields) for table, fields in old_columns.items()}
    assert all(before.values()), "Every original table must contain representative history."

    assert migrations.migrate(connection) == ["013", "014", "015", "016", "017", "018", "019", "020", "021"]

    after = {table: snapshot(connection, table, fields) for table, fields in old_columns.items()}
    assert {table: len(rows) for table, rows in after.items()} == {table: len(rows) for table, rows in before.items()}
    assert after == before

    with connection.cursor() as cursor:
        for table in ("ufw_log", "auth_events", "dns_events", "system_metrics", "analysis_ufw_traffic"):
            cursor.execute(f"SELECT host_id FROM {table}")
            assert all(row == (None,) for row in cursor.fetchall())
        cursor.execute("SELECT COUNT(*) FROM hosts")
        assert cursor.fetchone() == (0,)


def test_ufw_datetime_precision_and_historical_rows(empty_mysql):
    """Migration 017 preserves old rows and stores new UTC microseconds."""

    connection = empty_mysql
    tables, rules = read_schema()
    ensure_tables(connection, tuple(tables), rule_keys=tuple(rules))

    old_local_time = datetime(2026, 10, 22, 15, 0, 0)

    with connection.cursor() as cursor:
        assert save_event(cursor, ufw_line()) == 1

        # Simulate an existing row saved as local time.
        cursor.execute(
            "UPDATE ufw_log SET event_time = %s",
            (old_local_time,),
        )

        cursor.execute(
            "SELECT id, event_time, raw_line, event_hash "
            "FROM ufw_log ORDER BY id"
        )
        original = cursor.fetchall()

        cursor.execute(
            "SELECT DATETIME_PRECISION FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = 'ufw_log' "
            "AND column_name = 'event_time'"
        )
        assert cursor.fetchone()[0] == 0

    connection.commit()

    assert migrations.migrate(connection) == ["013", "014", "015", "016", "017", "018", "019", "020", "021"]

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT DATETIME_PRECISION FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = 'ufw_log' "
            "AND column_name = 'event_time'"
        )
        assert cursor.fetchone()[0] == 6

        cursor.execute(
            "SELECT id, event_time, raw_line, event_hash "
            "FROM ufw_log ORDER BY id"
        )
        assert cursor.fetchall() == original

        new_line = (
            "2026-10-22T15:30:00.654321+03:00 "
            "reported-other-name kernel: [UFW BLOCK] "
            "SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=2001\n"
        )

        assert save_event(cursor, new_line) == 1

        cursor.execute(
            "SELECT event_time FROM ufw_log WHERE raw_line = %s",
            (new_line.strip(),),
        )

        assert cursor.fetchone()[0] == datetime(
            2026, 10, 22, 12, 30, 0, 654321
        )

    connection.commit()

    assert migrations.migrate(connection) == []


def test_ufw_datetime_migration_recovers_after_interruption(empty_mysql, monkeypatch):
    """Migration 017 can resume after MySQL has committed its ALTER TABLE."""

    original_apply_one = migrations.apply_one

    def interrupted_apply(connection, version):
        original_apply_one(connection, version)

        if version == "017":
            raise RuntimeError("Simulated interruption after UFW ALTER TABLE")

    monkeypatch.setattr(migrations, "apply_one", interrupted_apply)

    with pytest.raises(RuntimeError, match="Simulated interruption"):
        migrations.migrate(empty_mysql)

    assert migrations.migration_status(empty_mysql)["017"][1] == "FAILED"

    monkeypatch.setattr(migrations, "apply_one", original_apply_one)

    assert migrations.migrate(empty_mysql) == ["017", "018", "019", "020", "021"]
    assert migrations.migrate(empty_mysql) == []


@pytest.mark.parametrize("failed_version", ["014", "015", "016"])
def test_ddl_failure_is_not_applied_and_restart_preserves_partial_work(empty_mysql, monkeypatch, failed_version):
    original = migrations.apply_one

    def fail_after_ddl(connection, version):
        if version == failed_version:
            if version == "014":
                ensure_tables(connection, ("hosts",), schema_file=migrations.REGISTRY)
            else:
                with connection.cursor() as cursor:
                    if version == "015":
                        migration_steps.add_column(cursor, "ufw_log", "host_id", "BIGINT UNSIGNED NULL")
                    else:
                        migration_steps.add_column(cursor, "ufw_log", "source_scope", "BIGINT UNSIGNED NOT NULL DEFAULT 0")
            raise RuntimeError("Simulated interruption after committed DDL")
        original(connection, version)

    monkeypatch.setattr(migrations, "apply_one", fail_after_ddl)

    with pytest.raises(RuntimeError):
        migrations.migrate(empty_mysql)

    assert migrations.migration_status(empty_mysql)[failed_version][1] == "FAILED"

    monkeypatch.setattr(migrations, "apply_one", original)

    migrations.migrate(empty_mysql)

    assert all(state == "APPLIED" for _, state in migrations.migration_status(empty_mysql).values())
    assert migrations.migrate(empty_mysql) == []


def test_checksum_mismatch_stops_before_any_schema_change(mysql):
    with mysql.cursor() as cursor:
        cursor.execute("UPDATE schema_migrations SET checksum = %s WHERE version = '014'", ("0" * 64,))
    mysql.commit()

    with pytest.raises(migrations.MigrationError, match="checksum"):
        migrations.migrate(mysql)


def test_two_same_named_hosts_and_one_shared_collector(mysql):
    first = enroll(mysql)
    second = enroll(mysql, collector_id=first.collector_id)

    assert first.host_id != second.host_id
    assert first.collector_id == second.collector_id

    with mysql.cursor() as cursor:
        update_host(cursor, first.host_id, reported_hostname="renamed", current_ip="2001:db8::99")
        cursor.execute("SELECT host_id, reported_hostname, current_ip FROM hosts WHERE host_id = %s", (first.host_id,))
        assert cursor.fetchone() == (first.host_id, "renamed", "2001:db8::99")
        cursor.execute("INSERT INTO log_sources (host_id, source_name, source_type, enabled) VALUES (%s, 'ssh', 'auth', TRUE)", (first.host_id,))
        another_source = cursor.lastrowid
        cursor.execute("INSERT INTO collector_sources VALUES (%s, %s, TRUE)", (first.collector_id, another_source))
        assert resolve_identity(cursor, another_source, first.collector_id, source_type="auth").host_id == first.host_id


def test_same_ufw_lines_are_saved_once_per_source_and_analyzed_separately(mysql):
    first = enroll(mysql)
    second = enroll(mysql, collector_id=first.collector_id)

    with mysql.cursor() as cursor:
        for identity in (first, second):
            for index in range(10):
                assert save_event(cursor, ufw_line(index), identity=identity) == 1
                assert save_event(cursor, ufw_line(index), identity=identity) == 0

    mysql.commit()

    findings = detect_port_scans(get_db_data(mysql, START, END))
    assert {finding["host_id"] for finding in findings} == {first.host_id, second.host_id}

    run_source_ip_analysis(mysql, START, END)
    run_port_analysis(mysql, START, END)
    run_traffic_analysis(mysql, START, END, now=END)

    with mysql.cursor() as cursor:
        for table in ("analysis_source_ips", "analysis_ufw_traffic", "analysis_ufw_traffic_daily"):
            cursor.execute(f"SELECT host_id, total_events FROM {table} WHERE host_id IS NOT NULL ORDER BY host_id")
            assert cursor.fetchall() == ((first.host_id, 10), (second.host_id, 10))

    assert analyze_traffic(mysql, START, END, host_id=first.host_id)["total_events"] == 10
    assert analyze_traffic(mysql, START, END)["total_events"] == 0


def test_same_ssh_lines_are_saved_once_per_source_and_detected_separately(mysql):
    first = enroll(mysql, source_type="auth")
    second = enroll(mysql, source_type="auth", collector_id=first.collector_id)

    with mysql.cursor() as cursor:
        for identity in (first, second):
            for index in range(5):
                event = parse_auth_line(f"2026-10-22T12:00:0{index}+00:00 same-name sshd[1]: Failed password for alice from 192.0.2.1 port 123 ssh2")
                assert event is not None
                assert save_auth(cursor, event, identity=identity) == 1
                assert save_auth(cursor, event, identity=identity) == 0

    mysql.commit()

    findings = detect_ssh_brute_force(get_auth_data(mysql, START, END))
    assert {finding["host_id"] for finding in findings} == {first.host_id, second.host_id}


def test_original_hostname_and_authenticated_sender_survive_registry_changes(mysql):
    identity = enroll(mysql)

    with mysql.cursor() as cursor:
        cursor.execute("INSERT INTO sender_identities (host_id, identity_type, identity_value, enabled) "
                       "VALUES (%s, 'certificate-san', 'authenticated.example.test', TRUE)", (identity.host_id,))
        sender = cursor.lastrowid
        cursor.execute("INSERT INTO sender_sources VALUES (%s, %s)", (sender, identity.source_id))
        trusted = resolve_identity(cursor, identity.source_id, identity.collector_id, source_type="ufw", sender_id=sender)
        save_event(cursor, ufw_line(), identity=trusted)
        update_host(cursor, identity.host_id, reported_hostname="registry-new-name", current_ip="192.0.2.99")
        cursor.execute("SELECT host_id, sender_id, reported_hostname FROM ufw_log")
        assert cursor.fetchone() == (identity.host_id, sender, "reported-other-name")
        cursor.execute("""INSERT INTO sender_certificates
            (sender_id, sha256_fingerprint, serial_number, valid_from, valid_until, status)
            VALUES (%s, %s, '01', %s, %s, 'ACTIVE')""", (sender, "a" * 64, START, END))
        cursor.execute("UPDATE sender_certificates SET status = 'REPLACED' WHERE sender_id = %s", (sender,))
        cursor.execute("""INSERT INTO sender_certificates
            (sender_id, sha256_fingerprint, serial_number, valid_from, valid_until, status)
            VALUES (%s, %s, '02', %s, %s, 'ACTIVE')""", (sender, "b" * 64, START, END))
        cursor.execute("SELECT host_id FROM sender_identities WHERE sender_id = %s", (sender,))
        assert cursor.fetchone() == (identity.host_id,)
        cursor.execute("INSERT INTO host_groups (group_name) VALUES ('web-servers')")
        group_id = cursor.lastrowid
        cursor.execute("INSERT INTO host_group_members VALUES (%s, %s)", (group_id, identity.host_id))


def test_file_checkpoint_is_scoped_to_source(mysql, tmp_path):
    first = enroll(mysql)
    second = enroll(mysql, collector_id=first.collector_id)

    path = tmp_path / "ufw.log"
    path.write_text(ufw_line())

    with mysql.cursor() as cursor:
        assert process_file(cursor, str(path), identity=first) == 1
        assert process_file(cursor, str(path), identity=second) == 1
        assert process_file(cursor, str(path), identity=first) == 0


def test_single_and_multi_host_alerts(mysql):
    first, second = enroll(mysql), enroll(mysql)

    with mysql.cursor() as cursor:
        for index in range(10):
            save_event(cursor, ufw_line(index), identity=first)

    mysql.commit()

    finding = detect_port_scans(get_db_data(mysql, START, END))[0]
    alert, evidence = build_alert(finding)
    assert save_alert(mysql, alert, evidence)

    with mysql.cursor() as cursor:
        cursor.execute("SELECT id, host_id FROM detection_alerts")
        alert_id, host_id = cursor.fetchone()
        assert host_id == first.host_id
        link_alert_hosts(cursor, alert_id, [(second.host_id, "RELATED")])
        cursor.execute("SELECT host_id, host_role FROM alert_hosts WHERE alert_id = %s ORDER BY host_id", (alert_id,))
        assert cursor.fetchall() == ((first.host_id, "TARGET"), (second.host_id, "RELATED"))


def test_dns_server_is_snapshotted_and_unknown_client_is_not_registered(mysql, monkeypatch):
    identity = enroll(mysql, source_type="dns")
    source = register_source(mysql, "test-dns", "adguard", "https://dns.example.test", enabled=True)

    with mysql.cursor() as cursor:
        cursor.execute("UPDATE dns_sources SET registry_source_id = %s WHERE id = %s", (identity.source_id, source))

    mysql.commit()

    monkeypatch.setenv("SIEM_DNS_SOURCE_ID", str(identity.source_id))
    monkeypatch.setenv("SIEM_COLLECTOR_ID", str(identity.collector_id))

    event = DNSEvent("test-dns", START.replace(tzinfo=timezone.utc), "2026-10-22T12:00:00Z", "192.0.2.10",
                     "example.test", "A", "NOERROR", "allowed", None, None, Decimal(1), False)

    assert save_events(mysql, source, [event], dedup_keys=[b"a" * 32]) == 1
    assert save_events(mysql, source, [event], dedup_keys=[b"a" * 32]) == 0

    with mysql.cursor() as cursor:
        cursor.execute("SELECT host_id, registry_source_id, source_id, client_ip, client_host_id FROM dns_events")
        assert cursor.fetchone() == (identity.host_id, identity.source_id, source, "192.0.2.10", None)
        cursor.execute("SELECT COUNT(*) FROM hosts")
        assert cursor.fetchone() == (1,)


def test_disabled_and_cross_host_bindings_are_rejected(mysql):
    first, second = enroll(mysql), enroll(mysql)

    with mysql.cursor() as cursor:
        cursor.execute("UPDATE log_sources SET enabled = FALSE WHERE source_id = %s", (first.source_id,))
        with pytest.raises(IdentityError):
            resolve_identity(cursor, first.source_id, first.collector_id, source_type="ufw")
        from database.identity import EventIdentity
        forged = EventIdentity(second.host_id, first.source_id, first.collector_id)

        with pytest.raises(pymysql.IntegrityError):
            save_event(cursor, ufw_line(), identity=forged)


def test_all_metric_writers_keep_two_hosts_separate(mysql, monkeypatch):
    from database.identity import approve_collector_source
    from database.identity import register_source as register_log_source
    from metrics.filesystem import db as filesystem
    from metrics.security.database import save_metrics_db as save_security
    from metrics.system.db import save_metrics_db as save_system

    first, second = enroll(mysql), enroll(mysql)
    monkeypatch.setattr(filesystem, "get_connection", lambda: mysql)

    # The filesystem API owns its connection. Keep the shared
    # test connection open while all writers are exercised.
    close = mysql.close
    monkeypatch.setattr(mysql, "close", lambda: None)

    try:
        for identity in (first, second):
            monkeypatch.setenv("SIEM_COLLECTOR_ID", str(identity.collector_id))

            for source_type in ("system", "filesystem", "security"):
                with mysql.cursor() as cursor:
                    source_id = register_log_source(cursor, identity.host_id, source_type, source_type, enabled=True)
                    approve_collector_source(cursor, identity.collector_id, source_id)
                mysql.commit()
                monkeypatch.setenv(f"SIEM_{source_type.upper()}_SOURCE_ID", str(source_id))

            save_system(mysql, [Decimal(1)] * 10)
            filesystem.save_metrics(3, 17)
            filesystem.save_metrics(4, 18)
            save_security(mysql, {"uptime": 1, "blocks": 2, "failed_logins": 3, "unique_ips": 4, "date": START.replace(tzinfo=timezone.utc)})

        with mysql.cursor() as cursor:
            for table in ("system_metrics", "filesystem_metrics", "security_metrics"):
                cursor.execute(f"SELECT host_id FROM {table} ORDER BY host_id")
                assert cursor.fetchall() == ((first.host_id,), (second.host_id,))

    finally:
        monkeypatch.setattr(mysql, "close", close)


def test_running_migration_after_process_exit_can_resume(empty_mysql, monkeypatch):
    original = migrations.apply_one

    def stop_process(connection, version):
        if version == "015":
            raise SystemExit("Simulated process exit")
        original(connection, version)

    monkeypatch.setattr(migrations, "apply_one", stop_process)

    with pytest.raises(SystemExit):
        migrations.migrate(empty_mysql)

    assert migrations.migration_status(empty_mysql)["015"][1] == "RUNNING"

    monkeypatch.setattr(migrations, "apply_one", original)

    assert migrations.migrate(empty_mysql) == ["015", "016", "017", "018", "019", "020", "021"]


def test_migrated_analysis_validators(mysql):
    from analysis.ufw.ports import validate_ports_schema
    from analysis.ufw.traffic import validate_traffic_schema
    from database.schema import validate_source_ips_schema

    validate_source_ips_schema(mysql)
    validate_ports_schema(mysql)
    validate_traffic_schema(mysql)


def test_runtime_account_needs_ledger_read_access_to_preserve_host_scope(mysql):
    identity = enroll(mysql)

    with mysql.cursor() as cursor:
        save_event(cursor, ufw_line(), identity=identity)
        cursor.execute("SELECT DATABASE()")
        name = cursor.fetchone()[0]

        # This account exists only on the private server with TCP disabled.
        cursor.execute("CREATE USER 'phase2_reader'@'localhost'")
        cursor.execute(f"GRANT SELECT ON `{name}`.ufw_log TO 'phase2_reader'@'localhost'")

    mysql.commit()

    reader = pymysql.connect(
        unix_socket=mysql.unix_socket,
        user="phase2_reader",
        database=name,
    )

    try:
        with pytest.raises(IdentityError, match="ledger"):
            get_db_data(reader, START, END)

        with mysql.cursor() as cursor:
            cursor.execute(f"GRANT SELECT ON `{name}`.schema_migrations TO 'phase2_reader'@'localhost'")

        assert get_db_data(reader, START, END)[0]["host_id"] == identity.host_id

    finally:
        reader.close()


def test_private_session_is_utc(empty_mysql):
    with empty_mysql.cursor() as cursor:
        cursor.execute("SELECT @@session.time_zone")
        assert cursor.fetchone() == ("+00:00",)


def test_utc_deployment_check_accepts_proven_legacy_history(empty_mysql):
    tables, rules = read_schema()
    ensure_tables(empty_mysql, tuple(tables), rule_keys=tuple(rules))
    with empty_mysql.cursor() as cursor:
        save_event(cursor, ufw_line())
    empty_mysql.commit()
    migrations.migrate(empty_mysql)
    migrations.check_ufw_utc_readiness(empty_mysql)


def test_utc_deployment_check_accepts_fresh_database(mysql):
    migrations.check_ufw_utc_readiness(mysql)


def test_017_running_after_process_exit_can_resume(empty_mysql, monkeypatch):
    original = migrations.apply_one

    def stop_after_ddl(connection, version):
        original(connection, version)
        if version == "017":
            raise SystemExit("Simulated process exit after DDL")

    monkeypatch.setattr(migrations, "apply_one", stop_after_ddl)
    with pytest.raises(SystemExit):
        migrations.migrate(empty_mysql)
    assert migrations.migration_status(empty_mysql)["017"][1] == "RUNNING"
    assert migrations.ufw_timestamp_schema(empty_mysql) == ("datetime", 6, "YES", None)
    monkeypatch.setattr(migrations, "apply_one", original)
    assert migrations.migrate(empty_mysql) == ["017", "018", "019", "020", "021"]
    assert migrations.migrate(empty_mysql) == []


def test_application_connection_sets_real_session_to_utc(mysql, monkeypatch):
    from database.connection import get_connection

    with mysql.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        name = cursor.fetchone()[0]
        cursor.execute("CREATE USER 'utc_session_test'@'localhost' IDENTIFIED BY 'synthetic-utc-password'")
        cursor.execute(f"GRANT SELECT ON `{name}`.* TO 'utc_session_test'@'localhost'")
    real_connect = pymysql.connect

    def private_connect(**kwargs):
        # The production factory is exercised against our socket, never TCP.
        kwargs["unix_socket"] = mysql.unix_socket
        return real_connect(**kwargs)

    for key, value in {"DB_HOST": "localhost", "DB_USER": "utc_session_test",
                       "DB_PASSWORD": "synthetic-utc-password", "DB_NAME": name}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DB_SSL_CA", raising=False)
    monkeypatch.setattr(pymysql, "connect", private_connect)
    connection = get_connection()
    assert connection is not None
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT @@session.time_zone, DATABASE()")
            assert cursor.fetchone() == ("+00:00", name)
    finally:
        connection.close()


def test_auth_collection_separates_trusted_sources_and_nullable_local_logins(mysql, tmp_path, monkeypatch):
    from ingestion.auth.collector import collect_auth_events

    first = enroll(mysql, source_type="auth")
    second = enroll(mysql, source_type="auth", collector_id=first.collector_id)
    logfile = tmp_path / "auth.log"
    logfile.write_text(
        "2026-10-22T12:00:00Z same-name sshd[1]: Failed password for alice from 192.0.2.1 port 123 ssh2\n"
        "2026-10-22T12:00:01Z same-name login[2]: LOGIN ON tty1 BY alice\n"
    )
    for identity in (first, second):
        monkeypatch.setenv("SIEM_AUTH_SOURCE_ID", str(identity.source_id))
        monkeypatch.setenv("SIEM_COLLECTOR_ID", str(identity.collector_id))
        assert collect_auth_events(mysql, logfile, collector_id="scoped-reader")["inserted"] == 2
        assert collect_auth_events(mysql, logfile, collector_id="scoped-reader")["inserted"] == 0
    with mysql.cursor() as cursor:
        cursor.execute("SELECT host_id, source_id, collector_id, source_ip FROM auth_events "
                       "WHERE event_type = 'LOCAL_LOGIN_SUCCESS' ORDER BY host_id")
        assert cursor.fetchall() == ((first.host_id, first.source_id, first.collector_id, None),
                                     (second.host_id, second.source_id, second.collector_id, None))
        cursor.execute("SELECT COUNT(*) FROM auth_ingestion_state WHERE collector_id = 'scoped-reader'")
        assert cursor.fetchone() == (2,)
