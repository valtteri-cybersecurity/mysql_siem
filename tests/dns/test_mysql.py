"""Opt-in integration tests: a private mysqld with networking disabled.

DNS_TEST_MYSQL=1 starts a temporary instance; no existing socket or DB is used.
"""

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pymysql
import pytest

from ingestion.dns import client_filters, collector, domain_filters
from ingestion.dns.adapters.adguard import normalize_event
from ingestion.dns.config import CollectorConfig
from ingestion.dns.db import (
    DNSStorageError,
    load_state,
    purge_events,
    register_source,
    save_events,
)
from ingestion.dns.models import DNSPage
from ingestion.dns.query_log import get_dns_query_log
from ingestion.dns.timestamps import timestamp_ns

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def mysql():
    if os.getenv("DNS_TEST_MYSQL") != "1":
        pytest.skip("Set DNS_TEST_MYSQL=1 to start an isolated test server.")
    executable = shutil.which("mysqld")
    if executable is None:
        pytest.fail("mysqld is required for explicitly enabled MySQL tests.")
    # Keep Unix socket paths short, independent of checkout/user directory names.
    with tempfile.TemporaryDirectory(prefix="dns-mysql-") as folder:
        root = Path(folder)
        data = root / "data"
        data.mkdir()
        log = root / "server.log"
        subprocess.run(
            [
                executable,
                "--no-defaults",
                "--initialize-insecure",
                f"--datadir={data}",
                f"--log-error={log}",
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        socket = root / "mysql.sock"
        process = subprocess.Popen(
            [
                executable,
                "--no-defaults",
                f"--datadir={data}",
                f"--socket={socket}",
                f"--pid-file={root / 'mysql.pid'}",
                f"--log-error={log}",
                "--skip-networking",
                "--mysqlx=OFF",
                "--performance-schema=OFF",
                "--innodb-buffer-pool-size=32M",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection = None
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail("Private MySQL startup failed: " + log.read_text())
                try:
                    connection = pymysql.connect(
                        unix_socket=str(socket),
                        user="root",
                        charset="utf8mb4",
                        connect_timeout=2,
                        read_timeout=5,
                        write_timeout=5,
                    )
                    break
                except pymysql.OperationalError:
                    time.sleep(0.1)
            if connection is None:
                pytest.fail("Private MySQL startup timed out.")
            with connection.cursor() as cursor:
                cursor.execute("CREATE DATABASE mysql_siem CHARACTER SET utf8mb4")
                cursor.execute("USE mysql_siem")
                migration = (
                    ROOT / "database/migrations/002_dns_telemetry.sql"
                ).read_text()
                statements = "\n".join(
                    line
                    for line in migration.splitlines()
                    if not line.lstrip().startswith("--")
                )
                for sql in statements.split(";"):
                    if sql.strip():
                        cursor.execute(sql)
            connection.commit()
            yield connection
        finally:
            # Shut down through this fixture's private socket: some execution
            # environments permit child processes but block process signals.
            if process.poll() is None:
                shutdown_connection = connection
                if shutdown_connection is None:
                    shutdown_connection = pymysql.connect(
                        unix_socket=str(socket),
                        user="root",
                        connect_timeout=2,
                        read_timeout=5,
                        write_timeout=5,
                    )
                try:
                    with shutdown_connection.cursor() as cursor:
                        cursor.execute("SHUTDOWN")
                finally:
                    shutdown_connection.close()
                process.wait(timeout=20)
            elif connection is not None:
                connection.close()


@pytest.fixture
def source(mysql):
    source_id = register_source(
        mysql,
        f"dns-{time.monotonic_ns()}",
        "adguard",
        "https://dns.example.net",
        enabled=True,
    )
    with mysql.cursor() as cursor:
        cursor.execute("SELECT source_name FROM dns_sources WHERE id=%s", (source_id,))
        source_name = cursor.fetchone()[0]
    mysql.commit()
    return source_id, source_name


def make_event(source_name, **changes):
    event = normalize_event(
        {
            "time": "2026-10-21T12:34:56.123456789+03:00",
            "client": "2001:db8::1",
            "question": {"name": "EXAMPLE.NET.", "type": "AAAA"},
            "status": "NOERROR",
            "reason": "NotFilteredNotFound",
            "elapsedMs": "1.23456789",
            "cached": False,
        },
        source_name,
    )
    return replace(event, **changes)


def test_real_mysql_roundtrip_with_identical_events(mysql, source):
    source_id, name = source
    event = make_event(name)
    state = {"version": 1, "timestamp": event.raw_timestamp}
    assert save_events(mysql, source_id, [event, event], state=state) == 2
    assert load_state(mysql, source_id) == state
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT event_time, raw_timestamp, client_ip, domain, elapsed_ms, dedup_key FROM dns_events WHERE source_id=%s ORDER BY id",
            (source_id,),
        )
        rows = cursor.fetchall()
    assert len(rows) == 2 and rows[0] == rows[1]
    assert rows[0][0] == datetime(2026, 10, 21, 9, 34, 56, 123456)
    assert rows[0][1] == event.raw_timestamp
    assert rows[0][2:4] == ("2001:db8::1", "example.net")
    assert rows[0][4] == event.elapsed_ms and rows[0][5] is None


def test_real_mysql_checkpoint_failure_rolls_back_events(mysql, source):
    source_id, name = source
    save_events(mysql, source_id, [], state={"version": 1, "position": "old"})
    with mysql.cursor() as cursor:
        cursor.execute(
            "CREATE TRIGGER reject_state BEFORE INSERT ON dns_collection_state FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture failure'"
        )
    try:
        with pytest.raises(DNSStorageError):
            save_events(
                mysql,
                source_id,
                [make_event(name)],
                state={"version": 1, "position": "new"},
            )
        assert load_state(mysql, source_id)["position"] == "old"
        with mysql.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM dns_events WHERE source_id=%s", (source_id,)
            )
            assert cursor.fetchone()[0] == 0
    finally:
        with mysql.cursor() as cursor:
            cursor.execute("DROP TRIGGER reject_state")


def test_real_mysql_sql_values_stay_literal(mysql, source):
    source_id, name = source
    domain = "x'); DROP TABLE dns_events; --"
    save_events(mysql, source_id, [make_event(name, domain=domain)])
    with mysql.cursor() as cursor:
        cursor.execute("SELECT domain FROM dns_events WHERE source_id=%s", (source_id,))
        assert cursor.fetchone()[0] == domain


def test_real_mysql_source_identity_and_disable_flag(mysql):
    source_id = register_source(
        mysql, "disabled-dns", "adguard", "https://dns.example.net"
    )
    assert (
        register_source(
            mysql, "disabled-dns", "adguard", "https://dns.example.net", enabled=True
        )
        == source_id
    )
    with pytest.raises(DNSStorageError, match="disabled"):
        save_events(mysql, source_id, [make_event("disabled-dns")])
    with pytest.raises(DNSStorageError, match="another server"):
        register_source(mysql, "disabled-dns", "adguard", "https://another.example.net")


def test_real_mysql_retention_boundary(mysql, source):
    source_id, name = source
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    cutoff = now - timedelta(days=30)
    save_events(
        mysql,
        source_id,
        [
            make_event(name, event_time=cutoff - timedelta(microseconds=1)),
            make_event(name, event_time=cutoff),
        ],
    )
    assert purge_events(mysql, now=now, batch_size=1) == 1
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT event_time FROM dns_events WHERE source_id=%s", (source_id,)
        )
        assert cursor.fetchall() == ((cutoff.replace(tzinfo=None),),)


def test_real_mysql_fk_blocks_unknown_source(mysql):
    with mysql.cursor() as cursor, pytest.raises(pymysql.IntegrityError):
        cursor.execute(
            "INSERT INTO dns_collection_state VALUES (%s, %s, %s)",
            (2**63, "{}", datetime(2026, 10, 21)),
        )
    mysql.rollback()


def test_real_mysql_application_privileges(mysql):
    with mysql.cursor() as cursor:
        cursor.execute(
            "CREATE USER 'dns_test'@'localhost' IDENTIFIED BY %s", ("fixture-password",)
        )
        cursor.execute(
            "GRANT SELECT, INSERT, UPDATE ON mysql_siem.dns_sources TO 'dns_test'@'localhost'"
        )
        cursor.execute(
            "GRANT SELECT, INSERT, DELETE ON mysql_siem.dns_events TO 'dns_test'@'localhost'"
        )
        cursor.execute(
            "GRANT SELECT, INSERT, UPDATE ON mysql_siem.dns_collection_state TO 'dns_test'@'localhost'"
        )
        cursor.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON mysql_siem.dns_client_filters TO 'dns_test'@'localhost'"
        )
        cursor.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON mysql_siem.dns_domain_filters TO 'dns_test'@'localhost'"
        )
    application = pymysql.connect(
        unix_socket=mysql.unix_socket,
        user="dns_test",
        password="fixture-password",
        database="mysql_siem",
        charset="utf8mb4",
        read_timeout=5,
        write_timeout=5,
    )
    try:
        source_id = register_source(
            application, "app-dns", "adguard", "https://dns.example.net", enabled=True
        )
        assert (
            save_events(
                application, source_id, [make_event("app-dns")], state={"version": 1}
            )
            == 1
        )
        assert load_state(application, source_id) == {"version": 1}
        key = bytes(range(32))
        keyed_event = make_event("app-dns")
        assert save_events(application, source_id, [keyed_event], dedup_keys=[key]) == 1
        assert save_events(application, source_id, [keyed_event], dedup_keys=[key]) == 0
        with application.cursor() as cursor, pytest.raises(pymysql.OperationalError):
            cursor.execute("CREATE TABLE forbidden (id INT)")
        application.rollback()
        filter_id = client_filters.add_client_filter(
            application, source_id, "2001:db8::1", hide_from_query_log=True
        )
        assert get_dns_query_log(application, source_id) == []
        assert len(get_dns_query_log(application, source_id, include_hidden=True)) == 2
        assert client_filters.delete_client_filter(application, source_id, filter_id)
        assert len(get_dns_query_log(application, source_id)) == 2
        domain_id = domain_filters.add_domain_filter(
            application, source_id, "example.net"
        )
        assert len(get_dns_query_log(application, source_id)) == 2
        assert domain_filters.delete_domain_filter(application, source_id, domain_id)
    finally:
        application.close()


def test_real_mysql_collector_resume_and_replay(mysql, source):
    from ingestion.dns.collector import DNSCollectionIncomplete, collect
    from ingestion.dns.config import CollectorConfig
    from ingestion.dns.db import find_source
    from ingestion.dns.models import DNSPage
    from ingestion.dns.timestamps import timestamp_ns

    source_id, name = source
    first = make_event(name)
    older = make_event(
        name,
        raw_timestamp="2026-10-21T09:33:00Z",
        event_time=datetime(2026, 10, 21, 9, 33, tzinfo=timezone.utc),
    )
    records = [first] * 5 + [older]

    class API:
        def fetch_page(self, *, limit, older_than, offset, deadline):
            matches = [
                item
                for item in records
                if timestamp_ns(item.raw_timestamp) < timestamp_ns(older_than)
            ]
            items = tuple(matches[offset : offset + limit])
            return DNSPage(items, items[-1].raw_timestamp if items else None)

    now = datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc)
    with pytest.raises(DNSCollectionIncomplete):
        collect(
            API(), mysql, source_id, CollectorConfig(max_pages=3), page_size=2, now=now
        )
    assert load_state(mysql, source_id)["completed_until"] is None
    assert load_state(mysql, source_id)["pending"]["cursor"] == first.raw_timestamp
    assert (
        collect(API(), mysql, source_id, CollectorConfig(), page_size=2, now=now)[
            "inserted"
        ]
        == 1
    )
    assert (
        collect(
            API(),
            mysql,
            source_id,
            CollectorConfig(),
            page_size=2,
            now=now + timedelta(minutes=5),
        )["inserted"]
        == 0
    )
    assert find_source(mysql, name, "adguard", "https://dns.example.net") == source_id
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*), COUNT(DISTINCT dedup_key) FROM dns_events WHERE source_id=%s",
            (source_id,),
        )
        assert cursor.fetchone() == (6, 6)


def test_real_mysql_source_lock_excludes_other_connection(mysql, source):
    from ingestion.dns.db import DNSCollectionBusy, source_lock

    other = pymysql.connect(
        unix_socket=mysql.unix_socket,
        user="root",
        database="mysql_siem",
        read_timeout=5,
        write_timeout=5,
    )
    source_id, _ = source
    try:
        with (
            source_lock(mysql, source_id),
            pytest.raises(DNSCollectionBusy),
            source_lock(other, source_id),
        ):
            pytest.fail("Second collector acquired an occupied source lock.")
        with source_lock(other, source_id):
            pass
    finally:
        other.close()


def test_real_mysql_legacy_rows_are_not_silently_recollected(mysql, source):
    from ingestion.dns.db import find_source

    source_id, name = source
    save_events(mysql, source_id, [make_event(name)])
    with pytest.raises(DNSStorageError, match="legacy rows"):
        find_source(mysql, name, "adguard", "https://dns.example.net")


@pytest.fixture(scope="module", autouse=True)
def client_filter_schema(mysql):
    for filename in ("005_dns_client_filters.sql", "006_dns_domain_filters.sql"):
        migration = (ROOT / "database/migrations" / filename).read_text()
        statements = "\n".join(
            line
            for line in migration.splitlines()
            if not line.lstrip().startswith("--")
        )
        with mysql.cursor() as cursor:
            for sql in statements.split(";"):
                if sql.strip():
                    cursor.execute(sql)
        mysql.commit()


@pytest.fixture
def filter_source(source, client_filter_schema):
    return source


def test_real_client_filter_schema_types_and_unique_key(mysql, client_filter_schema):
    with mysql.cursor() as cursor:
        cursor.execute("SHOW COLUMNS FROM dns_client_filters")
        columns = {row[0]: row[1] for row in cursor.fetchall()}
        assert columns["source_id"] == "bigint unsigned"
        for flag in ("hide_from_query_log", "exclude_from_collection", "enabled"):
            assert columns[flag] == "tinyint(1)"
        cursor.execute(
            "SHOW INDEX FROM dns_client_filters WHERE Key_name = 'uq_dns_client_filter'"
        )
        index = sorted(cursor.fetchall(), key=lambda row: row[3])
        assert [row[4] for row in index] == ["source_id", "client_ip"]
        assert all(row[1] == 0 for row in index)
    mysql.commit()


def test_real_client_filter_lifecycle_and_independent_options(mysql, filter_source):
    source_id, _ = filter_source
    rule_id = client_filters.add_client_filter(
        mysql,
        source_id,
        "192.0.2.15",
        "Smart TV",
        hide_from_query_log=True,
        exclude_from_collection=True,
    )
    rule = client_filters.get_active_client_filters(mysql, source_id)[0]
    assert rule["id"] == rule_id
    assert rule["hide_from_query_log"] is True
    assert rule["exclude_from_collection"] is True
    assert rule["created_at"] is not None and rule["updated_at"] is not None
    assert client_filters.update_client_filter_options(
        mysql, source_id, rule_id, hide_from_query_log=False
    )
    rule = client_filters.list_client_filters(mysql, source_id)[0]
    assert rule["hide_from_query_log"] is False
    assert rule["exclude_from_collection"] is True
    assert client_filters.update_client_filter_options(
        mysql, source_id, rule_id, exclude_from_collection=False
    )
    assert client_filters.update_client_filter_description(
        mysql, source_id, rule_id, "Living room — TV"
    )
    assert (
        client_filters.list_client_filters(mysql, source_id)[0]["description"]
        == "Living room — TV"
    )
    assert client_filters.disable_client_filter(mysql, source_id, rule_id)
    assert client_filters.get_active_client_filters(mysql, source_id) == []
    assert len(client_filters.list_client_filters(mysql, source_id)) == 1
    assert client_filters.enable_client_filter(mysql, source_id, rule_id)
    assert len(client_filters.get_active_client_filters(mysql, source_id)) == 1
    assert client_filters.update_client_filter_description(
        mysql, source_id, rule_id, ""
    )
    assert client_filters.delete_client_filter(mysql, source_id, rule_id)
    assert client_filters.list_client_filters(mysql, source_id) == []
    assert not client_filters.delete_client_filter(mysql, source_id, rule_id)


def test_real_client_filter_ipv6_normalization_prevents_duplicate(mysql, filter_source):
    source_id, _ = filter_source
    rule_id = client_filters.add_client_filter(
        mysql,
        source_id,
        "2001:0DB8:0000:0000:0000:0000:0000:0001",
        "Original",
        enabled=False,
    )
    with pytest.raises(ValueError, match="already exists"):
        client_filters.add_client_filter(
            mysql,
            source_id,
            "2001:db8::1",
            "Must not overwrite",
            hide_from_query_log=True,
        )
    rules = client_filters.list_client_filters(mysql, source_id)
    assert len(rules) == 1
    assert rules[0]["id"] == rule_id
    assert rules[0]["client_ip"] == "2001:db8::1"
    assert rules[0]["description"] == "Original"
    assert rules[0]["enabled"] is False
    assert rules[0]["hide_from_query_log"] is False


def test_real_client_filters_separate_sources_and_scope_every_mutation(
    mysql, filter_source
):
    source_id, _ = filter_source
    other_id = register_source(
        mysql, f"other-{time.monotonic_ns()}", "adguard", "https://other.example.net"
    )
    rule_id = client_filters.add_client_filter(
        mysql, source_id, "192.0.2.15", hide_from_query_log=True
    )
    other_rule_id = client_filters.add_client_filter(
        mysql, other_id, "192.0.2.15", exclude_from_collection=True
    )
    assert not client_filters.disable_client_filter(mysql, other_id, rule_id)
    assert not client_filters.enable_client_filter(mysql, other_id, rule_id)
    assert not client_filters.update_client_filter_options(
        mysql, other_id, rule_id, hide_from_query_log=False
    )
    assert not client_filters.update_client_filter_description(
        mysql, other_id, rule_id, "Wrong source"
    )
    assert not client_filters.delete_client_filter(mysql, other_id, rule_id)
    first = client_filters.get_active_client_filters(mysql, source_id)[0]
    other = client_filters.get_active_client_filters(mysql, other_id)[0]
    assert first["id"] == rule_id and first["hide_from_query_log"] is True
    assert other["id"] == other_rule_id and other["exclude_from_collection"] is True
    assert {rule_id, other_rule_id} <= {
        rule["id"] for rule in client_filters.list_client_filters(mysql)
    }
    assert client_filters.delete_client_filter(mysql, source_id, rule_id)
    assert (
        client_filters.get_active_client_filters(mysql, other_id)[0]["id"]
        == other_rule_id
    )


def test_real_client_filter_description_is_literal_data(mysql, filter_source):
    source_id, _ = filter_source
    text = "TV'); DELETE FROM dns_events; --"
    rule_id = client_filters.add_client_filter(mysql, source_id, "192.0.2.15", text)
    assert (
        client_filters.list_client_filters(mysql, source_id)[0]["description"] == text
    )
    assert client_filters.update_client_filter_description(
        mysql, source_id, rule_id, text + " updated"
    )
    assert (
        client_filters.list_client_filters(mysql, source_id)[0]["description"]
        == text + " updated"
    )


def test_real_client_filter_foreign_key_rejects_unknown_source(
    mysql, client_filter_schema
):
    with pytest.raises(DNSStorageError):
        client_filters.add_client_filter(mysql, 2**63, "192.0.2.15")
    assert client_filters.list_client_filters(mysql, 2**63) == []


def test_real_client_filter_foreign_key_prevents_orphan_rules(mysql, filter_source):
    source_id, _ = filter_source
    rule_id = client_filters.add_client_filter(mysql, source_id, "192.0.2.15")
    try:
        with mysql.cursor() as cursor, pytest.raises(pymysql.IntegrityError):
            cursor.execute("DELETE FROM dns_sources WHERE id = %s", (source_id,))
    finally:
        mysql.rollback()
    assert client_filters.list_client_filters(mysql, source_id)[0]["id"] == rule_id


def test_real_client_filter_management_leaves_events_and_checkpoint_unchanged(
    mysql, filter_source
):
    source_id, name = filter_source
    event = make_event(name)
    state = {"version": 1, "position": "unchanged"}
    assert save_events(mysql, source_id, [event], state=state) == 1
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM dns_events WHERE source_id = %s ORDER BY id", (source_id,)
        )
        before = cursor.fetchall()
    rule_id = client_filters.add_client_filter(
        mysql,
        source_id,
        event.client_ip,
        hide_from_query_log=True,
        exclude_from_collection=True,
    )
    client_filters.update_client_filter_description(mysql, source_id, rule_id, "Test")
    client_filters.disable_client_filter(mysql, source_id, rule_id)
    client_filters.enable_client_filter(mysql, source_id, rule_id)
    client_filters.update_client_filter_options(
        mysql, source_id, rule_id, hide_from_query_log=False
    )
    client_filters.delete_client_filter(mysql, source_id, rule_id)
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM dns_events WHERE source_id = %s ORDER BY id", (source_id,)
        )
        assert cursor.fetchall() == before
    assert load_state(mysql, source_id) == state


def test_real_client_filter_low_level_storage_does_not_apply_collection_policy(
    mysql, filter_source
):
    source_id, name = filter_source
    event = make_event(name)
    client_filters.add_client_filter(
        mysql,
        source_id,
        event.client_ip,
        hide_from_query_log=True,
        exclude_from_collection=True,
    )
    # Collection enforces policy; low-level storage stays independent.
    assert save_events(mysql, source_id, [event]) == 1


class ClientFilterQueryLog:
    def __init__(self, events):
        self.events = events
        self.calls = []

    def fetch_page(self, *, limit, older_than, offset, deadline):
        self.calls.append((older_than, offset))
        matches = sorted(
            (
                item
                for item in self.events
                if timestamp_ns(item.raw_timestamp) < timestamp_ns(older_than)
            ),
            key=lambda item: timestamp_ns(item.raw_timestamp),
            reverse=True,
        )
        items = tuple(matches[offset : offset + limit])
        return DNSPage(items, items[-1].raw_timestamp if items else None)


@pytest.mark.parametrize(
    "enabled,hide,exclude,saved",
    [
        (True, False, False, 1),
        (True, True, False, 1),
        (True, False, True, 0),
        (True, True, True, 0),
        (False, True, True, 1),
    ],
)
def test_real_collection_respects_only_enabled_exclusion(
    mysql, filter_source, enabled, hide, exclude, saved
):
    source_id, name = filter_source
    record = make_event(name)
    client_filters.add_client_filter(
        mysql,
        source_id,
        record.client_ip,
        hide_from_query_log=hide,
        exclude_from_collection=exclude,
        enabled=enabled,
    )
    result = collector.collect(
        ClientFilterQueryLog([record]),
        mysql,
        source_id,
        CollectorConfig(),
        now=datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc),
    )
    assert result["inserted"] == saved
    assert result["excluded"] == 1 - saved
    assert load_state(mysql, source_id)["pending"] is None
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) FROM dns_events WHERE source_id = %s", (source_id,)
        )
        assert cursor.fetchone()[0] == saved


def test_real_collection_same_client_is_not_excluded_from_another_source(
    mysql, filter_source
):
    source_id, name = filter_source
    other_name = f"collection-other-{time.monotonic_ns()}"
    other_id = register_source(
        mysql, other_name, "adguard", "https://other.example.net", enabled=True
    )
    client_filters.add_client_filter(
        mysql, source_id, "2001:db8::1", exclude_from_collection=True
    )
    now = datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc)
    for current_id, current_name, saved in (
        (source_id, name, 0),
        (other_id, other_name, 1),
    ):
        result = collector.collect(
            ClientFilterQueryLog([make_event(current_name)]),
            mysql,
            current_id,
            CollectorConfig(),
            now=now,
        )
        assert result["inserted"] == saved
        assert result["excluded"] == 1 - saved


@pytest.mark.parametrize(
    "remove_exclusion",
    [client_filters.disable_client_filter, client_filters.delete_client_filter],
)
def test_real_removing_exclusion_restores_collection_without_full_history_replay(
    mysql, filter_source, remove_exclusion
):
    source_id, name = filter_source
    recent = make_event(name)
    old = make_event(
        name,
        raw_timestamp="2026-10-21T08:00:00Z",
        event_time=datetime(2026, 10, 21, 8, tzinfo=timezone.utc),
    )
    rule_id = client_filters.add_client_filter(
        mysql, source_id, recent.client_ip, exclude_from_collection=True
    )
    now = datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc)
    assert (
        collector.collect(
            ClientFilterQueryLog([old, recent]),
            mysql,
            source_id,
            CollectorConfig(),
            now=now,
        )["excluded"]
        == 2
    )
    assert remove_exclusion(mysql, source_id, rule_id)
    new = make_event(
        name,
        raw_timestamp="2026-10-21T09:39:00Z",
        event_time=datetime(2026, 10, 21, 9, 39, tzinfo=timezone.utc),
    )
    records = [old, recent, new]
    result = collector.collect(
        ClientFilterQueryLog(records),
        mysql,
        source_id,
        CollectorConfig(),
        now=now + timedelta(minutes=5),
    )
    # Only the existing bounded overlap and new window are eligible, not 30 days again.
    assert result["inserted"] == 2 and result["excluded"] == 0
    assert (
        collector.collect(
            ClientFilterQueryLog(records),
            mysql,
            source_id,
            CollectorConfig(),
            now=now + timedelta(minutes=10),
        )["inserted"]
        == 0
    )
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) FROM dns_events WHERE source_id = %s", (source_id,)
        )
        assert cursor.fetchone()[0] == 2


@pytest.mark.parametrize("kept_count", [0, 1001])
@pytest.mark.parametrize("kind", ["client", "domain"])
def test_real_filtered_checkpoint_failure_and_restart_preserve_committed_rows(
    mysql, filter_source, kept_count, kind
):
    source_id, name = filter_source
    excluded = make_event(name, domain="scs.samsungqbe.com")
    allowed = make_event(name, client_ip="192.0.2.15", domain="example.net")
    records = [excluded] * 1000 + [allowed] * kept_count
    if kind == "client":
        client_filters.add_client_filter(
            mysql, source_id, excluded.client_ip, exclude_from_collection=True
        )
    else:
        domain_filters.add_domain_filter(mysql, source_id, excluded.domain)
    original_state = {
        "version": 1,
        "completed_until": None,
        "pending": {
            "upper": "2026-10-21T09:35:30Z",
            "lower": "2026-10-21T09:00:00Z",
            "cursor": "2026-10-21T09:35:30Z",
        },
    }
    save_events(mysql, source_id, [], state=original_state)
    with mysql.cursor() as cursor:
        cursor.execute(
            "CREATE TRIGGER reject_filtered_checkpoint BEFORE INSERT ON dns_collection_state FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture failure'"
        )
    now = datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc)
    try:
        with pytest.raises(DNSStorageError):
            collector.collect(
                ClientFilterQueryLog(records),
                mysql,
                source_id,
                CollectorConfig(),
                page_size=1000,
                now=now,
            )
        assert load_state(mysql, source_id) == original_state
        with mysql.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM dns_events WHERE source_id = %s", (source_id,)
            )
            assert cursor.fetchone()[0] == (1000 if kept_count else 0)
    finally:
        with mysql.cursor() as cursor:
            cursor.execute("DROP TRIGGER reject_filtered_checkpoint")
    result = collector.collect(
        ClientFilterQueryLog(records),
        mysql,
        source_id,
        CollectorConfig(),
        page_size=1000,
        now=now,
    )
    assert result["inserted"] == (1 if kept_count else 0)
    assert result["excluded"] == 1000
    assert load_state(mysql, source_id)["pending"] is None
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*), COUNT(DISTINCT dedup_key) FROM dns_events WHERE source_id = %s",
            (source_id,),
        )
        assert cursor.fetchone() == (kept_count, kept_count)


def test_real_rule_permission_error_stops_before_fetch_or_state_changes(
    mysql, filter_source
):
    source_id, name = filter_source
    with mysql.cursor() as cursor:
        cursor.execute(
            "CREATE USER 'filter_no_access'@'localhost' IDENTIFIED BY %s",
            ("fixture-password",),
        )
    connection = pymysql.connect(
        unix_socket=mysql.unix_socket,
        user="filter_no_access",
        password="fixture-password",
        read_timeout=5,
        write_timeout=5,
    )
    try:
        with mysql.cursor() as cursor:
            cursor.execute(
                "GRANT SELECT ON mysql_siem.dns_sources TO 'filter_no_access'@'localhost'"
            )
        connection.select_db("mysql_siem")
        log = ClientFilterQueryLog([make_event(name)])
        with pytest.raises(DNSStorageError):
            collector.collect(
                log,
                connection,
                source_id,
                CollectorConfig(),
                now=datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc),
            )
        assert not log.calls
        assert load_state(mysql, source_id) is None
    finally:
        connection.close()


def test_real_query_log_hide_toggle_preserves_events_and_state(mysql, filter_source):
    source_id, name = filter_source
    state = {"version": 1, "position": "unchanged"}
    save_events(mysql, source_id, [make_event(name)], state=state)
    original = get_dns_query_log(mysql, source_id)
    assert len(original) == 1
    rule_id = client_filters.add_client_filter(
        mysql, source_id, "2001:db8::1", hide_from_query_log=True
    )
    assert get_dns_query_log(mysql, source_id) == []
    assert get_dns_query_log(mysql, source_id, include_hidden=True) == original
    client_filters.disable_client_filter(mysql, source_id, rule_id)
    assert get_dns_query_log(mysql, source_id) == original
    client_filters.enable_client_filter(mysql, source_id, rule_id)
    assert get_dns_query_log(mysql, source_id) == []
    client_filters.update_client_filter_options(
        mysql, source_id, rule_id, hide_from_query_log=False
    )
    assert get_dns_query_log(mysql, source_id) == original
    client_filters.update_client_filter_options(
        mysql, source_id, rule_id, hide_from_query_log=True
    )
    client_filters.delete_client_filter(mysql, source_id, rule_id)
    assert get_dns_query_log(mysql, source_id) == original
    assert load_state(mysql, source_id) == state
    with mysql.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) FROM dns_events WHERE source_id = %s", (source_id,)
        )
        assert cursor.fetchone()[0] == 1


@pytest.mark.parametrize(
    "rule_ip,event_ip,hidden",
    [
        ("192.0.2.15", "192.0.2.15", True),
        ("2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001", True),
        ("::ffff:192.0.2.15", "::ffff:c000:20f", True),
        ("::ffff:c000:20f", "::ffff:192.0.2.15", True),
        ("192.0.2.15", "::ffff:192.0.2.15", False),
        ("::ffff:c000:20f", "192.0.2.15", False),
        ("192.0.2.15", "192.000.2.15", False),
        ("::ffff:c000:20f", "::ffff:192.000.2.15", False),
        ("fe80::1", "fe80::1%eth0", False),
        ("2001:db8::1", "2001:db8::/64", False),
        ("0.0.0.0", None, False),
        ("192.0.2.15", "192.0.2.15:53", False),
        ("0.0.0.0", "unknown", False),
        ("::1", "::1 ", False),
        ("::1", " ::1", False),
        ("192.0.2.15", "192.0.2.15 ", False),
    ],
)
def test_real_query_log_ip_comparison_is_normalized_and_unambiguous(
    mysql, filter_source, rule_ip, event_ip, hidden
):
    source_id, name = filter_source
    save_events(mysql, source_id, [make_event(name, client_ip=event_ip)])
    client_filters.add_client_filter(
        mysql, source_id, rule_ip, hide_from_query_log=True
    )
    assert len(get_dns_query_log(mysql, source_id)) == (0 if hidden else 1)
    assert len(get_dns_query_log(mysql, source_id, include_hidden=True)) == 1


def test_real_invalid_stored_rule_cannot_hide_a_different_valid_ip(
    mysql, filter_source
):
    source_id, name = filter_source
    save_events(mysql, source_id, [make_event(name, client_ip="192.0.2.15")])
    rule_id = client_filters.add_client_filter(
        mysql, source_id, "192.0.2.15", hide_from_query_log=True
    )
    # Simulate a bad external SQL edit bypassing the validated management API.
    with mysql.cursor() as cursor:
        cursor.execute(
            "UPDATE dns_client_filters SET client_ip = %s WHERE id = %s",
            ("192.000.2.15", rule_id),
        )
    mysql.commit()
    assert len(get_dns_query_log(mysql, source_id)) == 1


def test_real_query_log_visibility_is_source_scoped_even_when_including_hidden(
    mysql, filter_source
):
    source_id, name = filter_source
    other_name = f"view-other-{time.monotonic_ns()}"
    other_id = register_source(
        mysql, other_name, "adguard", "https://other.example.net"
    )
    save_events(mysql, source_id, [make_event(name)])
    # Storage requires an enabled source, even though Query Log can read paused sources.
    with mysql.cursor() as cursor:
        cursor.execute(
            "UPDATE dns_sources SET enabled = TRUE WHERE id = %s", (other_id,)
        )
    mysql.commit()
    save_events(mysql, other_id, [make_event(other_name)])
    client_filters.add_client_filter(
        mysql, source_id, "2001:db8::1", hide_from_query_log=True
    )
    assert get_dns_query_log(mysql, source_id) == []
    assert len(get_dns_query_log(mysql, other_id)) == 1
    for current in (source_id, other_id):
        assert {
            row["source_id"]
            for row in get_dns_query_log(mysql, current, include_hidden=True)
        } == {current}


def test_real_query_log_filters_before_limit_and_pages_timestamp_ties(
    mysql, filter_source
):
    source_id, name = filter_source
    visible = make_event(
        name,
        client_ip="192.0.2.15",
        raw_timestamp="2026-10-21T09:30:00Z",
        event_time=datetime(2026, 10, 21, 9, 30, tzinfo=timezone.utc),
    )
    hidden = make_event(name)
    save_events(mysql, source_id, [visible] * 5 + [hidden] * 160)
    client_filters.add_client_filter(
        mysql, source_id, hidden.client_ip, hide_from_query_log=True
    )
    seen = []
    before = None
    lengths = []
    while True:
        page = get_dns_query_log(mysql, source_id, limit=2, before=before)
        if not page:
            break
        lengths.append(len(page))
        seen.extend(row["id"] for row in page)
        before = (page[-1]["event_time"], page[-1]["id"])
    assert lengths == [2, 2, 1]
    assert len(set(seen)) == 5 and seen == sorted(seen, reverse=True)
    assert all(
        row["client_ip"] == hidden.client_ip
        for row in get_dns_query_log(mysql, source_id, limit=2, include_hidden=True)
    )


def test_real_query_log_cursor_does_not_repeat_rows_after_newer_inserts(
    mysql, filter_source
):
    source_id, name = filter_source
    record = make_event(name)
    save_events(mysql, source_id, [record] * 4)
    first = get_dns_query_log(mysql, source_id, limit=2)
    save_events(mysql, source_id, [record])
    second = get_dns_query_log(
        mysql, source_id, limit=2, before=(first[-1]["event_time"], first[-1]["id"])
    )
    assert len(second) == 2
    assert {row["id"] for row in first}.isdisjoint(row["id"] for row in second)
    assert all(row["id"] < first[-1]["id"] for row in second)


def test_real_both_filters_hide_history_but_cannot_recover_never_stored_events(
    mysql, filter_source
):
    source_id, name = filter_source
    previous = make_event(name)
    save_events(
        mysql, source_id, [previous], dedup_keys=collector.replay_keys([previous])
    )
    original = get_dns_query_log(mysql, source_id)
    rule_id = client_filters.add_client_filter(
        mysql,
        source_id,
        previous.client_ip,
        hide_from_query_log=True,
        exclude_from_collection=True,
    )
    new = make_event(
        name,
        raw_timestamp="2026-10-21T09:39:00Z",
        event_time=datetime(2026, 10, 21, 9, 39, tzinfo=timezone.utc),
    )
    result = collector.collect(
        ClientFilterQueryLog([new]),
        mysql,
        source_id,
        CollectorConfig(),
        now=datetime(2026, 10, 21, 9, 40, tzinfo=timezone.utc),
    )
    assert result["inserted"] == 0 and result["excluded"] == 1
    assert get_dns_query_log(mysql, source_id) == []
    assert get_dns_query_log(mysql, source_id, include_hidden=True) == original
    client_filters.update_client_filter_options(
        mysql, source_id, rule_id, hide_from_query_log=False
    )
    # Exclusion alone never hides or deletes previously stored history.
    assert get_dns_query_log(mysql, source_id) == original
    assert (
        client_filters.get_active_client_filters(mysql, source_id)[0][
            "exclude_from_collection"
        ]
        is True
    )
    assert all(
        row["raw_timestamp"] != new.raw_timestamp
        for row in get_dns_query_log(mysql, source_id, include_hidden=True)
    )


def test_real_domain_filter_schema_and_lifecycle(mysql, filter_source):
    source_id, name = filter_source
    record = make_event(name, domain="scs.samsungqbe.com")
    save_events(
        mysql, source_id, [record], state={"version": 1, "position": "unchanged"}
    )
    history = get_dns_query_log(mysql, source_id)
    rule_id = domain_filters.add_domain_filter(
        mysql, source_id, "SCS.SamsungQBE.COM.", "Samsung domain"
    )
    with pytest.raises(ValueError, match="already exists"):
        domain_filters.add_domain_filter(
            mysql, source_id, "scs.samsungqbe.com", "Must not overwrite"
        )
    assert (
        domain_filters.get_active_domain_filters(mysql, source_id)[0]["description"]
        == "Samsung domain"
    )
    assert domain_filters.update_domain_filter_description(
        mysql, source_id, rule_id, "Updated"
    )
    assert domain_filters.disable_domain_filter(mysql, source_id, rule_id)
    assert domain_filters.get_active_domain_filters(mysql, source_id) == []
    assert domain_filters.enable_domain_filter(mysql, source_id, rule_id)
    assert (
        domain_filters.list_domain_filters(mysql, source_id)[0]["domain"]
        == "scs.samsungqbe.com"
    )
    assert domain_filters.delete_domain_filter(mysql, source_id, rule_id)
    assert domain_filters.list_domain_filters(mysql, source_id) == []
    assert get_dns_query_log(mysql, source_id) == history
    assert load_state(mysql, source_id) == {"version": 1, "position": "unchanged"}
    with mysql.cursor() as cursor:
        cursor.execute("SHOW COLUMNS FROM dns_domain_filters")
        columns = {row[0]: row[1] for row in cursor.fetchall()}
        assert columns["source_id"] == "bigint unsigned"
        assert (
            columns["domain"] == "varchar(253)" and columns["enabled"] == "tinyint(1)"
        )
        cursor.execute(
            "SHOW INDEX FROM dns_domain_filters WHERE Key_name = 'uq_dns_domain_filter'"
        )
        index = sorted(cursor.fetchall(), key=lambda row: row[3])
        assert [row[4] for row in index] == ["source_id", "domain"]
        assert all(row[1] == 0 for row in index)


def test_real_domain_exclusion_is_exact_source_scoped_and_client_independent(
    mysql, filter_source
):
    source_id, name = filter_source
    other_name = f"domain-other-{time.monotonic_ns()}"
    other_id = register_source(
        mysql, other_name, "adguard", "https://other.example.net", enabled=True
    )
    rule_id = domain_filters.add_domain_filter(mysql, source_id, "scs.samsungqbe.com")
    target = make_event(
        name,
        domain="scs.samsungqbe.com",
        filtering_result="blocked",
        filtering_reason="FilteredBlackList",
    )
    allowed = make_event(name, domain="other.samsungqbe.com")
    child = make_event(name, domain="sub.scs.samsungqbe.com")
    other_client = make_event(name, domain="scs.samsungqbe.com", client_ip="192.0.2.15")
    now = datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc)
    result = collector.collect(
        ClientFilterQueryLog([target, allowed, child, other_client]),
        mysql,
        source_id,
        CollectorConfig(),
        page_size=1,
        now=now,
    )
    assert result["inserted"] == 2 and result["excluded"] == 2
    assert {row["domain"] for row in get_dns_query_log(mysql, source_id)} == {
        allowed.domain,
        child.domain,
    }
    result = collector.collect(
        ClientFilterQueryLog([make_event(other_name, domain=target.domain)]),
        mysql,
        other_id,
        CollectorConfig(),
        now=now,
    )
    assert result["inserted"] == 1 and result["excluded"] == 0
    assert not domain_filters.disable_domain_filter(mysql, other_id, rule_id)
    assert not domain_filters.delete_domain_filter(mysql, other_id, rule_id)
    assert not domain_filters.update_domain_filter_description(
        mysql, other_id, rule_id, "Wrong source"
    )
    other_rule = domain_filters.add_domain_filter(mysql, other_id, target.domain)
    assert {rule_id, other_rule} <= {
        row["id"] for row in domain_filters.list_domain_filters(mysql)
    }


@pytest.mark.parametrize(
    "remove_rule",
    [domain_filters.disable_domain_filter, domain_filters.delete_domain_filter],
)
def test_real_domain_exclusion_removal_keeps_checkpoint_and_prior_history(
    mysql, filter_source, remove_rule
):
    source_id, name = filter_source
    recent = make_event(name, domain="scs.samsungqbe.com")
    old = make_event(
        name,
        domain=recent.domain,
        raw_timestamp="2026-10-21T08:00:00Z",
        event_time=datetime(2026, 10, 21, 8, tzinfo=timezone.utc),
    )
    rule_id = domain_filters.add_domain_filter(mysql, source_id, recent.domain)
    now = datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc)
    assert (
        collector.collect(
            ClientFilterQueryLog([recent, old]),
            mysql,
            source_id,
            CollectorConfig(),
            now=now,
        )["excluded"]
        == 2
    )
    assert load_state(mysql, source_id)["pending"] is None
    assert remove_rule(mysql, source_id, rule_id)
    new = make_event(
        name,
        domain=recent.domain,
        raw_timestamp="2026-10-21T09:39:00Z",
        event_time=datetime(2026, 10, 21, 9, 39, tzinfo=timezone.utc),
    )
    result = collector.collect(
        ClientFilterQueryLog([recent, old, new]),
        mysql,
        source_id,
        CollectorConfig(),
        now=now + timedelta(minutes=5),
    )
    assert result["inserted"] == 2 and result["excluded"] == 0
    assert {row["raw_timestamp"] for row in get_dns_query_log(mysql, source_id)} == {
        recent.raw_timestamp,
        new.raw_timestamp,
    }


def test_real_domain_filter_foreign_key_and_literal_description(mysql, filter_source):
    source_id, _ = filter_source
    with pytest.raises(DNSStorageError):
        domain_filters.add_domain_filter(mysql, 2**63, "example.org")
    text = "Samsung'); DELETE FROM dns_events; --"
    rule_id = domain_filters.add_domain_filter(mysql, source_id, "example.org", text)
    assert (
        domain_filters.list_domain_filters(mysql, source_id)[0]["description"] == text
    )
    try:
        with mysql.cursor() as cursor, pytest.raises(pymysql.IntegrityError):
            cursor.execute("DELETE FROM dns_sources WHERE id = %s", (source_id,))
    finally:
        mysql.rollback()
    assert domain_filters.list_domain_filters(mysql, source_id)[0]["id"] == rule_id


def test_real_domain_rule_permission_error_stops_before_fetch(mysql, filter_source):
    source_id, name = filter_source
    with mysql.cursor() as cursor:
        cursor.execute(
            "CREATE USER 'domain_no_access'@'localhost' IDENTIFIED BY %s",
            ("fixture-password",),
        )
        cursor.execute(
            "GRANT SELECT ON mysql_siem.dns_sources TO 'domain_no_access'@'localhost'"
        )
        cursor.execute(
            "GRANT SELECT ON mysql_siem.dns_client_filters TO 'domain_no_access'@'localhost'"
        )
    connection = pymysql.connect(
        unix_socket=mysql.unix_socket,
        user="domain_no_access",
        password="fixture-password",
        database="mysql_siem",
        read_timeout=5,
        write_timeout=5,
    )
    try:
        api = ClientFilterQueryLog([make_event(name)])
        with pytest.raises(DNSStorageError):
            collector.collect(
                api,
                connection,
                source_id,
                CollectorConfig(),
                now=datetime(2026, 10, 21, 9, 36, tzinfo=timezone.utc),
            )
        assert not api.calls and load_state(mysql, source_id) is None
    finally:
        connection.close()
