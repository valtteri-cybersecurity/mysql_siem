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

from ingestion.dns.adapters.adguard import normalize_event
from ingestion.dns.db import (
    DNSStorageError,
    load_state,
    purge_events,
    register_source,
    save_events,
)

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
