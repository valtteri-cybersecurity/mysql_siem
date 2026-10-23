import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pymysql
import pytest

START = datetime(2026, 10, 22, 12)


@pytest.fixture
def events():
    rows = []
    for index, (action, protocol, port) in enumerate([
        ("BLOCK", "TCP", 22), ("ALLOW", "TCP", 443), ("AUDIT", "UDP", 53),
        ("BLOCK", "UDP", 53), (None, "ICMP", 0),
    ]):
        rows.append({"event_time": START + timedelta(seconds=index), "src_ip": "192.0.2.1",
                     "dst_ip": "198.51.100.1" if index < 2 else "2001:db8::1",
                     "action": action, "protocol": protocol, "dst_port": port})
    return rows


@pytest.fixture
def connection():
    connection = MagicMock()
    connection._siem_identity_ready = False
    cursor = connection.cursor.return_value
    cursor.__enter__.return_value = cursor
    cursor.fetchone.side_effect = [(1,), (1,)]
    return connection


@pytest.fixture(scope="session")
def analysis_private_server():
    if os.getenv("ANALYSIS_TEST_MYSQL") != "1":
        pytest.skip("Set ANALYSIS_TEST_MYSQL=1 to start a private, isolated MySQL server.")
    executable = shutil.which("mysqld")
    if executable is None:
        pytest.fail("Explicitly requested MySQL tests require mysqld.")
    with tempfile.TemporaryDirectory(prefix="analysis-mysql-") as folder:
        root = Path(folder)
        data = root / "data"
        data.mkdir()
        log = root / "server.log"
        subprocess.run([executable, "--no-defaults", "--initialize-insecure",
                        f"--datadir={data}", f"--log-error={log}"],
                       capture_output=True, check=True, timeout=60)
        socket = root / "mysql.sock"
        process = subprocess.Popen(
            [executable, "--no-defaults", f"--datadir={data}", f"--socket={socket}",
             f"--pid-file={root / 'mysql.pid'}", f"--log-error={log}",
             "--skip-networking", "--mysqlx=OFF", "--performance-schema=OFF",
             "--innodb-buffer-pool-size=32M"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        admin = None
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail("Private MySQL startup failed: " + log.read_text())
                try:
                    admin = pymysql.connect(unix_socket=str(socket), user="root",
                                            connect_timeout=2, read_timeout=5, write_timeout=5)
                    break
                except pymysql.OperationalError:
                    time.sleep(0.1)
            if admin is None:
                pytest.fail("Private MySQL startup timed out.")
            yield str(socket)
        finally:
            if admin is not None:
                try:
                    if process.poll() is None:
                        # The session fixture can be idle while other suites
                        # run. Use a fresh connection to shut down this private
                        # server, as the DNS fixture already does.
                        shutdown = pymysql.connect(unix_socket=str(socket), user="root",
                                                   connect_timeout=2, read_timeout=10)
                        try:
                            with shutdown.cursor() as cursor:
                                cursor.execute("SHUTDOWN")
                        finally:
                            shutdown.close()
                finally:
                    admin.close()
            # SHUTDOWN is asynchronous; wait for graceful exit before cleanup.
            if admin is None and process.poll() is None:
                process.terminate()
            process.wait(timeout=20)


@pytest.fixture
def unmigrated_mysql(analysis_private_server):
    connection = pymysql.connect(unix_socket=analysis_private_server, user="root", autocommit=False,
                                 charset="utf8mb4", connect_timeout=5, read_timeout=10)
    root = Path(__file__).resolve().parents[2]
    schema = (root / "database/schema.sql").read_text()
    try:
        name = f"analysis_test_{time.monotonic_ns()}"
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
        connection.select_db(name)
        # Only CREATE statements in the temporary database, never the dump's DROP statements.
        with connection.cursor() as cursor:
            for table in ("ufw_log",):
                statement = schema.split(f"CREATE TABLE `{table}`", 1)[1].split(";", 1)[0]
                cursor.execute(f"CREATE TABLE `{table}`" + statement)
        apply_analysis_migration(connection)
        yield connection
    finally:
        connection.close()


def apply_analysis_migration(connection, filename="009_analysis_source_ips.sql"):
    root = Path(__file__).resolve().parents[2]
    sql = (root / "database/migrations" / filename).read_text()
    # Only our migration files: support the mysql client's DELIMITER directive
    # so stored-procedure validation is tested exactly as it is deployed.
    delimiter = ";"
    statement = []
    with connection.cursor() as cursor:
        for line in sql.splitlines():
            if line.startswith("--") or not line.strip():
                continue
            if line.startswith("DELIMITER "):
                delimiter = line.split()[1]
                continue
            statement.append(line)
            if line.rstrip().endswith(delimiter):
                query = "\n".join(statement).rstrip()[:-len(delimiter)]
                cursor.execute(query)
                statement = []
    if statement:
        raise ValueError("Unterminated test migration statement.")
    connection.commit()


@pytest.fixture
def migrate_analysis():
    return apply_analysis_migration


@pytest.fixture
def mysql(unmigrated_mysql):
    return unmigrated_mysql
