"""Shared synthetic data and an opt-in private MySQL server for SSH tests."""

import hashlib
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

from database.auth_migrations import upgrade_auth_events
from detection.ssh_brute_force.detector import detect_ssh_brute_force

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 10, 22, 12)


@pytest.fixture
def apply_migration():
    def apply(connection, filename):
        sql = "\n".join(line for line in (ROOT / "database/migrations" / filename).read_text().splitlines()
                        if not line.lstrip().startswith("--"))
        with connection.cursor() as cursor:
            for statement in sql.split(";"):
                if statement.strip():
                    cursor.execute(statement)
        connection.commit()
    return apply


@pytest.fixture(scope="session")
def private_server():
    if os.getenv("SSH_TEST_MYSQL") != "1":
        pytest.skip("Set SSH_TEST_MYSQL=1 to start a private, isolated MySQL server.")
    executable = shutil.which("mysqld")
    if executable is None:
        pytest.fail("Explicitly requested MySQL tests require mysqld.")
    with tempfile.TemporaryDirectory(prefix="ssh-mysql-") as folder:
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
                        with admin.cursor() as cursor:
                            cursor.execute("SHUTDOWN")
                finally:
                    admin.close()
            # SHUTDOWN is asynchronous; wait for graceful exit before cleanup.
            if admin is None and process.poll() is None:
                process.terminate()
            process.wait(timeout=20)


@pytest.fixture
def mysql(private_server, apply_migration):
    connection = pymysql.connect(unix_socket=private_server, user="root", autocommit=False,
                                 charset="utf8mb4", connect_timeout=5, read_timeout=10)
    try:
        schema_name = f"ssh_test_{time.monotonic_ns()}"
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{schema_name}` CHARACTER SET utf8mb4")
        connection.select_db(schema_name)
        apply_migration(connection, "007_auth_events.sql")
        upgrade_auth_events(connection, ROOT / "database/migrations/021_auth_logins.sql")
        connection.commit()
        yield connection
    finally:
        connection.close()


@pytest.fixture
def sample_events():
    return [
        {"id": index + 1, "event_time": START + timedelta(seconds=index * 10),
         "source_ip": "192.0.2.1", "hostname": "server-a", "username": f"user{index}",
         "event_type": "SSH_AUTH_FAILURE", "service": "sshd",
         "event_hash": hashlib.sha256(f"synthetic-{index}".encode()).hexdigest()}
        for index in range(8)
    ]


@pytest.fixture
def finding(sample_events):
    return detect_ssh_brute_force(sample_events)[0]


@pytest.fixture
def connection():
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.__enter__.return_value = cursor
    return connection
