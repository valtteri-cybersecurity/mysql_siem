"""A private MySQL 8.4 instance. Never use application DB_* settings."""

import os
import shutil
import subprocess
import time

import pymysql
import pytest

from database.migrate import migrate


@pytest.fixture(scope="session")
def identity_server(tmp_path_factory):
    if os.getenv("SIEM_TEST_MYSQL") != "1":
        pytest.skip("Set SIEM_TEST_MYSQL=1 with MySQL 8.4 mysqld on PATH.")
    executable = shutil.which("mysqld")
    if executable is None:
        pytest.fail("The requested integration tests need MySQL 8.4 mysqld.")
    version = subprocess.run([executable, "--version"], capture_output=True, text=True, check=True).stdout
    if "Ver 8.4." not in version:
        pytest.fail("Phase-2 integration tests require Oracle MySQL 8.4 LTS.")
    root = tmp_path_factory.mktemp("siem-mysql")
    data, socket, log = root / "data", root / "mysql.sock", root / "server.log"
    subprocess.run([executable, "--no-defaults", "--initialize-insecure", f"--datadir={data}",
                    f"--log-error={log}"], check=True, capture_output=True, timeout=60)
    process = subprocess.Popen(
        [executable, "--no-defaults", f"--datadir={data}", f"--socket={socket}",
         f"--log-error={log}", f"--pid-file={root / 'mysql.pid'}", "--skip-networking", "--mysqlx=OFF",
         "--performance-schema=OFF", "--innodb-buffer-pool-size=32M"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    admin = None
    try:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and process.poll() is None:
            try:
                admin = pymysql.connect(unix_socket=str(socket), user="root", connect_timeout=2)
                break
            except pymysql.OperationalError:
                time.sleep(0.1)
        if admin is None:
            pytest.fail("Private MySQL startup failed: " + log.read_text())
        yield str(socket)
    finally:
        if admin is not None:
            try:
                with admin.cursor() as cursor:
                    cursor.execute("SHUTDOWN")
            finally:
                admin.close()
        elif process.poll() is None:
            process.terminate()
        process.wait(timeout=20)


@pytest.fixture
def empty_mysql(identity_server):
    connection = pymysql.connect(unix_socket=identity_server, user="root", charset="utf8mb4", autocommit=False)
    name = f"identity_test_{time.monotonic_ns()}"
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
        connection.select_db(name)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def mysql(empty_mysql):
    migrate(empty_mysql)
    return empty_mysql
