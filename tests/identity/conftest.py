"""A private MySQL 8.0 or 8.4 instance. Never use application DB_* settings."""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pymysql
import pytest

from database.migrate import migrate


def log_tail(path):
    return path.read_text(errors="replace")[-6000:] if path.exists() else "No server log."


@pytest.fixture(scope="session")
def identity_server(tmp_path_factory):
    if os.getenv("SIEM_TEST_MYSQL") != "1":
        pytest.skip("Set SIEM_TEST_MYSQL=1 with Oracle MySQL 8.0 or 8.4 mysqld on PATH.")
    executable = shutil.which("mysqld")
    limiter = shutil.which("prlimit")
    if executable is None or limiter is None:
        pytest.fail("Private MySQL tests require mysqld and Linux prlimit.")
    version = subprocess.run([executable, "--version"], capture_output=True,
                             text=True, check=True, timeout=5).stdout
    if "Ver 8.0." not in version and "Ver 8.4." not in version:
        pytest.fail("Integration tests require Oracle MySQL 8.0 or 8.4.")
    available = int(next(line.split()[1] for line in
                         Path("/proc/meminfo").read_text().splitlines()
                         if line.startswith("MemAvailable:")))
    if available < 2 * 1024 * 1024:
        pytest.fail("Private MySQL tests need at least 2 GiB MemAvailable; no server started.")
    root = tmp_path_factory.mktemp("siem-mysql")
    if shutil.disk_usage(root).free < 1024**3:
        pytest.fail("Private MySQL tests need 1 GiB free disk; no server started.")
    data, socket, log = root / "data", root / "mysql.sock", root / "server.log"
    # prlimit execs only our child. Limits cover initialization as well as startup.
    # Address-space limit is a ceiling, not a reservation of physical memory.
    command = [limiter, "--as=1610612736", "--cpu=300", "--core=0", "--", executable,
               "--no-defaults", f"--datadir={data}", f"--log-error={log}",
               "--innodb-buffer-pool-size=32M", "--innodb-redo-log-capacity=64M",
               "--performance-schema=OFF", "--max-connections=10",
               "--table-open-cache=64", "--table-definition-cache=400"]
    child_env = dict(os.environ, MALLOC_ARENA_MAX="2")
    print(f"Private MySQL {version.strip()}: initializing in {root}", flush=True)
    try:
        subprocess.run(command + ["--initialize-insecure"], check=True,
                       capture_output=True, timeout=60, env=child_env)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        pytest.fail(f"Private MySQL initialization failed ({type(error).__name__}): {log_tail(log)}")
    print("Private MySQL: starting socket-only server", flush=True)
    process = subprocess.Popen(command + [f"--socket={socket}", f"--pid-file={root / 'mysql.pid'}",
                               "--skip-networking", "--mysqlx=OFF"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=child_env)
    admin = None
    try:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and process.poll() is None:
            try:
                admin = pymysql.connect(unix_socket=str(socket), user="root", connect_timeout=2,
                                        read_timeout=10, write_timeout=10,
                                        init_command="SET time_zone = '+00:00'")
                break
            except pymysql.OperationalError:
                time.sleep(0.1)
        if admin is None:
            pytest.fail("Private MySQL startup failed: " + log_tail(log))
        with admin.cursor() as cursor:
            cursor.execute("SELECT @@datadir, @@skip_networking, @@port")
            directory, networking_disabled, _ = cursor.fetchone()
            if Path(directory).resolve() != data.resolve() or not networking_disabled:
                pytest.fail("Private MySQL isolation check failed.")
        print(f"Private MySQL: ready (PID {process.pid})", flush=True)
        yield str(socket)
    finally:
        # Always reap this exact Popen child, including shutdown/timeout failures.
        try:
            if admin is not None:
                try:
                    if process.poll() is None:
                        with admin.cursor() as cursor:
                            cursor.execute("SHUTDOWN")
                finally:
                    admin.close()
        finally:
            try:
                process.wait(timeout=20 if admin is not None else 0)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@pytest.fixture
def empty_mysql(identity_server):
    connection = pymysql.connect(
        unix_socket=identity_server,
        user="root",
        charset="utf8mb4",
        autocommit=False,
        connect_timeout=5, read_timeout=30, write_timeout=30,
        init_command="SET time_zone = '+00:00'"
    )

    name = f"identity_test_{time.monotonic_ns()}"

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4"
            )

        connection.select_db(name)

        yield connection

    finally:
        connection.close()


@pytest.fixture
def mysql(empty_mysql):
    migrate(empty_mysql)
    return empty_mysql
