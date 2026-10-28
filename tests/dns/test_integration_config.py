import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "relocated project"
    config = root / "config"
    config.mkdir(parents=True)
    shutil.copy(ROOT / "config/run_with_env.sh", config / "run_with_env.sh")
    runtime = root / "config/run_with_env.sh"
    runtime.write_text(runtime.read_text().replace(
        "LOCAL_STATE_DIR=/usr/local/lib/.mysql_siem-local",
        "LOCAL_STATE_DIR=" + shlex.quote(str(root / "local-state")),
    ))
    (config / "mysql.env").write_text(
        "DB_HOST=localhost\nDB_USER=test-user\nDB_PASSWORD=literal-password\n"
        "DB_NAME=mysql_siem\nDB_READ_TIMEOUT=15\n"
    )
    return root


def run_wrapper(project, *options):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("DB_", "ADGUARD_", "DNS_"))
    }
    return subprocess.run(
        [
            "bash",
            str(project / "config/run_with_env.sh"),
            *options,
            sys.executable,
            "-B",
            "-c",
            (
                "import json,os; print(json.dumps({k:v for k,v in os.environ.items() "
                "if k.startswith(('DB_', 'ADGUARD_', 'DNS_'))}))"
            ),
        ],
        cwd=project.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_other_collectors_do_not_require_dns_config(project):
    result = run_wrapper(project)
    assert result.returncode == 0
    assert json.loads(result.stdout)["DB_READ_TIMEOUT"] == "15"
    assert "ADGUARD_URL" not in result.stdout


def test_dns_opt_in_requires_config(project):
    result = run_wrapper(project, "--dns")
    assert result.returncode != 0
    assert "DNS configuration" in result.stderr


def test_dns_config_is_literal_and_relocatable(project):
    marker = project / "must-not-exist"
    password = f"$(touch {marker})"
    (project / "config/adguard.env").write_text(
        "ADGUARD_URL=https://dns.example.net\nADGUARD_USERNAME=test-user\n"
        f"ADGUARD_PASSWORD={password}\nADGUARD_PAGE_SIZE=250\n"
    )
    result = run_wrapper(project, "--dns")
    assert result.returncode == 0
    assert json.loads(result.stdout)["ADGUARD_PASSWORD"] == password
    assert not marker.exists()


@pytest.mark.parametrize(
    "extra", ["LD_PRELOAD=secret", "export ADGUARD_URL=secret", "bad-line"]
)
def test_unknown_dns_settings_are_rejected(project, extra):
    (project / "config/adguard.env").write_text(extra + "\n")
    result = run_wrapper(project, "--dns")
    assert result.returncode != 0
    assert "secret" not in result.stderr


def python_blocks():
    return re.findall(
        r"<<'PY'\n(.*?)\nPY", (ROOT / "install.sh").read_text(), re.DOTALL
    )


def test_installer_embedded_python_compiles():
    for block in python_blocks():
        compile(block, "installer-python", "exec")


def test_installer_no_longer_accepts_legacy_table_combinations():
    installer = (ROOT / 'install.sh').read_text()
    assert 'SCHEMA_EXISTS' not in installer
    assert 'Schema tables do not match' not in installer
    assert 'config.reset_installation reset' in installer


@pytest.mark.parametrize(
    "dns,client_filters,domain_filters",
    [
        (False, False, False),
        (True, False, False),
        (True, True, False),
        (False, True, False),
        (True, True, True),
        (True, False, True),
        (False, False, True),
    ],
)
def test_installer_grants_dns_only_when_tables_exist(
    monkeypatch, dns, client_filters, domain_filters
):
    block = next(block for block in python_blocks() if "grants = {" in block)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = [
        (table,)
        for table in (
            ("dns_sources", "dns_events", "dns_collection_state") if dns else ()
        )
    ]
    if client_filters:
        cursor.fetchall.return_value.append(("dns_client_filters",))
    if domain_filters:
        cursor.fetchall.return_value.append(("dns_domain_filters",))
    import pymysql

    monkeypatch.setattr(pymysql, "connect", MagicMock(return_value=connection))
    monkeypatch.setenv("DB_NAME", "mysql_siem")
    monkeypatch.setenv("DB_USER", "test-user")
    exec(compile(block, "installer-grants", "exec"), {})  # noqa: S102 - trusted repository block with mocked MySQL
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    dns_grants = [query for query in queries if "GRANT" in query and "`dns_" in query]
    assert len(dns_grants) == (
        3 + int(client_filters) + int(domain_filters) if dns else 0
    )
    if dns:
        assert any(
            "SELECT, INSERT, DELETE" in query and "dns_events" in query
            for query in dns_grants
        )
        assert not any("CREATE" in query or "DROP" in query for query in dns_grants)
        if domain_filters:
            assert any(
                "SELECT, INSERT, UPDATE, DELETE" in query
                and "`dns_domain_filters`" in query
                for query in dns_grants
            )
        if client_filters:
            assert any(
                "SELECT, INSERT, UPDATE, DELETE" in query
                and "`dns_client_filters`" in query
                for query in dns_grants
            )


def test_dns_collector_limits_are_loaded_as_data(project):
    (project / "config/adguard.env").write_text(
        "ADGUARD_URL=https://dns.example.net\nADGUARD_USERNAME=fixture-user\n"
        "ADGUARD_PASSWORD=fixture-password\nDNS_MAX_PAGES=250\nDNS_RETENTION_DAYS=30\n"
    )
    result = run_wrapper(project, "--dns")
    assert result.returncode == 0
    assert json.loads(result.stdout)["DNS_MAX_PAGES"] == "250"


def test_dns_schedule_is_generated_only_by_installer():
    installer = (ROOT / "install.sh").read_text()
    assert "$DNS_CRON\n$CRON_END" in installer
    assert not (ROOT / 'config/dns.cron.example').exists()


def test_dns_schema_uses_the_single_fresh_initializer():
    installer = (ROOT / 'install.sh').read_text()
    assert installer.count('-m config.reset_installation reset') == 1
    assert 'DNS_TABLE_COUNT' not in installer
    assert 'ensure_schema dns' not in installer


@pytest.mark.parametrize("configured", [False, True])
def test_installer_dns_setup_uses_existing_cron_model(project, configured):
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# DNS is optional:")
    end = installer.index("# Schedule the SSH jobs independently;", start)
    block = installer[start:end]
    log_helper = "prepare_runtime_log() {" + installer.split(
        "prepare_runtime_log() {", 1
    )[1].split("# Use file-descriptor operations", 1)[0]
    dns = project / "ingestion/dns"
    dns.mkdir(parents=True)
    wrapper = project / "config/run_with_env.sh"
    wrapper.write_text('#!/bin/bash\nprintf "REGISTER_ARGS:%s\\n" "$*"\n')
    wrapper.chmod(0o750)
    settings = project / "config/adguard.env"
    if configured:
        settings.write_text("private fixture settings\n")
    result = subprocess.run(
        [
            "bash",
            "-c",
            "set -euo pipefail\nlog() { :; }\n"
            "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
            "chown() { :; }\n"
            + log_helper
            + block
            + '\nprintf "DNS_JOB:%s\\n" "$DNS_CRON"',
        ],
        env={**os.environ, "PROJECT_DIR": str(project),
             "INSTALL_USER": "test-user",
             "APP_PYTHON": "/opt/mysql_siem-venv/bin/python"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert ("--register-source" in result.stdout) == configured
    assert ("*/5 * * * *" in result.stdout) == configured
    assert (dns / "cron.log").exists() == configured
    if configured:
        assert "--dns /opt/mysql_siem-venv/bin/python -m ingestion.dns.main" in result.stdout
        assert "/usr/bin/timeout --signal=TERM 270s" in result.stdout
        assert f'cd "{project}"' in result.stdout
        assert settings.read_text() == "private fixture settings\n"
        assert settings.stat().st_mode & 0o777 == 0o600
        assert (dns / "cron.log").stat().st_mode & 0o777 == 0o600


def test_dns_filters_are_initialized_with_the_fresh_baseline():
    from database.schema import read_schema
    tables, _rules = read_schema()
    assert {'dns_client_filters', 'dns_domain_filters'} <= set(tables)
    installer = (ROOT / 'install.sh').read_text()
    assert 'DNS_CLIENT_FILTER_COUNT' not in installer
    assert 'DNS_DOMAIN_FILTER_COUNT' not in installer
