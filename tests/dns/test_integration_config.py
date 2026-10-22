import ast
import json
import os
import re
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


@pytest.mark.parametrize(
    "extra,allowed",
    [
        (set(), True),
        ({"dns_sources", "dns_events", "dns_collection_state"}, True),
        ({"dns_sources"}, False),
        ({"unexpected"}, False),
        ({"detection_rules", "detection_alerts", "alert_evidence"}, True),
        (
            {
                "detection_rules",
                "detection_alerts",
                "alert_evidence",
                "detection_state",
            },
            True,
        ),
        (
            {
                "dns_sources",
                "dns_events",
                "dns_collection_state",
                "detection_rules",
                "detection_alerts",
                "alert_evidence",
                "detection_state",
            },
            True,
        ),
        ({"detection_rules"}, False),
        ({"detection_state"}, False),
    ],
)
def test_both_installer_schema_guards_accept_only_complete_dns(extra, allowed):
    checked = 0
    for block in python_blocks():
        tree = ast.parse(block)
        for node in ast.walk(tree):
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
                continue
            left = node.test.left
            if not isinstance(left, ast.Name) or left.id not in {"actual", "existing"}:
                continue
            if "dns_tables" not in ast.unparse(node.test):
                continue
            namespace = {}
            for assignment in ast.walk(tree):
                if isinstance(assignment, ast.Assign) and any(
                    isinstance(target, ast.Name)
                    and target.id
                    in {"expected", "dns_tables", "detection_tables", "state_tables"}
                    for target in assignment.targets
                ):
                    for target in assignment.targets:
                        if isinstance(target, ast.Name):
                            namespace[target.id] = ast.literal_eval(assignment.value)
            namespace[left.id] = namespace["expected"] | extra
            rejects = eval(
                compile(ast.Expression(node.test), "schema-guard", "eval"), namespace
            )
            assert rejects is not allowed
            checked += 1
    assert checked == 2


@pytest.mark.parametrize("dns", [False, True])
def test_installer_grants_dns_only_when_tables_exist(monkeypatch, dns):
    block = next(block for block in python_blocks() if "grants = {" in block)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = [
        (table,)
        for table in (
            ("dns_sources", "dns_events", "dns_collection_state") if dns else ()
        )
    ]
    import pymysql

    monkeypatch.setattr(pymysql, "connect", MagicMock(return_value=connection))
    monkeypatch.setenv("DB_NAME", "mysql_siem")
    monkeypatch.setenv("DB_USER", "test-user")
    exec(compile(block, "installer-grants", "exec"), {})  # noqa: S102 - trusted repository block with mocked MySQL
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    dns_grants = [query for query in queries if "GRANT" in query and "`dns_" in query]
    assert len(dns_grants) == (3 if dns else 0)
    if dns:
        assert any(
            "SELECT, INSERT, DELETE" in query and "dns_events" in query
            for query in dns_grants
        )
        assert not any("CREATE" in query or "DROP" in query for query in dns_grants)


def test_dns_collector_limits_are_loaded_as_data(project):
    (project / "config/adguard.env").write_text(
        "ADGUARD_URL=https://dns.example.net\nADGUARD_USERNAME=fixture-user\n"
        "ADGUARD_PASSWORD=fixture-password\nDNS_MAX_PAGES=250\nDNS_RETENTION_DAYS=30\n"
    )
    result = run_wrapper(project, "--dns")
    assert result.returncode == 0
    assert json.loads(result.stdout)["DNS_MAX_PAGES"] == "250"


def test_dns_cron_template_is_inactive():
    template = (ROOT / "config/dns.cron.example").read_text()
    assert all(
        not line.strip() or line.startswith("#") for line in template.splitlines()
    )
    assert "*/5 * * * *" in template
    installer = (ROOT / "install.sh").read_text()
    assert "$DNS_CRON\n$CRON_END" in installer


@pytest.mark.parametrize("table_count", [0, 1, 2, 3])
def test_installer_creates_only_absent_dns_schema(table_count):
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# Create DNS tables once;")
    end = installer.index("# Detection schema:", start)
    block = installer[start:end].replace("/usr/bin/mysql", "mock_mysql")
    script = (
        r"""
set -euo pipefail
log() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }
mock_mysql() {
    if [[ "$*" == *"SELECT COUNT"* ]]; then
        printf '%s\n' "$TEST_TABLE_COUNT"
    else
        printf 'MIGRATION_INPUT\n'
        cat
    fi
}
"""
        + block
    )
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **os.environ,
            "PROJECT_DIR": str(ROOT),
            "EXPECTED_DB_NAME": "mysql_siem",
            "TEST_TABLE_COUNT": str(table_count),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) == (table_count in (0, 3))
    if table_count == 0:
        assert "MIGRATION_INPUT" in result.stdout
        for table in ("dns_sources", "dns_events", "dns_collection_state"):
            assert f"CREATE TABLE {table}" in result.stdout
        assert "DROP TABLE" not in result.stdout
    else:
        assert "MIGRATION_INPUT" not in result.stdout
        if table_count != 3:
            assert "incomplete" in result.stderr


@pytest.mark.parametrize("configured", [False, True])
def test_installer_dns_setup_uses_existing_cron_model(project, configured):
    installer = (ROOT / "install.sh").read_text()
    start = installer.index("# DNS is optional:")
    end = installer.index("# Set application ownership", start)
    block = installer[start:end]
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
            + block
            + '\nprintf "DNS_JOB:%s\\n" "$DNS_CRON"',
        ],
        env={**os.environ, "PROJECT_DIR": str(project)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert ("--register-source" in result.stdout) == configured
    assert ("*/5 * * * *" in result.stdout) == configured
    assert (dns / "cron.log").exists() == configured
    if configured:
        assert "--dns /usr/bin/python3 -m ingestion.dns.main" in result.stdout
        assert "/usr/bin/timeout --signal=TERM 270s" in result.stdout
        assert f'cd "{project}"' in result.stdout
        assert settings.read_text() == "private fixture settings\n"
        assert settings.stat().st_mode & 0o777 == 0o600
        assert (dns / "cron.log").stat().st_mode & 0o777 == 0o600
