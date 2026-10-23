"""Installer sections run with fake MySQL/crontab and temporary project files."""

import ast
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pymysql
import pytest

from analysis.ufw import ports

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / "install.sh").read_text()


def section(start, end):
    return INSTALLER.split(start, 1)[1].split(end, 1)[0]


def test_installer_provisions_analysis_before_schema_validation_and_grants():
    setup = INSTALLER.index("ensure_schema analysis")
    guard = INSTALLER.index("# Verify tables and migrate")
    grants = INSTALLER.index("# Grant privileges only after")
    schedule = INSTALLER.index("# Schedule UFW Analysis;")
    assert setup < guard < grants < schedule
    assert "-m database.migrate check" in INSTALLER
    assert "-m database.migrate apply" not in INSTALLER
    assert "database/schema.py" in INSTALLER
    assert "SOURCE_IP_ANALYSIS_READY=1" in section("# Source IP Analysis schema:", "# Port Activity Analysis schema:")


def cron_command(project, ready="1", ports_ready="0"):
    block = section("# Schedule UFW Analysis;", "# Set application ownership")
    block = block[block.index("\n") + 1:]
    result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + block + '\nprintf "%s\\n" "$UFW_ANALYSIS_CRON"'],
        env={**os.environ, "PROJECT_DIR": str(project), "SOURCE_IP_ANALYSIS_READY": ready, "PORT_ANALYSIS_READY": ports_ready},
        text=True, capture_output=True, check=True)
    return result.stdout.strip()


def test_cron_prepares_environment_and_private_bounded_log(tmp_path):
    project = tmp_path / "project with spaces"
    command = cron_command(project)
    assert command.startswith("*/5 * * * * ")
    assert f'cd "{project}" && umask 077 && PYTHONPATH="{project}"' in command
    assert 'config/run_with_env.sh" /usr/bin/python3 -m analysis.ufw.main --recent-hours 2' in command
    assert f'--log-file "{project}/analysis/ufw/cron.log"' in command
    assert ">>" not in command
    log = project / "analysis/ufw/cron.log"
    assert log.stat().st_mode & 0o777 == 0o600
    log.write_text("keep previous log\n")
    assert cron_command(project) == command
    assert log.read_text() == "keep previous log\n"


def test_no_cron_without_prepared_schema(tmp_path):
    assert cron_command(tmp_path, "0") == ""
    assert not (tmp_path / "analysis/ufw/cron.log").exists()


def test_managed_cron_replaces_old_job_once_and_preserves_other_jobs(tmp_path):
    block = section("# Update only this installation's marked cron block.", 'log "Installation steps completed.')
    cron = tmp_path / "fake-crontab"
    cron.write_text("MAILTO=test-user\n17 * * * * echo keep-external\n"
                    "# BEGIN mysql_siem managed jobs\n"
                    "3 13 * * * python analysis/targeted_ports/main.py\n"
                    "1 13 * * * python analysis/attacking_ips/main.py\n"
                    "# END mysql_siem managed jobs\n")
    script = r'''set -euo pipefail
crontab() {
    if [[ "$*" == *" -l" ]]; then cat "$TEST_CRONTAB"; else cp "${@: -1}" "$TEST_CRONTAB"; fi
}
''' + block
    env = {**os.environ, "PROJECT_DIR": str(tmp_path), "INSTALL_USER": "test-user",
           "CRON_BEGIN": "# BEGIN mysql_siem managed jobs", "CRON_END": "# END mysql_siem managed jobs",
           "TEST_CRONTAB": str(cron), "UFW_ANALYSIS_CRON": cron_command(tmp_path, ports_ready="1"),
           "PORT_SCAN_CRON": "* * * * * echo keep-portscan", "DNS_CRON": "*/5 * * * * echo keep-dns",
           "SSH_AUTH_CRON": "* * * * * echo keep-auth", "SSH_DETECTION_CRON": "* * * * * echo keep-ssh"}
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    first = cron.read_text()
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    assert cron.read_text() == first
    assert first.count("-m analysis.ufw.main") == 1
    assert "--all --recent-hours 3" in first
    assert "analysis/attacking_ips" not in first
    assert "analysis/targeted_ports" not in first
    assert "analysis/daily_counts" not in first
    for item in ("MAILTO=test-user", "17 * * * * echo keep-external", "keep-portscan", "keep-dns",
                 "keep-auth", "keep-ssh"):
        assert item in first


@pytest.mark.parametrize("present", [False, True])
def test_new_table_grants_only_when_present_without_legacy_grants(monkeypatch, present):
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY", INSTALLER, re.DOTALL)
    block = next(block for block in blocks if "grants = {" in block)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = [("analysis_source_ips",)] if present else []
    monkeypatch.setattr(pymysql, "connect", MagicMock(return_value=connection))
    monkeypatch.setenv("DB_NAME", "mysql_siem")
    monkeypatch.setenv("DB_USER", "test-user")
    exec(compile(block, "mocked-installer-grants", "exec"), {})  # noqa: S102
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    new_grants = [query for query in queries if "`analysis_source_ips`" in query]
    assert len(new_grants) == int(present)
    if present:
        assert "GRANT SELECT, INSERT, DELETE" in new_grants[0]
    assert not any("top_attacking_ips" in query or "top_targeted_ports" in query for query in queries)
    assert any("GRANT SELECT, INSERT, DELETE ON `mysql_siem`.`analysis_ufw_ports`" in query for query in queries)


@pytest.mark.parametrize("legacy_present", [False, True])
def test_both_schema_guards_allow_retired_tables_without_dropping_them(legacy_present):
    checked = 0
    for block in re.findall(r"<<'PY'\n(.*?)\nPY", INSTALLER, re.DOTALL):
        tree = ast.parse(block)
        for node in ast.walk(tree):
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
                continue
            if "dns_tables" not in ast.unparse(node.test) or not isinstance(node.test.left, ast.Name):
                continue
            variable = node.test.left.id
            if variable not in {"existing", "actual"}:
                continue
            namespace = {}
            for assignment in ast.walk(tree):
                if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Set):
                    for target in assignment.targets:
                        if isinstance(target, ast.Name):
                            namespace[target.id] = ast.literal_eval(assignment.value)
            assert "top_attacking_ips" not in namespace["expected"]
            namespace[variable] = namespace["expected"] | {"analysis_source_ips"}
            if legacy_present:
                namespace[variable].add("top_attacking_ips")
            # Execute optional/retired-table normalization, then the whitelist check.
            discard = next(item for item in ast.walk(tree) if isinstance(item, ast.Expr)
                           and ast.unparse(item) == f"{variable}.discard('analysis_source_ips')")
            removals = [item for item in ast.walk(tree) if isinstance(item, ast.AugAssign)
                        and isinstance(item.target, ast.Name) and item.target.id == variable]
            normalization = ast.Module(body=[discard] + removals, type_ignores=[])
            exec(compile(normalization, "schema-removal", "exec"), namespace)  # noqa: S102
            assert eval(compile(ast.Expression(node.test), "schema-guard", "eval"), namespace) is False
            checked += 1
    assert checked == 2


@pytest.mark.parametrize("source,ports,selection", [("1", "1", "--all"), ("0", "1", "--ports")])
def test_port_cron_refreshes_three_hours(tmp_path, source, ports, selection):
    assert f"{selection} --recent-hours 3" in cron_command(tmp_path, source, ports)


@pytest.mark.parametrize("wrong_schema", [False, True])
def test_installer_preflight_closes_connection_and_rejects_wrong_schema(monkeypatch, connection, wrong_schema):
    block = section("<<'PY_CHECK_PORTS'\n", "\nPY_CHECK_PORTS")
    monkeypatch.setenv("DB_NAME", "private-test-only")
    monkeypatch.setattr(pymysql, "connect", Mock(return_value=connection))
    check = Mock(side_effect=ports.PortAnalysisError("wrong schema") if wrong_schema else None)
    monkeypatch.setattr(ports, "validate_ports_schema", check)
    if wrong_schema:
        with pytest.raises(SystemExit, match="wrong schema"):
            exec(compile(block, "installer-port-preflight", "exec"), {})  # noqa: S102
    else:
        exec(compile(block, "installer-port-preflight", "exec"), {})  # noqa: S102
    check.assert_called_once_with(connection)
    connection.close.assert_called_once()


@pytest.mark.parametrize("source,port,options", [
    ("1", "1", "--all --recent-hours 3"),
    ("0", "1", "--ports --recent-hours 3 --traffic"),
    ("1", "0", "--source-ips --recent-hours 3 --traffic"),
    ("0", "0", "--traffic"),
])
def test_ready_traffic_uses_one_shared_job(tmp_path, source, port, options):
    block = section("# Schedule UFW Analysis;", "# Set application ownership")
    block = block[block.index("\n") + 1:]
    result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + block + '\nprintf "%s\\n" "$UFW_ANALYSIS_CRON"'],
        env={**os.environ, "PROJECT_DIR": str(tmp_path), "SOURCE_IP_ANALYSIS_READY": source,
             "PORT_ANALYSIS_READY": port, "TRAFFIC_ANALYSIS_READY": "1"},
        text=True, capture_output=True, check=True)
    assert result.stdout.count("-m analysis.ufw.main") == 1
    assert options in result.stdout
    assert "daily_counts" not in result.stdout


def test_standalone_retired_cron_removed_only_for_this_installation(tmp_path):
    project = tmp_path / "project with spaces"
    cron = tmp_path / "crontab"
    keep = '2 13 * * * python /another/project/analysis/daily_counts/daily_counts.py\n'
    cron.write_text(keep + f'2 13 * * * python "{project}/analysis/daily_counts/daily_counts.py"\n'
                    + f'2 13 * * * cd "{project}" && python analysis/daily_counts/daily_counts.py\n'
                    + '19 * * * * echo keep-unrelated\n')
    block = section("# Update only this installation's marked cron block.", 'log "Installation steps completed.')
    script = r'''set -euo pipefail
crontab() {
    if [[ "$*" == *" -l" ]]; then cat "$TEST_CRONTAB"; else cp "${@: -1}" "$TEST_CRONTAB"; fi
}
''' + block
    env = {**os.environ, "PROJECT_DIR": str(project), "INSTALL_USER": "test-user",
           "CRON_BEGIN": "# BEGIN mysql_siem managed jobs", "CRON_END": "# END mysql_siem managed jobs",
           "TEST_CRONTAB": str(cron), "PORT_SCAN_CRON": "", "DNS_CRON": ""}
    for _ in range(2):
        subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
        result = cron.read_text()
        assert keep in result and '19 * * * * echo keep-unrelated' in result
        assert f'{project}/analysis/daily_counts/' not in result
        assert f'cd "{project}" && python analysis/daily_counts/' not in result
    assert result.count("# BEGIN mysql_siem managed jobs") == 1


def test_traffic_grants_and_retired_grants(monkeypatch):
    block = next(block for block in re.findall(r"<<'PY'\n(.*?)\nPY", INSTALLER, re.DOTALL) if "grants = {" in block)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = []
    monkeypatch.setattr(pymysql, "connect", Mock(return_value=connection))
    monkeypatch.setenv("DB_NAME", "private-test")
    monkeypatch.setenv("DB_USER", "test-user")
    exec(compile(block, "installer-traffic-grants", "exec"), {})  # noqa: S102
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    for table in ("analysis_ufw_traffic", "analysis_ufw_traffic_daily"):
        assert any(f"GRANT SELECT, INSERT, UPDATE ON `private-test`.`{table}`" in query for query in queries)
    assert not any("ufw_daily_actions_counts" in query for query in queries)


@pytest.mark.parametrize("wrong", [False, True])
def test_traffic_preflight_closes_connection_and_rejects_incompatible_schema(monkeypatch, connection, wrong):
    from analysis.ufw import traffic
    block = section("<<'PY_CHECK_TRAFFIC'\n", "\nPY_CHECK_TRAFFIC")
    monkeypatch.setenv("DB_NAME", "private-test")
    monkeypatch.setattr(pymysql, "connect", Mock(return_value=connection))
    check = Mock(side_effect=traffic.TrafficAnalysisError("wrong schema") if wrong else None)
    monkeypatch.setattr(traffic, "validate_traffic_schema", check)
    if wrong:
        with pytest.raises(SystemExit, match="wrong schema"):
            exec(compile(block, "installer-traffic-preflight", "exec"), {})  # noqa: S102
    else:
        exec(compile(block, "installer-traffic-preflight", "exec"), {})  # noqa: S102
    check.assert_called_once_with(connection)
    connection.close.assert_called_once()
