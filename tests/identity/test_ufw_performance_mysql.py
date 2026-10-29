"""Nine reproducible measurements; opt in explicitly to the private MySQL benchmark."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(os.getenv('SIEM_UFW_BENCHMARK') != '1', reason='Set SIEM_UFW_BENCHMARK=1 for the 1k/10k/100k private benchmark.')
def test_reproducible_before_after_and_filtering(request, tmp_path):
    baseline_value = os.getenv('SIEM_UFW_BASELINE_ROOT')
    if not baseline_value:
        pytest.fail('Set SIEM_UFW_BASELINE_ROOT to the unchanged Phase 3 source snapshot.')
    if not os.getenv('SIEM_UFW_BENCHMARK_CASE'):
        reports = []
        for size in (1000, 10000, 100000):
            for mode in ('A', 'B', 'C'):
                case = mode + '-' + str(size)
                output = tmp_path / (case + '.json')
                environment = dict(os.environ)
                environment['SIEM_UFW_BENCHMARK_CASE'] = case
                environment['SIEM_UFW_BENCHMARK_OUTPUT'] = str(output)
                child = subprocess.run([sys.executable, '-B', '-m', 'pytest', '-x', '-q', '-p', 'no:cacheprovider',
                                        str(Path(__file__).resolve())], env=environment, capture_output=True,
                                       text=True, timeout=1200, check=False)
                assert child.returncode == 0, child.stdout[-6000:] + child.stderr[-2000:]
                reports.extend(json.loads(output.read_text()))
                destination = os.getenv('SIEM_UFW_BENCHMARK_OUTPUT')
                if destination:
                    Path(destination).write_text(json.dumps(reports, indent=2))
        assert len(reports) == 9
        return
    mysql = request.getfixturevalue('mysql')
    identity_server = request.getfixturevalue('identity_server')
    baseline = Path(baseline_value)
    with mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        template = cursor.fetchone()[0]
    project = Path(__file__).resolve().parents[2]
    reports = []
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith(('DB_', 'SIEM_')):
            environment.pop(key)
    environment['SIEM_UFW_BENCHMARK'] = '1'
    selected = os.getenv("SIEM_UFW_BENCHMARK_CASE")
    expected_cases = 9
    if selected:
        if selected not in ("A-1000", "B-1000", "C-1000", "A-10000", "B-10000", "C-10000", "A-100000", "B-100000", "C-100000"):
            pytest.fail("Unknown benchmark case.")
        expected_cases = 1
    for size in (1000, 10000, 100000):
        for mode in ('A', 'B', 'C'):
            if selected and selected != mode + '-' + str(size):
                continue
            root = project
            if mode == 'A':
                root = baseline
            case = mode + '-' + str(size)
            output = tmp_path / (case + '.json')
            completed = subprocess.run([sys.executable, '-B', str(project / 'tests/benchmarks/ufw_workload.py'),
                                        '--socket', identity_server, '--template', template, '--root', str(root),
                                        '--mode', mode, '--size', str(size), '--work', str(tmp_path / case),
                                        '--output', str(output)],
                                       check=False, env=environment, capture_output=True, text=True, timeout=900)
            assert completed.returncode == 0, completed.stderr[-6000:]
            report = json.loads(output.read_text())
            assert report['size'] == size and report['mode'] == mode
            reports.append(report)
            destination = os.getenv('SIEM_UFW_BENCHMARK_OUTPUT')
            if destination:
                Path(destination).write_text(json.dumps(reports, indent=2))
            print(case + ': ' + str(round(report['seconds'], 3)) + ' seconds; queries=' + str(report['sql_queries']), flush=True)
    assert len(reports) == expected_cases
