"""Nine reproducible measurements; opt in explicitly to the private MySQL benchmark."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(os.getenv('SIEM_UFW_BENCHMARK') != '1', reason='Set SIEM_UFW_BENCHMARK=1 for the 1k/10k/100k private benchmark.')
def test_reproducible_before_after_and_filtering(mysql, identity_server, tmp_path):
    baseline_value = os.getenv('SIEM_UFW_BASELINE_ROOT')
    if not baseline_value:
        pytest.fail('Set SIEM_UFW_BASELINE_ROOT to the unchanged Phase 3 source snapshot.')
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
    for size in (1000, 10000, 100000):
        for mode in ('A', 'B', 'C'):
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
    assert len(reports) == 9
