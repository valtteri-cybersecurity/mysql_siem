"""Release benchmark. Run only through the private MySQL pytest fixture."""

import importlib.util
import json
import statistics
import subprocess
import time
from datetime import timedelta
from threading import Event, Thread
from typing import ClassVar

import psutil
import pymysql

from metrics import snapshot
from metrics.processes import main as processes_main
from metrics.processes.get import process_key
from metrics.services import main as services_main

BASELINE = '71f2d7b'
SCENARIOS = {
    'unchanged': (250, 100, 0, 0),
    'typical': (250, 100, 4, 5),
    'large': (1000, 300, 25, 15),
    'stress': (5000, 1000, 125, 50),
}


def load_baseline(tmp_path, relative_path):
    output = subprocess.run(  # nosec B603, B607
        ['git', 'show', f'{BASELINE}:{relative_path}'], capture_output=True, check=True,
    )
    module_name = 'baseline_' + relative_path.replace('/', '_').removesuffix('.py')
    path = tmp_path / (module_name + '.py')
    path.write_bytes(output.stdout)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkloadCursor(pymysql.cursors.Cursor):
    stats: ClassVar[dict | None] = None

    def execute(self, query, args=None):
        stats = self.stats
        if stats is None:
            return super().execute(query, args)
        started = time.perf_counter()
        affected = super().execute(query, args)
        stats['sql_ms'] += (time.perf_counter() - started) * 1000
        if isinstance(query, (bytes, bytearray)):
            query = query.decode('utf-8')
        words = query.split(None, 4)
        action = words[0].lower()
        if action in ('insert', 'update', 'delete'):
            stats[action] += 1
            if 'process_state' in words[:3] or 'service_state' in words[:3]:
                stats['state_' + action] += affected
        return affected


def measure(connection, collect, at):
    stats = dict.fromkeys(('insert', 'update', 'delete', 'state_insert', 'state_update', 'state_delete', 'sql_ms'), 0)
    finished = Event()
    process = psutil.Process()
    rss_start = process.memory_info().rss
    peak = [rss_start]

    def sample_rss():
        while not finished.wait(0.02):
            peak[0] = max(peak[0], process.memory_info().rss)

    with connection.cursor() as cursor:
        cursor.execute("SHOW SESSION STATUS LIKE 'Com_commit'")
        before = int(cursor.fetchone()[1])
    thread = Thread(target=sample_rss)
    thread.start()
    WorkloadCursor.stats = stats
    cpu = time.process_time()
    started = time.perf_counter()
    try:
        collect(at)
        stats['wall_ms'] = (time.perf_counter() - started) * 1000
        stats['cpu_ms'] = (time.process_time() - cpu) * 1000
        peak[0] = max(peak[0], process.memory_info().rss)
    finally:
        WorkloadCursor.stats = None
        finished.set()
        thread.join()
    stats['other_ms'] = max(0, stats['wall_ms'] - stats['sql_ms'])
    stats['rss_peak_mib'] = peak[0] / (1024 * 1024)
    stats['rss_growth_mib'] = (peak[0] - rss_start) / (1024 * 1024)
    with connection.cursor() as cursor:
        cursor.execute("SHOW SESSION STATUS LIKE 'Com_commit'")
        stats['transactions'] = int(cursor.fetchone()[1]) - before
    return stats


def sample_inventory(kind, scenario, boot_id):
    processes, services, process_changes, service_changes = SCENARIOS[scenario]
    before, after = {}, {}
    if kind == 'processes':
        for index in range(processes):
            pid = index + 100
            key = process_key(boot_id, pid, 1000.0)
            state = {
                'pid': pid, 'process_name': 'worker', 'username': 'synthetic', 'status': 'running',
                'cpu_percent': 1.0, 'memory_mb': 20.0, 'memory_percent': 0.1,
                'uid': 1000, 'euid': 1000, 'gid': 1000, 'egid': 1000,
                'executable_path': f'/synthetic/program-{index % 75}',
                'executable_identity_status': 'PATH_ONLY',
            }
            before[key] = state
            if index < process_changes:
                pid += processes
                key = process_key(boot_id, pid, 1001.0)
                state = {**state, 'pid': pid}
            if process_changes:
                state = {**state, 'cpu_percent': 4.5, 'memory_mb': 21.0}
            after[key] = state
    else:
        for index in range(services):
            name = f'worker-{index}.service'
            state = {
                'unit_id': name, 'unit_names': [name], 'description': 'Synthetic worker',
                'load_state': 'loaded', 'active_state': 'active', 'sub_state': 'running',
                'unit_file_state': 'enabled', 'main_pid': 200 + index,
                'configured_user': 'synthetic', 'configured_group': 'synthetic',
                'fragment_path': f'/synthetic/{name}', 'drop_in_paths': [],
            }
            before[name] = state
            if index < service_changes:
                state = {**state, 'active_state': 'inactive', 'sub_state': 'dead', 'main_pid': 0}
            after[name] = state
    return before, after


def storage(connection, kind, scope):
    _, events, state, _ = snapshot.TABLES[kind]
    window = 'service_measurement_windows'
    columns = 'JSON_STORAGE_SIZE(metrics) + JSON_STORAGE_SIZE(activity)'
    if kind == 'processes':
        window = 'process_measurement_windows'
        columns = 'JSON_STORAGE_SIZE(metrics) + JSON_STORAGE_SIZE(executables) + JSON_STORAGE_SIZE(parent_child)'
    with connection.cursor() as cursor:
        result = {}
        for label, table, expression in (
            ('state', state, 'JSON_STORAGE_SIZE(state)'),
            ('events', events, 'COALESCE(JSON_STORAGE_SIZE(previous_state),0) + COALESCE(JSON_STORAGE_SIZE(current_state),0)'),
            ('windows', window, columns),
            ('health', 'collector_health', 'JSON_STORAGE_SIZE(coverage) + JSON_STORAGE_SIZE(transitions)'),
        ):
            cursor.execute(f'SELECT COUNT(*), COALESCE(SUM({expression}), 0) FROM {table} '  # nosec B608
                           'WHERE host_id = %s AND source_id = %s', scope)
            count, size = cursor.fetchone()
            result[label] = [int(count), int(size)]
    connection.rollback()
    return result


def compare_version(connection, kind, scenario, version, legacy, legacy_diff, observed_at, inventories, monkeypatch):
    start, change = inventories
    current = start

    def observe(previous, **kwargs):
        if kind == 'processes':
            kwargs['measurements'].update(current)
        return current

    def collect(at):
        if version == 'current':
            if kind == 'processes':
                processes_main.collect_processes(connection, observed_at=at)
            else:
                services_main.collect_services(connection, observed_at=at)
            return
        identity, previous, baseline, lock = legacy.begin_snapshot(connection, kind)
        try:
            events = []
            if baseline:
                events = legacy_diff(current, previous)
            legacy.save_snapshot(connection, kind, identity, current, events, at)
            connection.commit()
        finally:
            legacy.release_snapshot_lock(connection, lock)

    module = services_main
    field = 'get_services'
    if kind == 'processes':
        module, field = processes_main, 'get_processes'
    monkeypatch.setattr(module, field, observe)
    identity = snapshot.get_identity(connection, kind)
    connection.rollback()
    scope = (identity.host_id, identity.source_id)
    _, history, state, _ = snapshot.TABLES[kind]
    # The test owns this synthetic scope in the socket-only database.
    with connection.cursor() as cursor:
        cursor.execute(f'DELETE FROM {history} WHERE host_id = %s AND source_id = %s', scope)  # nosec B608
        cursor.execute(f'DELETE FROM {state} WHERE host_id = %s AND source_id = %s', scope)  # nosec B608
        cursor.execute('DELETE FROM collector_snapshots WHERE host_id = %s AND source_id = %s', scope)
    connection.commit()
    collect(observed_at)
    results = []
    for run, sample in enumerate((change, start, change), 1):
        current = sample
        at = observed_at + timedelta(seconds=run * 10)
        results.append(measure(connection, collect, at))
    stored = storage(connection, kind, scope)
    summary = {}
    for field in results[0]:
        values = []
        for result in results:
            values.append(result[field])
        summary[field] = [round(statistics.median(values), 2), round(min(values), 2), round(max(values), 2)]
    print('RELEASE_BENCH ' + json.dumps({
        'kind': kind, 'scenario': scenario, 'version': version, 'repetitions': len(results),
        'median_min_max': summary, 'rows_and_json_bytes': stored,
    }), flush=True)
    assert stored['state'][0] == len(change)
    assert summary['transactions'][0] == 1
    if version == 'current' and scenario == 'unchanged':
        for field in ('state_insert', 'state_update', 'state_delete'):
            assert summary[field][2] == 0


def compare(connection, kind, scenario, legacy, legacy_diff, boot_id, observed_at, monkeypatch):
    inventories = sample_inventory(kind, scenario, boot_id)
    connection.cursorclass = WorkloadCursor
    try:
        for version in ('legacy', 'current'):
            compare_version(connection, kind, scenario, version, legacy, legacy_diff, observed_at,
                            inventories, monkeypatch)
    finally:
        connection.cursorclass = pymysql.cursors.Cursor
