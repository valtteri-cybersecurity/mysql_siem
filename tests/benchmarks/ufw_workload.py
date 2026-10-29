"""Run one reproducible workload against a verified private test socket only."""
import argparse
import contextlib
import hashlib
import io
import json
import os
import resource
import sys
import time
import tracemalloc
from datetime import datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pymysql

TABLES = ('hosts', 'log_sources', 'collectors', 'collector_sources', 'sender_identities', 'sender_sources',
          'schema_migrations', 'ufw_log', 'ufw_state', 'ufw_quarantine', 'ufw_quarantine_origins',
          'ufw_archives', 'ufw_archive_failures', 'ufw_file_checkpoints', 'ufw_collection_gaps',
          'ufw_archive_proofs', 'ufw_collection_health', 'ufw_filter_audit', 'ufw_filter_rules',
          'ufw_filter_seen', 'ufw_filter_stats')


class TimedCursor(pymysql.cursors.Cursor):
    metrics: ClassVar[dict] = {}

    def execute(self, query, args=None):
        label = query
        if isinstance(label, (bytes, bytearray)):
            label = label.decode('utf-8', errors='replace')
        category = 'other'
        if label.startswith('INSERT INTO ufw_log'):
            category = 'event_insert'
        elif label.startswith('SELECT') and 'event_hash' in label and 'ufw_log' in label:
            category = 'duplicate_lookup'
        elif 'ufw_file_checkpoints' in label or 'ufw_state' in label:
            category = 'checkpoint'
        elif 'ufw_filter_' in label:
            category = 'filtering'
        elif 'ufw_quarantine' in label:
            category = 'quarantine'
        started = time.perf_counter()
        try:
            return super().execute(query, args)
        finally:
            if category not in self.metrics:
                self.metrics[category] = {'queries': 0, 'seconds': 0.0}
            self.metrics[category]['queries'] += 1
            self.metrics[category]['seconds'] += time.perf_counter() - started


def identifier(name):
    if not name or not name.isascii():
        raise ValueError('Unsafe private database identifier.')
    for character in name:
        if not character.isalnum() and character != '_':
            raise ValueError('Unsafe private database identifier.')
    return '`' + name + '`'


def dataset(index, previous):
    kind = index % 16
    if kind == 12:
        return previous, 'duplicate'
    stamp = datetime(2026, 10, 29, 12) + timedelta(microseconds=index * 100)
    action = 'AUDIT'
    fields = 'IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=12345 DPT=3306'
    category = 'filter'
    if kind == 5:
        action = 'BLOCK'
        fields = 'IN=eth0 OUT= SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=' + str(1000 + index % 50000)
    elif kind == 6:
        action = 'ALLOW'
        fields = 'IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=443'
    elif kind == 7:
        fields = 'IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.53 PROTO=UDP DPT=53'
    elif kind == 8:
        fields = 'IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=445'
    elif kind == 9:
        fields = 'IN=eth0 OUT= SRC=10.0.0.1 DST=224.0.0.251 PROTO=UDP DPT=5353'
    elif kind == 10:
        action = 'BLOCK'
        fields = 'IN=eth0 OUT= SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP DPT=22'
    elif kind == 11:
        fields = 'IN=eth0 OUT= SRC=fd00::1 DST=ff02::1 PROTO=ICMPV6'
    elif kind == 13:
        fields = fields.replace('DPT=3306', 'DPT=99999')
        category = 'invalid'
    elif kind == 14:
        category = 'invalid'
    elif kind == 15:
        return ('ordinary message ' + str(index) + '\n').encode(), 'non_ufw'
    if 5 <= kind <= 11:
        category = 'normal'
    zone = 'Z'
    if kind == 14:
        zone = ''
    raw = (stamp.isoformat(timespec='microseconds') + zone + ' host [UFW ' + action + '] '
           + fields + ' UID=' + str(index) + '\n').encode()
    return raw, category


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket', required=True)
    parser.add_argument('--template', required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--mode', choices=('A', 'B', 'C'), required=True)
    parser.add_argument('--size', type=int, choices=(1000, 10000, 100000), required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if os.getenv('SIEM_UFW_BENCHMARK') != '1':
        raise RuntimeError('Private benchmark opt-in required.')
    sys.path.insert(0, str(Path(args.root).resolve()))
    from database.identity import (
        approve_collector_source,
        register_collector,
        register_host,
        register_source,
    )
    from ingestion import (
        splitter,
        ufw_archives,
        ufw_records,
        ufw_to_mysql,
        ufw_validation,
    )

    connection = pymysql.connect(unix_socket=args.socket, user='root', autocommit=False,
                                 charset='utf8mb4', init_command="SET time_zone='+00:00'",
                                 cursorclass=TimedCursor, read_timeout=30, write_timeout=30)
    with connection.cursor() as cursor:
        cursor.execute('SELECT @@datadir,@@skip_networking')
        directory, isolated = cursor.fetchone()
        if not isolated or 'siem-mysql' not in directory or Path(directory).parent != Path(args.socket).parent:
            raise RuntimeError('This is not the isolated pytest MySQL instance.')
        name = 'ufw_bench_' + args.mode.lower() + '_' + str(args.size) + '_' + str(time.monotonic_ns())
        cursor.execute('CREATE DATABASE ' + identifier(name) + ' CHARACTER SET utf8mb4')
        connection.select_db(name)
        for table in TABLES:
            cursor.execute('SHOW CREATE TABLE ' + identifier(args.template) + '.' + identifier(table))
            definition = cursor.fetchone()[1]
            cursor.execute(definition)
        cursor.execute('INSERT INTO schema_migrations SELECT * FROM ' + identifier(args.template) + '.schema_migrations')
        host = register_host(cursor, 'benchmark-host')
        cursor.execute("UPDATE hosts SET enrollment_status='ACTIVE' WHERE host_id=%s", (host,))
        collector = register_collector(cursor, 'benchmark-collector', enabled=True)
        source = register_source(cursor, host, 'benchmark-ufw', 'ufw', enabled=True)
        approve_collector_source(cursor, collector, source)
    connection.commit()
    os.environ['SIEM_COLLECTOR_ID'] = str(collector)
    os.environ['SIEM_UFW_SOURCE_ID'] = str(source)
    if args.mode == 'C':
        from ingestion.ufw_filters import change
        change(connection, source, host, True, actor='private-benchmark', reason='synthetic data only', acknowledge_risk=True)
    folder = Path(args.work)
    folder.mkdir(mode=0o700)
    path = folder / 'ufw.log'
    rotated = folder / 'ufw.log.9'
    compressed = folder / 'ufw.log.17.gz'
    import gzip
    expected = set()
    excluded = set()
    bad = set()
    previous = b''
    with path.open('wb') as active, rotated.open('wb') as rotation, gzip.open(compressed, 'wb') as archive:
        for index in range(args.size):
            raw, category = dataset(index, previous)
            previous = raw
            if category in ('normal', 'filter'):
                digest = hashlib.sha256(raw.strip()).hexdigest()
                expected.add(digest)
                if category == 'filter':
                    excluded.add(digest)
            elif category == 'invalid':
                bad.add(hashlib.sha256(raw).hexdigest())
            if index < args.size // 2:
                active.write(raw)
            else:
                archive.write(raw)
                if index < args.size // 2 + 100:
                    rotation.write(raw)
    ufw_to_mysql.LOGFILE = str(path)
    ufw_archives.CACHE = folder / 'cache'
    ufw_archives.cache_directory()
    def prepare(filename, digest):
        record = ufw_archives.read_manifest(ufw_archives.CACHE / (digest + '.json'))
        if record is None and ufw_archives.worker(filename, ufw_archives.CACHE, digest) != 0:
            raise RuntimeError('Synthetic gzip verification failed.')
        return ufw_archives.read_manifest(ufw_archives.CACHE / (digest + '.json'))
    ufw_archives.prepare = prepare
    timings = {'parsing': 0.0, 'validation_including_parse': 0.0, 'gzip': 0.0}
    def timed(function, key):
        def invoke(*arguments, **options):
            started = time.perf_counter()
            try:
                return function(*arguments, **options)
            finally:
                timings[key] += time.perf_counter() - started
        return invoke
    ufw_validation.parse_ufw_line = timed(splitter.parse_ufw_line, 'parsing')
    ufw_records.validate_event = timed(ufw_records.validate_event, 'validation_including_parse')
    ufw_to_mysql.validate_event = timed(ufw_to_mysql.validate_event, 'validation_including_parse')
    ufw_archives.process_archives = timed(ufw_archives.process_archives, 'gzip')
    TimedCursor.metrics = {}
    totals = {'inserted': 0, 'filtered': 0, 'duplicates': 0, 'quarantined': 0, 'lines_read': 0}
    cpu_before = resource.getrusage(resource.RUSAGE_SELF)
    tracemalloc.start()
    started = time.perf_counter()
    for _ in range(1000):
        with contextlib.redirect_stdout(io.StringIO()):
            result = ufw_to_mysql.process_log(connection, max_lines=5000, max_seconds=20)
        if result['status'] != 'SUCCESS':
            raise RuntimeError('Benchmark pass failed: ' + result.get('collection_state', 'unknown'))
        for key in totals:
            totals[key] += result.get(key, 0)
        if result.get('collection_state') == 'HEALTHY' and not result.get('archives_pending'):
            break
    else:
        raise RuntimeError('Benchmark did not finish within the pass limit.')
    wall = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    cpu_after = resource.getrusage(resource.RUSAGE_SELF)
    cpu = cpu_after.ru_utime + cpu_after.ru_stime - cpu_before.ru_utime - cpu_before.ru_stime
    metrics = TimedCursor.metrics.copy()
    actual = set()
    with connection.cursor() as cursor:
        cursor.execute('SELECT event_hash FROM ufw_log')
        for row in cursor.fetchall():
            actual.add(row[0])
        required = expected
        if args.mode == 'C':
            required = expected - excluded
        if actual != required or totals['inserted'] != len(required):
            raise AssertionError('Stored event hashes/counts differ from the exact synthetic source set.')
        cursor.execute('SELECT COUNT(*) FROM ufw_quarantine')
        if cursor.fetchone()[0] != len(bad) or totals['quarantined'] != len(bad):
            raise AssertionError('Quarantine differs from the exact malformed source set.')
        cursor.execute('SELECT COUNT(*) FROM ufw_filter_seen')
        filtered = cursor.fetchone()[0]
        expected_filtered = 0
        if args.mode == 'C':
            expected_filtered = len(excluded)
        if filtered != expected_filtered or totals['filtered'] != expected_filtered:
            raise AssertionError('Exact filtered count was inflated by replay or changed the baseline.')
        cursor.execute('ANALYZE TABLE ufw_log,ufw_quarantine,ufw_quarantine_origins,ufw_filter_seen,ufw_filter_stats')
        cursor.fetchall()
        cursor.execute('SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema=%s', (name,))
        allocated = int(cursor.fetchone()[0])
    queries = 0
    for value in metrics.values():
        queries += value['queries']
    report = {'mode': args.mode, 'size': args.size, 'seconds': wall,
              'valid_events_per_second': len(expected) / wall, 'input_lines_per_second': totals['lines_read'] / wall,
              'sql_queries': queries, 'sql': metrics, 'timing_seconds': timings,
              'validation_without_parse_seconds': max(0, timings['validation_including_parse'] - timings['parsing']),
              'mysql_allocated_bytes': allocated, 'python_peak_mib': peak / 1024**2,
              'process_rss_peak_mib': cpu_after.ru_maxrss / 1024, 'client_cpu_seconds': cpu,
              'client_cpu_percent_one_core': cpu * 100 / wall, 'counts': totals,
              'collector_sha256': hashlib.sha256(Path(ufw_to_mysql.__file__).read_bytes()).hexdigest(),
              'baseline_root': args.root, 'storage_includes_filtered_identity_ledger': True}
    Path(args.output).write_text(json.dumps(report, indent=2))
    connection.close()


if __name__ == '__main__':
    main()
