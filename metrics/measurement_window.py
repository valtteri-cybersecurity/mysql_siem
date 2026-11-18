"""Shared UTC bounds and storage for five-minute snapshot measurement windows."""

import json
from datetime import timedelta, timezone

from metrics.snapshot import SnapshotError

# Names are fixed here. Only values and the scope are supplied to SQL as parameters.
TABLES = {
    'processes': ('process_measurement_windows', ('metrics', 'executables', 'parent_child')),
    'services': ('service_measurement_windows', ('metrics', 'activity')),
}


def utc_datetime(observed_at):
    if observed_at.tzinfo is not None:
        return observed_at.astimezone(timezone.utc).replace(tzinfo=None)
    return observed_at


def window_bounds(observed_at):
    observed_at = utc_datetime(observed_at)
    minute = observed_at.minute - observed_at.minute % 5
    start = observed_at.replace(minute=minute, second=0, microsecond=0)
    return start, start + timedelta(minutes=5)


def add_metrics(metrics, counts):
    for field, value in counts.items():
        metric = metrics.get(field)
        if metric is None:
            metric = {'sum': 0, 'min': value, 'max': value, 'count': 0}
            metrics[field] = metric
        metric['sum'] += value
        metric['min'] = min(metric['min'], value)
        metric['max'] = max(metric['max'], value)
        # The mean is sum/count over the samples in which the metric was present.
        metric['count'] += 1


def update_window(connection, kind, identity, observed_at, accumulate):
    """Update one row under the caller's snapshot lock and transaction."""
    start, end = window_bounds(observed_at)
    scope = identity.host_id, identity.source_id
    table, columns = TABLES[kind]
    fields = ', '.join(columns)
    count, payloads = 0, []
    for _ in columns:
        payloads.append({})
    with connection.cursor() as cursor:
        cursor.execute(
            f'SELECT window_start, last_observed_at, sample_count, {fields} '  # nosec B608
            f'FROM {table} WHERE host_id = %s AND source_id = %s ORDER BY window_start DESC LIMIT 1', scope,
        )
        latest = cursor.fetchone()
        if latest is not None:
            if observed_at == latest[1]:
                return False
            if observed_at < latest[1]:
                raise SnapshotError('Observation predates the last accepted measurement.')
            if start == latest[0]:
                count = latest[2]
                payloads = list(map(json.loads, latest[3:]))

        accumulate(*payloads)
        values = []
        assignments = []
        for column, payload in zip(columns, payloads, strict=True):
            assignments.append(f'{column} = VALUES({column})')
            values.append(json.dumps(payload, ensure_ascii=False))
        placeholders = ', '.join(['%s'] * (8 + len(values)))
        cursor.execute(
            f'INSERT INTO {table} (host_id, source_id, collector_id, window_start, window_end, '  # nosec B608
            f'first_observed_at, last_observed_at, sample_count, {fields}) VALUES ({placeholders}) '
            'ON DUPLICATE KEY UPDATE collector_id = VALUES(collector_id), last_observed_at = VALUES(last_observed_at), '
            'sample_count = VALUES(sample_count), ' + ', '.join(assignments),
            scope + (identity.collector_id, start, end, observed_at, observed_at, count + 1) + tuple(values),
        )
    return True
