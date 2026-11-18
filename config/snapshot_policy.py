"""Environment settings for Process and Services snapshots and manual retention."""

import os
from dataclasses import dataclass

MAX_PROCESSES = 65536
MAX_SERVICES = 4096
MAX_COLLECTION_SECONDS = 40
MAX_SYSTEMCTL_SECONDS = 5
MAX_SYSTEMCTL_BYTES = 8 * 1024 * 1024
MAX_WRITES = 4 * MAX_PROCESSES


class SnapshotSettingError(ValueError):
    pass


def positive_setting(name, default, maximum):
    value = os.getenv(name)
    if value is None:
        return default
    if not value.isascii() or not value.isdecimal() or len(value) > len(str(maximum)):
        raise SnapshotSettingError(f'Invalid snapshot setting {name}.')
    number = int(value)
    if not 1 <= number <= maximum:
        raise SnapshotSettingError(f'Invalid snapshot setting {name}.')
    return number


def inventory_limit(kind):
    if kind == 'processes':
        return positive_setting('SIEM_SNAPSHOT_MAX_PROCESSES', MAX_PROCESSES, MAX_PROCESSES)
    return positive_setting('SIEM_SNAPSHOT_MAX_SERVICES', MAX_SERVICES, MAX_SERVICES)


def collection_seconds():
    return positive_setting('SIEM_SNAPSHOT_MAX_SECONDS', MAX_COLLECTION_SECONDS, MAX_COLLECTION_SECONDS)


@dataclass(frozen=True)
class RetentionPolicy:
    enabled: bool
    event_days: int
    window_days: int
    detail_days: int
    health_days: int
    batch_rows: int
    warning_mib: int


def retention_policy():
    enabled = os.getenv('SIEM_SNAPSHOT_RETENTION_ENABLED', '0')
    if enabled not in ('0', '1'):
        raise SnapshotSettingError('Invalid snapshot setting SIEM_SNAPSHOT_RETENTION_ENABLED.')
    windows = positive_setting('SIEM_SNAPSHOT_WINDOW_DAYS', 30, 36500)
    details = positive_setting('SIEM_SNAPSHOT_DETAIL_DAYS', min(30, windows), 36500)
    if details > windows:
        raise SnapshotSettingError('Detail retention cannot outlive its measurement window.')
    return RetentionPolicy(
        enabled == '1', positive_setting('SIEM_SNAPSHOT_EVENT_DAYS', 180, 36500), windows, details,
        positive_setting('SIEM_SNAPSHOT_HEALTH_DAYS', 30, 36500),
        positive_setting('SIEM_SNAPSHOT_RETENTION_BATCH_ROWS', 250, 1000),
        positive_setting('SIEM_SNAPSHOT_WARNING_MIB', 512, 1048576),
    )
