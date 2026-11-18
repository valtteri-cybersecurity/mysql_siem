"""Local processes collector: explicit collection and transaction lifetime."""

import argparse

import psutil
import pymysql

from config.run_logging import close_log, open_log, report
from config.snapshot_policy import SnapshotSettingError
from database.connection import get_connection
from metrics import collector_health, snapshot
from metrics.processes import database
from metrics.processes.get import (
    BootIdentityError,
    get_events,
    get_processes,
    normalize_boot_id,
    read_boot_id,
)


def collect_processes(connection, *, logger=None, observed_at=None):
    """Collect once. A replay uses the original observation timestamp."""
    with collector_health.collection(connection, 'processes', database.begin_collection, logger) as run:
        attempt, identity, previous, checkpoint = run
        boot_id = read_boot_id()
        previous_boot_id = None
        if checkpoint is not None and checkpoint[1] is not None:
            previous_boot_id = normalize_boot_id(checkpoint[1])
        same_boot = previous_boot_id == boot_id
        previous_observation = {}
        if same_boot:
            previous_observation = previous
        measurements = {}
        current = get_processes(previous_observation, boot_id=boot_id, coverage=attempt.coverage,
                                measurements=measurements)
        if read_boot_id() != boot_id:
            raise BootIdentityError('Linux boot ID changed during the observation.')
        if attempt.coverage.get('incomplete_process_count', 0):
            partial = attempt.coverage['observed_count'] > 0
            raise snapshot.ObservationError('INCOMPLETE_OBSERVATION', 'Process inventory incomplete.', partial=partial)
        events = []
        checkpoint_boot_id = None
        if same_boot:
            events = get_events(current, previous)
        else:
            checkpoint_boot_id = boot_id
        delta = database.save_collection(connection, identity, previous, current, events, checkpoint_boot_id,
                                         measurements, observed_at)
        if delta is None:
            attempt.replayed = True
            return 0
        attempt.set_delta(delta)
    if checkpoint is not None and previous_boot_id is None:
        report(logger, 'processes: established a new baseline; previous boot ID was unknown.')
    elif checkpoint is not None and not same_boot:
        report(logger, 'processes: detected a new Linux boot; established a new baseline.')
    return len(events)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Collect local processes snapshots.')
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)
    connection = logger = handler = None
    try:
        logger, handler = open_log('mysql_siem.processes', args.log_file)
        connection = get_connection(quiet=True)
        if connection is None:
            raise snapshot.ObservationError('DATABASE_ERROR', 'Database connection failed.')
        count = collect_processes(connection, logger=logger)
        report(logger, f'processes: committed snapshot; {count} changes.')
        return 0
    except snapshot.CollectionBusy:
        report(logger, 'processes: another run is active; observation skipped.')
        return 75
    except (SnapshotSettingError, snapshot.ResourceLimitError) as error:
        report(logger, f'processes: {error}', error=True)
        return 1
    except (psutil.Error, OSError, ValueError, pymysql.MySQLError) as error:
        code = collector_health.error_code(error)
        if isinstance(error, snapshot.ObservationError) and error.partial:
            report(logger, f'processes: partial observation ({code}).', error=True)
        else:
            report(logger, f'processes: collection error ({code}).', error=True)
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            close_log(logger, handler)


if __name__ == '__main__':
    raise SystemExit(main())
