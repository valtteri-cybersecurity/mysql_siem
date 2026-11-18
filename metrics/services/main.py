"""Local services collector: explicit collection and transaction lifetime."""

import argparse

import pymysql

from config.run_logging import close_log, open_log, report
from config.snapshot_policy import SnapshotSettingError
from database.connection import get_connection
from metrics import collector_health, snapshot
from metrics.services import database
from metrics.services.get import get_events, get_services


def collect_services(connection, *, logger=None, observed_at=None):
    """Collect once. A replay uses the original observation timestamp."""
    with collector_health.collection(connection, 'services', database.begin_collection, logger) as run:
        attempt, identity, previous, baseline = run
        current = get_services(previous, coverage=attempt.coverage)
        events = []
        if baseline:
            events = get_events(current, previous)
        delta = database.save_collection(connection, identity, previous, current, events, observed_at)
        if delta is None:
            attempt.replayed = True
            return 0
        attempt.set_delta(delta)
    return len(events)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Collect local services snapshots.')
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)
    connection = logger = handler = None
    try:
        logger, handler = open_log('mysql_siem.services', args.log_file)
        connection = get_connection(quiet=True)
        if connection is None:
            raise snapshot.ObservationError('DATABASE_ERROR', 'Database connection failed.')
        count = collect_services(connection, logger=logger)
        report(logger, f'services: committed snapshot; {count} changes.')
        return 0
    except snapshot.CollectionBusy:
        report(logger, 'services: another run is active; observation skipped.')
        return 75
    except (SnapshotSettingError, snapshot.ResourceLimitError) as error:
        report(logger, f'services: {error}', error=True)
        return 1
    except (OSError, ValueError, pymysql.MySQLError) as error:
        report(logger, f'services: collection error ({collector_health.error_code(error)}).', error=True)
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            close_log(logger, handler)


if __name__ == '__main__':
    raise SystemExit(main())
