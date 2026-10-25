"""Local services collector: explicit collection and transaction lifetime."""

import argparse

import pymysql

from config.run_logging import close_log, open_log, report
from database.connection import get_connection
from metrics import snapshot
from metrics.services import database
from metrics.services.get import get_events, get_services


def collect_services(connection):
    lock = None
    try:
        identity, previous, baseline, lock = database.begin_collection(connection)
        current = get_services(previous)
        events = []
        if baseline:
            events = get_events(current, previous)
        database.save_collection(connection, identity, current, events)
        connection.commit()
        return len(events)
    except BaseException:
        # An interruption before commit must also roll back the transaction.
        connection.rollback()
        raise
    finally:
        snapshot.release_snapshot_lock(connection, lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Collect local services snapshots.')
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)
    connection = logger = handler = None
    try:
        logger, handler = open_log('mysql_siem.services', args.log_file)
        connection = get_connection(quiet=True)
        if connection is None:
            raise snapshot.SnapshotError('Database connection failed.')
        count = collect_services(connection)
        report(logger, f'services: committed snapshot; {count} changes.')
        return 0
    except snapshot.CollectionBusy:
        report(logger, 'services: another run is active; observation skipped.')
        return 75
    except (OSError, ValueError, pymysql.MySQLError) as error:
        # Driver and registry messages may contain sensitive SQL or names.
        report(logger, f'services: collection failed ({type(error).__name__}).', error=True)
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            close_log(logger, handler)


if __name__ == '__main__':
    raise SystemExit(main())
