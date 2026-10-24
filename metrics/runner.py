"""Common connection lifetime, bounded logging and CLI error handling."""

import argparse

import pymysql

from config.run_logging import close_log, open_log, report
from database.connection import get_connection
from metrics.snapshot import CollectionBusy, SnapshotError


def run(kind, collect, argv=None):
    parser = argparse.ArgumentParser(description=f'Collect local {kind} snapshots.')
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)
    connection = logger = handler = None
    try:
        logger, handler = open_log('mysql_siem.' + kind, args.log_file)
        connection = get_connection(quiet=True)
        if connection is None:
            raise SnapshotError('Database connection failed.')
        count = collect(connection)
        report(logger, f'{kind}: committed snapshot; {count} changes.')
        return 0
    except CollectionBusy:
        report(logger, f'{kind}: another run is active; observation skipped.')
        return 75
    except (OSError, ValueError, pymysql.MySQLError) as error:
        # Registry and driver messages may contain sensitive SQL or names.
        report(logger, f'{kind}: collection failed ({type(error).__name__}).', error=True)
        return 1
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            close_log(logger, handler)
