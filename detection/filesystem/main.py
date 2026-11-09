"""Run with python -m detection.filesystem.main."""

import argparse

from database.connection import get_connection
from detection.filesystem.detector import CRITICAL_DIRECTORIES, CRITICAL_FILES
from detection.filesystem.runner import run_automatic
from metrics.filesystem.runtime import run_job


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--critical-file', action='append')
    parser.add_argument('--critical-directory', action='append')
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)

    def detect():
        connection = get_connection(quiet=True)
        if connection is None:
            return 'FAILED', 'Database connection failed.'
        try:
            count = run_automatic(connection, critical_files=args.critical_file or CRITICAL_FILES,
                                  critical_directories=args.critical_directory or CRITICAL_DIRECTORIES)
        finally:
            connection.close()
        return 'SUCCESS', f'alerts={count}'

    return run_job('FIM detection', args.log_file, detect)


if __name__ == '__main__':
    raise SystemExit(main())
