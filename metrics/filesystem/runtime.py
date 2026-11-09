"""Run and report one filesystem job with the shared rotating logs."""

import fcntl
import os
import signal
import time
from pathlib import Path

import pymysql

from config.run_logging import close_log, open_log, report
from metrics.filesystem.fim import RebaselineRequired
from metrics.snapshot import CollectionBusy


class _JobInterrupted(RuntimeError):
    """A termination signal stopped the current collection."""


def _stop(signum, frame):
    raise _JobInterrupted


def run_job(name, log_file, action):
    start = time.monotonic()
    logger = handler = lock = previous_signal = None
    status = 'FAILED'
    message = 'Collection stopped.'
    try:
        if log_file is not None:
            lock = os.open(Path(log_file).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CollectionBusy('Filesystem job is already running.') from None
            logger, handler = open_log(name, log_file)
            previous_signal = signal.signal(signal.SIGTERM, _stop)
            report(logger, f'{name} STARTED')
        status, message = action()
    except CollectionBusy:
        status = 'SKIPPED'
        message = 'Another run holds the collection lock.'
    except _JobInterrupted:
        message = 'Collection interrupted.'
    except RebaselineRequired:
        message = 'FIM configuration changed. Administrative rebaseline is required.'
    except (OSError, RuntimeError, ValueError, TypeError, pymysql.MySQLError):
        message = 'Collection or storage failed.'
    finally:
        if previous_signal is not None:
            signal.signal(signal.SIGTERM, previous_signal)
        try:
            if status == 'SUCCESS':
                exit_code = 0
            elif status == 'SKIPPED':
                exit_code = 75
            else:
                exit_code = 1
            report(logger, f'{name} {status} duration_seconds={time.monotonic() - start:.3f} {message}',
                   error=exit_code != 0)
        finally:
            close_log(logger, handler)
            if lock is not None:
                os.close(lock)
    return exit_code
