"""Small bounded-log helpers shared by the SSH collector and detection CLI."""

import logging
import sys
from logging.handlers import RotatingFileHandler


def open_log(name, filename):
    if filename is None:
        return None, None
    handler = RotatingFileHandler(filename, maxBytes=1000000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    return logger, handler


def report(logger, message, *, error=False):
    if logger is None:
        print(message, file=sys.stderr if error else sys.stdout)
    elif error:
        logger.error(message)
    else:
        logger.info(message)


def close_log(logger, handler):
    if handler is not None:
        logger.removeHandler(handler)
        handler.close()
