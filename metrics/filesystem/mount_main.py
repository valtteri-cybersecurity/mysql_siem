"""Run with python -m metrics.filesystem.mount_main."""

import argparse
import sys

from metrics.filesystem.mount_db import save_mount_metrics
from metrics.filesystem.mounts import collect_mount_metrics
from metrics.filesystem.runtime import run_job


def _collect():
    collection = collect_mount_metrics()
    mounts = len(collection.measurements)
    coverage = f'mounts={mounts} failures={len(collection.failures)}'
    if collection.status == 'partial':
        return 'PARTIAL', coverage
    if collection.status == 'failed' or not mounts:
        return 'FAILED', coverage

    inserted = save_mount_metrics(collection)
    return 'SUCCESS', f'{coverage} stored={inserted}'


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)
    return run_job('Filesystem mounts', args.log_file, _collect)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
