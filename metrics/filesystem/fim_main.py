"""Run with python -m metrics.filesystem.fim_main."""

import argparse
import sys
from pathlib import Path

from config.filesystem_runtime import read_config
from metrics.filesystem.fim_db import collect_fim, collect_fim_report
from metrics.filesystem.inventory import DEFAULT_CONFIG
from metrics.filesystem.runtime import run_job


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--log-file')
    args = parser.parse_args(argv)

    def collect():
        if args.config is None and args.log_file is None:
            changes = collect_fim()
            return 'SUCCESS', f'Filesystem inventory accepted. New events: {changes}.'
        config = DEFAULT_CONFIG
        if args.config is not None:
            _, config = read_config(args.config)
        return collect_fim_report(config)

    return run_job('Filesystem inventory', args.log_file, collect)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
