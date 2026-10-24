"""Protected local Processes collector entry point."""

from metrics.processes.database import collect_processes
from metrics.runner import run


def main(argv=None):
    return run('processes', collect_processes, argv)


if __name__ == '__main__':
    raise SystemExit(main())
