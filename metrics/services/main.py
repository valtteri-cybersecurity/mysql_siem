"""Protected local Services collector entry point."""

from metrics.runner import run
from metrics.services.database import collect_services


def main(argv=None):
    return run('services', collect_services, argv)


if __name__ == '__main__':
    raise SystemExit(main())
