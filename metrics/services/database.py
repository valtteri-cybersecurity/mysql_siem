"""Services use the shared identity, locking and atomic snapshot protocol."""

from metrics.services.get import get_events, get_services
from metrics.snapshot import collect_snapshot


def collect_services(connection):
    return collect_snapshot(connection, 'services', get_services, get_events)
