"""Services database operations, using the shared snapshot SQL."""

from metrics import snapshot
from metrics.measurement_window import utc_datetime
from metrics.services import windows


def begin_collection(connection, attempt=None):
    identity, previous, marker, lock = snapshot.begin_snapshot(connection, 'services', attempt)
    return identity, previous, bool(marker), lock


def save_collection(connection, identity, previous, current, events, observed_at=None):
    if observed_at is None:
        observed_at = snapshot.utc_now()
    observed_at = utc_datetime(observed_at)
    if not windows.save_window(connection, identity, observed_at, current, events):
        return None
    return snapshot.save_snapshot(connection, 'services', identity, previous, current, events, observed_at)
