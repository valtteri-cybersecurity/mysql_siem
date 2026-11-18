"""Processes database operations, using the shared snapshot SQL."""

from metrics import snapshot
from metrics.measurement_window import utc_datetime
from metrics.processes import windows


def begin_collection(connection, attempt=None):
    return snapshot.begin_snapshot(connection, 'processes', attempt)


def save_collection(connection, identity, previous, current, events, checkpoint_boot_id, measurements, observed_at=None):
    if observed_at is None:
        observed_at = snapshot.utc_now()
    observed_at = utc_datetime(observed_at)
    previous_observation = previous
    if checkpoint_boot_id is not None:
        previous_observation = None
    if not windows.save_window(connection, identity, observed_at, measurements, previous_observation, len(current)):
        return None
    return snapshot.save_snapshot(connection, 'processes', identity, previous, current, events, observed_at,
                                  process_boot_id=checkpoint_boot_id)
