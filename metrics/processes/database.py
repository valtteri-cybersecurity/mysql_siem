"""Processes database operations, using the shared snapshot SQL."""

from metrics import snapshot


def begin_collection(connection):
    return snapshot.begin_snapshot(connection, 'processes')


def save_collection(connection, identity, current, events):
    snapshot.save_snapshot(connection, 'processes', identity, current, events, snapshot.utc_now())
