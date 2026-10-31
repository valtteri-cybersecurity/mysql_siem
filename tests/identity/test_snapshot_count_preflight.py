"""Regression tests for mutable snapshot state during upgrades."""

import pytest

from database.migrate import (
    MigrationError,
    SNAPSHOT_STATE_TABLES,
    requires_monotonic_history_count,
)
from database.ufw_history import check_counts


@pytest.mark.parametrize(
    "table,previous,current",
    [
        ("process_state", 120, 90),
        ("process_state", 10, 0),
        ("service_state", 18, 7),
        ("service_state", 5, 0),
    ],
)
def test_snapshot_state_may_shrink(table, previous, current):
    assert table in SNAPSHOT_STATE_TABLES
    assert not requires_monotonic_history_count(table)

    check_counts(
        None,
        {table: previous},
        {table: current},
    )


@pytest.mark.parametrize(
    "table",
    [
        "ufw_log",
        "process_events",
        "service_events",
        "auth_events",
        "audit_events",
        "detection_alerts",
        "alert_evidence",
    ],
)
def test_historical_event_loss_still_blocked(table):
    assert requires_monotonic_history_count(table)

    with pytest.raises(
        MigrationError,
        match="Historical row counts decreased",
    ):
        check_counts(
            None,
            {table: 100},
            {table: 99},
        )


@pytest.mark.parametrize(
    "table",
    ["process_state", "service_state"],
)
def test_missing_snapshot_table_is_rejected(table):
    with pytest.raises(
        MigrationError,
        match="Snapshot state table disappeared",
    ):
        check_counts(None, {table: 5}, {})


@pytest.mark.parametrize(
    "value",
    [-1, None, True, 3.5],
)
def test_invalid_saved_state_count_is_rejected(value):
    with pytest.raises(
        MigrationError,
        match="Migration history counts are invalid",
    ):
        check_counts(
            None,
            {"process_state": value},
            {"process_state": 1},
        )


def test_snapshot_event_tables_are_not_exempt():
    assert SNAPSHOT_STATE_TABLES == frozenset({
        "process_state",
        "service_state",
    })

    assert requires_monotonic_history_count(
        "process_events"
    )
    assert requires_monotonic_history_count(
        "service_events"
    )
