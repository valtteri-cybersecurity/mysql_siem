from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from analysis.ufw.ports import aggregate_ports
from analysis.ufw.source_ips import aggregate_source_ips
from database.identity import (
    EventIdentity,
    IdentityError,
    configured_identity,
    event_scope,
    identity_schema_enabled,
    resolve_identity,
)
from detection.port_scan.detector import detect_port_scans
from detection.ssh_brute_force.detector import detect_ssh_brute_force

START = datetime(2026, 10, 22, 12)


@pytest.mark.parametrize("value", [0, -1, True, "1", 2**64])
def test_invalid_identity_rejected(value):
    with pytest.raises(IdentityError):
        EventIdentity(value, 2, 3)


def test_no_configuration_does_not_lookup_hostname_or_ip(monkeypatch):
    monkeypatch.delenv("SIEM_UFW_SOURCE_ID", raising=False)
    cursor = MagicMock()
    assert configured_identity(cursor, "ufw") is None
    cursor.execute.assert_not_called()


@pytest.mark.parametrize("source,collector", [("abc", "1"), ("1", "0"), ("1", None)])
def test_partial_or_bad_configuration_fails(monkeypatch, source, collector):
    monkeypatch.setenv("SIEM_UFW_SOURCE_ID", source)
    if collector is None:
        monkeypatch.delenv("SIEM_COLLECTOR_ID", raising=False)
    else:
        monkeypatch.setenv("SIEM_COLLECTOR_ID", collector)
    with pytest.raises(IdentityError):
        configured_identity(MagicMock(), "ufw")


def test_sender_is_validated_separately_from_reported_hostname():
    cursor = MagicMock()
    cursor.fetchone.side_effect = [(4,), (7,)]
    assert resolve_identity(cursor, 5, 6, source_type="ufw", sender_id=7) == EventIdentity(4, 5, 6, 7)
    assert "hostname" not in " ".join(call.args[0] for call in cursor.execute.call_args_list)


def ufw_events(host_id, count=10):
    return [{"id": host_id * 100 + index, "host_id": host_id, "source_id": host_id,
             "event_time": START + timedelta(seconds=index), "hostname": "same-name", "action": "BLOCK",
             "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP", "dst_port": 1000 + index}
            for index in range(count)]


def auth_events(host_id, count=5):
    return [{"id": host_id * 100 + index, "host_id": host_id, "source_id": host_id,
             "event_time": START + timedelta(seconds=index), "hostname": "same-name", "source_ip": "192.0.2.1",
             "event_type": "SSH_AUTH_FAILURE", "service": "sshd", "username": "alice"} for index in range(count)]


def test_port_scan_cannot_reach_threshold_by_combining_hosts():
    events = ufw_events(1, 5) + ufw_events(2, 5)
    for index, event in enumerate(events):
        event["dst_port"] = 1000 + index
    assert detect_port_scans(events) == []
    findings = detect_port_scans(ufw_events(1) + ufw_events(2))
    assert {finding["host_id"] for finding in findings} == {1, 2}


def test_ssh_cannot_reach_threshold_by_combining_same_named_hosts():
    assert detect_ssh_brute_force(auth_events(1, 3) + auth_events(2, 3)) == []
    findings = detect_ssh_brute_force(auth_events(1) + auth_events(2))
    assert {finding["host_id"] for finding in findings} == {1, 2}


def test_hostname_change_does_not_split_one_registered_host():
    events = auth_events(1)
    events[-1]["hostname"] = "new-name"
    assert detect_ssh_brute_force(events)[0]["failure_count"] == 5


@pytest.mark.parametrize("aggregate", [aggregate_source_ips, aggregate_ports])
def test_analysis_groups_same_observations_by_host(aggregate):
    rows = aggregate(ufw_events(1, 1) + ufw_events(2, 1), START, START + timedelta(hours=1))
    assert len(rows) == 2
    assert {row["host_id"] for row in rows} == {1, 2}
    assert all(row["total_events"] == 1 for row in rows)


def test_unassigned_source_is_never_a_host_identity():
    assert event_scope({"source_id": 17, "hostname": "trusted-looking"}) == ("source", 17)


def test_legacy_schema_is_checked_once_per_connection():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(0,), (0,)]
    assert identity_schema_enabled(connection) is False
    assert identity_schema_enabled(connection) is False
    assert cursor.execute.call_count == 2


@pytest.mark.parametrize("responses", [[(1,), ("RUNNING",)], [(0,), (5,)]])
def test_partial_upgrade_or_hidden_ledger_never_uses_legacy_grouping(responses):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.side_effect = responses
    with pytest.raises(IdentityError):
        identity_schema_enabled(connection)
    assert "_siem_identity_ready" not in connection.__dict__


def test_completed_migration_uses_host_scope():
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.side_effect = [(1,), ("APPLIED",)]
    assert identity_schema_enabled(connection) is True
