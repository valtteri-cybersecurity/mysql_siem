from copy import deepcopy
from unittest.mock import Mock

import pytest

from detection.common.alerts import make_alert_fingerprint
from detection.ssh_brute_force import runner
from detection.ssh_brute_force.db import SSHDetectionError
from detection.ssh_brute_force.detector import detect_ssh_brute_force
from detection.ssh_brute_force.formatting import build_alert


def test_ssh_content_and_auth_evidence(finding):
    alert, evidence = build_alert(finding)
    assert alert["title"] == "SSH Brute Force Attempt"
    assert alert["rule_key"] == "SSH_BRUTE_FORCE_001"
    assert alert["source_ip"] == "192.0.2.1"
    assert alert["first_seen"] == finding["first_seen"]
    assert alert["last_seen"] == finding["last_seen"]
    assert alert["details"] == {
        "hostname": "server-a", "failure_count": 8, "window_seconds": 60,
        "threshold": 5, "usernames": [f"user{i}" for i in range(8)],
    }
    assert evidence == [("AUTH", i) for i in range(1, 9)]
    assert "raw_message" not in alert["details"]


def test_fingerprint_order_is_stable_and_duplicate_evidence_is_removed(finding):
    before = deepcopy(finding)
    expected = build_alert(finding)
    finding["evidence_ids"] = list(reversed(finding["evidence_ids"])) + [1]
    finding["usernames"].reverse()
    assert build_alert(finding) == expected
    assert before["evidence_ids"] == list(range(1, 9))


@pytest.mark.parametrize("field,value", [
    ("source_ip", "192.0.2.2"), ("hostname", "server-b"),
    ("evidence_ids", list(range(11, 19))),
])
def test_different_groups_and_episodes_have_different_fingerprints(finding, field, value):
    original = build_alert(finding)[0]["alert_fingerprint"]
    finding[field] = value
    assert build_alert(finding)[0]["alert_fingerprint"] != original


def test_fingerprint_is_isolated_from_port_scan_rule():
    identity = {"source_ip": "192.0.2.1", "evidence_ids": [1, 2]}
    assert make_alert_fingerprint("SSH_BRUTE_FORCE_001", identity) != make_alert_fingerprint("PORT_SCAN_001", identity)


@pytest.fixture
def store_dependencies(monkeypatch, sample_events):
    dependencies = {
        "get_rule": Mock(return_value=(9, "HIGH", 1)),
        "get_evidence_events": Mock(return_value=sample_events),
        "get_related_alert_ids": Mock(return_value=[]),
        "save_alert": Mock(return_value=True),
        "find_related_alert": Mock(),
        "get_alert_evidence_ids": Mock(return_value=list(range(1, 9))),
        "update_alert": Mock(return_value=True),
    }
    for name, dependency in dependencies.items():
        monkeypatch.setattr(runner, name, dependency)
    return dependencies


def test_shared_storage_is_used_inside_callers_transaction(connection, finding, store_dependencies):
    assert runner.store_detection(connection, finding) == "new_alerts_saved"
    save = store_dependencies["save_alert"]
    save.assert_called_once_with(connection, *build_alert(finding), manage_transaction=False)
    store_dependencies["get_rule"].assert_called_once_with(connection, lock=True)
    connection.commit.assert_not_called()
    connection.rollback.assert_not_called()


def test_existing_fingerprint_is_skipped(connection, finding, store_dependencies):
    store_dependencies["save_alert"].return_value = False
    assert runner.store_detection(connection, finding) == "existing_alerts_skipped"


def test_disabled_rule_does_not_save(connection, finding, store_dependencies):
    store_dependencies["get_rule"].return_value = (9, "HIGH", 0)
    with pytest.raises(SSHDetectionError, match="disabled"):
        runner.store_detection(connection, finding)
    store_dependencies["save_alert"].assert_not_called()


@pytest.mark.parametrize("mutation", ["wrong_host", "wrong_count", "nonqualifying", "wrong_type"])
def test_actual_sources_must_match_finding(connection, finding, sample_events, store_dependencies, mutation):
    if mutation == "wrong_host":
        finding["hostname"] = "server-b"
    elif mutation == "wrong_count":
        finding["failure_count"] = 100
    elif mutation == "nonqualifying":
        store_dependencies["get_evidence_events"].return_value = sample_events[:4]
    else:
        sample_events[0]["event_type"] = "SSH_AUTH_SUCCESS"
    with pytest.raises(SSHDetectionError):
        runner.store_detection(connection, finding)
    store_dependencies["save_alert"].assert_not_called()


def test_metadata_usernames_come_from_source_rows(connection, finding, store_dependencies):
    finding["usernames"] = ["fake-user"]
    runner.store_detection(connection, finding)
    alert = store_dependencies["save_alert"].call_args.args[1]
    assert "fake-user" not in alert["details"]["usernames"]


def test_overlap_extends_existing_alert_using_union_count(connection, sample_events, store_dependencies):
    finding = detect_ssh_brute_force(sample_events[3:])[0]
    store_dependencies["get_evidence_events"].side_effect = [sample_events[3:], sample_events]
    store_dependencies["get_related_alert_ids"].return_value = [23]
    store_dependencies["get_alert_evidence_ids"].return_value = [1, 2, 3, 4, 5]
    store_dependencies["find_related_alert"].return_value = {
        "id": 23, "first_seen": sample_events[0]["event_time"],
        "last_seen": sample_events[4]["event_time"], "details": {"hostname": "server-a"},
    }
    assert runner.store_detection(connection, finding) == "alerts_updated"
    update = store_dependencies["update_alert"].call_args
    assert update.args[1] == 23
    assert update.args[4]["failure_count"] == 8  # Not 5 + 5.
    assert update.args[5] == [("AUTH", i) for i in range(1, 9)]
    store_dependencies["save_alert"].assert_not_called()


def test_multiple_saved_alerts_are_not_silently_cross_linked(connection, finding, store_dependencies):
    store_dependencies["get_related_alert_ids"].return_value = [23, 24]
    with pytest.raises(SSHDetectionError, match="multiple saved SSH alerts"):
        runner.store_detection(connection, finding)
    store_dependencies["update_alert"].assert_not_called()
    store_dependencies["save_alert"].assert_not_called()
