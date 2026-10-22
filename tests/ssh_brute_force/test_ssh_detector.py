"""Synthetic SSH event lists; the detector must never need MySQL."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from detection.ssh_brute_force.detector import detect_ssh_brute_force

START = datetime(2026, 10, 22, 12)


def make_events(count=5, *, start=START, step=1, first_id=1, **changes):
    events = []
    for index in range(count):
        event = {
            "id": first_id + index,
            "event_time": start + timedelta(seconds=index * step),
            "hostname": "server-a", "source_ip": "192.0.2.1",
            "username": "alice", "service": "sshd", "event_type": "SSH_AUTH_FAILURE",
        }
        event.update(changes)
        events.append(event)
    return events


def test_four_failures_do_not_detect():
    assert detect_ssh_brute_force(make_events(4)) == []


def test_five_failures_and_result_fields():
    assert detect_ssh_brute_force(make_events()) == [{
        "rule_key": "SSH_BRUTE_FORCE_001", "source_ip": "192.0.2.1",
        "hostname": "server-a", "failure_count": 5, "first_seen": START,
        "last_seen": START + timedelta(seconds=4), "evidence_ids": [1, 2, 3, 4, 5],
        "usernames": ["alice"],
    }]


def test_six_failures_are_one_detection():
    result = detect_ssh_brute_force(make_events(6))
    assert len(result) == 1
    assert result[0]["failure_count"] == 6


def test_usernames_are_not_grouping_keys():
    events = make_events()
    for index, event in enumerate(events):
        event["username"] = f"user-{index}"
    assert detect_ssh_brute_force(events)[0]["usernames"] == [f"user-{i}" for i in range(5)]


@pytest.mark.parametrize("field,value", [("hostname", "server-b"), ("source_ip", "192.0.2.2")])
def test_groups_are_separate(field, value):
    events = make_events()
    events[-1][field] = value
    assert detect_ssh_brute_force(events) == []
    events += make_events(first_id=10, **{field: value})
    assert len(detect_ssh_brute_force(events)) == 1


def test_failures_too_far_apart():
    assert detect_ssh_brute_force(make_events(step=16)) == []


def test_calendar_minute_boundary():
    events = make_events(start=START + timedelta(seconds=58))
    assert detect_ssh_brute_force(events)[0]["failure_count"] == 5


def test_empty_input():
    assert detect_ssh_brute_force([]) == []


@pytest.mark.parametrize("elapsed,expected", [(59.999999, True), (60, True), (60.000001, False)])
def test_inclusive_window_boundary(elapsed, expected):
    events = make_events()
    events[-1]["event_time"] = START + timedelta(seconds=elapsed)
    assert bool(detect_ssh_brute_force(events)) is expected


def test_window_slides_past_old_failure():
    events = make_events(1, start=START - timedelta(seconds=61), first_id=99) + make_events()
    assert detect_ssh_brute_force(events)[0]["evidence_ids"] == [1, 2, 3, 4, 5]


def test_ipv6_equivalent_spellings_group_together():
    events = make_events(source_ip="2001:db8::1")
    events[0]["source_ip"] = "2001:0db8:0:0:0:0:0:1"
    assert detect_ssh_brute_force(events)[0]["source_ip"] == "2001:db8::1"


def test_unsorted_input_is_not_mutated():
    events = list(reversed(make_events()))
    before = deepcopy(events)
    assert detect_ssh_brute_force(events)[0]["evidence_ids"] == [1, 2, 3, 4, 5]
    assert events == before


def test_separate_episodes():
    events = make_events() + make_events(start=START + timedelta(seconds=120), first_id=6)
    result = detect_ssh_brute_force(events)
    assert [item["failure_count"] for item in result] == [5, 5]
    assert result[1]["evidence_ids"] == [6, 7, 8, 9, 10]


def test_continuous_attack_merges_overlapping_windows():
    result = detect_ssh_brute_force(make_events(100, step=10))
    assert len(result) == 1
    assert result[0]["failure_count"] == 100
    assert result[0]["last_seen"] == START + timedelta(seconds=990)


def test_sparse_bridge_does_not_merge_episodes():
    events = make_events()
    events += make_events(8, start=START + timedelta(seconds=40), step=30, first_id=6)
    events += make_events(start=START + timedelta(seconds=300), first_id=14)
    result = detect_ssh_brute_force(events)
    assert len(result) == 2
    assert set(result[0]["evidence_ids"]).isdisjoint(result[1]["evidence_ids"])


def test_shared_boundary_event_merges_windows():
    events = make_events(step=15)
    events += make_events(4, start=START + timedelta(seconds=61), first_id=6)
    assert len(detect_ssh_brute_force(events)) == 1


def test_nonqualifying_tail_is_excluded():
    events = make_events() + make_events(1, start=START + timedelta(seconds=65), first_id=6)
    assert detect_ssh_brute_force(events)[0]["evidence_ids"] == [1, 2, 3, 4, 5]


def test_duplicate_id_does_not_reach_threshold():
    events = make_events(4)
    assert detect_ssh_brute_force(events + [dict(events[0])]) == []


def test_duplicate_hash_with_different_ids_does_not_reach_threshold():
    events = make_events(4)
    events[0]["event_hash"] = "a" * 64
    duplicate = dict(events[0], id=99)
    assert detect_ssh_brute_force(events + [duplicate]) == []


def test_unsaved_duplicate_content_does_not_reach_threshold():
    events = make_events(4)
    for event in events:
        del event["id"]
    assert detect_ssh_brute_force(events + [dict(events[0])]) == []


def test_distinct_ids_preserve_simultaneous_attempts():
    assert detect_ssh_brute_force(make_events(step=0))[0]["failure_count"] == 5


def test_unsaved_hashes_preserve_simultaneous_attempts():
    events = make_events(step=0)
    for index, event in enumerate(events):
        del event["id"]
        event["event_hash"] = f"{index:064x}"
    result = detect_ssh_brute_force(events)[0]
    assert result["failure_count"] == 5
    assert result["evidence_ids"] == []


@pytest.mark.parametrize("field", ["hostname", "source_ip", "event_time", "event_type", "service"])
def test_missing_required_field(field):
    events = make_events()
    del events[0][field]
    assert detect_ssh_brute_force(events) == []


@pytest.mark.parametrize("changes", [
    {"hostname": None}, {"hostname": " "}, {"hostname": []},
    {"source_ip": None}, {"source_ip": "wrong"}, {"source_ip": []},
    {"source_ip": "fe80::1%eth0"}, {"source_ip": "192.0.2.0/24"},
    {"event_time": "invalid"}, {"event_time": "2026-02-30 12:00:00"},
    {"event_time": "2026-10-22"}, {"event_time": None},
    {"service": "sudo"}, {"service": []}, {"event_type": "SSH_AUTH_SUCCESS"},
])
def test_invalid_event_does_not_complete_detection(changes):
    events = make_events()
    events[0].update(changes)
    assert detect_ssh_brute_force(events) == []


def test_malformed_items_do_not_hide_valid_detection():
    assert len(detect_ssh_brute_force([None, [], "bad", {}, 42] + make_events())) == 1


def test_mysql_and_aware_timestamps_use_utc():
    events = make_events()
    events[0]["event_time"] = "2026-10-22 12:00:00.000000"
    events[1]["event_time"] = "2026-10-22T15:00:01+03:00"
    events[2]["event_time"] = datetime(2026, 10, 22, 12, 0, 2, tzinfo=timezone.utc)
    assert detect_ssh_brute_force(events)[0]["failure_count"] == 5


def test_results_do_not_include_raw_messages_or_extra_secrets():
    events = make_events(password="secret", raw_message="private evidence")
    result = detect_ssh_brute_force(events)[0]
    assert "password" not in result
    assert "raw_message" not in result
