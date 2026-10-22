"""Port-scan detection uses synthetic UFW rows and no database."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from detection.port_scan.detector import detect_port_scans

START = datetime(2026, 10, 22, 12, 0, 0)


def make_events(count=10, *, start=START, step=1, first_id=1, **changes):
    events = []
    for index in range(count):
        event = {
            "id": first_id + index,
            "event_time": start + timedelta(seconds=index * step),
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "protocol": "TCP",
            "action": "BLOCK",
            "dst_port": 1000 + index,
        }
        event.update(changes)
        events.append(event)
    return events


def test_fewer_than_ten_distinct_ports():
    assert detect_port_scans(make_events(9)) == []


def test_exactly_ten_ports_and_result_fields():
    events = make_events()
    assert detect_port_scans(events) == [{
        "rule_key": "PORT_SCAN_001",
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "protocol": "TCP",
        "distinct_ports": list(range(1000, 1010)),
        "first_seen": START,
        "last_seen": START + timedelta(seconds=9),
        "evidence_ids": list(range(1, 11)),
    }]


def test_more_than_ten_ports():
    detections = detect_port_scans(make_events(15))
    assert len(detections) == 1
    assert detections[0]["distinct_ports"] == list(range(1000, 1015))
    assert detections[0]["evidence_ids"] == list(range(1, 16))


def test_repeated_port_does_not_meet_threshold():
    assert detect_port_scans(make_events(30, dst_port=443)) == []
    events = make_events(9) + make_events(20, dst_port=1000)
    assert detect_port_scans(events) == []


def test_repeated_port_keeps_evidence_without_increasing_port_count():
    events = make_events() + make_events(1, dst_port=1000, first_id=11)
    result = detect_port_scans(events)[0]
    assert len(result["distinct_ports"]) == 10
    assert sorted(result["evidence_ids"]) == list(range(1, 12))


@pytest.mark.parametrize("elapsed, detected", [
    (timedelta(seconds=60) - timedelta(microseconds=1), True),
    (timedelta(seconds=60), True),
    (timedelta(seconds=60, microseconds=1), False),
])
def test_exact_window_boundary(elapsed, detected):
    events = make_events()
    events[-1]["event_time"] = START + elapsed
    assert bool(detect_port_scans(events)) is detected


def test_ten_ports_spread_over_more_than_sixty_seconds():
    assert detect_port_scans(make_events(step=7)) == []


@pytest.mark.parametrize("field, other", [
    ("src_ip", "192.0.2.2"),
    ("dst_ip", "198.51.100.2"),
    ("protocol", "UDP"),
])
def test_different_groups_do_not_combine(field, other):
    events = make_events()
    for event in events[5:]:
        event[field] = other
    assert detect_port_scans(events) == []


@pytest.mark.parametrize("field, other", [
    ("src_ip", "192.0.2.2"),
    ("dst_ip", "198.51.100.2"),
    ("protocol", "UDP"),
])
def test_each_qualifying_group_gets_its_own_detection(field, other):
    events = make_events() + make_events(first_id=11, **{field: other})
    results = detect_port_scans(events)
    assert len(results) == 2
    assert sorted(len(result["evidence_ids"]) for result in results) == [10, 10]


def test_sliding_window_crosses_calendar_minute():
    start = START + timedelta(seconds=40)
    result = detect_port_scans(make_events(start=start, step=4))[0]
    assert result["first_seen"] == start
    assert result["last_seen"] == START + timedelta(seconds=76)


def test_sliding_window_discards_old_events_before_finding_scan():
    old = make_events(1, start=START - timedelta(seconds=61), dst_port=80)
    result = detect_port_scans(old + make_events(first_id=2))[0]
    assert result["first_seen"] == START
    assert result["evidence_ids"] == list(range(2, 12))
    assert 80 not in result["distinct_ports"]


def test_empty_input():
    assert detect_port_scans([]) == []


@pytest.mark.parametrize("field", [
    "src_ip", "dst_ip", "dst_port", "event_time", "action", "protocol",
])
def test_missing_required_field_is_skipped(field):
    events = make_events()
    del events[0][field]
    assert detect_port_scans(events) == []


@pytest.mark.parametrize("changes", [
    {"src_ip": None}, {"src_ip": ""}, {"src_ip": "not-an-ip"},
    {"src_ip": []}, {"dst_ip": None}, {"dst_ip": ""}, {"dst_ip": 123},
    {"dst_port": None}, {"dst_port": "invalid"}, {"dst_port": ""},
    {"dst_port": 0}, {"dst_port": -1}, {"dst_port": 65536},
    {"dst_port": 443.5}, {"dst_port": 443.0}, {"dst_port": True},
    {"dst_port": []}, {"dst_port": "1.5"}, {"dst_port": "-1"},
    {"event_time": None}, {"event_time": "not-a-date"},
    {"event_time": "2026-02-30 12:00:00"},
    {"event_time": "2026-10-22"}, {"event_time": 123},
    {"event_time": START.replace(tzinfo=timezone.utc)},
    {"event_time": "2026-10-22T12:00:00+03:00"},
    {"action": "UNKNOWN"}, {"action": None}, {"action": []},
    {"protocol": "ICMP"}, {"protocol": None}, {"protocol": []},
])
def test_invalid_event_cannot_complete_a_scan(changes):
    events = make_events()
    events[0].update(changes)
    assert detect_port_scans(events) == []


def test_malformed_items_do_not_hide_a_valid_scan():
    events = [None, 123, [], "invalid", {}, {"event_time": "bad"}]
    events += make_events()
    assert len(detect_port_scans(events)) == 1


def test_unsorted_input_is_not_mutated():
    events = list(reversed(make_events()))
    before = deepcopy(events)
    result = detect_port_scans(events)[0]
    assert result["evidence_ids"] == list(range(1, 11))
    assert events == before


@pytest.mark.parametrize("action", ["BLOCK", "AUDIT", "ALLOW"])
def test_allowed_actions(action):
    assert len(detect_port_scans(make_events(action=action))) == 1


@pytest.mark.parametrize("actions", [
    ("BLOCK", "AUDIT"),
    ("BLOCK", "ALLOW"),
    ("AUDIT", "ALLOW"),
    ("BLOCK", "AUDIT", "ALLOW"),
])
def test_allowed_actions_can_combine(actions):
    events = make_events()
    for index, event in enumerate(events):
        event["action"] = actions[index % len(actions)]
    results = detect_port_scans(events)
    assert len(results) == 1
    assert results[0]["evidence_ids"] == list(range(1, 11))


def test_mysql_timestamp_strings_and_numeric_port_strings():
    events = make_events()
    for index, event in enumerate(events):
        if index % 2 == 0:
            event["event_time"] = event["event_time"].strftime("%Y-%m-%d %H:%M:%S")
        else:
            event["event_time"] = event["event_time"].strftime("%Y-%m-%d %H:%M:%S.%f")
        event["dst_port"] = str(event["dst_port"])
    assert detect_port_scans(events)[0]["first_seen"] == START


@pytest.mark.parametrize("port", [1, 65535])
def test_valid_port_boundaries(port):
    events = make_events()
    events[0]["dst_port"] = port
    assert port in detect_port_scans(events)[0]["distinct_ports"]


def test_equivalent_ipv6_addresses_are_grouped():
    events = make_events(src_ip="2001:db8::1", dst_ip="2001:db8::2")
    events[0]["src_ip"] = "2001:0db8:0:0:0:0:0:1"
    result = detect_port_scans(events)[0]
    assert result["source_ip"] == "2001:db8::1"
    assert result["destination_ip"] == "2001:db8::2"


def test_separate_scans_in_same_group():
    first = make_events()
    second = make_events(start=START + timedelta(seconds=120), first_id=11)
    results = detect_port_scans(second + first)
    assert len(results) == 2
    assert results[0]["evidence_ids"] == list(range(1, 11))
    assert results[1]["evidence_ids"] == list(range(11, 21))


def test_continuous_scan_merges_overlapping_windows():
    result = detect_port_scans(make_events(100, step=5))
    assert len(result) == 1
    assert result[0]["last_seen"] == START + timedelta(seconds=495)
    assert result[0]["distinct_ports"] == list(range(1000, 1100))
    assert result[0]["evidence_ids"] == list(range(1, 101))


def test_sparse_traffic_between_scans_does_not_merge_them():
    events = make_events()
    for index in range(1, 8):
        events += make_events(1, start=START + timedelta(seconds=index * 30),
                              dst_port=443, first_id=10 + index)
    events += make_events(start=START + timedelta(seconds=240), first_id=18)
    results = detect_port_scans(events)
    assert len(results) == 2
    assert set(results[0]["evidence_ids"]).isdisjoint(results[1]["evidence_ids"])


def test_shared_boundary_event_merges_qualifying_windows():
    events = make_events(step=6)
    events += make_events(9, start=START + timedelta(seconds=61), first_id=11)
    assert len(detect_port_scans(events)) == 1


def test_nonqualifying_tail_is_not_in_evidence():
    events = make_events()
    events += make_events(1, start=START + timedelta(seconds=70), first_id=11)
    result = detect_port_scans(events)[0]
    assert result["last_seen"] == START + timedelta(seconds=9)
    assert 11 not in result["evidence_ids"]


def test_missing_or_invalid_ids_do_not_prevent_detection():
    events = make_events()
    del events[0]["id"]
    for index, bad_id in enumerate([None, "3", [], True, 0, -1], start=1):
        events[index]["id"] = bad_id
    result = detect_port_scans(events)[0]
    assert result["evidence_ids"] == [8, 9, 10]


def test_duplicate_evidence_ids_are_listed_once():
    events = make_events()
    events += [dict(events[0])]
    result = detect_port_scans(events)[0]
    assert result["evidence_ids"] == list(range(1, 11))


def test_events_with_equal_timestamps():
    assert len(detect_port_scans(make_events(step=0))) == 1
