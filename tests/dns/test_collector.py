import copy
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from ingestion.dns import collector
from ingestion.dns.adapters.adguard import AdGuardAPIError, normalize_event
from ingestion.dns.collector import (
    DNSCollectionError,
    DNSCollectionIncomplete,
    collect,
    replay_keys,
)
from ingestion.dns.config import CollectorConfig
from ingestion.dns.db import DNSStorageError
from ingestion.dns.models import DNSPage
from ingestion.dns.timestamps import timestamp_ns

NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


def event(at="2026-10-21T11:59:00.123456789Z", name="example.net"):
    return normalize_event(
        {
            "time": at,
            "client": "192.0.2.1",
            "question": {"name": name, "type": "A"},
            "reason": "NotFilteredNotFound",
            "status": "NOERROR",
        },
        "dns",
    )


class QueryLog:
    def __init__(self, events):
        self.events = list(events)
        self.calls = []
        self.failure_at = None

    def fetch_page(self, *, limit, older_than, offset, deadline):
        self.calls.append((older_than, offset))
        if len(self.calls) == self.failure_at:
            raise AdGuardAPIError("API fixture failure")
        matches = sorted(
            (
                item
                for item in self.events
                if timestamp_ns(item.raw_timestamp) < timestamp_ns(older_than)
            ),
            key=lambda item: timestamp_ns(item.raw_timestamp),
            reverse=True,
        )
        data = tuple(matches[offset : offset + limit])
        return DNSPage(data, data[-1].raw_timestamp if data else None)


class MemoryStore:
    def __init__(self):
        self.state = None
        self.rows = {}
        self.calls = 0
        self.failure_at = None

    def save(self, connection, source_id, events, *, state=None, dedup_keys=None):
        self.calls += 1
        if self.calls == self.failure_at:
            raise RuntimeError("simulated process interruption")
        inserted = 0
        for key, item in zip(dedup_keys or (), events):
            if key not in self.rows:
                self.rows[key] = item
                inserted += 1
        if state is not None:
            self.state = copy.deepcopy(state)
        return inserted


@pytest.fixture
def store(monkeypatch):
    store = MemoryStore()
    monkeypatch.setattr(
        collector, "source_lock", lambda connection, source_id: nullcontext()
    )
    monkeypatch.setattr(
        collector,
        "load_state",
        lambda connection, source_id: copy.deepcopy(store.state),
    )
    monkeypatch.setattr(collector, "save_events", store.save)
    monkeypatch.setattr(
        collector, "get_active_domain_filters", lambda connection, source_id: []
    )
    monkeypatch.setattr(
        collector, "get_active_client_filters", lambda connection, source_id: []
    )
    return store


def run(log, **kwargs):
    return collect(
        log,
        object(),
        7,
        kwargs.pop("settings", CollectorConfig()),
        now=kwargs.pop("now", NOW),
        **kwargs,
    )


def test_timestamp_ties_cross_pages_and_replay_preserves_counts(store):
    item = event()
    log = QueryLog([item] * 5 + [event("2026-10-21T11:58:00Z")])
    assert run(log, page_size=2)["inserted"] == 6
    assert len(store.rows) == 6 and store.state["pending"] is None
    assert (
        run(QueryLog(log.events), page_size=2, now=NOW + timedelta(minutes=5))[
            "inserted"
        ]
        == 0
    )
    # A later identical observation increases the observed multiplicity by one.
    assert (
        run(
            QueryLog(log.events + [item]), page_size=2, now=NOW + timedelta(minutes=10)
        )["inserted"]
        == 1
    )


def test_submicrosecond_timestamps_remain_distinct(store):
    items = [event(f"2026-10-21T11:59:00.12345600{digit}Z") for digit in range(1, 5)]
    assert run(QueryLog(items), page_size=1)["inserted"] == 4
    assert len(store.rows) == 4


def test_new_events_above_fixed_fence_wait_for_next_run(store):
    newest = event("2026-10-21T11:59:40Z")
    log = QueryLog([event(), newest])
    assert run(log)["inserted"] == 1
    assert newest not in store.rows.values()
    assert run(QueryLog(log.events), now=NOW + timedelta(minutes=5))["inserted"] == 1


def test_page_budget_resumes_at_complete_group_not_offset(store):
    items = [event(f"2026-10-21T11:5{minute}:00Z") for minute in (9, 8, 7)]
    with pytest.raises(DNSCollectionIncomplete):
        run(QueryLog(items), page_size=2, settings=CollectorConfig(max_pages=1))
    assert store.state["completed_until"] is None
    assert store.state["pending"]["cursor"] == items[0].raw_timestamp
    assert len(store.rows) == 1
    log = QueryLog(items)
    assert run(log, page_size=2)["inserted"] == 2
    assert log.calls[0] == (items[0].raw_timestamp, 0)
    assert len(store.rows) == 3 and store.state["pending"] is None


def test_api_failure_resumes_pending_window(store):
    items = [event(), event("2026-10-21T11:58:00Z")]
    log = QueryLog(items)
    log.failure_at = 2
    with pytest.raises(AdGuardAPIError):
        run(log, page_size=2)
    assert store.state["completed_until"] is None and len(store.rows) == 1
    assert run(QueryLog(items), page_size=2)["inserted"] == 1
    assert len(store.rows) == 2


def test_partial_chunk_commit_replays_without_duplicate_rows(store):
    items = [event()] * 1001
    # First pending state, first 1000 rows, then interruption before final chunk/state.
    store.failure_at = 3
    with pytest.raises(RuntimeError):
        run(QueryLog(items), page_size=1000)
    assert len(store.rows) == 1000
    assert store.state["pending"]["cursor"] == store.state["pending"]["upper"]
    store.failure_at = None
    assert run(QueryLog(items), page_size=1000)["inserted"] == 1
    assert len(store.rows) == 1001


def test_offsets_reanchor_to_open_group(store):
    items = [event(f"2026-10-21T11:{minute:02}:00Z") for minute in range(59, 20, -1)]
    log = QueryLog(items)
    assert run(log, page_size=2)["inserted"] == len(items)
    assert max(offset for _, offset in log.calls) <= 1


def test_partial_tail_is_not_committed_when_group_limit_exceeded(store):
    with pytest.raises(DNSCollectionError, match="group exceeds"):
        run(
            QueryLog([event()] * 3),
            page_size=2,
            settings=CollectorConfig(max_group_events=2),
        )
    assert not store.rows and store.state["completed_until"] is None


def test_ambiguous_empty_page_cannot_complete(store):
    class AmbiguousLog:
        def fetch_page(self, **kwargs):
            return DNSPage((), "2026-10-21T11:00:00Z")

    with pytest.raises(DNSCollectionError, match="Ambiguous"):
        run(AmbiguousLog())
    assert store.state["completed_until"] is None


def test_out_of_order_page_restarts_original_fence(store):
    class ChangingLog:
        def fetch_page(self, **kwargs):
            return DNSPage((event("2026-10-21T11:58:00Z"), event()), None)

    with pytest.raises(DNSCollectionError, match="changed order"):
        run(ChangingLog())
    assert store.state["pending"]["cursor"] == store.state["pending"]["upper"]
    assert not store.rows


def test_corrupt_and_expired_checkpoints_do_not_fetch(store):
    log = QueryLog([])
    store.state = {"version": 2}
    with pytest.raises(DNSCollectionError, match="Unsupported"):
        run(log)
    store.state = {
        "version": 1,
        "completed_until": "2026-08-01T00:00:00Z",
        "pending": None,
    }
    with pytest.raises(DNSCollectionError, match="retention"):
        run(log)
    assert not log.calls


def test_completed_lower_boundary_can_resume_after_final_commit_interruption(store):
    stamp = "2026-10-21T11:00:00Z"
    store.state = {
        "version": 1,
        "completed_until": None,
        "pending": {
            "upper": "2026-10-21T11:59:30Z",
            "lower": stamp,
            "cursor": stamp,
        },
    }
    log = QueryLog([])
    assert run(log)["inserted"] == 0
    assert not log.calls and store.state["pending"] is None


def test_time_budget_keeps_pending_checkpoint(store, monkeypatch):
    ticks = iter([0, 241])
    monkeypatch.setattr(collector.time, "monotonic", lambda: next(ticks))
    with pytest.raises(DNSCollectionIncomplete, match="time budget"):
        run(QueryLog([]))
    assert store.state["completed_until"] is None


def test_replay_key_normalizes_equivalent_timestamp_formats():
    first = event("2026-10-21T11:59:00.123456789Z")
    equivalent = replace(first, raw_timestamp="2026-10-21T14:59:00.123456789+03:00")
    assert replay_keys([first]) == replay_keys([equivalent])
    assert replay_keys([first, first])[0] != replay_keys([first, first])[1]


def test_backwards_clock_does_not_resume_a_future_pending_window(store):
    original = {
        "version": 1,
        "completed_until": None,
        "pending": {
            "upper": "2026-10-22T12:00:00Z",
            "lower": "2026-10-01T00:00:00Z",
            "cursor": "2026-10-22T11:00:00Z",
        },
    }
    store.state = copy.deepcopy(original)
    log = QueryLog([])
    with pytest.raises(DNSCollectionError, match="clock moved backwards"):
        run(log)
    assert store.state == original and not log.calls and store.calls == 0


@pytest.fixture
def exclusions(store, monkeypatch):
    loader = Mock(
        return_value=[{"client_ip": "192.0.2.1", "exclude_from_collection": True}]
    )
    monkeypatch.setattr(collector, "get_active_client_filters", loader)
    return loader


def test_excludes_only_collection_flag_and_loads_rules_once(store, exclusions):
    exclusions.return_value.append(
        {
            "client_ip": "192.0.2.2",
            "exclude_from_collection": False,
            "hide_from_query_log": True,
        }
    )
    records = [event(), replace(event(), client_ip="192.0.2.2")]
    log = QueryLog(records)
    result = run(log, page_size=1)
    assert result["inserted"] == 1 and result["excluded"] == 1
    assert result["fetched"] == 2
    assert [row.client_ip for row in store.rows.values()] == ["192.0.2.2"]
    exclusions.assert_called_once()
    assert exclusions.call_args.args[1] == 7


@pytest.mark.parametrize("value", ["2001:db8::1", "2001:0DB8:0:0:0:0:0:1"])
def test_ipv6_exclusion_normalizes_event_client_for_lookup(store, exclusions, value):
    exclusions.return_value = [
        {"client_ip": "2001:db8::1", "exclude_from_collection": True}
    ]
    result = run(QueryLog([replace(event(), client_ip=value)]))
    assert result["excluded"] == 1 and result["inserted"] == 0
    assert store.state["pending"] is None


@pytest.mark.parametrize("value", [None, "", "unknown", "192.0.2.0/24", "fe80::1%eth0"])
def test_untrusted_or_missing_client_never_matches_fallback_ip(
    store, exclusions, value
):
    exclusions.return_value = [
        {"client_ip": "0.0.0.0", "exclude_from_collection": True}
    ]
    result = run(QueryLog([replace(event(), client_ip=value)]))
    assert result["excluded"] == 0 and result["inserted"] == 1


def test_all_excluded_timestamp_ties_page_and_complete_with_no_rows(store, exclusions):
    records = [event()] * 5 + [event("2026-10-21T11:58:00Z")]
    log = QueryLog(records)
    result = run(log, page_size=2)
    assert result["inserted"] == 0 and result["excluded"] == 6
    assert result["fetched"] == 6
    assert store.state["completed_until"] == "2026-10-21T11:59:30.000000+00:00"
    assert store.state["pending"] is None and not store.rows
    assert len(log.calls) < 10
    result = run(QueryLog(records), page_size=2, now=NOW + timedelta(minutes=5))
    assert result["inserted"] == 0 and store.state["pending"] is None
    assert store.state["completed_until"] == "2026-10-21T12:04:30.000000+00:00"


def test_excluded_groups_preserve_safe_cursor_across_budget_restart(store, exclusions):
    records = [event(f"2026-10-21T11:5{minute}:00Z") for minute in (9, 8, 7)]
    with pytest.raises(DNSCollectionIncomplete):
        run(QueryLog(records), page_size=2, settings=CollectorConfig(max_pages=1))
    assert store.state["completed_until"] is None
    assert store.state["pending"]["cursor"] == records[0].raw_timestamp
    assert not store.rows
    log = QueryLog(records)
    result = run(log, page_size=2)
    assert result["excluded"] == 2 and result["inserted"] == 0
    assert log.calls[0] == (records[0].raw_timestamp, 0)
    assert store.state["pending"] is None


def test_filter_read_failure_leaves_api_and_checkpoint_untouched(store, exclusions):
    exclusions.side_effect = DNSStorageError("DNS database operation failed.")
    log = QueryLog([event()])
    with pytest.raises(DNSStorageError):
        run(log)
    assert not log.calls and store.state is None and store.calls == 0


def test_failed_all_excluded_checkpoint_is_not_advanced(store, exclusions, monkeypatch):
    def fail_group(connection, source_id, events, *, state=None, dedup_keys=None):
        if dedup_keys is not None:
            raise DNSStorageError("DNS database operation failed.")
        return store.save(
            connection, source_id, events, state=state, dedup_keys=dedup_keys
        )

    monkeypatch.setattr(collector, "save_events", fail_group)
    log = QueryLog([event()])
    with pytest.raises(DNSStorageError):
        run(log)
    assert store.state["completed_until"] is None
    assert store.state["pending"]["cursor"] == store.state["pending"]["upper"]
    assert not store.rows
    monkeypatch.setattr(collector, "save_events", store.save)
    assert run(QueryLog(log.events))["excluded"] == 1
    assert store.state["pending"] is None


def test_disabling_exclusion_keeps_existing_checkpoint_and_bounded_overlap(
    store, exclusions
):
    old = event("2026-10-21T11:00:00Z")
    recent = event()
    assert run(QueryLog([old, recent]))["excluded"] == 2
    exclusions.return_value = []
    new = event("2026-10-21T12:04:00Z")
    result = run(QueryLog([old, recent, new]), now=NOW + timedelta(minutes=5))
    assert result["excluded"] == 0 and result["inserted"] == 2
    assert old not in store.rows.values()
    assert recent in store.rows.values() and new in store.rows.values()
    assert store.state["pending"] is None


def test_filter_snapshot_is_used_for_whole_run(store, exclusions):
    class ChangingRulesLog(QueryLog):
        def fetch_page(self, **kwargs):
            exclusions.return_value = []
            return super().fetch_page(**kwargs)

    result = run(ChangingRulesLog([event()] * 4), page_size=1)
    assert result["excluded"] == 4 and not store.rows
    exclusions.assert_called_once()


def test_replay_keys_remain_stable_after_partial_filtered_group(store, exclusions):
    records = [event()] * 1000 + [replace(event(), client_ip="192.0.2.2")] * 1001
    # Initial state, excluded first chunk, 1000 kept rows, final kept row fails.
    store.failure_at = 4
    with pytest.raises(RuntimeError):
        run(QueryLog(records), page_size=1000)
    assert len(store.rows) == 1000
    assert store.state["pending"]["cursor"] == store.state["pending"]["upper"]
    store.failure_at = None
    result = run(QueryLog(records), page_size=1000)
    assert result["inserted"] == 1 and result["excluded"] == 1000
    assert len(store.rows) == 1001 and store.state["pending"] is None


def test_replay_keeps_multiplicity_when_exclusion_changes_between_runs(
    store, exclusions
):
    items = [event()] * 3 + [replace(event(), client_ip="192.0.2.2")] * 3
    assert run(QueryLog(items), page_size=2)["inserted"] == 3
    exclusions.return_value = []
    assert (
        run(QueryLog(items), page_size=2, now=NOW + timedelta(minutes=5))["inserted"]
        == 3
    )
    assert len(store.rows) == 6
    assert (
        run(QueryLog(items), page_size=2, now=NOW + timedelta(minutes=10))["inserted"]
        == 0
    )


def test_empty_filtered_final_chunk_commits_checkpoint_after_replay(store, exclusions):
    records = [replace(event(), client_ip="192.0.2.2")] + [event()] * 1000
    store.failure_at = 3
    with pytest.raises(RuntimeError):
        run(QueryLog(records), page_size=1000)
    assert len(store.rows) == 1
    assert store.state["pending"]["cursor"] == store.state["pending"]["upper"]
    store.failure_at = None
    result = run(QueryLog(records), page_size=1000)
    assert result["inserted"] == 0 and result["excluded"] == 1000
    assert len(store.rows) == 1 and store.state["pending"] is None


@pytest.fixture
def domain_exclusions(store, monkeypatch):
    loader = Mock(return_value=[{"domain": "scs.samsungqbe.com"}])
    monkeypatch.setattr(collector, "get_active_domain_filters", loader)
    return loader


@pytest.mark.parametrize("domain", ["scs.samsungqbe.com", "SCS.SamsungQBE.COM."])
def test_exact_domain_exclusion_applies_after_normalization(
    store, domain_exclusions, domain
):
    result = run(QueryLog([replace(event(), domain=domain)]))
    assert result["inserted"] == 0 and result["excluded"] == 1
    assert store.state["pending"] is None
    domain_exclusions.assert_called_once()
    assert domain_exclusions.call_args.args[1] == 7


@pytest.mark.parametrize(
    "domain",
    [
        "sub.scs.samsungqbe.com",
        "otherscs.samsungqbe.com",
        "samsungqbe.com",
        "scs.samsungqbe.com.evil.example",
        "example.org",
        "unknown domain",
        "https://scs.samsungqbe.com",
        "K.example",
    ],
)
def test_domain_rule_does_not_match_other_names_or_untrusted_values(
    store, domain_exclusions, domain
):
    result = run(QueryLog([replace(event(), domain=domain)]))
    assert result["excluded"] == 0 and result["inserted"] == 1


def test_ip_and_domain_exclusion_count_event_only_once(
    store, exclusions, domain_exclusions
):
    result = run(QueryLog([replace(event(), domain="scs.samsungqbe.com")]))
    assert result["excluded"] == 1 and not store.rows


def test_domain_only_rule_preserves_other_queries_from_same_client(
    store, domain_exclusions
):
    skipped = replace(event(), domain="scs.samsungqbe.com")
    allowed = replace(event(), domain="example.org")
    result = run(QueryLog([skipped, allowed]), page_size=1)
    assert result["inserted"] == 1 and result["excluded"] == 1
    assert list(store.rows.values()) == [allowed]


def test_all_domain_excluded_pages_resume_and_advance_checkpoint(
    store, domain_exclusions
):
    records = [
        replace(event(f"2026-10-21T11:5{minute}:00Z"), domain="scs.samsungqbe.com")
        for minute in (9, 8, 7)
    ]
    with pytest.raises(DNSCollectionIncomplete):
        run(QueryLog(records), page_size=2, settings=CollectorConfig(max_pages=1))
    assert store.state["pending"]["cursor"] == records[0].raw_timestamp
    assert not store.rows
    log = QueryLog(records)
    result = run(log, page_size=2)
    assert result["inserted"] == 0 and result["excluded"] == 2
    assert log.calls[0] == (records[0].raw_timestamp, 0)
    assert store.state["pending"] is None


def test_domain_rule_read_failure_leaves_checkpoint_and_api_untouched(
    store, domain_exclusions
):
    domain_exclusions.side_effect = DNSStorageError("DNS database operation failed.")
    log = QueryLog([event()])
    with pytest.raises(DNSStorageError):
        run(log)
    assert not log.calls and store.state is None and store.calls == 0


def test_disabling_domain_rule_restores_new_queries_without_history_reset(
    store, domain_exclusions
):
    records = [
        replace(event(stamp), domain="scs.samsungqbe.com")
        for stamp in ("2026-10-21T11:00:00Z", "2026-10-21T11:59:00Z")
    ]
    assert run(QueryLog(records))["excluded"] == 2
    domain_exclusions.return_value = []
    new = replace(event("2026-10-21T12:04:00Z"), domain="scs.samsungqbe.com")
    result = run(QueryLog(records + [new]), now=NOW + timedelta(minutes=5))
    assert result["inserted"] == 2
    assert records[0] not in store.rows.values()


def test_domain_filtered_group_replays_after_partial_commit(store, domain_exclusions):
    records = [replace(event(), domain="scs.samsungqbe.com")] * 1000 + [event()] * 1001
    store.failure_at = 4
    with pytest.raises(RuntimeError):
        run(QueryLog(records), page_size=1000)
    assert len(store.rows) == 1000
    assert store.state["pending"]["cursor"] == store.state["pending"]["upper"]
    store.failure_at = None
    result = run(QueryLog(records), page_size=1000)
    assert result["inserted"] == 1 and result["excluded"] == 1000
    assert len(store.rows) == 1001 and store.state["pending"] is None
