"""Bounded collection and replay handling, independent of any HTTP client."""

import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from ingestion.dns.db import load_state, save_events, source_lock
from ingestion.dns.timestamps import parse_timestamp, timestamp_ns


class DNSCollectionError(RuntimeError):
    """Safe-to-log collection or checkpoint failure."""


class DNSCollectionIncomplete(DNSCollectionError):
    """Budget exhausted: retain pending state and continue next scheduled run."""


def fingerprint(event):
    # All normalized analytical fields plus exact time. Not an API event ID.
    fields = (
        timestamp_ns(event.raw_timestamp),
        event.client_ip,
        event.domain,
        event.query_type,
        event.response_code,
        event.filtering_result,
        event.filtering_reason,
        event.upstream,
        str(event.elapsed_ms.normalize()) if event.elapsed_ms is not None else None,
        event.cached,
    )
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).digest()


def replay_keys(events):
    counts = Counter()
    result = []
    for event in events:
        digest = fingerprint(event)
        counts[digest] += 1
        result.append(
            hashlib.sha256(digest + counts[digest].to_bytes(8, "big")).digest()
        )
    return result


def validate_state(state):
    if state is None:
        return {"version": 1, "completed_until": None, "pending": None}
    if (
        not isinstance(state, dict)
        or type(state.get("version")) is not int
        or state["version"] != 1
        or set(state) != {"version", "completed_until", "pending"}
    ):
        raise DNSCollectionError("Unsupported DNS checkpoint; manual review required.")
    try:
        completed = state["completed_until"]
        if completed is not None:
            timestamp_ns(completed)
        pending = state["pending"]
        if pending is not None:
            if not isinstance(pending, dict) or set(pending) != {
                "upper",
                "lower",
                "cursor",
            }:
                raise ValueError
            lower, cursor, upper = (
                timestamp_ns(pending[key]) for key in ("lower", "cursor", "upper")
            )
            if not lower <= cursor <= upper:
                raise ValueError
            if completed is not None and timestamp_ns(completed) > upper:
                raise ValueError
    except (ValueError, TypeError, KeyError):
        raise DNSCollectionError(
            "Invalid DNS checkpoint; manual review required."
        ) from None
    return state


def save_group(connection, source_id, events, state, deadline):
    keys = replay_keys(events)
    inserted = 0
    for start in range(0, len(events), 1000):
        if time.monotonic() >= deadline:
            raise DNSCollectionIncomplete(
                "DNS run time budget reached; recovery remains pending."
            )
        end = start + 1000
        inserted += save_events(
            connection,
            source_id,
            events[start:end],
            dedup_keys=keys[start:end],
            state=state if end >= len(events) else None,
        )
    return inserted


def collect(adapter, connection, source_id, settings, *, page_size=1000, now=None):
    """Resume from a complete timestamp group; never persist an unstable offset.

    Request a fixed older_than fence plus increasing offsets within this run.
    A group spanning page boundaries is closed only by an older event or EOF.
    On restart, a partial group is read from the beginning with the same keys.
    """
    if type(page_size) is not int or not 1 <= page_size <= 1000:
        raise ValueError("Invalid DNS page size.")
    now = now if now is not None else datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("DNS collection time must be timezone-aware.")
    now = now.astimezone(timezone.utc)
    deadline = time.monotonic() + settings.max_seconds
    with source_lock(connection, source_id):
        state = validate_state(load_state(connection, source_id))
        retention_start = now - timedelta(days=settings.retention_days)
        if (
            state["completed_until"] is not None
            and parse_timestamp(state["completed_until"]) < retention_start
        ):
            raise DNSCollectionError(
                "DNS checkpoint exceeds retention; manual recovery required."
            )
        if (
            state["pending"] is not None
            and parse_timestamp(state["pending"]["upper"]) > now
        ):
            raise DNSCollectionError(
                "DNS clock moved backwards; pending checkpoint unchanged."
            )
        if state["pending"] is None:
            upper = now - timedelta(seconds=settings.settle_seconds)
            lower = retention_start
            if state["completed_until"] is not None:
                completed = parse_timestamp(state["completed_until"])
                if completed > upper:
                    raise DNSCollectionError(
                        "DNS clock moved backwards; checkpoint unchanged."
                    )
                lower = max(
                    lower, completed - timedelta(seconds=settings.overlap_seconds)
                )
            state["pending"] = {
                "upper": upper.isoformat(timespec="microseconds"),
                "lower": lower.isoformat(timespec="microseconds"),
                "cursor": upper.isoformat(timespec="microseconds"),
            }
            save_events(connection, source_id, [], state=state)

        pending = state["pending"]
        anchor = pending["cursor"]
        anchor_ns, lower_ns = timestamp_ns(anchor), timestamp_ns(pending["lower"])
        offset = inserted = pages = 0
        group = []
        group_time = None
        previous = None
        finished = False
        if anchor_ns == lower_ns:
            finished = True
        for _ in range(settings.max_pages if not finished else 0):
            if time.monotonic() >= deadline:
                raise DNSCollectionIncomplete(
                    "DNS run time budget reached; recovery remains pending."
                )
            page = adapter.fetch_page(
                limit=page_size,
                older_than=anchor,
                offset=offset,
                deadline=deadline,
            )
            pages += 1
            ready = []
            if not page.events:
                if page.oldest is not None:
                    raise DNSCollectionError(
                        "Ambiguous empty DNS page; checkpoint not completed."
                    )
                ready = group
                group = []
                finished = True
            else:
                # A short page is not EOF; the API can limit disk scans.
                for event in page.events:
                    current = timestamp_ns(event.raw_timestamp)
                    if current >= anchor_ns or (
                        previous is not None and current > previous
                    ):
                        # Already committed keys make restarting this fence safe.
                        pending["cursor"] = pending["upper"]
                        save_events(connection, source_id, [], state=state)
                        raise DNSCollectionError(
                            "DNS pages changed order or fence; next run restarts the window."
                        )
                    previous = current
                    if group and current != group_time:
                        ready.extend(group)
                        group = []
                    if current < lower_ns:
                        finished = True
                        break
                    group_time = current
                    group.append(event)
                    if len(group) > settings.max_group_events:
                        raise DNSCollectionError(
                            "DNS timestamp group exceeds limit; manual review required."
                        )
            if ready:
                pending["cursor"] = ready[-1].raw_timestamp
                inserted += save_group(connection, source_id, ready, state, deadline)
            if finished:
                break
            # Re-anchor after complete groups, keeping offsets bounded to the
            # open timestamp group instead of eventually exceeding disk scan caps.
            anchor = pending["cursor"]
            anchor_ns = timestamp_ns(anchor)
            offset = len(group)
        if not finished:
            raise DNSCollectionIncomplete(
                "DNS page budget reached; recovery remains pending."
            )
        completed_state = {
            "version": 1,
            "completed_until": pending["upper"],
            "pending": None,
        }
        save_events(connection, source_id, [], state=completed_state)
        return {"inserted": inserted, "pages": pages}
