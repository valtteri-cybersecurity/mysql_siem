"""DNS storage primitives. No HTTP, pagination or collection activation."""

import json
import re
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

import pymysql

from ingestion.dns.models import DNSEvent


class DNSStorageError(RuntimeError):
    """Safe-to-log database failure without SQL payloads or credentials."""


@contextmanager
def transaction(connection):
    """Public operations own their transaction; use a dedicated connection."""
    cursor = None
    try:
        connection.begin()
        cursor = connection.cursor()
        yield cursor
        connection.commit()
    except pymysql.MySQLError:
        try:
            connection.rollback()
        finally:
            raise DNSStorageError("DNS database operation failed.") from None
    except Exception:
        connection.rollback()
        raise
    finally:
        if cursor is not None:
            cursor.close()


def validate_id(source_id):
    if type(source_id) is not int or not 1 <= source_id < 2**64:
        raise ValueError("Invalid DNS source ID.")


def validate_text(value, length, *, optional=False):
    if value is None and optional:
        return
    if (
        not isinstance(value, str)
        or not value
        or len(value) > length
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("Invalid DNS text field.")


def utc_datetime(value):
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("DNS times must be timezone-aware datetimes.")
    value = value.astimezone(timezone.utc).replace(tzinfo=None)
    if value.year < 1000:
        raise ValueError("DNS time is outside the MySQL DATETIME range.")
    return value


def register_source(connection, source_name, source_type, base_url, *, enabled=False):
    """Register explicitly; existing source identity and enabled flag stay intact."""
    if not isinstance(source_name, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,64}", source_name
    ):
        raise ValueError("Invalid DNS source name.")
    if not isinstance(source_type, str) or not re.fullmatch(
        r"[a-z0-9_-]{1,32}", source_type
    ):
        raise ValueError("Invalid DNS source type.")
    validate_text(base_url, 2048)
    try:
        url = urlsplit(base_url)
        port = url.port
    except ValueError:
        raise ValueError("Invalid DNS source URL.") from None
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or any(char.isspace() for char in base_url)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("DNS source URL must be HTTPS without credentials or filters.")
    if not isinstance(enabled, bool):
        raise TypeError("DNS enabled flag must be boolean.")
    base_url = base_url.rstrip("/")

    with transaction(connection) as cursor:
        cursor.execute(
            """
            INSERT INTO dns_sources (source_name, source_type, base_url, enabled)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)
            """,
            (source_name, source_type, base_url, enabled),
        )
        cursor.execute(
            "SELECT id, source_type, base_url FROM dns_sources WHERE source_name = %s",
            (source_name,),
        )
        row = cursor.fetchone()
        if row is None or row[1:] != (source_type, base_url):
            raise DNSStorageError("DNS source name is already bound to another server.")
        source_id = row[0]
    return source_id


def event_values(source_id, event):
    if not isinstance(event, DNSEvent):
        raise TypeError("Expected normalized DNSEvent objects.")
    for value, length, optional in (
        (event.source_name, 64, False),
        (event.raw_timestamp, 64, False),
        (event.client_ip, 45, True),
        (event.domain, 1024, False),
        (event.query_type, 32, False),
        (event.response_code, 64, True),
        (event.filtering_result, 32, False),
        (event.filtering_reason, 128, True),
        (event.upstream, 2048, True),
    ):
        validate_text(value, length, optional=optional)
    if event.cached is not None and not isinstance(event.cached, bool):
        raise ValueError("DNS cache flag must be boolean or None.")
    elapsed = event.elapsed_ms
    if elapsed is not None:
        if (
            not isinstance(elapsed, Decimal)
            or not elapsed.is_finite()
            or not 0 <= elapsed <= Decimal("99999999999.999999999")
        ):
            raise ValueError("DNS duration is outside the storage range.")
        try:
            if elapsed != elapsed.quantize(Decimal("0.000000001")):
                raise ValueError("DNS duration exceeds storage precision.")
        except InvalidOperation:
            raise ValueError("Invalid DNS duration.") from None
    return (
        source_id,
        utc_datetime(event.event_time),
        event.raw_timestamp,
        event.client_ip,
        event.domain,
        event.query_type,
        event.response_code,
        event.filtering_result,
        event.filtering_reason,
        event.upstream,
        event.elapsed_ms,
        event.cached,
    )


def save_events(connection, source_id, events, *, state=None, dedup_keys=None):
    """Commit one bounded batch and optional state together.

    With optional collector replay keys, skip only explicitly matching keys.

    The caller decides when state is safe to advance. This method does not infer
    completion from a page's `oldest` value. No INSERT IGNORE or silent truncation.
    """
    validate_id(source_id)
    if not isinstance(events, (list, tuple)) or len(events) > 1000:
        raise ValueError("DNS batch must contain at most 1000 normalized events.")
    values = [event_values(source_id, event) for event in events]
    if dedup_keys is not None:
        if len(dedup_keys) != len(events) or any(
            type(key) is not bytes or len(key) != 32 for key in dedup_keys
        ):
            raise ValueError(
                "DNS replay keys must be 32-byte values matching the batch."
            )
        values = [row + (key,) for row, key in zip(values, dedup_keys)]
    state_json = None
    if state is not None:
        if not isinstance(state, dict):
            raise ValueError("DNS collection state must be an object.")
        try:
            state_json = json.dumps(state, allow_nan=False, sort_keys=True)
        except (TypeError, ValueError, RecursionError):
            raise ValueError("DNS collection state must be valid JSON.") from None
        if len(state_json.encode("utf-8")) > 65536:
            raise ValueError("DNS collection state exceeds 64 KiB.")

    with transaction(connection) as cursor:
        cursor.execute(
            "SELECT source_name, enabled FROM dns_sources WHERE id = %s FOR UPDATE",
            (source_id,),
        )
        source = cursor.fetchone()
        if source is None or not source[1]:
            raise DNSStorageError("DNS source is missing or disabled.")
        if any(event.source_name != source[0] for event in events):
            raise ValueError("DNS events do not match the registered source.")
        if values and dedup_keys is not None:
            # PyMySQL safely expands sequence parameters, including binary keys.
            cursor.execute(
                "SELECT dedup_key FROM dns_events WHERE source_id = %s AND dedup_key IN %s",
                (source_id, tuple(dedup_keys)),
            )
            seen = {row[0] for row in cursor.fetchall()}
            fresh = []
            for row in values:
                if row[-1] not in seen:
                    fresh.append(row)
                    seen.add(row[-1])
            values = fresh
        if values:
            if dedup_keys is None:
                sql = """
                    INSERT INTO dns_events (
                        source_id, event_time, raw_timestamp, client_ip, domain,
                        query_type, response_code, filtering_result, filtering_reason,
                        upstream, elapsed_ms, cached
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
            else:
                sql = """
                    INSERT INTO dns_events (
                        source_id, event_time, raw_timestamp, client_ip, domain,
                        query_type, response_code, filtering_result, filtering_reason,
                        upstream, elapsed_ms, cached, dedup_key
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
            cursor.executemany(sql, values)
        inserted = cursor.rowcount if values else 0
        if state_json is not None:
            now = utc_datetime(datetime.now(timezone.utc))
            cursor.execute(
                """
                INSERT INTO dns_collection_state (source_id, state_data, updated_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE state_data = %s, updated_at = %s
                """,
                (
                    source_id,
                    state_json,
                    now,
                    state_json,
                    now,
                ),
            )
    return inserted


def load_state(connection, source_id):
    validate_id(source_id)
    with transaction(connection) as cursor:
        cursor.execute(
            "SELECT state_data FROM dns_collection_state WHERE source_id = %s",
            (source_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        try:
            state = json.loads(row[0])
        except (TypeError, ValueError, RecursionError):
            raise DNSStorageError("Stored DNS collection state is invalid.") from None
        if not isinstance(state, dict):
            raise DNSStorageError("Stored DNS collection state must be an object.")
    return state


def purge_events(
    connection, *, retention_days=30, batch_size=1000, now=None, source_id=None
):
    """Explicit maintenance operation: delete at most one batch, never on import."""
    if type(retention_days) is not int or not 1 <= retention_days <= 36500:
        raise ValueError("Invalid DNS retention period.")
    if type(batch_size) is not int or not 1 <= batch_size <= 10000:
        raise ValueError("Invalid DNS purge batch size.")
    cutoff = utc_datetime(now if now is not None else datetime.now(timezone.utc))
    cutoff -= timedelta(days=retention_days)
    if source_id is not None:
        validate_id(source_id)
    with transaction(connection) as cursor:
        if source_id is None:
            cursor.execute(
                "DELETE FROM dns_events WHERE event_time < %s ORDER BY event_time LIMIT %s",
                (cutoff, batch_size),
            )
        else:
            cursor.execute(
                "DELETE FROM dns_events WHERE source_id = %s AND event_time < %s ORDER BY event_time LIMIT %s",
                (source_id, cutoff, batch_size),
            )
        deleted = cursor.rowcount
    return deleted


class DNSCollectionBusy(DNSStorageError):
    """Another collector already owns this source's named lock."""


@contextmanager
def source_lock(connection, source_id):
    validate_id(source_id)
    name = f"mysql_siem_dns_{source_id}"
    with transaction(connection) as cursor:
        cursor.execute("SELECT GET_LOCK(%s, 0)", (name,))
        row = cursor.fetchone()
        if row is None or row[0] != 1:
            raise DNSCollectionBusy("DNS source is already being collected.")
    try:
        yield
    finally:
        with transaction(connection) as cursor:
            cursor.execute("SELECT RELEASE_LOCK(%s)", (name,))
            row = cursor.fetchone()
            if row is None or row[0] != 1:
                raise DNSStorageError("DNS source lock was lost.")


def find_source(connection, source_name, source_type, base_url):
    with transaction(connection) as cursor:
        cursor.execute(
            """
            SELECT id, source_type, base_url, enabled,
                EXISTS(SELECT 1 FROM dns_events WHERE source_id = dns_sources.id AND dedup_key IS NULL)
            FROM dns_sources WHERE source_name = %s
            """,
            (source_name,),
        )
        row = cursor.fetchone()
        if row is None or not row[3]:
            raise DNSStorageError(
                "DNS source must be registered and explicitly enabled."
            )
        if row[1:3] != (source_type, base_url.rstrip("/")):
            raise DNSStorageError(
                "DNS source configuration differs from its registration."
            )
        if row[4]:
            raise DNSStorageError(
                "DNS source has legacy rows without replay keys; manual baseline required."
            )
    return row[0]
