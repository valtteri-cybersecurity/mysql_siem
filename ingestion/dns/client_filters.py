"""Manage source-scoped DNS client rules independently of collection and views."""

from ipaddress import ip_address

import pymysql

from ingestion.dns.db import DNSStorageError, transaction, validate_id, validate_text

FILTER_COLUMNS = (
    "id",
    "source_id",
    "client_ip",
    "description",
    "hide_from_query_log",
    "exclude_from_collection",
    "enabled",
    "created_at",
    "updated_at",
)


def normalize_client_ip(value):
    """Return one canonical address; reject networks, zones and non-string input.

    IPv4-mapped IPv6 remains IPv6, matching the existing AdGuard normalizer.
    Invalid event client values must never fall back to an address such as 0.0.0.0.
    """
    if not isinstance(value, str) or "%" in value:
        raise ValueError("A valid IPv4 or IPv6 client address is required.")
    try:
        return str(ip_address(value))
    except ValueError:
        raise ValueError("A valid IPv4 or IPv6 client address is required.") from None


def validate_boolean(value):
    if type(value) is not bool:
        raise ValueError("DNS client filter options must be booleans.")


def validate_description(value):
    if value != "":
        validate_text(value, 255)


def validate_filter_id(value):
    if type(value) is not int or not 1 <= value < 2**64:
        raise ValueError("Invalid DNS client filter ID.")


def add_client_filter(
    connection,
    source_id,
    client_ip,
    description="",
    *,
    hide_from_query_log=False,
    exclude_from_collection=False,
    enabled=True,
):
    """Insert one rule and return its ID; duplicates never overwrite an old rule."""
    validate_id(source_id)
    client_ip = normalize_client_ip(client_ip)
    validate_description(description)
    for value in (hide_from_query_log, exclude_from_collection, enabled):
        validate_boolean(value)
    with transaction(connection) as cursor:
        try:
            cursor.execute(
                """
                INSERT INTO dns_client_filters
                    (source_id, client_ip, description, hide_from_query_log,
                     exclude_from_collection, enabled)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    source_id,
                    client_ip,
                    description,
                    hide_from_query_log,
                    exclude_from_collection,
                    enabled,
                ),
            )
        except pymysql.IntegrityError as error:
            if error.args and error.args[0] == 1062:
                raise ValueError(
                    "A DNS client filter already exists for this source and IP."
                ) from None
            raise
        filter_id = cursor.lastrowid
    return filter_id


def list_client_filters(connection, source_id=None):
    """Return dictionaries for all sources, or only the specified source."""
    return _list_client_filters(connection, source_id, active_only=False)


def get_active_client_filters(connection, source_id):
    """Return enabled rules for exactly one source, including both option flags."""
    validate_id(source_id)
    return _list_client_filters(connection, source_id, active_only=True)


def _list_client_filters(connection, source_id, *, active_only):
    if source_id is not None:
        validate_id(source_id)
    sql = """
        SELECT id, source_id, client_ip, description, hide_from_query_log,
               exclude_from_collection, enabled, created_at, updated_at
        FROM dns_client_filters
        WHERE (%s IS NULL OR source_id = %s)
          AND (%s = FALSE OR enabled = TRUE)
        ORDER BY source_id, id
    """
    with transaction(connection) as cursor:
        cursor.execute(sql, (source_id, source_id, active_only))
        rules = []
        for row in cursor.fetchall():
            rule = dict(zip(FILTER_COLUMNS, row))
            try:
                rule["client_ip"] = normalize_client_ip(rule["client_ip"])
            except ValueError:
                raise DNSStorageError("Invalid stored DNS client filter IP.") from None
            for name in ("hide_from_query_log", "exclude_from_collection", "enabled"):
                if rule[name] not in (0, 1):
                    raise DNSStorageError("Invalid stored DNS client filter option.")
                rule[name] = bool(rule[name])
            rules.append(rule)
    return rules


def update_client_filter_options(
    connection,
    source_id,
    filter_id,
    *,
    hide_from_query_log=None,
    exclude_from_collection=None,
):
    """Update either or both options atomically; None leaves an option unchanged."""
    if hide_from_query_log is None and exclude_from_collection is None:
        raise ValueError("At least one DNS client filter option is required.")
    for value in (hide_from_query_log, exclude_from_collection):
        if value is not None:
            validate_boolean(value)
    return _update_client_filter(
        connection,
        source_id,
        filter_id,
        """
        UPDATE dns_client_filters
        SET hide_from_query_log = COALESCE(%s, hide_from_query_log),
            exclude_from_collection = COALESCE(%s, exclude_from_collection)
        WHERE source_id = %s AND id = %s
        """,
        (hide_from_query_log, exclude_from_collection),
    )


def update_client_filter_description(connection, source_id, filter_id, description):
    validate_description(description)
    return _update_client_filter(
        connection,
        source_id,
        filter_id,
        "UPDATE dns_client_filters SET description = %s WHERE source_id = %s AND id = %s",
        (description,),
    )


def enable_client_filter(connection, source_id, filter_id):
    return _set_client_filter_enabled(connection, source_id, filter_id, True)


def disable_client_filter(connection, source_id, filter_id):
    return _set_client_filter_enabled(connection, source_id, filter_id, False)


def _set_client_filter_enabled(connection, source_id, filter_id, enabled):
    return _update_client_filter(
        connection,
        source_id,
        filter_id,
        "UPDATE dns_client_filters SET enabled = %s WHERE source_id = %s AND id = %s",
        (enabled,),
    )


def _update_client_filter(connection, source_id, filter_id, sql, values):
    validate_id(source_id)
    validate_filter_id(filter_id)
    with transaction(connection) as cursor:
        cursor.execute(sql, values + (source_id, filter_id))
        changed = cursor.rowcount > 0
    return changed


def delete_client_filter(connection, source_id, filter_id):
    """Delete only a rule, never stored DNS events or collection state."""
    validate_id(source_id)
    validate_filter_id(filter_id)
    with transaction(connection) as cursor:
        cursor.execute(
            "DELETE FROM dns_client_filters WHERE source_id = %s AND id = %s",
            (source_id, filter_id),
        )
        deleted = cursor.rowcount > 0
    return deleted
