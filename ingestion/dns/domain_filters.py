"""Manage exact-domain collection exclusions without changing the DNS server."""

import re

import pymysql

from ingestion.dns.db import DNSStorageError, transaction, validate_id, validate_text

DOMAIN_FILTER_COLUMNS = (
    "id",
    "source_id",
    "domain",
    "description",
    "enabled",
    "created_at",
    "updated_at",
)


def normalize_domain(value):
    """Canonical ASCII DNS name; no wildcards, URL syntax or implicit IDNA mapping.

    Underscores support service-query labels. IDNs must be supplied as ASCII
    A-labels (punycode); untrusted Unicode is never mapped to a different name.
    """
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("A valid ASCII DNS domain is required.")
    domain = value.lower().removesuffix(".")
    if not domain or len(domain) > 253:
        raise ValueError("Invalid DNS domain length.")
    for label in domain.split("."):
        if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label):
            raise ValueError("Invalid DNS domain label.")
    return domain


def add_domain_filter(connection, source_id, domain, description="", *, enabled=True):
    """Add one source-scoped exclusion and return its ID; never overwrite duplicates."""
    validate_id(source_id)
    domain = normalize_domain(domain)
    _validate_description(description)
    if type(enabled) is not bool:
        raise ValueError("DNS domain filter enabled must be a boolean.")
    with transaction(connection) as cursor:
        try:
            cursor.execute(
                """
                INSERT INTO dns_domain_filters (source_id, domain, description, enabled)
                VALUES (%s, %s, %s, %s)
                """,
                (source_id, domain, description, enabled),
            )
        except pymysql.IntegrityError as error:
            if error.args and error.args[0] == 1062:
                raise ValueError(
                    "A DNS domain filter already exists for this source and domain."
                ) from None
            raise
        filter_id = cursor.lastrowid
    return filter_id


def list_domain_filters(connection, source_id=None):
    return _list_domain_filters(connection, source_id, active_only=False)


def get_active_domain_filters(connection, source_id):
    validate_id(source_id)
    return _list_domain_filters(connection, source_id, active_only=True)


def _list_domain_filters(connection, source_id, *, active_only):
    if source_id is not None:
        validate_id(source_id)
    with transaction(connection) as cursor:
        cursor.execute(
            """
            SELECT id, source_id, domain, description, enabled, created_at, updated_at
            FROM dns_domain_filters
            WHERE (%s IS NULL OR source_id = %s)
              AND (%s = FALSE OR enabled = TRUE)
            ORDER BY source_id, id
            """,
            (source_id, source_id, active_only),
        )
        rules = []
        for row in cursor.fetchall():
            rule = dict(zip(DOMAIN_FILTER_COLUMNS, row))
            try:
                rule["domain"] = normalize_domain(rule["domain"])
            except ValueError:
                raise DNSStorageError("Invalid stored DNS domain filter.") from None
            if rule["enabled"] not in (0, 1):
                raise DNSStorageError("Invalid stored DNS domain filter option.")
            rule["enabled"] = bool(rule["enabled"])
            rules.append(rule)
    return rules


def update_domain_filter_description(connection, source_id, filter_id, description):
    _validate_description(description)
    return _update_domain_filter(
        connection,
        source_id,
        filter_id,
        "UPDATE dns_domain_filters SET description = %s WHERE source_id = %s AND id = %s",
        (description,),
    )


def enable_domain_filter(connection, source_id, filter_id):
    return _set_domain_filter_enabled(connection, source_id, filter_id, True)


def disable_domain_filter(connection, source_id, filter_id):
    return _set_domain_filter_enabled(connection, source_id, filter_id, False)


def _set_domain_filter_enabled(connection, source_id, filter_id, enabled):
    return _update_domain_filter(
        connection,
        source_id,
        filter_id,
        "UPDATE dns_domain_filters SET enabled = %s WHERE source_id = %s AND id = %s",
        (enabled,),
    )


def _update_domain_filter(connection, source_id, filter_id, sql, values):
    validate_id(source_id)
    _validate_filter_id(filter_id)
    with transaction(connection) as cursor:
        cursor.execute(sql, values + (source_id, filter_id))
        changed = cursor.rowcount > 0
    return changed


def delete_domain_filter(connection, source_id, filter_id):
    """Delete only the rule, never stored events or collection progress."""
    validate_id(source_id)
    _validate_filter_id(filter_id)
    with transaction(connection) as cursor:
        cursor.execute(
            "DELETE FROM dns_domain_filters WHERE source_id = %s AND id = %s",
            (source_id, filter_id),
        )
        changed = cursor.rowcount > 0
    return changed


def _validate_filter_id(value):
    if type(value) is not int or not 1 <= value < 2**64:
        raise ValueError("Invalid DNS domain filter ID.")


def _validate_description(value):
    if value != "":
        validate_text(value, 255)
