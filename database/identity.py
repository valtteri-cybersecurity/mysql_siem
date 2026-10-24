"""Explicit registry bindings shared by collectors, analyses and detections.

Registry writes belong to an administrator. Runtime collectors only read approved
bindings. No function in this module identifies a machine by its hostname or IP.
The caller owns the transaction unless a function explicitly says otherwise.
"""

import os
from dataclasses import dataclass

from ingestion.ip_addresses import canonical_ip


class IdentityError(ValueError):
    """A missing, disabled or inconsistent identity binding."""


def identity_schema_enabled(connection):
    """Read the migration ledger once per dedicated runtime connection.

    A pre-phase-2 database can still serve legacy jobs. An interrupted upgrade
    fails closed: jobs must wait until the administrator completes migration.
    Reconnect after upgrading; migrate() also invalidates its own connection.
    """
    cached = connection.__dict__.get("_siem_identity_ready")
    if cached is not None:
        return cached
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM information_schema.tables "
                       "WHERE table_schema = DATABASE() AND table_name = 'schema_migrations'")
        if cursor.fetchone() != (1,):
            # information_schema hides tables without privileges. Never let a
            # missing ledger grant turn registered events into legacy groups.
            cursor.execute("SELECT COUNT(*) FROM information_schema.columns "
                           "WHERE table_schema = DATABASE() AND column_name = 'host_id'")
            row = cursor.fetchone()
            if row is not None and type(row[0]) is int and row[0] > 0:
                raise IdentityError("Host columns exist but the migration ledger is not visible; check SELECT permissions.")
            connection._siem_identity_ready = False
            return False
        cursor.execute("SELECT status FROM schema_migrations WHERE version = '016'")
        if cursor.fetchone() != ("APPLIED",):
            raise IdentityError("Identity migration is incomplete; keep runtime jobs stopped.")
    connection._siem_identity_ready = True
    return True


def validate_id(value):
    if type(value) is not int or not 1 <= value < 2**64:
        raise IdentityError("Identity IDs must be positive unsigned BIGINT values.")
    return value


def validate_text(value, *, maximum=255, optional=False):
    if value is None and optional:
        return value
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise IdentityError("Invalid registry text value.")
    return value


@dataclass(frozen=True)
class EventIdentity:
    host_id: int
    source_id: int
    collector_id: int
    sender_id: int | None = None

    def __post_init__(self):
        for value in (self.host_id, self.source_id, self.collector_id):
            validate_id(value)
        if self.sender_id is not None:
            validate_id(self.sender_id)

    def values(self):
        return self.host_id, self.source_id, self.collector_id, self.sender_id


def register_host(cursor, administrative_name, *, reported_hostname=None, current_ip=None,
                  os_name=None, os_version=None):
    """Always allocate a new ID, even when another machine has the same name."""
    validate_text(administrative_name)
    for value in (reported_hostname, os_name, os_version):
        validate_text(value, optional=True)
    if current_ip is not None:
        current_ip = canonical_ip(current_ip)
    cursor.execute(
        """INSERT INTO hosts
           (administrative_name, reported_hostname, current_ip, os_name, os_version)
           VALUES (%s, %s, %s, %s, %s)""",
        (administrative_name, reported_hostname, current_ip, os_name, os_version),
    )
    return cursor.lastrowid


def update_host(cursor, host_id, *, reported_hostname, current_ip):
    validate_id(host_id)
    validate_text(reported_hostname, optional=True)
    if current_ip is not None:
        current_ip = canonical_ip(current_ip)
    cursor.execute("UPDATE hosts SET reported_hostname = %s, current_ip = %s WHERE host_id = %s",
                   (reported_hostname, current_ip, host_id))


SOURCE_TYPES = {"ufw", "auth", "dns", "system", "filesystem", "security"}


def register_source(cursor, host_id, source_name, source_type, *, enabled=False):
    """Create a new source for an existing host; never reuse an unrelated ID."""
    validate_id(host_id)
    validate_text(source_name, maximum=128)
    if not isinstance(source_type, str) or source_type not in SOURCE_TYPES or type(enabled) is not bool:
        raise IdentityError("Invalid source type or enabled flag.")
    cursor.execute("INSERT INTO log_sources (host_id, source_name, source_type, enabled) VALUES (%s, %s, %s, %s)",
                   (host_id, source_name, source_type, enabled))
    return cursor.lastrowid


def register_collector(cursor, collector_name, *, enabled=False):
    validate_text(collector_name, maximum=128)
    if type(enabled) is not bool:
        raise IdentityError("The collector enabled flag must be boolean.")
    cursor.execute("INSERT INTO collectors (collector_name, enabled) VALUES (%s, %s)", (collector_name, enabled))
    return cursor.lastrowid


def approve_collector_source(cursor, collector_id, source_id):
    """Explicit administrator action; runtime accounts only SELECT this table."""
    validate_id(collector_id)
    validate_id(source_id)
    cursor.execute("""INSERT INTO collector_sources (collector_id, source_id, enabled)
        VALUES (%s, %s, TRUE) ON DUPLICATE KEY UPDATE enabled = TRUE""", (collector_id, source_id))


def resolve_identity(cursor, source_id, collector_id, *, source_type, sender_id=None):
    """Resolve an approved source, never any field supplied inside a log line.

    A future authenticated transport may pass sender_id only after verifying its
    peer. This API validates the enrolled sender/source relation; it does not
    authenticate network traffic or validate a certificate chain.
    """
    validate_id(source_id)
    validate_id(collector_id)
    validate_text(source_type, maximum=32)
    cursor.execute(
        """SELECT s.host_id FROM log_sources s
           JOIN hosts h ON h.host_id = s.host_id
           JOIN collector_sources cs ON cs.source_id = s.source_id
           JOIN collectors c ON c.collector_id = cs.collector_id
           WHERE s.source_id = %s AND c.collector_id = %s AND s.source_type = %s
             AND s.enabled = TRUE AND cs.enabled = TRUE AND c.enabled = TRUE
             AND h.enrollment_status = 'ACTIVE' FOR SHARE""",
        (source_id, collector_id, source_type),
    )
    row = cursor.fetchone()
    if row is None:
        raise IdentityError("Source/collector binding is missing, disabled or not enrolled.")
    if sender_id is not None:
        validate_id(sender_id)
        cursor.execute(
            """SELECT sender_id FROM sender_identities
               WHERE sender_id = %s AND host_id = %s AND enabled = TRUE
                 AND EXISTS (SELECT 1 FROM sender_sources
                             WHERE sender_id = %s AND source_id = %s) FOR SHARE""",
            (sender_id, row[0], sender_id, source_id),
        )
        if cursor.fetchone() is None:
            raise IdentityError("Authenticated sender is not approved for this host/source.")
    return EventIdentity(row[0], source_id, collector_id, sender_id)


def configured_identity(cursor, source_type):
    """Missing configuration keeps legacy data explicitly unassigned.

    A partial or invalid configuration fails before advancing any checkpoint.
    The DNS integration supplies its own registered binding separately.
    """
    source = os.getenv(f"SIEM_{source_type.upper()}_SOURCE_ID")
    collector = os.getenv("SIEM_COLLECTOR_ID")
    if source is None:
        if source_type != 'dns' and os.getenv('SIEM_LOCAL_IDENTITY_REQUIRED') == '1':
            raise IdentityError('A required local source identity is missing.')
        return None
    if collector is None:
        raise IdentityError("SIEM_COLLECTOR_ID is required with a configured source.")
    try:
        source_id, collector_id = int(source), int(collector)
    except ValueError:
        raise IdentityError("Collector/source configuration must contain numeric IDs.") from None
    return resolve_identity(cursor, source_id, collector_id, source_type=source_type)


def event_scope(event):
    """Separate registered machines, unassigned sources and legacy observations.

    The legacy hostname bucket is only an analytical bucket, never a trusted host
    identity. Old raw rows and historical alerts remain unassigned.
    """
    host_id = event.get("host_id")
    if host_id is not None:
        validate_id(host_id)
        return "host", host_id
    source_id = event.get("source_id")
    if source_id is not None:
        validate_id(source_id)
        return "source", source_id
    return "legacy", event.get("hostname") or ""
