"""Resumable, additive phase-2 DDL, with explicit index replacements.

All SQL identifiers below are repository constants, never CLI/log input. MySQL
commits each ALTER separately. Introspection makes an interrupted run resumable.
Old IDs, timestamps, hashes, checkpoints and payloads are never rewritten.
"""

EVENT_TABLES = ("ufw_log", "auth_events", "system_metrics", "filesystem_metrics", "security_metrics")
ANALYSIS_TABLES = ("analysis_source_ips", "analysis_ufw_ports", "analysis_ufw_traffic", "analysis_ufw_traffic_daily")


def columns(cursor, table):
    cursor.execute("SELECT column_name FROM information_schema.columns "
                   "WHERE table_schema = DATABASE() AND table_name = %s", (table,))
    return {row[0] for row in cursor.fetchall()}


def add_column(cursor, table, name, definition):
    if name not in columns(cursor, table):
        cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN `{name}` {definition}")


def add_constraint(cursor, table, name, definition):
    cursor.execute("SELECT constraint_name FROM information_schema.table_constraints "
                   "WHERE table_schema = DATABASE() AND table_name = %s AND constraint_name = %s", (table, name))
    if cursor.fetchone() is None:
        cursor.execute(f"ALTER TABLE `{table}` ADD CONSTRAINT `{name}` {definition}")


def replace_key(cursor, table, name, fields, *, unique=True):
    cursor.execute("SELECT column_name FROM information_schema.statistics "
                   "WHERE table_schema = DATABASE() AND table_name = %s AND index_name = %s "
                   "ORDER BY seq_in_index", (table, name))
    current = tuple(row[0] for row in cursor.fetchall())
    if current == fields:
        return
    if name == "PRIMARY":
        drop = "DROP PRIMARY KEY, " if current else ""
        create = "ADD PRIMARY KEY"
    else:
        drop = f"DROP INDEX `{name}`, " if current else ""
        kind = "UNIQUE " if unique else ""
        create = f"ADD {kind}KEY `{name}`"
    field_sql = ", ".join(f"`{field}`" for field in fields)
    # DROP/ADD within one atomic ALTER never leaves a table without its key.
    cursor.execute(f"ALTER TABLE `{table}` {drop}{create} ({field_sql})")


def add_host(cursor, table):
    add_column(cursor, table, "host_id", "BIGINT UNSIGNED NULL")
    add_constraint(cursor, table, f"fk_{table}_host", "FOREIGN KEY (host_id) REFERENCES hosts (host_id)")


def event_identity(connection):
    with connection.cursor() as cursor:
        for table in EVENT_TABLES:
            add_host(cursor, table)
            for name in ("source_id", "collector_id", "sender_id"):
                add_column(cursor, table, name, "BIGINT UNSIGNED NULL")
            add_constraint(cursor, table, f"fk_{table}_source_host",
                           "FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id)")
            add_constraint(cursor, table, f"fk_{table}_collector_source",
                           "FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id)")
            add_constraint(cursor, table, f"fk_{table}_sender_host",
                           "FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id)")
            add_constraint(cursor, table, f"chk_{table}_identity",
                           "CHECK ((host_id IS NULL AND source_id IS NULL AND collector_id IS NULL AND sender_id IS NULL) "
                           "OR (host_id IS NOT NULL AND source_id IS NOT NULL AND collector_id IS NOT NULL))")
        add_column(cursor, "ufw_log", "reported_hostname", "VARCHAR(255) NULL")
        for table in ANALYSIS_TABLES + ("detection_alerts",):
            add_host(cursor, table)
        # DNS's existing source_id keeps its meaning and numeric values.
        add_column(cursor, "dns_sources", "registry_source_id", "BIGINT UNSIGNED NULL")
        add_constraint(cursor, "dns_sources", "fk_dns_registry_source",
                       "FOREIGN KEY (registry_source_id) REFERENCES log_sources (source_id)")
        for name in ("host_id", "registry_source_id", "collector_id"):
            add_column(cursor, "dns_events", name, "BIGINT UNSIGNED NULL")
        add_constraint(cursor, "dns_events", "fk_dns_event_host", "FOREIGN KEY (host_id) REFERENCES hosts (host_id)")
        add_constraint(cursor, "dns_events", "fk_dns_event_source_host",
                       "FOREIGN KEY (registry_source_id, host_id) REFERENCES log_sources (source_id, host_id)")
        add_constraint(cursor, "dns_events", "fk_dns_event_collector_source",
                       "FOREIGN KEY (collector_id, registry_source_id) REFERENCES collector_sources (collector_id, source_id)")
        add_constraint(cursor, "dns_events", "chk_dns_server_identity",
                       "CHECK ((host_id IS NULL AND registry_source_id IS NULL AND collector_id IS NULL) "
                       "OR (host_id IS NOT NULL AND registry_source_id IS NOT NULL AND collector_id IS NOT NULL))")
        # A client IP remains an observation; no backfill or automatic mapping.
        add_column(cursor, "dns_events", "client_host_id", "BIGINT UNSIGNED NULL")
        add_column(cursor, "dns_events", "client_sender_id", "BIGINT UNSIGNED NULL")
        add_constraint(cursor, "dns_events", "fk_dns_client_host", "FOREIGN KEY (client_host_id) REFERENCES hosts (host_id)")
        add_constraint(cursor, "dns_events", "fk_dns_client_sender_host",
                       "FOREIGN KEY (client_sender_id, client_host_id) REFERENCES sender_identities (sender_id, host_id)")
        add_constraint(cursor, "dns_events", "chk_dns_client_identity",
                       "CHECK ((client_host_id IS NULL AND client_sender_id IS NULL) "
                       "OR (client_host_id IS NOT NULL AND client_sender_id IS NOT NULL))")


def scoped_keys(connection):
    scoped_tables = [
        ("ufw_log", "source_id"), ("auth_events", "source_id"),
        ("filesystem_metrics", "host_id"), ("security_metrics", "host_id"),
    ]
    for table in ANALYSIS_TABLES:
        scoped_tables.append((table, "host_id"))
    with connection.cursor() as cursor:
        for table, identity_column in scoped_tables:
            scope = "source_scope" if identity_column == "source_id" else "host_scope"
            add_column(cursor, table, scope, "BIGINT UNSIGNED NOT NULL DEFAULT 0")
            add_constraint(cursor, table, f"chk_{table}_scope", f"CHECK ({scope} = COALESCE({identity_column}, 0))")
        replace_key(cursor, "ufw_log", "uq_ufw_event_hash", ("source_scope", "event_hash"))
        replace_key(cursor, "auth_events", "uq_auth_event_hash", ("source_scope", "event_hash"))
        replace_key(cursor, "filesystem_metrics", "PRIMARY", ("metric_date", "host_scope"))
        replace_key(cursor, "security_metrics", "PRIMARY", ("date", "host_scope"))
        replace_key(cursor, "analysis_source_ips", "PRIMARY", ("period_start", "period_end", "source_ip", "host_scope"))
        replace_key(cursor, "analysis_ufw_ports", "uq_ufw_ports_period",
                    ("period_start", "period_end", "destination_ip", "destination_port", "protocol", "host_scope"))
        replace_key(cursor, "analysis_ufw_traffic", "uq_traffic_period", ("period_start", "period_end", "host_scope"))
        replace_key(cursor, "analysis_ufw_traffic_daily", "uq_traffic_period", ("analysis_date", "host_scope"))
        for table in ("ufw_state", "auth_ingestion_state"):
            add_column(cursor, table, "source_scope", "BIGINT UNSIGNED NOT NULL DEFAULT 0")
        replace_key(cursor, "ufw_state", "uq_ufw_state_file", ("file_device", "file_inode", "source_scope"))
        replace_key(cursor, "auth_ingestion_state", "PRIMARY", ("collector_id", "file_device", "file_inode", "source_scope"))
        for table, time_field in (("ufw_log", "event_time"), ("auth_events", "event_time"),
                                  ("system_metrics", "timestamp"), ("dns_events", "event_time")):
            replace_key(cursor, table, f"idx_{table}_host_time", ("host_id", time_field), unique=False)
