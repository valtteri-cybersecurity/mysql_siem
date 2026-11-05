"""DNS rule maintenance on a private database, with strict current upgrade proofs."""

import pytest

from config import installation_backup as backup
from config import installation_health as health
from config import reset_installation as reset
from database import migrate
from ingestion.dns.client_filters import add_client_filter, delete_client_filter
from ingestion.dns.db import purge_events, register_source
from ingestion.dns.domain_filters import add_domain_filter, delete_domain_filter


def test_dns_rule_deletion_allows_upgrade_but_preservation_stays_strict(empty_mysql, monkeypatch, tmp_path):
    connection = empty_mysql
    versions = []
    for migration in migrate.MIGRATIONS:
        if migration[0] <= '016':
            versions.append(migration)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(versions))
        migrate.migrate(connection)
    source = register_source(connection, 'dns-rule-test', 'adguard', 'https://dns.example.test')
    removed_client = add_client_filter(connection, source, '192.0.2.1')
    retained_client = add_client_filter(connection, source, '192.0.2.2')
    removed_domain = add_domain_filter(connection, source, 'old.example.test')
    add_domain_filter(connection, source, 'kept.example.test')
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO dns_events '
                       '(source_id,event_time,raw_timestamp,client_ip,domain,query_type,filtering_result) '
                       "VALUES (%s,'2026-01-01','2026-01-01T00:00:00Z','192.0.2.1','example.test','A','allowed')",
                       (source,))
    connection.commit()
    versions = []
    for migration in migrate.MIGRATIONS:
        if migration[0] <= '026':
            versions.append(migration)
    with monkeypatch.context() as old:
        old.setattr(migrate, 'MIGRATIONS', tuple(versions))
        migrate.migrate(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM schema_migrations WHERE version<='026' ORDER BY version")
        original_ledger = cursor.fetchall()
    assert delete_client_filter(connection, source, removed_client)
    assert delete_domain_filter(connection, source, removed_domain)
    reset.check_ufw_before_upgrade(connection)

    # Old rule counts may shrink, but losing a rule during active DDL must fail.
    original_apply = migrate.apply_one
    def remove_during_migration(connection, version):
        original_apply(connection, version)
        if version == '027':
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM dns_client_filters WHERE id=%s', (retained_client,))
    with monkeypatch.context() as interrupted:
        interrupted.setattr(migrate, 'apply_one', remove_during_migration)
        with pytest.raises(migrate.MigrationError, match='Historical row counts decreased'):
            migrate.migrate(connection)
    assert migrate.migration_status(connection)['027'][1] == 'FAILED'
    assert migrate.migrate(connection) == ['027', '028']
    assert migrate.migrate(connection) == []
    health.verify_schema(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM schema_migrations WHERE version<='026' ORDER BY version")
        assert cursor.fetchall() == original_ledger

    # The current backup preserves every remaining rule, even with matching counts.
    tables = backup.snapshot_rows(connection, tmp_path)
    for table in ('dns_client_filters', 'dns_domain_filters'):
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM ' + table)
        with pytest.raises(backup.BackupError, match='rows are missing'):
            backup.verify_rows(connection, tmp_path, tables)
        connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE dns_domain_filters SET domain='changed.example.test'")
    with pytest.raises(backup.BackupError, match='values changed'):
        backup.verify_rows(connection, tmp_path, tables)
    connection.rollback()
    backup.verify_rows(connection, tmp_path, tables, exact=True)

    # The old retention API has no deletion proof: it must not bypass event safety.
    assert purge_events(connection, retention_days=1) == 1
    with pytest.raises(reset.ResetError, match='Historical row counts decreased: dns_events'):
        reset.check_ufw_before_upgrade(connection)
