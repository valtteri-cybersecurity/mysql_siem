"""Only old DNS rule counts are mutable; event and upgrade proofs stay strict."""

import pytest

from database.migrate import (
    DNS_CONFIGURATION_TABLES,
    MigrationError,
    requires_monotonic_history_count,
)
from database.ufw_history import check_counts


@pytest.mark.parametrize('table', ['dns_client_filters', 'dns_domain_filters'])
@pytest.mark.parametrize('count', [0, 1, 5])
def test_old_dns_rule_counts_may_decrease(table, count):
    assert table in DNS_CONFIGURATION_TABLES
    assert not requires_monotonic_history_count(table, across_upgrades=True)
    check_counts(None, {table: 5}, {table: count})


@pytest.mark.parametrize('table', ['dns_client_filters', 'dns_domain_filters'])
def test_active_migration_still_requires_dns_rules_to_survive(table):
    assert requires_monotonic_history_count(table)
    with pytest.raises(MigrationError, match='Historical row counts decreased'):
        check_counts(None, {table: 5}, {table: 4}, across_upgrades=False)


@pytest.mark.parametrize('table', ['dns_client_filters', 'dns_domain_filters'])
def test_missing_dns_configuration_table_is_not_a_rule_deletion(table):
    with pytest.raises(MigrationError, match='DNS configuration table disappeared'):
        check_counts(None, {table: 0}, {})


@pytest.mark.parametrize('value', [-1, None, True, 1.5])
@pytest.mark.parametrize('table', ['dns_client_filters', 'dns_domain_filters'])
def test_invalid_dns_rule_counts_are_rejected(table, value):
    with pytest.raises(MigrationError, match='counts are invalid'):
        check_counts(None, {table: value}, {table: 0})


@pytest.mark.parametrize('table', ['dns_events', 'dns_sources', 'dns_collection_state',
                                 'ufw_log', 'auth_events', 'detection_alerts', 'alert_evidence'])
def test_unproven_event_or_checkpoint_loss_is_still_rejected(table):
    assert requires_monotonic_history_count(table, across_upgrades=True)
    with pytest.raises(MigrationError, match='Historical row counts decreased'):
        check_counts(None, {table: 5}, {table: 4})
