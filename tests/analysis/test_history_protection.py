"""Historical interval guards must run before destructive analysis writes."""
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from analysis.ufw import ports, source_ips
from database import ufw_analysis_history
from database.migrate import MigrationError


@pytest.mark.parametrize('writer', [ports.run_port_analysis, source_ips.run_source_ip_analysis])
def test_protected_interval_rolls_back_before_any_write(monkeypatch, writer):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(1,), None, (1,)]
    monkeypatch.setattr(ufw_analysis_history, 'marked', lambda connection, table: True)
    start = datetime(2026, 1, 1)
    with pytest.raises(MigrationError, match='migration 027'):
        writer(connection, start, start + timedelta(hours=1))
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once()
    for call in cursor.execute.call_args_list:
        assert call.args[0].startswith('SELECT')
    cursor.executemany.assert_not_called()


def test_marker_without_migration_baseline_is_not_trusted(monkeypatch):
    from database.migrate import MigrationError
    monkeypatch.setattr(ufw_analysis_history, 'marked', lambda connection, table: True)
    with pytest.raises(MigrationError, match='no recorded baseline'):
        ufw_analysis_history.capture(MagicMock())
