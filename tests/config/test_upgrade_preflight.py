"""The upgrade preflight must preserve ambiguous UFW history."""

import json
from unittest.mock import MagicMock

import pytest

from config import reset_installation as setup
from database import migrate


@pytest.mark.parametrize('state', [None, 'RUNNING', 'FAILED'])
@pytest.mark.parametrize('history_table', [None, 'ufw_log', 'analysis_ufw_traffic',
                                          'detection_state', 'alert_evidence'])
def test_preflight_allows_isolatable_raw_history_but_blocks_unsafe_dependencies(monkeypatch, state, history_table):
    connection = MagicMock()
    ledger = {}
    if state is not None:
        ledger['017'] = ('checksum', state)
    counts = {}
    if history_table is not None:
        counts[history_table] = 1
    monkeypatch.setattr(migrate, 'migration_status', lambda _: ledger)
    monkeypatch.setattr(migrate, 'history_counts', lambda _: dict(counts))
    cursor = connection.cursor.return_value.__enter__.return_value
    query = ['']
    def execute(sql, args=None):
        query[0] = sql
    def fetchone():
        if 'row_counts' in query[0]:
            saved = {}
            for table in ('ufw_log',) + migrate.ANALYSIS_TABLES + ('detection_state', 'detection_alerts', 'alert_evidence'):
                saved[table] = 0
            return (json.dumps(saved),)
        if history_table == 'alert_evidence':
            return (1,)
        return (0,)
    cursor.execute.side_effect = execute
    cursor.fetchone.side_effect = fetchone
    cursor.fetchall.return_value = []
    if history_table == 'detection_state':
        cursor.fetchall.return_value = [(None,)]
    if history_table in (None, 'ufw_log'):
        setup.check_ufw_before_upgrade(connection)
    else:
        with pytest.raises(setup.ResetError, match='history|evidence'):
            setup.check_ufw_before_upgrade(connection)
    for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list:
        assert call.args[0].startswith('SELECT')
    connection.commit.assert_not_called()


@pytest.mark.parametrize('state', ['RUNNING', 'FAILED'])
def test_saved_history_is_not_lost_when_current_table_is_empty(monkeypatch, state):
    connection = MagicMock()
    monkeypatch.setattr(migrate, 'migration_status', lambda _: {'017': ('checksum', state)})
    monkeypatch.setattr(migrate, 'history_counts', lambda _: {})
    saved = json.dumps({'ufw_log': 12})
    connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (saved,)
    with pytest.raises(setup.ResetError, match='counts decreased'):
        setup.check_ufw_before_upgrade(connection)


@pytest.mark.parametrize('saved', [None, '[]', 'null', '{broken',
                                  '{"ufw_log": true}', '{"ufw_log": -1}',
                                  '{"ufw_log": "12"}'])
def test_invalid_interrupted_ledger_stops_upgrade(monkeypatch, saved):
    connection = MagicMock()
    monkeypatch.setattr(migrate, 'migration_status', lambda _: {'017': ('checksum', 'FAILED')})
    monkeypatch.setattr(migrate, 'history_counts', lambda _: {})
    row = None
    if saved is not None:
        row = (saved,)
    connection.cursor.return_value.__enter__.return_value.fetchone.return_value = row
    with pytest.raises(setup.ResetError, match='ledger is missing|counts are invalid'):
        setup.check_ufw_before_upgrade(connection)


def test_unknown_migration_state_stops_before_history_queries(monkeypatch):
    connection = MagicMock()
    monkeypatch.setattr(migrate, 'migration_status', lambda _: {'017': ('checksum', 'UNKNOWN')})
    history = MagicMock()
    monkeypatch.setattr(migrate, 'history_counts', history)
    with pytest.raises(setup.ResetError, match='Unknown UFW'):
        setup.check_ufw_before_upgrade(connection)
    history.assert_not_called()
