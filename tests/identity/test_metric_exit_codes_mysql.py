"""Actual metric writes and trigger failures on the private MySQL fixture."""

import importlib
from datetime import datetime, timezone

import pymysql
import pytest

from database.schema import ensure_tables


@pytest.mark.parametrize('kind,table', [
    ('system', 'system_metrics'),
    ('security', 'security_metrics'),
    ('filesystem', 'filesystem_metrics'),
])
def test_metric_exit_code_and_preservation_on_real_sql_failure(empty_mysql, identity_server, monkeypatch, capsys, kind, table):
    ensure_tables(empty_mysql, (table,))
    with empty_mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        name = cursor.fetchone()[0]
    empty_mysql.commit()
    def connect():
        return pymysql.connect(unix_socket=identity_server, database=name, user='root',
                               charset='utf8mb4', autocommit=False, read_timeout=30, write_timeout=30,
                               init_command="SET time_zone='+00:00'")
    main = importlib.import_module('metrics.' + kind + '.main')
    writer_module = 'db'
    if kind == 'security':
        writer_module = 'database'
    writer = importlib.import_module('metrics.' + kind + '.' + writer_module)
    monkeypatch.setattr(writer, 'identity_schema_enabled', lambda connection: False)
    monkeypatch.setattr(writer, 'configured_identity', lambda cursor, source: None)
    if kind == 'filesystem':
        monkeypatch.setattr(writer, 'get_connection', connect)
        monkeypatch.setattr(main, 'get_all_files', lambda: 17)
        monkeypatch.setattr(main, 'get_modified_files', lambda: 3)
    else:
        monkeypatch.setattr(main, 'get_connection', connect)
        if kind == 'system':
            monkeypatch.setattr(main, 'get_data', lambda: tuple(range(10)))
        else:
            data = {'date': datetime(2026, 11, 5, tzinfo=timezone.utc),
                    'uptime': 1, 'blocks': 2, 'failed_logins': 3, 'unique_ips': 4}
            monkeypatch.setattr(main, 'get_data', lambda connection: data)
    assert main.main() == 0
    observer = connect()
    try:
        with observer.cursor() as cursor:
            cursor.execute('SELECT * FROM ' + table)
            original = cursor.fetchall()
            assert len(original) == 1
            cursor.execute('CREATE TRIGGER reject_metric BEFORE INSERT ON ' + table
                           + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='PRIVATE SQL FAILURE'")
        assert main.main() == 1
        observer.rollback()
        with observer.cursor() as cursor:
            cursor.execute('SELECT * FROM ' + table)
            assert cursor.fetchall() == original
        assert 'PRIVATE SQL FAILURE' not in capsys.readouterr().out
    finally:
        observer.close()
