"""All database operations below use a strict, read-only fake connection."""

import ast
from pathlib import Path
from unittest.mock import Mock

import pymysql
import pytest

from config import reset_installation as reset

USAGE = 'GRANT USAGE ON *.* TO `pythonuser`@`localhost`'
SETTINGS = {'DB_HOST': 'localhost', 'DB_USER': 'pythonuser',
            'DB_PASSWORD': 'synthetic-test-only', 'DB_NAME': 'mysql_siem'}


class ReadOnlyConnection:
    def __init__(self, grants=None, exists=True, roles=''):
        self.grants = [(USAGE,)] if grants is None else grants
        self.exists = exists
        self.roles = roles
        self.statements = []
        self.failure = None

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        assert sql.startswith(('SELECT ', 'SHOW ')), 'Unexpected database mutation'
        assert 'GET_LOCK' not in sql, 'Validation must fail before reset preparation'
        self.statements.append(sql)
        if self.failure is not None and sql.startswith(self.failure):
            raise pymysql.OperationalError(1142, 'synthetic private diagnostic')

    def fetchone(self):
        sql = self.statements[-1]
        if sql == 'SELECT VERSION()':
            return ('8.0.46',)
        if sql == 'SELECT @@GLOBAL.mandatory_roles':
            return (self.roles,)
        if 'mysql.user' in sql:
            return (int(self.exists),)
        if 'information_schema.schemata' in sql:
            return (1,)
        raise AssertionError('Unexpected query: ' + sql)

    def fetchall(self):
        assert self.statements[-1] == "SHOW GRANTS FOR 'pythonuser'@'localhost'"
        return self.grants

    def select_db(self, name):
        raise AssertionError('Rejected grants must stop before schema selection')


def attempt(connection, operation, monkeypatch):
    if operation == 'reset':
        prepare = Mock(side_effect=AssertionError('Unexpected identity reset preparation'))
        reset.reset_database(connection, SETTINGS, approved=True, prepare=prepare)
    else:
        history = Mock(side_effect=AssertionError('Unexpected upgrade history check'))
        monkeypatch.setattr(reset, 'check_ufw_before_upgrade', history)
        reset.check_upgrade_database(connection)


@pytest.mark.parametrize('table,privileges', reset.RUNTIME_TABLE_PRIVILEGES.items())
def test_approved_table_privileges_are_accepted(table, privileges):
    grant = f'GRANT {privileges} ON `mysql_siem`.`{table}` TO `pythonuser`@`localhost`'
    connection = ReadOnlyConnection([(USAGE,), (grant,)])
    reset.validate_account(connection, allow_missing=False)
    assert connection.statements[-1] == "SHOW GRANTS FOR 'pythonuser'@'localhost'"


def test_existing_account_with_usage_only_is_accepted():
    reset.validate_account(ReadOnlyConnection(), allow_missing=False)


def test_privilege_order_and_separate_grant_rows_do_not_change_meaning():
    connection = ReadOnlyConnection([
        (USAGE,),
        ('GRANT INSERT, SELECT ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost`',),
        ('GRANT UPDATE ON `mysql_siem`.`audit_checkpoints` TO `pythonuser`@`localhost`',),
    ])
    reset.validate_account(connection)


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
@pytest.mark.parametrize('grant', [
    'GRANT ALL PRIVILEGES ON `mysql_siem`.* TO `pythonuser`@`localhost`',
    'GRANT SELECT ON `mysql_siem`.* TO `pythonuser`@`localhost`',
    'GRANT ALL PRIVILEGES ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost`',
    'GRANT SELECT ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost` WITH GRANT OPTION',
    'GRANT USAGE ON *.* TO `pythonuser`@`localhost` WITH GRANT OPTION',
    'GRANT ALL PRIVILEGES ON *.* TO `pythonuser`@`localhost`',
    'GRANT SELECT ON *.* TO `pythonuser`@`localhost`',
    'GRANT FILE ON *.* TO `pythonuser`@`localhost`',
    'GRANT BACKUP_ADMIN ON *.* TO `pythonuser`@`localhost`',
    'GRANT `shared_role`@`%` TO `pythonuser`@`localhost`',
    'GRANT `role1`@`%`,`role2`@`localhost` TO `pythonuser`@`localhost`',
    'GRANT `shared_role`@`%` TO `pythonuser`@`localhost` WITH ADMIN OPTION',
    "GRANT PROXY ON ''@'' TO `pythonuser`@`localhost`",
    'GRANT CREATE ON `mysql_siem`.`ufw_log` TO `pythonuser`@`localhost`',
    'GRANT DELETE ON `mysql_siem`.`audit_events` TO `pythonuser`@`localhost`',
    'GRANT UPDATE ON `mysql_siem`.`process_events` TO `pythonuser`@`localhost`',
    'GRANT SELECT ON `other`.`ufw_log` TO `pythonuser`@`localhost`',
    'GRANT SELECT ON `mysql_siem`.`unknown_table` TO `pythonuser`@`localhost`',
    'GRANT SELECT ON `mysql_siem`.`hosts` TO `pythonuser`@`%`',
    'GRANT SELECT ON `mysql_siem`.`hosts` TO `other_user`@`localhost`',
    'REVOKE SELECT ON `mysql`.* FROM `pythonuser`@`localhost`',
    'GRANT SELECT ON `mysql_siem`.`hosts` TO `pythonuser`@`localhost`; extra text',
])
def test_unsafe_grants_stop_reset_and_upgrade_before_mutations(monkeypatch, operation, grant):
    connection = ReadOnlyConnection([(USAGE,), (grant,)])
    with pytest.raises(reset.ResetError, match='Unsafe runtime privileges'):
        attempt(connection, operation, monkeypatch)


READ_ONLY_TABLES = []
for table, privileges in reset.RUNTIME_TABLE_PRIVILEGES.items():
    if privileges == 'SELECT':
        READ_ONLY_TABLES.append(table)


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
@pytest.mark.parametrize('table', READ_ONLY_TABLES)
@pytest.mark.parametrize('privilege', ['INSERT', 'UPDATE', 'DELETE'])
def test_registry_identity_and_read_only_tables_reject_writes(monkeypatch, operation, table, privilege):
    grant = f'GRANT SELECT, {privilege} ON `mysql_siem`.`{table}` TO `pythonuser`@`localhost`'
    connection = ReadOnlyConnection([(grant,)])
    with pytest.raises(reset.ResetError, match='Unsafe runtime privileges'):
        attempt(connection, operation, monkeypatch)


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
@pytest.mark.parametrize('roles', ['`admin_role`@`%`', '`read_role`@`%`', None])
def test_mandatory_roles_or_unknown_role_state_stop_before_mutations(monkeypatch, operation, roles):
    connection = ReadOnlyConnection([(USAGE,)], roles=roles)
    with pytest.raises(reset.ResetError, match='mandatory roles or unknown role state'):
        attempt(connection, operation, monkeypatch)
    assert "SHOW GRANTS FOR 'pythonuser'@'localhost'" not in connection.statements


def test_missing_account_is_only_allowed_for_new_reset_setup():
    connection = ReadOnlyConnection(exists=False)
    reset.validate_account(connection)
    assert "SHOW GRANTS FOR 'pythonuser'@'localhost'" not in connection.statements
    with pytest.raises(reset.ResetError, match='missing'):
        reset.validate_account(connection, allow_missing=False)


def test_upgrade_with_missing_account_stops_before_schema_work(monkeypatch):
    with pytest.raises(reset.ResetError, match='missing'):
        attempt(ReadOnlyConnection(exists=False), 'upgrade', monkeypatch)


def test_missing_account_still_checks_implicit_mandatory_roles():
    with pytest.raises(reset.ResetError, match='mandatory roles'):
        reset.validate_account(ReadOnlyConnection(exists=False, roles='`admin_role`@`%`'))


@pytest.mark.parametrize('operation', ['reset', 'upgrade'])
@pytest.mark.parametrize('query', ['SHOW GRANTS', 'SELECT @@GLOBAL.mandatory_roles', 'SELECT COUNT(*) FROM mysql.user'])
def test_failed_privilege_queries_fail_closed_without_exposing_diagnostics(monkeypatch, operation, query):
    connection = ReadOnlyConnection([(USAGE,)])
    connection.failure = query
    with pytest.raises(reset.ResetError, match='Cannot verify pythonuser privileges') as error:
        attempt(connection, operation, monkeypatch)
    assert 'private diagnostic' not in str(error.value)
    assert SETTINGS['DB_PASSWORD'] not in str(error.value)


@pytest.mark.parametrize('rows', [[], [(None,)], [('incomplete',)], [('two', 'columns')]])
def test_empty_or_malformed_grants_never_authorize_reset(rows):
    with pytest.raises(reset.ResetError):
        reset.validate_account(ReadOnlyConnection(rows))


def test_every_literal_installer_grant_fits_the_same_table_policy():
    installer = (Path(__file__).resolve().parents[2] / 'install.sh').read_text()
    block = installer.split('# Grant privileges only after the tables have been created.', 1)[1]
    block = block.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    checked = set()
    for node in ast.walk(ast.parse(block)):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(value, ast.Constant):
                    grant = f'GRANT {value.value} ON `mysql_siem`.`{key.value}` TO `pythonuser`@`localhost`'
                    reset.validate_runtime_grants([(grant,)])
                    checked.add(key.value)
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
            for item in node.iter.elts:
                assert isinstance(item, ast.Constant)
                assert reset.RUNTIME_TABLE_PRIVILEGES[item.value] == 'SELECT'
                checked.add(item.value)
    assert {'ufw_log', 'audit_events', 'dns_sources', 'auth_events', 'detection_rules'} <= checked
    assert 'WITH GRANT OPTION' not in block
    assert 'REVOKE ' not in block
