"""Exercise deployment schema verification with the installer runtime grants."""

from pathlib import Path

import pymysql

from config.installation_health import verify_schema


def test_deployment_schema_health_with_installer_grants(mysql, identity_server, monkeypatch):
    installer = Path(__file__).resolve().parents[2] / 'install.sh'
    grants = installer.read_text().split('# Grant privileges only after the tables have been created.', 1)[1]
    grants = grants.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    with mysql.cursor() as cursor:
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        cursor.execute("CREATE USER 'installation_health_test'@'localhost' IDENTIFIED BY 'private-test'")

    def connect_grants(**_kwargs):
        return connect('root')

    def connect(user, password=''):
        return real_connect(unix_socket=identity_server, user=user, password=password, database=database)

    real_connect = pymysql.connect
    try:
        with monkeypatch.context() as setup:
            setup.setenv('DB_NAME', database)
            setup.setenv('DB_USER', 'installation_health_test')
            setup.setattr(pymysql, 'connect', connect_grants)
            exec(grants, {})  # noqa: S102
        with connect('installation_health_test', 'private-test') as runtime:
            verify_schema(runtime)
    finally:
        with mysql.cursor() as cursor:
            cursor.execute("DROP USER 'installation_health_test'@'localhost'")
