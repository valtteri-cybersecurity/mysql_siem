import os
import ssl
from unittest.mock import MagicMock

import pymysql
import pytest

from database.connection import get_connection


@pytest.fixture
def connect(monkeypatch):
    for key in os.environ:
        if key.startswith("DB_"):
            monkeypatch.delenv(key)
    for key, value in {
        "DB_HOST": "localhost",
        "DB_USER": "test-user",
        "DB_PASSWORD": "secret-value",
        "DB_NAME": "mysql_siem",
    }.items():
        monkeypatch.setenv(key, value)
    connect = MagicMock()
    connect.return_value.cursor.return_value.__enter__.return_value.fetchone.return_value = (
        "Ssl_cipher",
        "TLS_AES_256_GCM_SHA384",
    )
    monkeypatch.setattr(pymysql, "connect", connect)
    return connect


def test_existing_no_argument_call_works(connect):
    assert get_connection() is connect.return_value
    kwargs = connect.call_args.kwargs
    assert kwargs["charset"] == "utf8mb4"
    assert kwargs["autocommit"] is False
    assert kwargs["init_command"] == "SET time_zone = '+00:00'"
    assert (
        kwargs["connect_timeout"],
        kwargs["read_timeout"],
        kwargs["write_timeout"],
    ) == (5, 30, 30)
    assert "ssl" not in kwargs


def test_remote_database_uses_verified_tls(connect, monkeypatch):
    monkeypatch.setenv("DB_HOST", "mysql.example.net")
    assert get_connection() is connect.return_value
    context = connect.call_args.kwargs["ssl"]
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_tls_can_be_required_for_local_database(connect):
    assert get_connection(require_tls=True) is connect.return_value
    assert connect.call_args.kwargs["ssl"].check_hostname is True


def test_tls_downgrade_rejected(connect, monkeypatch, capsys):
    monkeypatch.setenv("DB_HOST", "mysql.example.net")
    cursor = connect.return_value.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = ("Ssl_cipher", "")
    assert get_connection() is None
    connect.return_value.close.assert_called_once()
    assert "secret-value" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "setting,value",
    [
        ("DB_PORT", "0"),
        ("DB_PORT", "65536"),
        ("DB_CONNECT_TIMEOUT", "0"),
        ("DB_READ_TIMEOUT", "-1"),
        ("DB_WRITE_TIMEOUT", "301"),
        ("DB_READ_TIMEOUT", "secret-value"),
        ("DB_HOST", ""),
    ],
)
def test_invalid_settings_do_not_connect(connect, monkeypatch, capsys, setting, value):
    monkeypatch.setenv(setting, value)
    assert get_connection() is None
    connect.assert_not_called()
    assert "secret-value" not in capsys.readouterr().out


def test_missing_settings_do_not_connect(connect, monkeypatch):
    monkeypatch.delenv("DB_NAME")
    assert get_connection() is None
    connect.assert_not_called()


def test_connection_errors_hide_credentials(connect, capsys):
    connect.side_effect = pymysql.OperationalError("secret-value")
    assert get_connection() is None
    assert "secret-value" not in capsys.readouterr().out


def test_ca_file_is_explicit(connect, monkeypatch):
    context = ssl.create_default_context()
    create = MagicMock(return_value=context)
    monkeypatch.setattr(ssl, "create_default_context", create)
    monkeypatch.setenv("DB_SSL_CA", "relative-ca.pem")
    assert get_connection() is connect.return_value
    create.assert_called_once_with(cafile="relative-ca.pem")


def test_old_driver_is_rejected_before_remote_authentication(connect, monkeypatch):
    monkeypatch.setattr(pymysql, "VERSION", (1, 1, 2, "final"))
    monkeypatch.setenv("DB_HOST", "mysql.example.net")
    assert get_connection() is None
    connect.assert_not_called()


def test_old_driver_keeps_local_api_compatibility(connect, monkeypatch):
    monkeypatch.setattr(pymysql, "VERSION", (1, 0, 2, None))
    assert get_connection() is connect.return_value
