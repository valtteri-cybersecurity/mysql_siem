import os
import ssl
from datetime import datetime

import pymysql


def get_connection(*, require_tls=False):
    """Shared connection; existing no-argument calls remain supported.

    Remote hosts always require verified TLS. Local loopback remains compatible
    with the existing installer unless a CA or require_tls is supplied.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    connection = None
    try:
        required = {
            key: os.environ[key]
            for key in ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
        }
        if not all(required.values()):
            raise ValueError("Missing database configuration.")
        settings = {}
        for key, default in (
            ("DB_PORT", 3306),
            ("DB_CONNECT_TIMEOUT", 5),
            ("DB_READ_TIMEOUT", 30),
            ("DB_WRITE_TIMEOUT", 30),
        ):
            value = int(os.getenv(key, str(default)))
            maximum = 65535 if key == "DB_PORT" else 300
            if not 1 <= value <= maximum:
                raise ValueError("Invalid database numeric setting.")
            settings[key.removeprefix("DB_").lower()] = value
        ca_file = os.getenv("DB_SSL_CA") or None
        tls_required = bool(
            require_tls
            or ca_file
            or required["DB_HOST"] not in {"localhost", "127.0.0.1", "::1"}
        )
        if tls_required and pymysql.VERSION[:2] < (1, 2):
            # Older drivers can authenticate without TLS when the server omits
            # TLS support. Fail before sending any credentials in that case.
            raise ValueError("Verified database TLS requires PyMySQL 1.2 or newer.")
        if tls_required:
            settings["ssl"] = ssl.create_default_context(cafile=ca_file)
        connection = pymysql.connect(
            host=required["DB_HOST"],
            user=required["DB_USER"],
            password=required["DB_PASSWORD"],
            database=required["DB_NAME"],
            charset="utf8mb4",
            autocommit=False,
            **settings,
        )
        if tls_required:
            # PyMySQL may connect without TLS if the server lacks TLS support.
            # Refuse that connection before allowing application queries.
            with connection.cursor() as cursor:
                cursor.execute("SHOW STATUS LIKE %s", ("Ssl_cipher",))
                cipher = cursor.fetchone()
            if cipher is None or not cipher[1]:
                raise ssl.SSLError("The database did not negotiate TLS.")
        print(f"{timestamp}:   Database connection successful!")
        return connection
    except (pymysql.MySQLError, OSError, ValueError, KeyError):
        if connection is not None:
            connection.close()
        # Driver errors can contain usernames, host details or SQL payloads.
        print(f"{timestamp}:   Database connection or configuration failed.")
        return None
