from datetime import datetime, timezone

import pymysql

from database.identity import configured_identity, identity_schema_enabled


def save_metrics_db(connection, data):
    observed_at = data["date"]
    if not isinstance(observed_at, datetime) or observed_at.utcoffset() is None:
        raise ValueError("Security measurement time must include a timezone.")
    observed_at = observed_at.astimezone(timezone.utc).replace(microsecond=0)
    timestamp = observed_at.strftime("%Y-%m-%d %H:%M:%S")
    cursor = None

    try:
        identity_schema_enabled(connection)
        cursor = connection.cursor()
        identity = configured_identity(cursor, "security")

        sql_message = """
        INSERT INTO security_metrics
            (uptime, blocks, failed_logins, unique_ips, date)
        VALUES
            (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            uptime = VALUES(uptime),
            blocks = VALUES(blocks),
            failed_logins = VALUES(failed_logins),
            unique_ips = VALUES(unique_ips);
        """

        values = (
            data["uptime"],
            data["blocks"],
            data["failed_logins"],
            data["unique_ips"],
            observed_at.replace(tzinfo=None)
        )
        if identity is not None:
            sql_message = """INSERT INTO security_metrics
                (uptime, blocks, failed_logins, unique_ips, date,
                 host_id, source_id, collector_id, sender_id, host_scope)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE uptime = VALUES(uptime), blocks = VALUES(blocks),
                    failed_logins = VALUES(failed_logins), unique_ips = VALUES(unique_ips),
                    source_id = VALUES(source_id), collector_id = VALUES(collector_id),
                    sender_id = VALUES(sender_id)"""
            values += identity.values() + (identity.host_id,)
        cursor.execute(sql_message, values)

        connection.commit()

        print(
            f"{timestamp}:   "
            "Security-metrics successfully written to the database!"
        )

    except pymysql.MySQLError:
        print(f"{timestamp}:   Security metric database operation failed.")

        if connection:
            connection.rollback()

    finally:
        if cursor:
            cursor.close()
