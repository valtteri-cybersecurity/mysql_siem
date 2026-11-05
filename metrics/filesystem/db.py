from datetime import datetime

from database.connection import get_connection
from database.identity import configured_identity, identity_schema_enabled


def save_metrics(modified_last_day, total_files):
    connection = get_connection()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if connection is None:
        raise ValueError("Database connection failed.")

    cursor = None

    try:
        identity_schema_enabled(connection)
        cursor = connection.cursor()
        identity = configured_identity(cursor, "filesystem")

        sql = """
            INSERT INTO filesystem_metrics
            (metric_date, modified_last_day, total_files)
            VALUES (CURDATE(), %s, %s)

            ON DUPLICATE KEY UPDATE
            modified_last_day = VALUES(modified_last_day),
            total_files = VALUES(total_files)
        """

        values = (modified_last_day, total_files)
        if identity is not None:
            sql = """INSERT INTO filesystem_metrics
                (metric_date, modified_last_day, total_files, host_id, source_id,
                 collector_id, sender_id, host_scope)
                VALUES (CURDATE(), %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE modified_last_day = VALUES(modified_last_day),
                    total_files = VALUES(total_files), source_id = VALUES(source_id),
                    collector_id = VALUES(collector_id), sender_id = VALUES(sender_id)"""
            values += identity.values() + (identity.host_id,)
        cursor.execute(sql, values)
        connection.commit()

        print(f"{timestamp}:   Data written successfully")

    except BaseException:
        connection.rollback()
        raise

    finally:
        try:
            if cursor:
                cursor.close()
        finally:
            connection.close()
        print(f"{timestamp}:   Database connection closed")
