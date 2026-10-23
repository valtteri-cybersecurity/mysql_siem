from datetime import datetime

import pymysql

from database.identity import configured_identity, identity_schema_enabled


def save_metrics_db(connection, data):
    cursor = None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        identity_schema_enabled(connection)
        cursor = connection.cursor()
        identity = configured_identity(cursor, "system")

        sql = """
            INSERT INTO system_metrics (
                uptime_hours,
                cpuload1,
                cpuload5,
                cpuload15,
                cpu_usage,
                cpu_temperature,
                ram_free_mb,
                disk_used,
                disk_free,
                disk_usage,
                timestamp
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """

        values = tuple(data)
        if identity is not None:
            sql = """INSERT INTO system_metrics (
                uptime_hours, cpuload1, cpuload5, cpuload15, cpu_usage,
                cpu_temperature, ram_free_mb, disk_used, disk_free, disk_usage,
                timestamp, host_id, source_id, collector_id, sender_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s)"""
            values += identity.values()
        cursor.execute(sql, values)
        connection.commit()

        print(
            f"{timestamp}:   "
            "System-metrics successfully written to the database!"
        )

    except pymysql.MySQLError:
        print(f"{timestamp}:   System metric database operation failed.")

        if connection:
            connection.rollback()

    finally:
        if cursor:
            cursor.close()
