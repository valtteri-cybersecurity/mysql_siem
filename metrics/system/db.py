from datetime import datetime

import pymysql

from database.connection import get_connection


def save_metrics_db(connection, data):
    cursor = None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor = connection.cursor()

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

        cursor.execute(sql, data)
        connection.commit()

        print(
            f"{timestamp}:   "
            "System-metrics successfully written to the database!"
        )

    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}")

        if connection:
            connection.rollback()

    finally:
        if cursor:
            cursor.close()
