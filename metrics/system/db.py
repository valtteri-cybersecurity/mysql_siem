import os
import pymysql
from get import get_timestamp

def db_connect():
    timestamp = get_timestamp()
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )

        print(f"{timestamp}:   Connection to the database has been created successfully.")
        return connection

    except pymysql.MySQLError as error:
        print(f"{timestamp}:   Database error: {error}")
        return None


def save_metrics_db(connection, data):
    cursor = None
    timestamp = get_timestamp()

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

        print(f"{timestamp}:   System-metrics successfully written to the database!")
        print()
        
    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}")

        if connection:
            connection.rollback()

    finally:
        if cursor:
            cursor.close()
