from datetime import datetime

import pymysql

from database.connection import get_connection


def save_metrics(modified_last_day, total_files):
    connection = get_connection()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if connection is None:
        return None

    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
            INSERT INTO filesystem_metrics
            (metric_date, modified_last_day, total_files)
            VALUES (CURDATE(), %s, %s)

            ON DUPLICATE KEY UPDATE
            modified_last_day = VALUES(modified_last_day),
            total_files = VALUES(total_files)
        """

        cursor.execute(sql, (modified_last_day, total_files))
        connection.commit()

        print(f"{timestamp}:   Data written successfully")

    except pymysql.DatabaseError as error:
        print(f"{timestamp}:   Error writing into database")
        print(f"{timestamp}:   {error}")
        connection.rollback()

    finally:
        if cursor:
            cursor.close()

        connection.close()
        print(f"{timestamp}:   Database connection closed")
