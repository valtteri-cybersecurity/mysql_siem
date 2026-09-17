from datetime import datetime

import pymysql


def save_metrics_db(connection, data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = None

    try:
        cursor = connection.cursor()

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

        cursor.execute(sql_message, (
            data["uptime"],
            data["blocks"],
            data["failed_logins"],
            data["unique_ips"],
            data["date"]
        ))

        connection.commit()

        print(
            f"{timestamp}:   "
            "Security-metrics successfully written to the database!"
        )

    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}")

        if connection:
            connection.rollback()

    finally:
        if cursor:
            cursor.close()
