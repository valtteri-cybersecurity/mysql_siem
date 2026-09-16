import pymysql
from get_data import get_timestamp

def db_connect():
    timestamp = get_timestamp()
    try:
        connection = pymysql.connect(
            host='localhost',
            user='pythonuser',
            password='NeekerinViimeinenMatka666',
            database='homesystem'
        )
        print(f"{timestamp}:   Connection to the database has been created")
        return connection
    
    except pymysql.MySQLError as error:
        print(f"{timestamp}:   Database error: {error}")
        return None

def save_metrics_db(connection, data):
    timestamp = get_timestamp()
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
        print(f"{timestamp}:   Security-metrics successfully written to the database!")
        print()
    except pymysql.MySQLError as error:
        print(f"{timestamp}DATABASE ERROR: {error}")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()