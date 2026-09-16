import os
import pymysql
from utils import timestamp_util

def connect_db():
    timestamp = timestamp_util()
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
        if connection:
            print(f"{timestamp}:   Connection to the database successfull.")
        else:
            print(f"{timestamp}:   Connection to the database failed.")
        
        return connection
    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}")
        return None


def get_db_data(connection):
    timestamp = timestamp_util()
    cursor = None

    if connection:
        try:
            cursor = connection.cursor()

            sql = """
            SELECT src_ip, COUNT(*) AS hits
            FROM ufw_log
            WHERE DATE(event_time) = CURDATE()
            AND action = 'BLOCK'
            AND src_ip NOT LIKE '192.168.%'
            AND src_ip NOT LIKE '10.88%'
            AND src_ip NOT LIKE '10.2.%'
            AND src_ip NOT LIKE 'fe80:%'
            AND src_ip NOT LIKE 'fdeb:%'
            GROUP BY src_ip
            ORDER BY hits DESC;
            """

            cursor.execute(sql)

            results = cursor.fetchall()

            return results

        except pymysql.MySQLError as error:
            print(f"{timestamp}: DATABASE ERROR: {error}")
            return None

        finally:
            if cursor:
                cursor.close()

    return None

def write_data_db(connection, results):
    timestamp = timestamp_util()
    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
        INSERT INTO top_attacking_ips
        (metric_date, src_ip, hits)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
        hits = VALUES(hits)
        """

        data = []

        for item in results:
            data.append(
                (
                    item["metric_date"],
                    item["src_ip"],
                    item["hits"]
                )
            )

        cursor.executemany(sql, data)

        connection.commit()

        print(f"{timestamp}:   Data successfully written to the database.")

    except pymysql.MySQLError as error:
        print(f"{timestamp}: DATABASE ERROR: {error}")

    finally:
        if cursor:
            cursor.close()
