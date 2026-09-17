import pymysql

from detection.port_scan.utils import timestamp_util

def get_db_data(connection):
    cursor = None
    timestamp = timestamp_util()

    if connection:
        try:
            cursor = connection.cursor()

            sql = """
            SELECT event_time, src_ip, dst_port
            FROM ufw_log
            WHERE action = 'BLOCK' AND DATE(event_time) = CURDATE()
            ORDER BY event_time;
            """

            cursor.execute(sql)
            results = cursor.fetchall()

            return results

        except pymysql.MySQLError as error:
            print(f"{timestamp}:   DATABASE ERROR: {error}")
            return None

        finally:
            if cursor:
                cursor.close()
