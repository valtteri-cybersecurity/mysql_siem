import pymysql
from utils import timestamp_util

def db_connect():
    timestamp = timestamp_util()
    try:
        connection = pymysql.connect(
            host = 'localhost',
            user = 'pythonuser',
            password = 'NeekerinViimeinenMatka666',
            database = 'homesystem'
        )
        if connection:
            return connection
        else:
            print(f"{timestamp}:   Connection refused")
            return None

    except pymysql.MySQLError as error:
        (f"{timestamp}:   DATABASE ERROR: {error}")

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