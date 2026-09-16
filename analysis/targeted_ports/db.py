```python
import os
import pymysql
from utils import timestamp_util, date_util

def db_connect():
    timestamp = timestamp_util()
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
        if not connection:
            print(f"{timestamp}:   Connection to the database failed.")
        else:
            return connection
    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}")    

def get_data_db(connection):
    timestamp = timestamp_util()
    cursor = None

    try:
        cursor = connection.cursor()
        cursor.execute("""
                       SELECT dst_port, COUNT(*) AS hits
                       FROM ufw_log
                       WHERE DATE(event_time) = CURDATE() AND action = 'BLOCK'
                       GROUP BY dst_port
                       ORDER BY hits DESC;
                       
                       """)
  
        results = cursor.fetchall()

        print(f"{timestamp}:   Data successfully read from the database.")
        return results
    
    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}") 
    finally:
        if cursor:
            cursor.close()


def write_data_db(connection, parsed_data):
    timestamp = timestamp_util()
    date = date_util()

    try:
        cursor = connection.cursor()

        sql = """
        INSERT INTO top_targeted_ports
        (metric_date, dst_port, hits)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
        hits = VALUES(hits);
        """

        data = []

        for item in parsed_data:
            data.append(
                (
                    date,
                    item["dst_port"],
                    item["hits"]
                )
            )

        cursor.executemany(sql, data)

        connection.commit()

        print(f"{timestamp}:   Data successfully written into the database.")

        cursor.close()

    except pymysql.MySQLError as error:
        print(f"{timestamp}:   DATABASE ERROR: {error}")
```

