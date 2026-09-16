import os
import pymysql
from get import get_timestamp

def connect_db():
    tries = 0
    timestamp = get_timestamp()

    while tries < 3:
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
                print(f"{timestamp}:   Database connection successful!")

            return connection

        except pymysql.DatabaseError as e:
            tries += 1
            print(f"Connection attempt {tries} failed")
            print(e)

    print("Program shutting down after three unsuccesful database connection attempts...")
    return None


def save_metrics(modified_last_day, total_files):

    connection = connect_db()
    timestamp = get_timestamp()

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

    except pymysql.DatabaseError as e:
        print(f"{timestamp}:   Error writing into database")
        print(f"{timestamp}:   ", e)
        connection.rollback()

    finally:
        if cursor:
            cursor.close()

        print(f"{timestamp}:   Database connection closed")
