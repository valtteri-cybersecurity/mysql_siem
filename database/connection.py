import os
from datetime import datetime

import pymysql


def get_connection():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )

        print(
            f"{timestamp}:   "
            "Database connection successful!"
        )

        return connection

    except pymysql.MySQLError as error:
        print(f"{timestamp}:   Database error: {error}")
        return None
