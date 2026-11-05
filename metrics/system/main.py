import pymysql

from database.connection import get_connection
from metrics.system.db import save_metrics_db
from metrics.system.get import get_data, get_timestamp


def main():
    connection = None
    timestamp = get_timestamp()

    try:
        connection = get_connection()

        if not connection:
            print(f"{timestamp}:   Connection to the database failed.")
            return 1

        data = get_data()

        if data:
            save_metrics_db(connection, data)
        else:
            print(f"{timestamp}:   No measurement data received.")
            return 1

        return 0

    except (OSError, ValueError, pymysql.MySQLError):
        print(f"{timestamp}:   System metric collection failed.")
        return 1

    finally:
        if connection:
            connection.close()
            print(f"{timestamp}:   Database connection closed.")


if __name__ == "__main__":
    raise SystemExit(main())
