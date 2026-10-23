import pymysql

from database.connection import get_connection
from metrics.security.database import save_metrics_db
from metrics.security.get_data import get_data


def main():
    connection = None

    try:
        connection = get_connection()

        if not connection:
            print("Database connection failed.")
            return

        data = get_data(connection)
        save_metrics_db(connection, data)

    except (OSError, ValueError, pymysql.MySQLError):
        print("Security metric collection failed.")

    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    main()
