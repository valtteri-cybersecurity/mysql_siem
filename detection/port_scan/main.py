from database.connection import get_connection

from detection.port_scan.utils import timestamp_util
from detection.port_scan.db import get_db_data


def main():
    timestamp = timestamp_util()
    connection = None

    try:
        connection = get_connection()

        if not connection:
            print(f"{timestamp}:   Connection to the database failed.")
            return

        rawdata = get_db_data(connection)
        print(rawdata)

    except Exception as error:
        print(f"{timestamp}:   Error during program execution: {error}")

    finally:
        if connection:
            connection.close()
            print(f"{timestamp}:   Database connection closed.")


if __name__ == "__main__":
    main()
