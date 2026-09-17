from database.connection import get_connection

from analysis.attacking_ips.utils import timestamp_util
from analysis.attacking_ips.db import get_db_data, write_data_db
from analysis.attacking_ips.get import parse_raw_result


def main():
    timestamp = timestamp_util()
    connection = None

    try:
        connection = get_connection()

        if not connection:
            print(f"{timestamp}:   Connection to the database failed.")
            return

        raw = get_db_data(connection)
        data = parse_raw_result(raw)
        write_data_db(connection, data)

    except Exception as error:
        print(f"{timestamp}:   Error during program execution: {error}")

    finally:
        if connection:
            connection.close()
            print(f"{timestamp}:   Database connection closed.")


if __name__ == "__main__":
    main()
