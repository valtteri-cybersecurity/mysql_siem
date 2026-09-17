from database.connection import get_connection

from metrics.system.get import get_data, get_timestamp
from metrics.system.db import save_metrics_db


def main():
    connection = None
    timestamp = get_timestamp()

    try:
        connection = get_connection()

        if not connection:
            print(f"{timestamp}:   Connection to the database failed.")
            return

        data = get_data()

        if data:
            save_metrics_db(connection, data)
        else:
            print(f"{timestamp}:   No measurement data received.")

    except Exception as error:
        print(f"{timestamp}:   Error during program execution: {error}")

    finally:
        if connection:
            connection.close()
            print(f"{timestamp}:   Database connection closed.")


if __name__ == "__main__":
    main()
