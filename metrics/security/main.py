from database.connection import get_connection

from metrics.security.get_data import get_data
from metrics.security.database import save_metrics_db


def main():
    connection = None

    try:
        connection = get_connection()

        if not connection:
            print("Database connection failed.")
            return

        data = get_data(connection)
        save_metrics_db(connection, data)

    except Exception as error:
        print(f"ERROR DURING EXECUTION: {error}")

    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    main()
