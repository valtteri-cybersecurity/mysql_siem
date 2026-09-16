from get import get_data, get_timestamp
from db import db_connect, save_metrics_db
import time


def main():
    connection = None
    timestamp = get_timestamp()
    try:
        connection = db_connect()

        if not connection:
            print(f"{timestamp}:   Connection to the database failed.")
       
        data = get_data()
       
        if data:
            save_metrics_db(connection, data)
        else:
            print(f"{timestamp}:   No measurement data received.")
           
    except Exception as e:
        print(f"{timestamp}:   Error during program execution: {e}")
       
    finally:

        if connection:
            connection.close()
            print(f"{timestamp}:   Database connection closed.")


if __name__ == "__main__":
    main()


