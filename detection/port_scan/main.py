from utils import timestamp_util
from db import db_connect, get_db_data

def main():
    timestamp = timestamp_util()
    connection = db_connect()
    rawdata = get_db_data(connection)
    print(rawdata)
    if connection:
        connection.close()


if __name__ == "__main__":
    main()