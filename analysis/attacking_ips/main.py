from utils import timestamp_util
from db import connect_db, get_db_data, write_data_db
from get import parse_raw_result

def main():
    timestamp = timestamp_util()
    connection = connect_db()
    raw = get_db_data(connection)
    data = parse_raw_result(raw)
    write_data_db(connection, data)
        
    if connection:
        connection.close()


if __name__ == "__main__":
    main()