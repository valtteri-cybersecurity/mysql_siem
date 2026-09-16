from get import parse_raw_results
from db import get_data_db, db_connect, write_data_db
from utils import timestamp_util, date_util

def main():  
    connection = db_connect()
    results = get_data_db(connection)
    parsed_data = parse_raw_results(results)
    write_data_db(connection, parsed_data)

if __name__ == "__main__":
    main()