from get_data import get_data
from database import db_connect, save_metrics_db

def main():
    connection = None

    try:
        connection = db_connect()
        
        if connection == None:
            print("Database connection failed.")
            return

        data = get_data(connection)
        save_metrics_db(connection, data)
 
    except Exception as e:
        print(f"ERROR DURING EXECUTION: {e}")

    finally:
        if connection:
            connection.close()

if __name__ == "__main__":
    main()