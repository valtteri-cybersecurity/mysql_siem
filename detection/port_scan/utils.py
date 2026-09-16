from datetime import datetime

def timestamp_util():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return timestamp