from utils import timestamp_util
from db import db_connect

def parse_raw_results(results):
    parsed_data = []
    
    for dst_port, hits in results:
        data = {
            "dst_port": dst_port,
            "hits": hits
        }

        parsed_data.append(data)
    return parsed_data