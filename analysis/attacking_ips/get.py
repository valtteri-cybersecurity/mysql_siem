from utils import date_util

def parse_raw_result(results):
    date = date_util()

    all_data = []

    for ip, hits in results:
        data = {
            "metric_date": date, 
            "src_ip": ip,
            "hits": hits
        }

        all_data.append(data)
    return all_data