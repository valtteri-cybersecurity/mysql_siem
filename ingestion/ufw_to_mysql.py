import os
import sys
import hashlib
import pymysql

sys.path.append("/home/nordman/omapython/pro/mysql_siem/ingestion")
from splitter import parse_ufw_line

LOGFILE = "/var/log/ufw.log"


def convert_port(port_value):
    if port_value:
        try:
            return int(port_value)
        except ValueError:
            return 0
    return 0


connection = None
cursor = None

try:
    connection = pymysql.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"]
    )

    cursor = connection.cursor()

    cursor.execute("SELECT last_position FROM ufw_state WHERE id = 1")
    result = cursor.fetchone()

    if result is None:
        last_position = 0
        cursor.execute(
            """
            INSERT INTO ufw_state (id, logfile, last_position)
            VALUES (1, %s, 0)
            """,
            (LOGFILE,)
        )
        connection.commit()
    else:
        last_position = result[0]

    current_size = os.path.getsize(LOGFILE)

    if last_position > current_size:
        last_position = 0

    inserted_rows = 0

    with open(LOGFILE, "r", encoding="utf-8", errors="ignore") as infile:
        infile.seek(last_position)

        for line in infile:
            clean_line = line.strip()

            if clean_line == "":
                continue

            info_table = parse_ufw_line(line)

            event_time = info_table.get("timestamp")
            action = info_table.get("action")
            src_ip = info_table.get("src_ip")
            dst_ip = info_table.get("dst_ip")
            protocol = info_table.get("protocol")

            src_port = info_table.get("src_prt")
            dst_port = info_table.get("dst_prt")

            src_port = convert_port(src_port)
            dst_port = convert_port(dst_port)

            event_hash = hashlib.sha256(clean_line.encode("utf-8")).hexdigest()

            sql = """
            INSERT IGNORE INTO ufw_log (
                event_time,
                action,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                raw_line,
                event_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            values = (
                event_time,
                action,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                clean_line,
                event_hash
            )

            cursor.execute(sql, values)

            if cursor.rowcount == 1:
                inserted_rows += 1

        new_position = infile.tell()

    cursor.execute(
        """
        UPDATE ufw_state
        SET logfile = %s, last_position = %s
        WHERE id = 1
        """,
        (LOGFILE, new_position)
    )

    connection.commit()

    print(f"Done. New UFW rows inserted: {inserted_rows}")
    print(f"Old position: {last_position}")
    print(f"New position: {new_position}")
    print(f"Current logfile size: {current_size}")

except Exception as e:
    print("Error:", e)

finally:
    if cursor:
        cursor.close()
    if connection:
        connection.close()
