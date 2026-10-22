import glob
import hashlib
import os

from database.connection import get_connection
from ingestion.splitter import parse_ufw_line


LOGFILE = "/var/log/ufw.log"


def convert_port(port_value):
    if port_value:
        try:
            return int(port_value)
        except ValueError:
            return 0

    return 0


def get_logfiles():
    logfiles = [LOGFILE]

    rotated_files = sorted(glob.glob(LOGFILE + ".*"))

    for filename in rotated_files:
        suffix = filename[len(LOGFILE) + 1:]

        if suffix.isdigit():
            logfiles.append(filename)

    return logfiles


def save_event(cursor, line):
    clean_line = line.strip()

    if clean_line == "":
        return 0

    info_table = parse_ufw_line(line)

    event_time = info_table.get("timestamp")
    action = info_table.get("action")
    src_ip = info_table.get("src_ip")
    dst_ip = info_table.get("dst_ip")
    protocol = info_table.get("protocol")

    src_port = convert_port(info_table.get("src_prt"))
    dst_port = convert_port(info_table.get("dst_prt"))

    event_hash = hashlib.sha256(
        clean_line.encode("utf-8")
    ).hexdigest()

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
        return 1

    return 0


def process_file(cursor, filename):
    inserted_rows = 0

    try:
        infile = open(filename, "rb")
    except FileNotFoundError:
        if filename == LOGFILE:
            raise

        print(f"Rotated logfile disappeared: {filename}")
        return 0

    with infile:
        file_info = os.fstat(infile.fileno())

        file_device = file_info.st_dev
        file_inode = file_info.st_ino
        current_size = file_info.st_size

        cursor.execute(
            """
            SELECT last_position
            FROM ufw_state
            WHERE file_device = %s
              AND file_inode = %s
            """,
            (file_device, file_inode)
        )

        result = cursor.fetchone()

        if result is None:
            last_position = 0
        else:
            last_position = result[0]

        if current_size < last_position:
            print(f"Logfile has become smaller: {filename}")
            last_position = 0

        infile.seek(last_position)

        while True:
            line_start = infile.tell()
            raw_line = infile.readline()

            if raw_line == b"":
                break

            if not raw_line.endswith(b"\n"):
                infile.seek(line_start)
                break

            line = raw_line.decode("utf-8", errors="ignore")
            inserted_rows += save_event(cursor, line)

        new_position = infile.tell()

        cursor.execute(
            """
            INSERT INTO ufw_state (
                logfile,
                last_position,
                file_device,
                file_inode
            )
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                logfile = %s,
                last_position = %s
            """,
            (
                filename,
                new_position,
                file_device,
                file_inode,
                filename,
                new_position
            )
        )

    return inserted_rows


def process_log(connection):
    cursor = None
    lock_acquired = False

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT GET_LOCK(%s, 0)",
            ("mysql_siem_ufw_ingestion",)
        )

        result = cursor.fetchone()

        if result[0] != 1:
            raise RuntimeError("Another UFW collector is running.")

        lock_acquired = True
        inserted_rows = 0

        logfiles = get_logfiles()

        for filename in logfiles:
            inserted_rows += process_file(cursor, filename)

        connection.commit()

        print(f"Done. New UFW rows inserted: {inserted_rows}")

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            try:
                if lock_acquired:
                    cursor.execute(
                        "SELECT RELEASE_LOCK(%s)",
                        ("mysql_siem_ufw_ingestion",)
                    )
            finally:
                cursor.close()


def main():
    connection = None

    try:
        connection = get_connection()

        if not connection:
            print("Database connection failed.")
            return

        process_log(connection)

    except Exception as error:
        print(f"Error during program execution: {error}")

    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    main()
