from datetime import datetime

def get_failed_logins():

    date = datetime.now().strftime("%Y-%m-%d")
    file = "/var/log/auth.log"
    failed_attempts_today = 0

    with open(file, 'r') as infile:
        for line in infile:

            if date in line:
                rivi = line.strip()

                if (
                    "authentication failure" in rivi
                    or "authentication error" in rivi
                    or "failed password" in rivi
                ):
                    failed_attempts_today += 1

    return failed_attempts_today


def get_blocks_today(connection):

    cursor = connection.cursor()
    sql_message = """
    SELECT COUNT(*) AS block_count_today
    FROM ufw_log
    WHERE action = 'BLOCK'
    AND DATE(event_time) = CURDATE();
    """

    cursor.execute(sql_message)
    tulos = cursor.fetchone()[0]

    cursor.close()

    return tulos

def get_unique_ips_today(connection):

    cursor = connection.cursor()

    sql_message = """
    SELECT COUNT(DISTINCT src_ip) AS unique_ips_today
    FROM ufw_log
    WHERE action = 'BLOCK'
    AND DATE(event_time) = CURDATE();
    """

    cursor.execute(sql_message)

    tulos = cursor.fetchone()[0]

    cursor.close()
    return tulos

def get_uptime():
    tiedosto = "/proc/uptime"

    with open(tiedosto, 'r') as infile:
        uptime = float(infile.readline().strip().split()[0])
        uptime = round(uptime / 3600, 2)
    return uptime

def get_timestamp():
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return date

def get_data(connection):
    uptime = get_uptime()
    unique_ips = get_unique_ips_today(connection)
    blocks = get_blocks_today(connection)
    failed_logins = get_failed_logins()
    date = get_timestamp()

    data = {
        'uptime': uptime,
        'blocks': blocks,
        'failed_logins': failed_logins,
        'unique_ips': unique_ips,
        'date': date
    }
    return(data)
