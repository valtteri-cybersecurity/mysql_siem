import glob
import pymysql
import os

from datetime import datetime

date = datetime.now().strftime("%Y-%m-%d")
block_count = 0
allow_count = 0
audit_count = 0
total_count = 0
total_average_week = 0

connection = pymysql.connect(
    host=os.environ['DB_HOST'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD'],
    database=os.environ['DB_NAME']
)

cursor = connection.cursor()

logfiles = sorted(glob.glob("/var/log/ufw.log*"))

for logfile in logfiles:
    with open(logfile, 'r', encoding='utf-8', errors='ignore') as infile:
        for line in infile:
            if date in line:
                if "UFW BLOCK" in line:
                    block_count += 1
                elif "UFW ALLOW" in line:
                    allow_count += 1
                elif "UFW AUDIT" in line:
                    audit_count += 1

total_count = audit_count + allow_count + block_count

# Haetaan ufw_log-taulusta viimeisen 7 päivän päivittäisten BLOCK-tapahtumien keskiarvo
avg_sql = """
    SELECT ROUND(AVG(daily_blocks), 2)
    FROM (
        SELECT DATE(event_time) AS day, COUNT(*) AS daily_blocks
        FROM ufw_log
        WHERE action = 'BLOCK'
          AND event_time >= CURDATE() - INTERVAL 6 DAY
        GROUP BY DATE(event_time)
    ) AS block_days
"""

cursor.execute(avg_sql)
result = cursor.fetchone()

if result[0] is not None:
    total_average_week = result[0]
else:
    total_average_week = 0.00

sql = """
    INSERT INTO ufw_daily_actions_counts
    (day, audit_count, allow_count, block_count, total_count, total_average_week)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        audit_count = VALUES(audit_count),
        allow_count = VALUES(allow_count),
        block_count = VALUES(block_count),
        total_count = VALUES(total_count),
        total_average_week = VALUES(total_average_week)
"""

cursor.execute(sql, (date, audit_count, allow_count, block_count, total_count, total_average_week))
connection.commit()
cursor.close()
connection.close()

print("Code is commited successfully")