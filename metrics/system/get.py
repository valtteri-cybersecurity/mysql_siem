import glob
import os
import time
from datetime import datetime


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_uptime():
    with open("/proc/uptime", "r") as file:
        uptime_seconds = float(file.read().strip().split()[0])

    return int(uptime_seconds // 3600)


def get_cpu_temp():
    for zone in glob.glob("/sys/class/thermal/thermal_zone*"):
        try:
            with open(f"{zone}/type", "r") as file:
                sensor_type = file.read().strip().lower()

            if "cpu" in sensor_type or "pkg" in sensor_type or "x86" in sensor_type:
                with open(f"{zone}/temp", "r") as file:
                    return round(int(file.read()) / 1000, 1)

        except OSError:
            continue

    return None


def get_cpu_load_avg():
    with open("/proc/loadavg", "r") as file:
        load_average = file.read().strip().split()

    return (
        float(load_average[0]),
        float(load_average[1]),
        float(load_average[2]),
    )


def get_meminfo():
    memory = {
        "memtotal": None,
        "memfree": None,
        "memavailable": None,
        "buffers": None,
        "cached": None,
    }

    with open("/proc/meminfo", "r") as file:
        for line in file:
            key, value = line.split(":", 1)
            value_kb = int(value.strip().split()[0])

            if key == "MemTotal":
                memory["memtotal"] = round(value_kb / 1024, 1)

            elif key == "MemFree":
                memory["memfree"] = round(value_kb / 1024, 1)

            elif key == "MemAvailable":
                memory["memavailable"] = round(value_kb / 1024, 1)

            elif key == "Buffers":
                memory["buffers"] = round(value_kb / 1024, 1)

            elif key == "Cached":
                memory["cached"] = round(value_kb / 1024, 1)

    return memory


def get_disk_usage():
    info = os.statvfs("/")

    total = info.f_blocks * info.f_frsize
    free = info.f_bavail * info.f_frsize
    used = total - free

    used_gb = round(used / (1024 ** 3), 2)
    free_gb = round(free / (1024 ** 3), 2)
    usage_percent = round((used / (used + free)) * 100, 1)

    return used_gb, free_gb, usage_percent


def get_cpu_usage():
    with open("/proc/stat", "r") as file:
        cpu = file.readline().split()

    idle_start = int(cpu[4])
    total_start = sum(map(int, cpu[1:]))

    time.sleep(1)

    with open("/proc/stat", "r") as file:
        cpu = file.readline().split()

    idle_end = int(cpu[4])
    total_end = sum(map(int, cpu[1:]))

    idle = idle_end - idle_start
    total = total_end - total_start

    return round((1 - idle / total) * 100, 1)


def get_data():
    uptime = get_uptime()
    cpu_avg = get_cpu_load_avg()
    cpu_usage = get_cpu_usage()
    cpu_temp = get_cpu_temp()
    mem_info = get_meminfo()
    disk_used, disk_free, disk_percent = get_disk_usage()

    return (
        uptime,
        cpu_avg[0],
        cpu_avg[1],
        cpu_avg[2],
        cpu_usage,
        cpu_temp,
        mem_info["memavailable"],
        disk_used,
        disk_free,
        disk_percent,
    )
