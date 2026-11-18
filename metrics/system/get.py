import os
from datetime import datetime
from pathlib import Path

from metrics.system.cpu import (
    get_cpu_observation,
    legacy_temperature,
    read_load_averages,
    sample_cpu_usage,
)
from metrics.system.sensors import AMBIGUOUS, READ_ERROR, read_sensors


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_uptime():
    with open("/proc/uptime", "r") as file:
        uptime_seconds = float(file.read().strip().split()[0])

    return int(uptime_seconds // 3600)


def get_cpu_temp():
    status, temperature = legacy_temperature(read_sensors())
    if status in {AMBIGUOUS, READ_ERROR}:
        print(f"CPU temperature: {status}.")
    return temperature


def get_cpu_load_avg():
    return read_load_averages(Path("/proc/loadavg"))


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
    return sample_cpu_usage(Path("/proc/stat"))["cpu_usage_percent"]


def get_data():
    uptime = get_uptime()
    cpu = get_cpu_observation()
    temperature_status = cpu["measurement_status"]["legacy_cpu_temperature_c"]
    if temperature_status in {AMBIGUOUS, READ_ERROR}:
        print(f"CPU temperature: {temperature_status}.")
    mem_info = get_meminfo()
    disk_used, disk_free, disk_percent = get_disk_usage()

    return (
        uptime,
        cpu["load_1min"],
        cpu["load_5min"],
        cpu["load_15min"],
        cpu["cpu_usage_percent"],
        cpu["legacy_cpu_temperature_c"],
        mem_info["memavailable"],
        disk_used,
        disk_free,
        disk_percent,
    )
