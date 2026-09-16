import os
import time
import glob
from datetime import datetime


def get_timestamp():
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return date

def get_uptime():
    file = "/proc/uptime"
    with open(file, 'r') as f:
        result = float(f.read().strip().split()[0])

    hours = int(result // 3600)

    return hours

def get_cpu_temp():
    for zone in glob.glob("/sys/class/thermal/thermal_zone*"):
        try:
            with open(f"{zone}/type") as f:
                sensor_type = f.read().strip().lower()

            if "cpu" in sensor_type or "pkg" in sensor_type or "x86" in sensor_type:
                with open(f"{zone}/temp") as f:
                    return round(int(f.read()) / 1000, 1)

        except OSError:
            continue

    return None

def get_cpu_load_avg():
    file = "/proc/loadavg"
    with open(file, 'r') as f:
        resultlist = f.read().strip().split()
        result_1 = resultlist[0]
        result_2 = resultlist[1]
        result_3 = resultlist[2]
        
    return result_1, result_2, result_3

def get_meminfo():
    file = "/proc/meminfo"
    
    memory_dict = {
        "memtotal": None,
        "memfree": None,
        "memavailable": None,
        "buffers": None,
        "cached": None
    }
    
    with open(file, 'r') as f:
        result = f.read()
    
    # Remove 'kB' and split into tokens
    result = result.replace("kB", "").strip()
    resultlist = result.split()
    
    # Parse the list (key: value pairs)
    for i in range(len(resultlist)):
        item = resultlist[i]
        
        if item.startswith("MemTotal:"):
            kb = int(resultlist[i + 1])
            memory_dict["memtotal"] = round(kb / 1024, 1)
        
        elif item.startswith("MemFree:"):
            kb = int(resultlist[i + 1])
            memory_dict["memfree"] = round(kb / 1024, 1)
            
        elif item.startswith("MemAvailable:"):
            kb = int(resultlist[i + 1])
            memory_dict["memavailable"] = round(kb / 1024, 1)
            
        elif item.startswith("Buffers:"):
            kb = int(resultlist[i + 1])
            memory_dict["buffers"] = round(kb / 1024, 1)
            
        elif item.startswith("Cached:"):
            kb = int(resultlist[i + 1])
            memory_dict["cached"] = round(kb / 1024, 1)
    
    return memory_dict

def get_disk_usage():
    info = os.statvfs("/")

    total = info.f_blocks * info.f_frsize
    free = info.f_bavail * info.f_frsize
    used = total - free

    # Muutetaan gigatavuiksi
    used = round(used / (1024 ** 3), 2)
    free = round(free / (1024 ** 3), 2)

    percent = round((used / (used + free)) * 100, 1)

    return used, free, percent


used, free, percent = get_disk_usage()

def get_cpu_usage():
    with open("/proc/stat", "r") as file:
        cpu = file.readline().split()

    idle1 = int(cpu[4])
    total1 = sum(map(int, cpu[1:]))

    time.sleep(1)

    with open("/proc/stat", "r") as file:
        cpu = file.readline().split()

    idle2 = int(cpu[4])
    total2 = sum(map(int, cpu[1:]))

    idle = idle2 - idle1
    total = total2 - total1

    usage = round((1 - idle / total) * 100, 1)

    return usage

def get_data():
    timestamp = get_timestamp()
    uptime = get_uptime()
    cpu_avg = get_cpu_load_avg()
    cpu_usage = get_cpu_usage()
    cpu_temp = get_cpu_temp()
    mem_info = get_meminfo()
    disk_used, disk_free, disk_percent = get_disk_usage()
    
    # Palautetaan kaikki yhtenä tasaisena tuplena, joka sopii SQL:ään
    return (
        uptime,                    # uptime_hours
        float(cpu_avg[0]),         # cpuload1
        float(cpu_avg[1]),         # cpuload5
        float(cpu_avg[2]),         # cpuload15
        cpu_usage,                 # cpu_usage
        cpu_temp,                  # cpu_temperature
        mem_info["memavailable"],  # ram_usage (käytettävissä oleva muisti)
        disk_used,                 # disk_used
        disk_free,                 # disk_free
        disk_percent               # disk_usage (%)
    )
