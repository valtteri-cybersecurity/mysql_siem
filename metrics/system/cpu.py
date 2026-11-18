"""Read a bounded Linux CPU observation for the System Metrics collector."""

import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic, sleep

from metrics.system import sensors

AVAILABLE = sensors.AVAILABLE
UNAVAILABLE = sensors.UNAVAILABLE
READ_ERROR = sensors.READ_ERROR
AMBIGUOUS = sensors.AMBIGUOUS
PARTIAL = "PARTIAL"

COUNTER_FIELDS = (
    "user", "nice", "system", "idle", "iowait", "irq", "softirq",
    "steal", "guest", "guest_nice",
)
MAX_LOGICAL_CPUS = 4096
MAX_PROC_LINE = 512
MAX_COUNTER = 2**64 - 1
CPU_ROW = re.compile(rb"cpu([0-9]{1,10})")
POLICY_NAME = re.compile(r"policy[0-9]{1,10}")
THROTTLE_FIELDS = ("core_throttle_count", "package_throttle_count")

SAMPLE_SECONDS = 1
MIN_SAMPLE_SECONDS = 0.1
MAX_SAMPLE_SECONDS = 5


def _unsigned(value):
    if len(value) > 20 or not value.isascii() or not value.isdigit():
        raise ValueError("invalid kernel counter")
    number = int(value)
    if number > MAX_COUNTER:
        raise ValueError("kernel counter overflow")
    return number


def _counters(fields):
    if len(fields) < 4:
        return None
    values = []
    try:
        for field in fields[:len(COUNTER_FIELDS)]:
            values.append(_unsigned(field))
    except ValueError:
        return None
    return tuple(values)


def read_cpu_counters(path):
    """Read only the initial CPU rows of /proc/stat and keep the raw counters."""
    try:
        with path.open("rb") as file:
            line = file.readline(MAX_PROC_LINE + 1)
            fields = line.split()
            if len(line) > MAX_PROC_LINE or not fields or fields[0] != b"cpu":
                raise ValueError("invalid aggregate CPU row")
            aggregate = _counters(fields[1:])
            cores = {}
            while True:
                line = file.readline(MAX_PROC_LINE + 1)
                if not line.startswith(b"cpu"):
                    break
                fields = line.split()
                match = CPU_ROW.fullmatch(fields[0])
                if len(line) > MAX_PROC_LINE or not match or len(cores) == MAX_LOGICAL_CPUS:
                    raise ValueError("invalid or oversized CPU inventory")
                cpu_id = int(match[1])
                if cpu_id in cores:
                    raise ValueError("duplicate logical CPU")
                cores[cpu_id] = _counters(fields[1:])
    except FileNotFoundError:
        return UNAVAILABLE, None, {}
    except (OSError, ValueError):
        return READ_ERROR, None, {}

    if aggregate is None:
        return READ_ERROR, aggregate, cores
    return AVAILABLE, aggregate, cores


def _usage(before, after):
    if before is None or after is None or len(before) != len(after):
        return READ_ERROR, None

    deltas = []
    for old, new in zip(before, after):
        if new < old:
            return READ_ERROR, None
        deltas.append(new - old)

    # Linux includes guest and guest_nice in user and nice, respectively.
    if len(deltas) >= 9 and deltas[8] > deltas[0]:
        return READ_ERROR, None
    if len(deltas) >= 10 and deltas[9] > deltas[1]:
        return READ_ERROR, None
    total = sum(deltas[:8])
    if total == 0:
        return UNAVAILABLE, None
    busy = sum(deltas[:3]) + sum(deltas[5:7])
    return AVAILABLE, round(100 * busy / total, 1)


def sample_cpu_usage(path):
    before_status, before_total, before_cores = read_cpu_counters(path)
    started = monotonic()
    sleep(SAMPLE_SECONDS)
    after_status, after_total, after_cores = read_cpu_counters(path)
    elapsed = monotonic() - started
    valid_interval = MIN_SAMPLE_SECONDS <= elapsed <= MAX_SAMPLE_SECONDS

    per_core = {}
    invalid_core_delta = False
    for cpu_id in sorted(before_cores.keys() | after_cores.keys()):
        online = cpu_id in after_cores
        status, percent = UNAVAILABLE, None
        if online and after_cores[cpu_id] is None:
            status = READ_ERROR
            invalid_core_delta = True
        elif valid_interval and online and cpu_id in before_cores:
            status, percent = _usage(before_cores[cpu_id], after_cores[cpu_id])
            if status == READ_ERROR:
                invalid_core_delta = True
        per_core[cpu_id] = {"cpu_usage_percent": percent, "online": online, "measurement_status": status}

    count_status = after_status
    logical_cpu_count = None
    if after_cores:
        count_status = AVAILABLE
        logical_cpu_count = len(after_cores)
    elif count_status == AVAILABLE:
        count_status = UNAVAILABLE
    topology_changed = None
    if before_cores and after_cores:
        topology_changed = before_cores.keys() != after_cores.keys()

    status, percent = UNAVAILABLE, None
    if READ_ERROR in (before_status, after_status) or invalid_core_delta:
        status = READ_ERROR
    elif valid_interval and topology_changed is False:
        status, percent = _usage(before_total, after_total)

    return {
        "cpu_usage_percent": percent,
        "cpu_usage_per_core": per_core,
        "logical_cpu_count": logical_cpu_count,
        "cpu_topology_changed": topology_changed,
        "cpu_sample_interval_seconds": elapsed,
        "cpu_counter_samples": {
            "fields": COUNTER_FIELDS,
            "before": {"aggregate": before_total, "per_core": before_cores},
            "after": {"aggregate": after_total, "per_core": after_cores},
        },
        "measurement_status": {
            "cpu_usage_percent": status,
            "logical_cpu_count": count_status,
        },
    }


def read_load_averages(path):
    with path.open("rb") as file:
        line = file.readline(MAX_PROC_LINE + 1)
    fields = line.split()
    if len(line) > MAX_PROC_LINE or len(fields) < 3:
        raise ValueError("invalid load average")
    values = []
    for field in fields[:3]:
        value = float(field)
        if not math.isfinite(value) or value < 0:
            raise ValueError("invalid load average")
        values.append(value)
    return tuple(values)


def _group_status(statuses):
    statuses = set(statuses)
    if AVAILABLE in statuses:
        if statuses == {AVAILABLE}:
            return AVAILABLE
        return PARTIAL
    if AMBIGUOUS in statuses:
        return AMBIGUOUS
    if READ_ERROR in statuses:
        return READ_ERROR
    return UNAVAILABLE


def _attribute(directory_fd, name):
    try:
        return AVAILABLE, _unsigned(sensors._read(directory_fd, name))
    except FileNotFoundError:
        return UNAVAILABLE, None
    except (OSError, ValueError):
        return READ_ERROR, None


def _frequency(cpu_fd):
    # Use the policy attributes directly. cpuN/cpufreq is a link to a policy.
    try:
        policy_root = sensors._open_directory(cpu_fd, ("cpufreq",))
    except FileNotFoundError:
        return UNAVAILABLE, None
    except OSError:
        return READ_ERROR, None

    frequencies = {}
    statuses = []
    try:
        with os.scandir(policy_root) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_LOGICAL_CPUS + 16:
                    return READ_ERROR, None
                if not POLICY_NAME.fullmatch(entry.name):
                    continue
                if len(frequencies) == MAX_LOGICAL_CPUS:
                    return READ_ERROR, None
                try:
                    policy_fd = sensors._open_directory(policy_root, (entry.name,))
                    try:
                        status, khz = _attribute(policy_fd, "cpuinfo_cur_freq")
                    finally:
                        os.close(policy_fd)
                except FileNotFoundError:
                    status, khz = UNAVAILABLE, None
                except OSError:
                    status, khz = READ_ERROR, None
                mhz = None
                if khz == 0:
                    status = READ_ERROR
                elif khz is not None:
                    mhz = khz / 1000
                frequencies[entry.name] = {
                    "mhz": mhz, "source": "cpuinfo_cur_freq", "measurement_status": status,
                }
                statuses.append(status)
    except OSError:
        return READ_ERROR, None
    finally:
        os.close(policy_root)
    return _group_status(statuses), frequencies or None


def _throttling(cpu_fd, online_cpus):
    counters = {}
    statuses = []
    for cpu_id in online_cpus:
        try:
            throttle_fd = sensors._open_directory(cpu_fd, (f"cpu{cpu_id}", "thermal_throttle"))
        except FileNotFoundError:
            statuses.append(UNAVAILABLE)
            continue
        except OSError:
            statuses.append(READ_ERROR)
            continue
        try:
            counts = {}
            count_statuses = {}
            for name in THROTTLE_FIELDS:
                status, counts[name] = _attribute(throttle_fd, name)
                count_statuses[name] = status
                statuses.append(status)
            counts["measurement_status"] = count_statuses
            counters[cpu_id] = counts
        finally:
            os.close(throttle_fd)

    # Package counters are broadcast to each logical CPU. Retain the raw values.
    return _group_status(statuses), counters or None


def _cpu_sysfs(root, online_cpus):
    try:
        root_fd = os.open(root, sensors.DIRECTORY_FLAGS)
        try:
            cpu_fd = sensors._open_directory(root_fd, ("devices", "system", "cpu"))
        finally:
            os.close(root_fd)
    except FileNotFoundError:
        return (UNAVAILABLE, None), (UNAVAILABLE, None)
    except OSError:
        return (READ_ERROR, None), (READ_ERROR, None)

    try:
        return _frequency(cpu_fd), _throttling(cpu_fd, online_cpus)
    finally:
        os.close(cpu_fd)


def _temperature_sample(sensor):
    temperature = None
    if sensor.status == AVAILABLE:
        temperature = sensor.temperature
    critical_attribute = None
    if sensor.critical_temperature is not None:
        critical_attribute = sensor.channel + "_crit"
    return {
        "identity": sensor.identity,
        "source": sensor.source,
        "temperature_c": temperature,
        "critical_temperature_c": sensor.critical_temperature,
        "critical_temperature_attribute": critical_attribute,
        "measurement_status": sensor.status,
        "errors": sensor.errors.copy(),
    }


def _thermal_observation(scan):
    package_status, selected = sensors.select_cpu_package(scan)
    package_temperature = None
    if selected:
        package_temperature = selected[0].temperature

    packages = []
    cores = []
    core_statuses = []
    core_max = None
    fans = []
    fan_statuses = []
    for sensor in scan.sensors:
        if sensor.kind == "cpu_package":
            packages.append(_temperature_sample(sensor))
        elif sensor.kind == "cpu_core":
            cores.append(_temperature_sample(sensor))
            core_statuses.append(sensor.status)
            if sensor.status == AVAILABLE and (core_max is None or sensor.temperature > core_max):
                core_max = sensor.temperature
        elif sensor.kind == "cpu_unknown" and package_status == UNAVAILABLE:
            package_status = sensor.status
        elif sensor.kind == "fan":
            rpm = None
            if sensor.status == AVAILABLE:
                rpm = sensor.rpm
            fans.append({"identity": sensor.identity, "rpm": rpm, "measurement_status": sensor.status})
            fan_statuses.append(sensor.status)

    if scan.errors:
        if package_status == UNAVAILABLE:
            package_status = READ_ERROR
        core_statuses.append(READ_ERROR)
        fan_statuses.append(READ_ERROR)
    core_status = _group_status(core_statuses)
    fan_status = _group_status(fan_statuses)
    if scan.limited:
        core_status = fan_status = AMBIGUOUS
        core_max = None

    legacy_status, legacy_value = legacy_temperature(scan)
    return {
        "legacy_cpu_temperature_c": legacy_value,
        "cpu_package_temperature_c": package_temperature,
        "cpu_package_temperatures": packages,
        "cpu_core_temperatures": cores,
        "cpu_max_core_temperature_c": core_max,
        "fan_rpm": fans or None,
        "measurement_status": {
            "cpu_package_temperature_c": package_status,
            "cpu_max_core_temperature_c": core_status,
            "fan_rpm": fan_status,
            "legacy_cpu_temperature_c": legacy_status,
        },
    }


def legacy_temperature(scan):
    status, selected = sensors.select_cpu(scan)
    if status != AVAILABLE:
        return status, None
    hottest = selected[0].temperature
    for sensor in selected[1:]:
        hottest = max(hottest, sensor.temperature)
    return status, round(hottest, 1)


def get_cpu_observation(proc_root=Path("/proc"), sys_root=Path("/sys")):
    """Return CPU measurements and the raw inputs needed by later checkpoints."""
    observation = sample_cpu_usage(proc_root / "stat")
    statuses = observation["measurement_status"]
    try:
        load = read_load_averages(proc_root / "loadavg")
        statuses["load"] = AVAILABLE
    except FileNotFoundError:
        load = (None, None, None)
        statuses["load"] = UNAVAILABLE
    except (OSError, ValueError):
        load = (None, None, None)
        statuses["load"] = READ_ERROR
    observation["load_1min"], observation["load_5min"], observation["load_15min"] = load

    cpu_ids = observation["cpu_counter_samples"]["after"]["per_core"]
    frequency, throttle = _cpu_sysfs(sys_root, cpu_ids)
    statuses["cpu_frequency_mhz"], observation["cpu_frequency_mhz"] = frequency
    statuses["thermal_throttle_count"], observation["thermal_throttle_count"] = throttle

    scan = sensors.read_sensors(sys_root)
    thermal = _thermal_observation(scan)
    statuses.update(thermal.pop("measurement_status"))
    observation.update(thermal)
    observation["observed_at"] = datetime.now(timezone.utc)
    return observation
