"""Read bounded Linux hwmon and thermal observations without changing sysfs."""

import errno
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

AVAILABLE = "AVAILABLE"
UNAVAILABLE = "UNAVAILABLE"
READ_ERROR = "READ_ERROR"
AMBIGUOUS = "AMBIGUOUS"

MAX_SENSORS = 256
MAX_DEVICES = 64
MAX_DIRECTORY_ENTRIES = 512
MAX_PATH_PARTS = 32
MAX_VALUE_BYTES = 128

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
DEVICE_NAMES = {"hwmon": r"hwmon[0-9]+", "thermal": r"thermal_zone[0-9]+"}
CHANNEL_INPUT = re.compile(r"((?:temp|fan)[1-9][0-9]{0,3})_input")
CHIP_TEMPERATURE = re.compile(r"nct(?:6775|6776|6779|679[1-9])")


@dataclass
class Sensor:
    source: str
    driver: str | None
    device_path: str | None
    channel: str
    kind: str
    label: str | None = None
    status: str = AVAILABLE
    temperature: float | None = None
    max_temperature: float | None = None
    critical_temperature: float | None = None
    rpm: int | None = None
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def identity(self):
        return self.source, self.device_path, self.driver, self.channel, self.label


@dataclass
class SensorScan:
    sensors: list[Sensor] = field(default_factory=list)
    interfaces: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    limited: bool = False


def _open_directory(root_fd, parts):
    # Walk only the approved, bounded path. No component may itself be a symlink.
    fd = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except OSError:
        os.close(fd)
        raise


def _device_path(root, class_fd, source, name):
    try:
        target = os.readlink(name, dir_fd=class_fd)
    except OSError as error:
        if error.errno != errno.EINVAL:
            raise
        return ("class", source, name), None

    if os.path.isabs(target):
        target = os.path.relpath(target, root)
    else:
        target = os.path.normpath(os.path.join("class", source, target))

    parts = Path(target).parts
    if not 3 <= len(parts) <= MAX_PATH_PARTS or parts[0] != "devices":
        raise ValueError("unexpected sysfs device path")
    if not re.fullmatch(DEVICE_NAMES[source], parts[-1]):
        raise ValueError("unexpected sysfs device name")
    parent = parts[:-1]
    if source == "hwmon":
        if parent[-1] != "hwmon":
            raise ValueError("unexpected hwmon device path")
        if parent != ("devices", "virtual", "hwmon"):
            parent = parent[:-1]
    elif parent[-1] != "thermal":
        raise ValueError("unexpected thermal device path")
    return parts, "/" + "/".join(parent)


def _names(fd, pattern, limit, scan):
    names = []
    with os.scandir(fd) as entries:
        for index, entry in enumerate(entries):
            if index == MAX_DIRECTORY_ENTRIES:
                scan.limited = True
                break
            if re.fullmatch(pattern, entry.name):
                if len(names) == limit:
                    scan.limited = True
                    break
                names.append(entry.name)
    return sorted(names)


def _read(fd, name):
    value_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        if not stat.S_ISREG(os.fstat(value_fd).st_mode):
            raise ValueError("not a regular attribute")
        raw = os.read(value_fd, MAX_VALUE_BYTES + 1)
    finally:
        os.close(value_fd)
    if len(raw) > MAX_VALUE_BYTES:
        raise ValueError("attribute too long")
    value = raw.decode("ascii").removesuffix("\n")
    if not value.isprintable() or not value.strip():
        raise ValueError("invalid attribute text")
    return value.strip()


def _text(fd, name, errors, *, optional=False):
    try:
        return _read(fd, name)
    except FileNotFoundError:
        if not optional:
            errors[name] = "missing attribute"
    except OSError:
        errors[name] = "cannot read attribute"
    except ValueError:
        errors[name] = "invalid attribute"
    return None


def _number(fd, name, errors, *, optional=False, rpm=False):
    value = _text(fd, name, errors, optional=optional)
    if value is None:
        return None
    if re.fullmatch(r"[+-]?[0-9]{1,9}", value):
        number = int(value)
        if rpm and number >= 0:
            return number
        if not rpm and -273150 <= number <= 1000000:
            return number / 1000
    errors[name] = "invalid numeric value"
    return None


def _hwmon_temperature(driver, channel, label):
    if driver == "coretemp":
        if channel == "temp1" and re.fullmatch(r"Package id [0-9]+", label or ""):
            return "cpu_package", None
        if channel != "temp1" and re.fullmatch(r"Core [0-9]+", label or ""):
            return "cpu_core", None
        return "cpu_unknown", "unrecognized coretemp channel or label"

    if driver == "k10temp":
        if channel == "temp2" and label == "Tdie":
            return "cpu_package", None
        if re.fullmatch(r"temp(?:[3-9]|10)", channel) and re.fullmatch(r"Tccd[1-8]", label or ""):
            return "temperature", None
        return "cpu_unknown", "no physical CPU temperature confirmed (Tctl can be a control value)"

    # The hwmon ABI permits millivolts for some thermistors. Only convert
    # temperatures for drivers and channels with known units.
    if driver == "acpitz":
        return "temperature", None
    if driver in {"pch_skylake", "pch_cannonlake"} and channel == "temp1":
        return "temperature", None
    if driver == "amdgpu" and channel in {"temp1", "temp2", "temp3"}:
        return "temperature", None
    if driver == "nvme" and re.fullmatch(r"temp[1-9]", channel):
        return "temperature", None
    if CHIP_TEMPERATURE.fullmatch(driver):
        return "temperature", None
    return "temperature", "temperature units are not verified for this channel"


def _hwmon_sensor(fd, driver, path, input_name):
    channel = input_name.removesuffix("_input")
    sensor = Sensor("hwmon", driver, path, channel, "temperature")
    if channel.startswith("fan"):
        sensor.kind = "fan"
        sensor.rpm = _number(fd, input_name, sensor.errors, rpm=True)
        if sensor.rpm is None:
            sensor.status = READ_ERROR
        return sensor

    sensor.label = _text(fd, channel + "_label", sensor.errors, optional=True)
    sensor.kind, reason = _hwmon_temperature(driver, channel, sensor.label)
    if reason:
        sensor.status = AMBIGUOUS
        sensor.errors["identity"] = reason
        return sensor

    sensor.temperature = _number(fd, input_name, sensor.errors)
    sensor.max_temperature = _number(fd, channel + "_max", sensor.errors, optional=True)
    sensor.critical_temperature = _number(fd, channel + "_crit", sensor.errors, optional=True)
    if sensor.temperature is None:
        sensor.status = READ_ERROR
    return sensor


def _thermal_sensor(fd, driver, path):
    sensor = Sensor("thermal", driver, path, "temp", "temperature")
    if driver == "x86_pkg_temp":
        sensor.kind = "cpu_package"
    sensor.temperature = _number(fd, "temp", sensor.errors)
    if sensor.temperature is None:
        sensor.status = READ_ERROR
    return sensor


def _read_device(fd, source, path, scan):
    errors = {}
    name = "name"
    if source == "thermal":
        name = "type"
    driver = _text(fd, name, errors)
    if driver is None:
        scan.errors.append(f"{source}: {errors[name]} ({name})")
        return

    remaining = MAX_SENSORS - len(scan.sensors)
    if source == "thermal":
        if remaining == 0:
            scan.limited = True
        else:
            scan.sensors.append(_thermal_sensor(fd, driver, path))
        return
    for input_name in _names(fd, CHANNEL_INPUT, remaining, scan):
        scan.sensors.append(_hwmon_sensor(fd, driver, path, input_name))


def _scan_interface(root, root_fd, source, scan):
    try:
        class_fd = _open_directory(root_fd, ("class", source))
    except FileNotFoundError:
        scan.interfaces[source] = UNAVAILABLE
        return
    except OSError:
        scan.interfaces[source] = READ_ERROR
        scan.errors.append(f"{source}: cannot open interface")
        return

    scan.interfaces[source] = AVAILABLE
    try:
        for name in _names(class_fd, DEVICE_NAMES[source], MAX_DEVICES, scan):
            try:
                parts, path = _device_path(root, class_fd, source, name)
                device_fd = _open_directory(root_fd, parts)
                try:
                    _read_device(device_fd, source, path, scan)
                finally:
                    os.close(device_fd)
            except (OSError, ValueError):
                scan.errors.append(f"{source}/{name}: cannot safely read device")
    except OSError:
        scan.interfaces[source] = READ_ERROR
        scan.errors.append(f"{source}: cannot list interface")
    finally:
        os.close(class_fd)


def _flag_duplicate_identities(sensors):
    seen = {}
    for sensor in sensors:
        identity = sensor.identity
        if sensor.kind == "cpu_core":
            # Within one device a core label identifies one physical core.
            identity = (sensor.source, sensor.device_path, sensor.driver, "cpu_core", sensor.label)
        previous = seen.get(identity)
        if previous is not None:
            for duplicate in (previous, sensor):
                duplicate.status = AMBIGUOUS
                duplicate.errors["identity"] = "duplicate identity"
        else:
            seen[identity] = sensor


def _of_kind(sensors, kind, source):
    matches = []
    for sensor in sensors:
        if sensor.kind == kind and sensor.source == source:
            matches.append(sensor)
    return matches


def read_sensors(root=Path("/sys")):
    """Read hwmon and fall back to thermal if no usable hwmon package exists."""
    scan = SensorScan()
    try:
        root = Path(root).absolute()
        root_fd = os.open(root, DIRECTORY_FLAGS)
    except FileNotFoundError:
        scan.interfaces = {"hwmon": UNAVAILABLE, "thermal": UNAVAILABLE}
        return scan
    except OSError:
        scan.interfaces = {"hwmon": READ_ERROR, "thermal": READ_ERROR}
        scan.errors.append("cannot open sysfs")
        return scan

    try:
        _scan_interface(root, root_fd, "hwmon", scan)
        packages = _of_kind(scan.sensors, "cpu_package", "hwmon")
        if not packages or (len(packages) == 1 and packages[0].status != AVAILABLE):
            _scan_interface(root, root_fd, "thermal", scan)
    finally:
        os.close(root_fd)

    _flag_duplicate_identities(scan.sensors)
    return scan


def select_cpu_package(scan):
    """Choose a package reading without substituting a core temperature."""
    if scan.limited:
        return AMBIGUOUS, []

    status = UNAVAILABLE
    for source in ("hwmon", "thermal"):
        packages = _of_kind(scan.sensors, "cpu_package", source)
        if len(packages) > 1:
            return AMBIGUOUS, []
        if packages:
            status = packages[0].status
            if status == AVAILABLE:
                return status, packages
    return status, []


def select_cpu(scan):
    """Choose one package or the reliable cores of one device; keep all observations."""
    status, packages = select_cpu_package(scan)
    if status in {AVAILABLE, AMBIGUOUS}:
        return status, packages

    cores = _of_kind(scan.sensors, "cpu_core", "hwmon")
    devices = set()
    labels = set()
    core_status = AVAILABLE
    for sensor in cores:
        devices.add(sensor.device_path)
        if sensor.label in labels or sensor.status == AMBIGUOUS:
            return AMBIGUOUS, []
        labels.add(sensor.label)
        if sensor.status == READ_ERROR:
            core_status = READ_ERROR
    if len(devices) > 1 or (len(cores) > 1 and None in devices):
        return AMBIGUOUS, []
    if cores:
        return core_status, cores

    status = UNAVAILABLE
    for sensor in scan.sensors:
        if sensor.kind in {"cpu_package", "cpu_unknown"}:
            if sensor.status == READ_ERROR:
                return READ_ERROR, []
            if sensor.status == AMBIGUOUS:
                status = AMBIGUOUS
    if scan.errors:
        status = READ_ERROR
    return status, []
