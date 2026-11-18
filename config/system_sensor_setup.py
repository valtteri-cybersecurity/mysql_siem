"""Report sensor support as the SIEM service account, without reading SIEM settings."""

import os
import subprocess

from metrics.system.sensors import AVAILABLE, read_sensors, select_cpu


def package_installed():
    try:
        result = subprocess.run(
            ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}", "lm-sensors"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "installed"


def main():
    if os.geteuid() == 0:
        print("Run the system sensor check as the mysql_siem service user.")
        return 1
    if not package_installed():
        print("Cannot verify that lm-sensors is installed.")
        return 1

    scan = read_sensors()
    for source, status in scan.interfaces.items():
        print(f"Sensor interface {source}: {status}.")
    for error in scan.errors:
        print(f"Sensor check: {error}.")
    if scan.limited:
        print("Sensor check: inventory limit reached.")
    for sensor in scan.sensors:
        if sensor.kind not in {"cpu_package", "cpu_core", "cpu_unknown"}:
            continue
        message = (
            f"{sensor.source} {sensor.driver!r} {sensor.device_path!r} "
            f"{sensor.channel} {sensor.label!r}: {sensor.status}"
        )
        if sensor.status == AVAILABLE:
            message += f" ({sensor.temperature:g} °C)"
        print(message)
        for name, reason in sensor.errors.items():
            print(f"  {name}: {reason}")

    status, _ = select_cpu(scan)
    print(f"CPU temperature: {status}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
