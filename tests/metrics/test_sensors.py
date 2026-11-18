"""Exercise sysfs discovery without depending on kernel drivers or physical sensors."""

import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from config import system_sensor_setup
from metrics.system import cpu, db, get, main, sensors


def hwmon(root, slot, driver, attributes, *, device=None):
    if device is None:
        device = "platform/" + driver
    directory = root / "devices" / device / "hwmon" / f"hwmon{slot}"
    return device_fixture(root, "hwmon", directory, {"name": driver, **attributes})


def thermal(root, slot, zone_type, value):
    directory = root / "devices/virtual/thermal" / f"thermal_zone{slot}"
    return device_fixture(root, "thermal", directory, {"type": zone_type, "temp": value})


def device_fixture(root, source, directory, attributes):
    class_dir = root / "class" / source
    class_dir.mkdir(parents=True, exist_ok=True)
    directory.mkdir(parents=True)
    for name, value in attributes.items():
        (directory / name).write_text(str(value) + "\n", encoding="utf-8")
    (class_dir / directory.name).symlink_to(os.path.relpath(directory, class_dir))
    return directory


def intel_package(root, slot=0, *, temp=46375, device="platform/coretemp.0", label="Package id 0"):
    return hwmon(root, slot, "coretemp", {"temp1_input": temp, "temp1_label": label}, device=device)


def read_cpu(root):
    return sensors.select_cpu(sensors.read_sensors(root))


def test_cpu_package_has_priority_over_hotter_cores_and_thermal_zones(tmp_path, monkeypatch):
    hwmon(tmp_path, 3, "coretemp", {
        "temp1_input": 46375,
        "temp1_label": "Package id 0",
        "temp2_input": 60000,
        "temp2_label": "Core 0",
    })
    thermal(tmp_path, 5, "x86_pkg_temp", 99000)
    scan = sensors.read_sensors(tmp_path)
    status, chosen = sensors.select_cpu(scan)
    assert status == sensors.AVAILABLE
    assert len(chosen) == 1
    assert chosen[0].channel == "temp1"
    assert chosen[0].driver == "coretemp"
    assert chosen[0].source == "hwmon"
    assert chosen[0].temperature == 46.375
    assert scan.interfaces == {"hwmon": sensors.AVAILABLE}
    monkeypatch.setattr(get, "read_sensors", lambda: scan)
    assert get.get_cpu_temp() == 46.4


def test_verified_cores_stay_separate_and_only_the_hottest_of_one_device_is_stored(tmp_path, monkeypatch):
    hwmon(tmp_path, 2, "coretemp", {
        "temp2_label": "Core 0", "temp2_input": 51000,
        "temp6_label": "Core 4", "temp6_input": 49000,
    })
    scan = sensors.read_sensors(tmp_path)
    status, chosen = sensors.select_cpu(scan)
    assert status == sensors.AVAILABLE
    assert [(chosen[0].label, chosen[0].temperature), (chosen[1].label, chosen[1].temperature)] == [
        ("Core 0", 51.0), ("Core 4", 49.0),
    ]
    monkeypatch.setattr(get, "read_sensors", lambda: scan)
    assert get.get_cpu_temp() == 51.0


def test_motherboard_gpu_and_acpi_are_not_cpu_temperatures(tmp_path):
    intel_package(tmp_path)
    hwmon(tmp_path, 1, "nct6798", {"temp1_input": 75000, "temp1_label": "CPU"})
    hwmon(tmp_path, 2, "amdgpu", {"temp1_input": 95000, "temp1_label": "edge"})
    hwmon(tmp_path, 3, "acpitz", {"temp1_input": 80000})
    scan = sensors.read_sensors(tmp_path)
    status, chosen = sensors.select_cpu(scan)
    assert status == sensors.AVAILABLE
    assert chosen[0].temperature == 46.375
    observations = {}
    for sensor in scan.sensors:
        if sensor.kind == "temperature":
            observations[sensor.driver] = sensor.temperature
    assert observations == {"nct6798": 75.0, "amdgpu": 95.0, "acpitz": 80.0}


@pytest.mark.parametrize("driver,attributes", [
    ("coretemp", {"temp1_input": 50000}),
    ("coretemp", {"temp1_input": 50000, "temp1_label": "Core 0"}),
    ("k10temp", {"temp1_input": 50000, "temp1_label": "Tctl"}),
    ("k10temp", {"temp1_input": 50000, "temp1_label": "Tdie"}),
])
def test_uncertain_cpu_temperature_is_never_selected(tmp_path, driver, attributes):
    hwmon(tmp_path, 0, driver, attributes)
    scan = sensors.read_sensors(tmp_path)
    assert scan.sensors[0].status == sensors.AMBIGUOUS
    assert scan.sensors[0].temperature is None
    assert scan.sensors[0].errors["identity"]
    assert sensors.select_cpu(scan) == (sensors.AMBIGUOUS, [])


def test_k10temp_uses_physical_tdie_channel(tmp_path):
    hwmon(tmp_path, 4, "k10temp", {
        "temp1_input": 70000, "temp1_label": "Tctl",
        "temp2_input": 58250, "temp2_label": "Tdie",
        "temp3_input": 62000, "temp3_label": "Tccd1",
    })
    status, chosen = read_cpu(tmp_path)
    assert status == sensors.AVAILABLE
    assert chosen[0].label == "Tdie"
    assert chosen[0].temperature == 58.25


def test_unsupported_temperature_units_are_not_inferred_from_name_or_label(tmp_path):
    hwmon(tmp_path, 0, "unknown_chip", {"temp1_input": 1100, "temp1_label": "Package id 0"})
    scan = sensors.read_sensors(tmp_path)
    assert scan.sensors[0].temperature is None
    assert scan.sensors[0].status == sensors.AMBIGUOUS
    assert sensors.select_cpu(scan) == (sensors.UNAVAILABLE, [])


def test_multiple_packages_are_not_combined(tmp_path):
    intel_package(tmp_path)
    intel_package(tmp_path, 1, device="platform/coretemp.1", label="Package id 1")
    scan = sensors.read_sensors(tmp_path)
    assert len(scan.sensors) == 2
    assert scan.sensors[0].identity != scan.sensors[1].identity
    assert sensors.select_cpu(scan) == (sensors.AMBIGUOUS, [])


def test_duplicate_identities_remain_distinct_observations(tmp_path):
    intel_package(tmp_path, 0, temp=45000)
    intel_package(tmp_path, 1, temp=46000)
    scan = sensors.read_sensors(tmp_path)
    first, second = scan.sensors
    assert first.identity == second.identity
    assert first.errors["identity"] == second.errors["identity"] == "duplicate identity"
    assert first.status == second.status == sensors.AMBIGUOUS
    assert first.temperature != second.temperature
    assert sensors.select_cpu(scan) == (sensors.AMBIGUOUS, [])


def test_thermal_fallback_requires_exact_zone_type(tmp_path):
    thermal(tmp_path, 0, "acpitz", 95000)
    thermal(tmp_path, 1, "not-cpu-pkg", 89000)
    thermal(tmp_path, 2, "x86_pkg_temp", 44000)
    status, chosen = read_cpu(tmp_path)
    assert status == sensors.AVAILABLE
    assert chosen[0].source == "thermal"
    assert chosen[0].temperature == 44.0


def test_thermal_zones_with_same_type_do_not_get_combined(tmp_path):
    thermal(tmp_path, 0, "x86_pkg_temp", 41000)
    thermal(tmp_path, 1, "x86_pkg_temp", 42000)
    assert read_cpu(tmp_path) == (sensors.AMBIGUOUS, [])


@pytest.mark.parametrize("create_interfaces", [False, True])
def test_system_without_sensors_is_unavailable(tmp_path, create_interfaces):
    if create_interfaces:
        (tmp_path / "class/hwmon").mkdir(parents=True)
        (tmp_path / "class/thermal").mkdir()
    scan = sensors.read_sensors(tmp_path)
    assert not scan.sensors
    assert not scan.errors
    assert sensors.select_cpu(scan) == (sensors.UNAVAILABLE, [])


def test_permission_failure_is_reported(tmp_path, monkeypatch):
    intel_package(tmp_path)
    real_read = sensors._read

    def read(fd, name):
        if name == "temp1_input":
            raise PermissionError()
        return real_read(fd, name)

    monkeypatch.setattr(sensors, "_read", read)
    scan = sensors.read_sensors(tmp_path)
    assert scan.sensors[0].errors == {"temp1_input": "cannot read attribute"}
    assert scan.sensors[0].temperature is None
    assert sensors.select_cpu(scan) == (sensors.READ_ERROR, [])


@pytest.mark.parametrize("value", ["not numeric", "42.5", "-273151", "9" * 200])
def test_invalid_sensor_values_are_read_errors(tmp_path, value):
    intel_package(tmp_path, temp=value)
    assert read_cpu(tmp_path) == (sensors.READ_ERROR, [])


def test_invalid_label_cannot_identify_package(tmp_path):
    intel_package(tmp_path, label="Package id 0\x1b")
    scan = sensors.read_sensors(tmp_path)
    assert sensors.select_cpu(scan) == (sensors.AMBIGUOUS, [])
    assert scan.sensors[0].label is None
    assert scan.sensors[0].errors["temp1_label"] == "invalid attribute"


def test_stable_identity_ignores_hwmon_registration_order(tmp_path):
    first = tmp_path / "before"
    second = tmp_path / "after"
    intel_package(first, 0)
    hwmon(first, 1, "nct6798", {"temp1_input": 70000})
    intel_package(second, 12)
    hwmon(second, 0, "nct6798", {"temp1_input": 70000})
    identities = []
    for root in (first, second):
        observed = {}
        for item in sensors.read_sensors(root).sensors:
            observed[item.identity] = item.temperature
        identities.append(observed)
    assert identities[0] == identities[1]


def test_signed_temperature_limits_and_fan_rpm(tmp_path):
    hwmon(tmp_path, 5, "nct6798", {
        "temp1_input": "-5125", "temp1_max": "61250", "temp1_crit": "85000",
        "temp2_input": "0", "temp2_crit": "unknown",
        "fan1_input": "1275", "fan2_input": "0", "fan3_input": "-1",
    })
    fan1, fan2, fan3, temp1, temp2 = sensors.read_sensors(tmp_path).sensors
    assert (temp1.temperature, temp1.max_temperature, temp1.critical_temperature) == (-5.125, 61.25, 85.0)
    assert temp2.temperature == 0
    assert temp2.max_temperature is temp2.critical_temperature is None
    assert temp2.status == sensors.AVAILABLE
    assert "temp2_crit" in temp2.errors
    assert fan1.rpm == 1275
    assert fan2.rpm == 0
    assert fan3.status == sensors.READ_ERROR


def test_inventory_limit_prevents_cpu_selection_from_a_partial_scan(tmp_path, monkeypatch):
    hwmon(tmp_path, 0, "coretemp", {
        "temp1_input": 46000, "temp1_label": "Package id 0",
        "temp2_input": 48000, "temp2_label": "Core 0",
    })
    monkeypatch.setattr(sensors, "MAX_SENSORS", 1)
    scan = sensors.read_sensors(tmp_path)
    assert len(scan.sensors) == 1
    assert scan.limited
    assert sensors.select_cpu(scan) == (sensors.AMBIGUOUS, [])


def test_inert_entries_cannot_make_directory_scan_unbounded(tmp_path, monkeypatch):
    for index in range(5):
        (tmp_path / "class/hwmon" / f"unused{index}").mkdir(parents=True)
    monkeypatch.setattr(sensors, "MAX_DIRECTORY_ENTRIES", 4)
    scan = sensors.read_sensors(tmp_path)
    assert scan.limited
    assert sensors.select_cpu(scan) == (sensors.AMBIGUOUS, [])


@pytest.mark.parametrize("link", ["class", "device", "attribute"])
def test_symlinks_cannot_escape_approved_sysfs_paths(tmp_path, link):
    root = tmp_path / "sys"
    directory = intel_package(root)
    outside = intel_package(tmp_path / "outside")
    if link == "class":
        path = root / "class/hwmon/hwmon0"
        target = outside
    elif link == "device":
        path = root / "devices/platform"
        path.rename(root / "devices/original")
        target = tmp_path / "outside/devices/platform"
    else:
        path = directory / "temp1_input"
        target = outside / "temp1_input"
    if path.is_symlink() or path.is_file():
        path.unlink()
    path.symlink_to(target)
    status, chosen = read_cpu(root)
    assert status == sensors.READ_ERROR
    assert not chosen


def test_vm_without_sensors_keeps_writing_existing_nullable_system_metric(tmp_path, monkeypatch):
    connection = Mock()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    proc = tmp_path / "proc"
    proc.mkdir()
    stat = proc / "stat"
    stat.write_text("cpu 0 0 0 0\ncpu0 0 0 0 0\n")

    def next_cpu_sample(_):
        stat.write_text("cpu 50 0 0 50\ncpu0 50 0 0 50\n")

    (proc / "loadavg").write_text("1 2 3 1/10 123\n")
    monkeypatch.setattr(cpu, "sleep", next_cpu_sample)
    monkeypatch.setattr(cpu, "monotonic", Mock(side_effect=[10.0, 11.0]))
    monkeypatch.setattr(get, "get_cpu_observation", lambda: cpu.get_cpu_observation(proc, tmp_path / "sys"))
    monkeypatch.setattr(get, "get_uptime", lambda: 123)
    monkeypatch.setattr(get, "get_meminfo", lambda: {"memavailable": 456})
    monkeypatch.setattr(get, "get_disk_usage", lambda: (7, 8, 9))
    monkeypatch.setattr(db, "identity_schema_enabled", lambda _: False)
    monkeypatch.setattr(db, "configured_identity", lambda *_: None)

    assert main.main() == 0
    execute = connection.cursor.return_value.execute
    execute.assert_called_once()
    insert, values = execute.call_args.args
    assert insert.lstrip().startswith("INSERT INTO system_metrics")
    assert "cpu_temperature" in insert
    assert values == (123, 1, 2, 3, 50, None, 456, 7, 8, 9)
    connection.commit.assert_called_once()
    schema = Path(__file__).resolve().parents[2] / "database/schema.sql"
    assert "`cpu_temperature` decimal(10,2) DEFAULT NULL" in schema.read_text()


def test_setup_reports_found_and_missing_cpu_for_unprivileged_user(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(system_sensor_setup.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(system_sensor_setup, "package_installed", lambda: True)
    monkeypatch.setattr(system_sensor_setup, "read_sensors", lambda: sensors.read_sensors(tmp_path))
    assert system_sensor_setup.main() == 0
    assert "CPU temperature: UNAVAILABLE" in capsys.readouterr().out

    intel_package(tmp_path)
    assert system_sensor_setup.main() == 0
    output = capsys.readouterr().out
    assert "hwmon 'coretemp'" in output
    assert "Package id 0" in output
    assert "46.375 °C" in output
    assert "CPU temperature: AVAILABLE" in output


def test_setup_verifies_exact_package_without_running_sensor_tools(monkeypatch):
    run = Mock(return_value=Mock(returncode=0, stdout="installed\n"))
    monkeypatch.setattr(system_sensor_setup.subprocess, "run", run)
    assert system_sensor_setup.package_installed()
    run.assert_called_once_with(
        ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}", "lm-sensors"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    run.return_value.stdout = "config-files"
    assert not system_sensor_setup.package_installed()
