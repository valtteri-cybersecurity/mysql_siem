"""CPU observations use isolated copies of Linux proc and sysfs attributes."""

from datetime import timedelta, timezone
from unittest.mock import Mock

import pytest

from metrics.system import cpu, get
from tests.metrics.test_sensors import hwmon, intel_package

BEFORE = b"cpu 0 0 0 0\ncpu0 0 0 0 0\n"
AFTER = b"cpu 25 0 0 75\ncpu0 25 0 0 75\n"


@pytest.fixture
def linux(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    proc.mkdir()
    sysfs = tmp_path / "sys"
    sysfs.mkdir()
    stat = proc / "stat"
    (proc / "loadavg").write_text("0.25 0.50 0.75 1/20 123\n")
    stat.write_bytes(BEFORE)
    wait = Mock(side_effect=lambda _: stat.write_bytes(AFTER))
    monkeypatch.setattr(cpu, "sleep", wait)
    monkeypatch.setattr(cpu, "monotonic", Mock(side_effect=[10.0, 11.0]))
    return proc, sysfs


def mock_samples(monkeypatch, path, before, after, *, elapsed=1.0):
    path.write_bytes(before)
    monkeypatch.setattr(cpu, "sleep", lambda _: path.write_bytes(after))
    monkeypatch.setattr(cpu, "monotonic", Mock(side_effect=[10.0, 10.0 + elapsed]))


@pytest.mark.parametrize("user,idle,expected", [(0, 100, 0.0), (100, 0, 100.0), (25, 75, 25.0)])
def test_usage_from_two_integer_samples(linux, monkeypatch, user, idle, expected):
    proc, _ = linux
    stat = proc / "stat"
    counters = f" {user} 0 0 {idle}\n"
    after = ("cpu" + counters + "cpu0" + counters).encode()
    mock_samples(monkeypatch, stat, BEFORE, after)
    data = cpu.sample_cpu_usage(stat)
    assert data["cpu_usage_percent"] == expected
    assert data["cpu_usage_per_core"][0]["cpu_usage_percent"] == expected
    assert data["measurement_status"]["cpu_usage_percent"] == cpu.AVAILABLE
    assert data["logical_cpu_count"] == 1
    assert data["cpu_sample_interval_seconds"] == 1
    assert data["cpu_counter_samples"]["after"]["aggregate"] == (user, 0, 0, idle)


def test_guest_and_guest_nice_are_not_counted_twice(linux, monkeypatch):
    proc, _ = linux
    stat = proc / "stat"
    mock_samples(
        monkeypatch, stat,
        b"cpu 30 10 0 100 0 0 0 0 12 3\ncpu0 30 10 0 100 0 0 0 0 12 3\n",
        b"cpu 65 25 0 150 0 0 0 0 32 13\ncpu0 65 25 0 150 0 0 0 0 32 13\n",
    )
    data = cpu.sample_cpu_usage(stat)
    assert data["cpu_usage_percent"] == 50.0
    assert data["cpu_usage_per_core"][0]["cpu_usage_percent"] == 50.0
    assert data["cpu_counter_samples"]["after"]["aggregate"][-2:] == (32, 13)


def test_iowait_and_steal_contribute_elapsed_ticks_but_not_cpu_work(linux, monkeypatch):
    proc, _ = linux
    zero = b" 0 0 0 0 0 0 0 0\n"
    end = b" 10 0 10 40 15 3 2 20\n"
    path = proc / "stat"
    mock_samples(monkeypatch, path, b"cpu" + zero + b"cpu0" + zero, b"cpu" + end + b"cpu0" + end)
    assert cpu.sample_cpu_usage(path)["cpu_usage_percent"] == 25.0


@pytest.mark.parametrize("cpu_ids,expected_count", [((0, 3, 8), 3), ((0, 8), 2), ((0,), 1)])
def test_hotplug_suppresses_aggregate_even_when_cpu_count_is_unchanged(linux, monkeypatch, cpu_ids, expected_count):
    proc, _ = linux
    path = proc / "stat"
    before = b"cpu 100 0 0 100\ncpu0 25 0 0 75\ncpu3 75 0 0 25\n"
    after = b"cpu 10000 0 0 160\n"
    for cpu_id in cpu_ids:
        if cpu_id == 3:
            after += b"cpu3 90 0 0 110\n"
        else:
            after += f"cpu{cpu_id} 65 0 0 135\n".encode()
    mock_samples(monkeypatch, path, before, after)
    data = cpu.sample_cpu_usage(path)

    assert data["logical_cpu_count"] == expected_count
    assert data["cpu_topology_changed"] is True
    assert data["cpu_usage_percent"] is None
    assert data["measurement_status"]["cpu_usage_percent"] == cpu.UNAVAILABLE
    assert data["cpu_usage_per_core"][0]["cpu_usage_percent"] == 40.0
    for cpu_id, online in ((8, True), (3, False)):
        changed = (cpu_id in cpu_ids) == online
        if changed:
            assert data["cpu_usage_per_core"][cpu_id] == {
                "cpu_usage_percent": None, "online": online, "measurement_status": cpu.UNAVAILABLE,
            }


@pytest.mark.parametrize("after,elapsed,expected_status", [
    (BEFORE, 1.0, cpu.UNAVAILABLE),
    (AFTER, 0.03, cpu.UNAVAILABLE),
    (AFTER, -0.5, cpu.UNAVAILABLE),
    (AFTER, 6.0, cpu.UNAVAILABLE),
    (b"cpu 0 0 0 2\ncpu0 0 0 0 2 0\n", 1.0, cpu.READ_ERROR),
    (b"cpu 25 0 0 75\ncpu0 invalid 0 0 75\n", 1.0, cpu.READ_ERROR),
    (b"cpu 25 0 0 75\n", 1.0, cpu.UNAVAILABLE),
    (b"cpu negative 0 0 75\ncpu0 25 0 0 75\n", 1.0, cpu.READ_ERROR),
    (b"not a cpu row\n", 1.0, cpu.READ_ERROR),
])
def test_invalid_or_incomplete_intervals_do_not_produce_usage(linux, monkeypatch, after, elapsed, expected_status):
    proc, _ = linux
    path = proc / "stat"
    mock_samples(monkeypatch, path, BEFORE, after, elapsed=elapsed)
    data = cpu.sample_cpu_usage(path)
    assert data["cpu_usage_percent"] is None
    assert data["measurement_status"]["cpu_usage_percent"] == expected_status


def test_counter_decrease_rejected_even_when_total_increases(linux, monkeypatch):
    proc, _ = linux
    path = proc / "stat"
    start = b" 100 0 0 100 10 0 0 0\n"
    end = b" 99 0 0 300 10 0 0 0\n"
    mock_samples(monkeypatch, path, b"cpu" + start + b"cpu0" + start, b"cpu" + end + b"cpu0" + end)
    data = cpu.sample_cpu_usage(path)
    assert data["cpu_usage_percent"] is None
    assert data["cpu_usage_per_core"][0]["measurement_status"] == cpu.READ_ERROR


def test_first_read_missing_cannot_be_replaced_by_cumulative_data(linux):
    proc, _ = linux
    stat = proc / "stat"
    stat.unlink()
    data = cpu.sample_cpu_usage(stat)
    assert data["logical_cpu_count"] == 1
    assert data["cpu_usage_percent"] is None
    assert data["cpu_usage_per_core"][0]["measurement_status"] == cpu.UNAVAILABLE
    assert data["cpu_counter_samples"]["before"]["aggregate"] is None


def test_virtual_machine_can_report_cpu_without_optional_kernel_interfaces(linux):
    proc, sysfs = linux
    observed = get.get_cpu_observation(proc, sysfs)
    assert observed["cpu_usage_percent"] == 25.0
    assert (observed["load_1min"], observed["load_5min"], observed["load_15min"]) == (0.25, 0.50, 0.75)
    assert observed["cpu_core_temperatures"] == []
    for field in ("cpu_package_temperature_c", "cpu_max_core_temperature_c", "fan_rpm",
                  "cpu_frequency_mhz", "thermal_throttle_count"):
        assert observed[field] is None
        assert observed["measurement_status"][field] == cpu.UNAVAILABLE
    assert observed["observed_at"].tzinfo is timezone.utc
    assert observed["observed_at"].utcoffset() == timedelta(0)


def test_frequency_only_reports_values_from_hardware_attribute(linux):
    proc, sysfs = linux
    cpufreq = sysfs / "devices/system/cpu/cpufreq"
    for index in range(3):
        (cpufreq / f"policy{index}").mkdir(parents=True)
    (cpufreq / "policy0/cpuinfo_cur_freq").write_text("2256375\n")
    (cpufreq / "policy1/scaling_cur_freq").write_text("900000\n")
    (cpufreq / "policy2/cpuinfo_cur_freq").write_text("0\n")
    observed = cpu.get_cpu_observation(proc, sysfs)
    frequency = observed["cpu_frequency_mhz"]
    assert observed["measurement_status"]["cpu_frequency_mhz"] == cpu.PARTIAL
    assert frequency["policy0"] == {
        "mhz": 2256.375, "source": "cpuinfo_cur_freq", "measurement_status": cpu.AVAILABLE,
    }
    assert frequency["policy1"]["mhz"] is None
    assert frequency["policy1"]["measurement_status"] == cpu.UNAVAILABLE
    assert frequency["policy2"]["measurement_status"] == cpu.READ_ERROR


def test_package_cores_critical_threshold_and_fans_have_separate_observations(linux):
    proc, sysfs = linux
    hwmon(sysfs, 0, "coretemp", {
        "temp1_input": 51250, "temp1_label": "Package id 0", "temp1_crit": 100000,
        "temp2_input": 67250, "temp2_label": "Core 0", "temp2_crit": 98000,
        "temp3_input": 65250, "temp3_label": "Core 1", "temp3_crit": 99000,
    })
    hwmon(sysfs, 1, "nct6798", {"temp1_input": 95500, "temp1_label": "CPU", "fan1_input": 1150})
    data = cpu.get_cpu_observation(proc, sysfs)
    assert data["cpu_package_temperature_c"] == 51.25
    assert data["cpu_max_core_temperature_c"] == 67.25
    package, = data["cpu_package_temperatures"]
    assert package["critical_temperature_c"] == 100.0
    assert package["critical_temperature_attribute"] == "temp1_crit"
    assert package["identity"][0] == "hwmon"
    assert package["identity"][2] == "coretemp"
    first, second = data["cpu_core_temperatures"]
    assert first["temperature_c"] == 67.25
    assert second["temperature_c"] == 65.25
    assert first["critical_temperature_c"] == 98.0
    assert second["critical_temperature_attribute"] == "temp3_crit"
    fan, = data["fan_rpm"]
    assert fan["rpm"] == 1150
    assert fan["identity"][2] == "nct6798"


def test_thermal_identity_distinguishes_replacement_from_hwmon_renumbering(linux, monkeypatch):
    proc, sysfs = linux
    changed = sysfs.parent / "changed"
    renumbered = sysfs.parent / "renumbered"
    intel_package(sysfs, 0, device="platform/coretemp.0", label="Package id 0")
    intel_package(renumbered, 9, device="platform/coretemp.0", label="Package id 0")
    intel_package(changed, 0, device="platform/coretemp.1", label="Package id 1")
    monkeypatch.setattr(cpu, "monotonic", Mock(side_effect=[10, 11, 20, 21, 30, 31]))
    samples = []
    for root in (sysfs, renumbered, changed):
        sample, = cpu.get_cpu_observation(proc, root)["cpu_package_temperatures"]
        samples.append(sample["identity"])
    assert samples[0] == samples[1]
    assert samples[0] != samples[2]


def test_only_verified_cores_contribute_to_max_and_motherboard_is_never_cpu_package(linux):
    proc, sysfs = linux
    hwmon(sysfs, 0, "coretemp", {
        "temp2_input": 52250, "temp2_label": "Core 0",
        "temp3_input": "invalid", "temp3_label": "Core 1",
    })
    hwmon(sysfs, 1, "nct6798", {"temp1_input": 95500, "temp1_label": "CPU"})
    data = cpu.get_cpu_observation(proc, sysfs)
    assert data["cpu_package_temperature_c"] is None
    assert data["measurement_status"]["cpu_package_temperature_c"] == cpu.UNAVAILABLE
    assert data["cpu_max_core_temperature_c"] == 52.25
    assert data["measurement_status"]["cpu_max_core_temperature_c"] == cpu.PARTIAL
    assert data["cpu_core_temperatures"][1]["temperature_c"] is None
    assert data["cpu_core_temperatures"][1]["measurement_status"] == cpu.READ_ERROR
    assert data["legacy_cpu_temperature_c"] is None



def test_duplicate_core_labels_from_one_device_are_ambiguous(linux):
    proc, sysfs = linux
    hwmon(sysfs, 0, "coretemp", {
        "temp2_input": 55000, "temp2_label": "Core 0",
        "temp3_input": 90000, "temp3_label": "Core 0",
    })
    data = cpu.get_cpu_observation(proc, sysfs)
    assert data["cpu_max_core_temperature_c"] is None
    assert data["measurement_status"]["cpu_max_core_temperature_c"] == cpu.AMBIGUOUS
    first, second = data["cpu_core_temperatures"]
    assert first["identity"] != second["identity"]
    assert first["temperature_c"] is second["temperature_c"] is None


def test_throttle_counters_are_independent_and_retain_a_reset_value(linux, monkeypatch):
    proc, sysfs = linux
    path = proc / "stat"
    stat = AFTER + b"cpu1 0 0 0 75\n"
    mock_samples(monkeypatch, path, stat, stat)
    monkeypatch.setattr(cpu, "monotonic", Mock(side_effect=[10, 11, 20, 21]))

    for index in (0, 1):
        throttle = sysfs / "devices/system/cpu" / f"cpu{index}" / "thermal_throttle"
        throttle.mkdir(parents=True)
        (throttle / "core_throttle_count").write_text(f"{index + 2}\n")
        (throttle / "package_throttle_count").write_text("9007199254740993\n")
    before = cpu.get_cpu_observation(proc, sysfs)
    assert before["thermal_throttle_count"][0]["core_throttle_count"] == 2
    assert before["thermal_throttle_count"][1]["core_throttle_count"] == 3
    assert before["thermal_throttle_count"][0]["package_throttle_count"] == 9007199254740993
    assert before["thermal_throttle_count"][1]["package_throttle_count"] == 9007199254740993
    assert before["measurement_status"]["thermal_throttle_count"] == cpu.AVAILABLE

    for index in (0, 1):
        throttle = sysfs / "devices/system/cpu" / f"cpu{index}" / "thermal_throttle"
        (throttle / "package_throttle_count").write_text("0\n")
    after = cpu.get_cpu_observation(proc, sysfs)
    assert after["thermal_throttle_count"][0]["package_throttle_count"] == 0
    assert after["thermal_throttle_count"][1]["package_throttle_count"] == 0
    assert after["measurement_status"]["thermal_throttle_count"] == cpu.AVAILABLE


def test_throttle_invalid_and_missing_attributes_have_separate_statuses(linux):
    proc, sysfs = linux
    throttle = sysfs / "devices/system/cpu/cpu0/thermal_throttle"
    throttle.mkdir(parents=True)
    (throttle / "core_throttle_count").write_text("-1\n")
    observation = cpu.get_cpu_observation(proc, sysfs)
    counters = observation["thermal_throttle_count"][0]
    assert counters["core_throttle_count"] is None
    assert counters["package_throttle_count"] is None
    assert counters["measurement_status"] == {
        "core_throttle_count": cpu.READ_ERROR, "package_throttle_count": cpu.UNAVAILABLE,
    }


@pytest.mark.parametrize("bad_row", [b"cpu2 3 0 0 5\n", b"cpu0 " + b"9" * 1024 + b"\n"])
def test_stat_resource_limits_never_return_a_truncated_inventory(linux, monkeypatch, bad_row):
    proc, _ = linux
    path = proc / "stat"
    mock_samples(monkeypatch, path, BEFORE + bad_row, AFTER + bad_row)
    monkeypatch.setattr(cpu, "MAX_LOGICAL_CPUS", 1)
    data = cpu.sample_cpu_usage(path)
    assert data["measurement_status"]["cpu_usage_percent"] == cpu.READ_ERROR
    assert data["logical_cpu_count"] is None
    assert data["cpu_usage_per_core"] == {}


def test_frequency_scan_drops_partial_results_if_it_exceeds_policy_limit(linux, monkeypatch):
    proc, sysfs = linux
    monkeypatch.setattr(cpu, "MAX_LOGICAL_CPUS", 1)
    for index in (0, 1):
        policy = sysfs / "devices/system/cpu/cpufreq" / f"policy{index}"
        policy.mkdir(parents=True)
        (policy / "cpuinfo_cur_freq").write_text("2300000\n")
    data = cpu.get_cpu_observation(proc, sysfs)
    assert data["cpu_frequency_mhz"] is None
    assert data["measurement_status"]["cpu_frequency_mhz"] == cpu.READ_ERROR


def test_sysfs_cpu_attributes_do_not_follow_symlinks(linux):
    proc, sysfs = linux
    policy = sysfs / "devices/system/cpu/cpufreq/policy0"
    policy.mkdir(parents=True)
    external = proc / "unrelated"
    external.write_text("2300000\n")
    (policy / "cpuinfo_cur_freq").symlink_to(external)
    data = cpu.get_cpu_observation(proc, sysfs)
    assert data["cpu_frequency_mhz"]["policy0"]["mhz"] is None
    assert data["measurement_status"]["cpu_frequency_mhz"] == cpu.READ_ERROR


def test_legacy_scalar_entry_points_and_tuple_reuse_current_observation(linux, monkeypatch):
    proc, sysfs = linux
    intel_package(sysfs, temp=53250)
    monkeypatch.setattr(cpu, "monotonic", Mock(side_effect=[10, 11, 20, 21]))
    monkeypatch.setattr(get, "get_uptime", lambda: 123)
    monkeypatch.setattr(get, "get_meminfo", lambda: {"memavailable": 456})
    monkeypatch.setattr(get, "get_disk_usage", lambda: (7, 8, 9))
    observation = Mock(side_effect=lambda: cpu.get_cpu_observation(proc, sysfs))
    monkeypatch.setattr(get, "get_cpu_observation", observation)
    monkeypatch.setattr(get, "read_sensors", lambda: cpu.sensors.read_sensors(sysfs))
    assert get.get_cpu_temp() == 53.2

    sampled = get.sample_cpu_usage
    monkeypatch.setattr(get, "sample_cpu_usage", lambda _: sampled(proc / "stat"))
    assert get.get_cpu_usage() == 25.0
    # Start the next observation with the original counters again.
    (proc / "stat").write_bytes(BEFORE)
    assert get.get_data() == (123, 0.25, 0.50, 0.75, 25.0, 53.2, 456, 7, 8, 9)
    observation.assert_called_once_with()
