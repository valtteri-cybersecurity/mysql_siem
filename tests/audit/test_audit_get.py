import copy
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from ingestion.audit import get, main

NOW = datetime.fromtimestamp(1792886410, timezone.utc)
STATUS = {"lost": 0, "boot_id": "00000000-0000-0000-0000-000000000001", "daemon_pid": 42}


@pytest.fixture
def source(monkeypatch, event_text):
    monkeypatch.setattr(get, "source_status", Mock(return_value=dict(STATUS)))
    command = Mock(return_value=(0, event_text(), ""))
    monkeypatch.setattr(get, "run_command", command)
    return command


def test_commands_bounds_and_candidate_checkpoint(source):
    result = main.collect(now=NOW)
    assert result["issues"] == []
    assert len(result["events"]) == 1
    checkpoint = result["checkpoint"]
    assert checkpoint["until"] == (NOW - timedelta(seconds=10)).isoformat()
    assert checkpoint["anchor"]["event_id"] == "1792886390.123:12"
    json.dumps(checkpoint)  # Can later be stored transactionally without file I/O.
    command = source.call_args.args[0]
    assert command[:5] == ["/usr/sbin/ausearch", "--input-logs", "--message", "SYSCALL", "--debug"]
    assert "--checkpoint" not in command
    assert "--start" in command and "--end" in command
    assert source.call_args.kwargs["max_bytes"] == get.MAX_BYTES
    assert get.source_status.call_count == 2


def test_resume_checks_anchor_and_overlaps_without_mutating_input(source):
    checkpoint = main.collect(now=NOW)["checkpoint"]
    original = copy.deepcopy(checkpoint)
    source.reset_mock()
    batch = get.read_batch(checkpoint=checkpoint, now=NOW + timedelta(seconds=100))
    assert source.call_count == 2
    assert source.call_args_list[0].args[0][-2:] == ["--event", "12"]
    assert batch["start"] == datetime.fromisoformat(checkpoint["until"]) - timedelta(seconds=2)
    assert batch["end"] - batch["start"] == timedelta(seconds=60)
    assert checkpoint == original


def test_missing_rotated_anchor_is_an_error(source):
    checkpoint = main.collect(now=NOW)["checkpoint"]
    source.return_value = (1, "", "<no matches>\n")
    with pytest.raises(RuntimeError, match="anchor missing"):
        main.collect(now=NOW + timedelta(seconds=20), checkpoint=checkpoint)


def test_reboot_and_daemon_restart_rejected(source):
    checkpoint = main.collect(now=NOW)["checkpoint"]
    get.source_status.return_value = dict(STATUS, boot_id="00000000-0000-0000-0000-000000000002")
    with pytest.raises(RuntimeError, match="rebooted"):
        get.read_batch(checkpoint=checkpoint, now=NOW)
    get.source_status.side_effect = [dict(STATUS), dict(STATUS, daemon_pid=99)]
    with pytest.raises(RuntimeError, match="source changed"):
        get.read_batch(now=NOW)


@pytest.mark.parametrize("code,output,error", [
    (1, "", "Permission denied"), (1, "", ""), (2, "", "<no matches>"),
    (0, "", "read warning"), (1, "partial data", "<no matches>"), (10, "", ""),
])
def test_read_errors_are_never_empty_success(source, code, output, error):
    source.return_value = (code, output, error)
    with pytest.raises(RuntimeError, match="Ausearch failed"):
        main.collect(now=NOW)


@pytest.mark.parametrize("result", [(0, "", ""), (1, "", "<no matches>\n")])
def test_empty_success_reports_unverified_retention(source, result):
    source.return_value = result
    batch = main.collect(now=NOW)
    assert batch["events"] == []
    assert batch["issues"] == []
    assert batch["checkpoint"] is not None
    assert batch["coverage"] == "retention_unverified"


@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError, TimeoutError, KeyboardInterrupt])
def test_source_failure_or_interruption_propagates_without_candidate(source, error):
    source.side_effect = error("not logged")
    with pytest.raises(error):
        main.collect(now=NOW)


def test_incomplete_or_malformed_batch_never_proposes_checkpoint(source, event_text):
    source.return_value = (0, event_text() + "invalid record\n", "")
    result = main.collect(now=NOW)
    assert result["issues"]
    assert result["checkpoint"] is None
    source.return_value = (0, event_text().replace("items=1", "items=2"), "")
    assert main.collect(now=NOW)["checkpoint"] is None


def test_event_limit_does_not_advance_checkpoint(source, event_text):
    source.return_value = (0, event_text() + event_text(serial=13), "")
    with pytest.raises(ValueError, match="event limit"):
        main.collect(now=NOW, max_events=1)


def test_half_open_boundary_is_replayed_next_run(source, event_text):
    # The event is exactly at the end second and belongs to the next window.
    source.return_value = (0, event_text(seconds=1792886400), "")
    assert main.collect(now=NOW)["events"] == []
    assert len(main.collect(now=NOW + timedelta(seconds=1))["events"]) == 1


@pytest.mark.parametrize("settings", [
    {"window_seconds": 0}, {"window_seconds": True}, {"max_events": 0},
    {"max_bytes": 100}, {"timeout": float("nan")}, {"timeout": 0},
    {"now": NOW.replace(tzinfo=None)}, {"start": NOW}, {"checkpoint": {}},
])
def test_invalid_settings_fail_before_commands(source, settings):
    arguments = {"now": NOW}
    arguments.update(settings)
    with pytest.raises((ValueError, TypeError)):
        get.read_batch(**arguments)
    source.assert_not_called()
    get.source_status.assert_not_called()


def test_foreign_or_future_checkpoint_rejected(source):
    checkpoint = main.collect(now=NOW)["checkpoint"]
    with pytest.raises(ValueError, match="source"):
        get.read_batch(checkpoint=checkpoint, source_id="other", now=NOW)
    with pytest.raises(ValueError, match="clock moved"):
        get.read_batch(checkpoint=checkpoint, now=NOW - timedelta(seconds=1))


@pytest.mark.parametrize("output", [
    "enabled 1\npid 0\nlost 0\n", "enabled 0\npid 1\nlost 0\n",
    "enabled 1\npid 1\nlost 3\n", "enabled 1\npid 1\n",
    "enabled 1\npid 1\nlost bad\n", "enabled 1\npid 1\nlost 0\nlost 0\n",
])
def test_unavailable_or_losing_audit_source(monkeypatch, output):
    monkeypatch.setattr(get, "run_command", Mock(return_value=(0, output, "")))
    with pytest.raises((ValueError, RuntimeError)):
        get.source_status(time.monotonic() + 2)


def test_read_only_status_command_and_boot_identity(monkeypatch):
    command = Mock(return_value=(0, "enabled 2\npid 42\nlost 0\nbacklog 0\n", ""))
    monkeypatch.setattr(get, "run_command", command)
    monkeypatch.setattr(get.Path, "read_text", lambda self: STATUS["boot_id"])
    assert get.source_status(time.monotonic() + 2) == STATUS
    assert command.call_args.args[0] == ["/usr/sbin/auditctl", "-s"]


def test_status_permission_failure(monkeypatch):
    monkeypatch.setattr(get, "run_command", Mock(return_value=(1, "", "denied")))
    with pytest.raises(RuntimeError, match="status is unavailable"):
        get.source_status(time.monotonic() + 2)


def test_pending_kernel_backlog_blocks_checkpoint(monkeypatch):
    monkeypatch.setattr(get, "run_command", Mock(return_value=(
        0, "enabled 1\npid 42\nlost 0\nbacklog 12\n", "")))
    with pytest.raises(RuntimeError, match="not drained"):
        get.source_status(time.monotonic() + 2)


def test_normal_rotation_with_retained_anchor_and_empty_window(source):
    checkpoint = main.collect(now=NOW)["checkpoint"]
    anchor_output = source.return_value
    source.side_effect = [anchor_output, (1, "", "<no matches>\n")]
    result = main.collect(now=NOW + timedelta(seconds=20), checkpoint=checkpoint)
    assert result["events"] == []
    assert result["checkpoint"]["anchor"] == checkpoint["anchor"]
    assert result["checkpoint"]["until"] > checkpoint["until"]


def test_log_paths_never_become_command_arguments(source, event_text):
    source.return_value = (0, event_text("/etc/sudoers.d/$(touch marker)"), "")
    result = main.collect(now=NOW)
    assert result["events"][0]["paths"][0]["path"] == "/etc/sudoers.d/$(touch marker)"
    assert "touch" not in repr(source.call_args_list)


def test_command_environment_and_return_code(monkeypatch):
    popen = get.subprocess.Popen
    recorded = []

    def start(*args, **kwargs):
        recorded.append(kwargs)
        return popen(*args, **kwargs)

    monkeypatch.setattr(get.subprocess, "Popen", start)
    result = get.run_command([sys.executable, "-c", "import sys; print('safe'); sys.exit(7)"],
                             deadline=time.monotonic() + 5, max_bytes=1024)
    assert result == (7, "safe\n", "")
    assert recorded[0]["env"]["TZ"] == "UTC"
    assert recorded[0]["env"]["LC_ALL"] == "C"
    assert "shell" not in recorded[0]
    assert recorded[0]["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_streaming_size_cap_before_buffering_large_output(stream):
    script = f"import sys; sys.{stream}.write('x' * 2000000)"
    with pytest.raises(ValueError, match="output limit"):
        get.run_command([sys.executable, "-c", script], deadline=time.monotonic() + 5, max_bytes=1024)


def test_timeout_kills_and_reaps_child(monkeypatch):
    popen = get.subprocess.Popen
    children = []

    def start(*args, **kwargs):
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(get.subprocess, "Popen", start)
    with pytest.raises(TimeoutError):
        get.run_command([sys.executable, "-c", "import time; time.sleep(10)"],
                        deadline=time.monotonic() + 0.1, max_bytes=1024)
    assert children[0].returncode is not None
    assert children[0].stdout.closed and children[0].stderr.closed


def test_keyboard_interrupt_also_reaps_child(monkeypatch):
    popen = get.subprocess.Popen
    children = []

    def start(*args, **kwargs):
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(get.subprocess, "Popen", start)
    monkeypatch.setattr(get.selectors.EpollSelector, "select", Mock(side_effect=KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        get.run_command([sys.executable, "-c", "import time; time.sleep(10)"],
                        deadline=time.monotonic() + 5, max_bytes=1024)
    assert children[0].returncode is not None
