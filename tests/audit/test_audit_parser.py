import re
from datetime import datetime, timezone

import pytest

from ingestion.audit.parser import parse_events


@pytest.mark.parametrize("path,target", [
    ("/etc/passwd", "passwd"), ("/etc/shadow", "shadow"), ("/etc/sudoers", "sudoers"),
    ("/etc/sudoers.d/admin", "sudoers"), ("/etc/sudoers.d/team/admin", "sudoers"),
])
def test_default_targets_and_safe_metadata(event_text, path, target):
    result = parse_events(event_text(path))
    assert result["issues"] == []
    assert len(result["events"]) == 1
    event = result["events"][0]
    assert event["targets"] == [target]
    assert event["paths"][0]["path"] == path
    assert (event["auid"], event["uid"], event["euid"], event["pid"], event["ppid"]) == (1000, 0, 0, 20, 10)
    assert event["program"] == "test-editor"
    assert event["executable"] == "/usr/bin/test-editor"
    assert event["rule_key"] == "account_files"
    assert event["operation"] == "write_open"
    assert event["event_time"] == datetime.fromtimestamp(1792886390, timezone.utc).replace(microsecond=123000)
    assert event["event_id"] == "1792886390.123:12"
    assert event["success"] is True
    assert not any(key in event for key in ("a0", "a1", "a2", "proctitle", "raw_message", "cwd"))
    assert "DO_NOT_RETAIN" not in repr(result)
    assert "7465737400736563726574" not in repr(result)


@pytest.mark.parametrize("syscall,operation", [
    (1, "write"), (76, "write"), (90, "permissions"), (92, "ownership"),
    (188, "attributes"), (280, "attributes"), (98765, "unknown"), (437, "unknown"),
])
def test_operations(event_text, syscall, operation):
    assert parse_events(event_text(syscall=syscall))["events"][0]["operation"] == operation


@pytest.mark.parametrize("arch,syscall", [("40000003", 15), ("c00000b7", 53)])
def test_architecture_specific_syscalls(event_text, arch, syscall):
    assert parse_events(event_text(arch=arch, syscall=syscall))["events"][0]["operation"] == "permissions"


def test_unknown_arch_does_not_guess_x86_syscall(event_text):
    event = parse_events(event_text(arch="unknown", syscall=90))["events"][0]
    assert event["syscall"] is None
    assert event["operation"] == "unknown"


@pytest.mark.parametrize("success,exit_code,confirmed", [("yes", 0, True), ("no", -13, False)])
def test_confirmed_deletion_and_failed_attempt(event_text, success, exit_code, confirmed):
    event = parse_events(event_text(syscall=87, nametype="DELETE", success=success, exit_code=exit_code))["events"][0]
    assert event["success"] is (success == "yes")
    assert event["paths"][0]["deletion_confirmed"] is confirmed
    assert event["exit_code"] == exit_code


def test_delete_requires_delete_path_evidence(event_text):
    event = parse_events(event_text(syscall=87, nametype="NORMAL", exit_code=0))["events"][0]
    assert event["paths"][0]["deletion_confirmed"] is False


def test_atomic_replace_and_multiple_targets_are_one_event(event_text):
    text = event_text("/etc/passwd", syscall=82, nametype="DELETE", extra_paths=[
        ("/etc/passwd", "CREATE"), ("/etc/shadow", "DELETE"), ("/etc", "PARENT"),
    ])
    result = parse_events(text)
    assert len(result["events"]) == 1
    assert result["events"][0]["targets"] == ["passwd", "shadow"]
    assert result["events"][0]["operation"] == "replace"
    assert len(result["events"][0]["paths"]) == 3
    assert all(not path["deletion_confirmed"] for path in result["events"][0]["paths"])


def test_new_sudoers_file(event_text):
    event = parse_events(event_text("/etc/sudoers.d/new", nametype="CREATE"))["events"][0]
    assert event["operation"] == "create"


def test_relative_hex_and_normalized_paths(event_text):
    text = event_text("./sudoers.d/../passwd").replace('name="./sudoers.d/../passwd"', 'name=706173737764')
    text = text.replace('comm="test-editor"', 'comm=7465737420656469746f72')
    event = parse_events(text)["events"][0]
    assert event["paths"][0]["path"] == "/etc/passwd"
    assert event["program"] == "test editor"
    assert parse_events(event_text("//etc/passwd"))["events"]


def test_relative_directory_fd_is_not_assumed_to_be_cwd(event_text):
    result = parse_events(event_text("passwd").replace("a0=ffffff9c", "a0=3"))
    assert result["events"] == []
    assert result["issues"][0]["reason"] == "unresolved_directory_fd"


def test_creat_on_existing_file_is_write_open(event_text):
    assert parse_events(event_text(syscall=85))["events"][0]["operation"] == "write_open"
    assert parse_events(event_text(syscall=85, nametype="CREATE"))["events"][0]["operation"] == "create"


@pytest.mark.parametrize("path", ["/etc/passwd.bak", "/etc/shadow-old", "/etc/sudoers.different/a", "/tmp/other"])
def test_unknown_paths_ignored(event_text, path):
    result = parse_events(event_text(path))
    assert result["events"] == []
    assert len(result["anchors"]) == 1


def test_parent_directory_is_not_a_changed_target(event_text):
    assert parse_events(event_text("/etc/sudoers.d", nametype="PARENT"))["events"] == []


def test_read_only_open_ignored(event_text):
    assert parse_events(event_text().replace("a2=241", "a2=0"))["events"] == []


def test_missing_optional_fields_remain_unknown(event_text):
    text = event_text()
    for field in ('auid=1000 ', 'uid=0 ', 'euid=0 ', 'ppid=10 ', 'comm="test-editor" ',
                  'exe="/usr/bin/test-editor" ', 'key="account_files" ', 'success=yes ', 'exit=3 '):
        text = re.sub(r"(?<!\S)" + re.escape(field), "", text)
    result = parse_events(text)
    assert result["issues"] == []
    event = result["events"][0]
    for field in ("auid", "uid", "euid", "ppid", "program", "executable", "rule_key", "success", "exit_code"):
        assert event[field] is None


@pytest.mark.parametrize("auid", ["4294967295", "-1"])
def test_unset_auid(event_text, auid):
    assert parse_events(event_text().replace("auid=1000", "auid=" + auid))["events"][0]["auid"] is None


@pytest.mark.parametrize("remove,reason", [
    ("type=PATH", "incomplete_paths"), ("type=SYSCALL", "missing_or_duplicate_syscall"),
])
def test_incomplete_groups(event_text, remove, reason):
    text = "\n".join(line for line in event_text().splitlines() if remove not in line)
    result = parse_events(text)
    assert result["events"] == []
    assert result["issues"][0]["reason"] == reason
    assert result["anchors"] == []


@pytest.mark.parametrize("old,new", [
    ("items=1", ""), ("items=1", "items=2"), ("item=0", "item=5"),
    ("pid=20", "pid=bad"), ("success=yes", "success=maybe"), ("exit=3", "exit=-13"),
    ("syscall=257", ""), ('name="/etc/passwd"', "name=not-hex"),
    ('name="/etc/passwd"', 'name="passwd"'),
])
def test_malformed_and_missing_required_fields(event_text, old, new):
    text = event_text().replace(old, new)
    if new == 'name="passwd"':
        text = "\n".join(line for line in text.splitlines() if "type=CWD" not in line)
    result = parse_events(text)
    assert result["events"] == []
    assert result["issues"]


def test_malformed_record_is_reported_without_raw_data(event_text):
    result = parse_events(event_text() + "sensitive invalid record\n")
    assert result["issues"] == [{"event_id": None, "reason": "invalid_record"}]
    assert "sensitive" not in repr(result)


def test_interleaved_records_dedup_and_identity(event_text):
    first = event_text(serial=12).splitlines()
    second = event_text(serial=13).splitlines()
    text = "\n".join(first[:3] + second[:3] + first[3:] + second[3:] + first)
    result = parse_events(text)
    assert len(result["events"]) == 2
    assert result["issues"] == []
    original = parse_events(event_text())["events"][0]["event_hash"]
    assert result["events"][0]["event_hash"] == original
    assert result["events"][1]["event_hash"] != original
    assert parse_events(event_text(), source_id="other")["events"][0]["event_hash"] != original
    assert len(parse_events(event_text(node="a") + event_text(node="b"))["events"]) == 2


def test_enriched_records_use_raw_fields_only(event_text):
    text = event_text().replace('key="account_files" ', 'key="account_files" \x1dAUID="root" ')
    assert parse_events(text)["issues"] == []


def test_custom_file_directory_and_program_targets(event_text):
    targets = [{"name": "custom", "files": ["/tmp/config"], "directories": ["/opt/config"],
                "executables": ["/usr/bin/test-editor"]}]
    assert parse_events(event_text("/tmp/config"), targets=targets)["events"][0]["targets"] == ["custom"]
    assert parse_events(event_text("/opt/config/sub/file"), targets=targets)["events"]
    assert parse_events(event_text("/tmp/other"), targets=targets)["events"]


def test_event_limit_never_silently_truncates(event_text):
    with pytest.raises(ValueError, match="event limit"):
        parse_events(event_text() + event_text(serial=13), max_events=1)


def test_invalid_time_and_empty_result(event_text):
    assert parse_events(event_text().replace("1792886390.123", "999999999999.123"))["issues"]
    assert parse_events("") == {"events": [], "issues": [], "anchors": []}
