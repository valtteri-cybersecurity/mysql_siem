from datetime import datetime

import pytest

from ingestion.auth.parser import parse_auth_line


def log_line(message="Failed password for alice from 192.0.2.1 port 54321 ssh2", **changes):
    parts = {"time": "2026-10-22T15:00:00.123456+03:00", "host": "server-a", "service": "sshd[1234]"}
    parts.update(changes)
    return f"{parts['time']} {parts['host']} {parts['service']}: {message}\n"


def test_normal_failure_and_original_timestamp():
    event = parse_auth_line(log_line())
    assert event["event_time"] == datetime(2026, 10, 22, 12, 0, 0, 123456)
    assert event["hostname"] == "server-a"
    assert event["source_ip"] == "192.0.2.1"
    assert event["username"] == "alice"
    assert event["service"] == "sshd"
    assert event["event_type"] == "SSH_AUTH_FAILURE"
    assert event["raw_message"] == log_line().rstrip("\n")
    assert len(event["event_hash"]) == 64


def test_invalid_user_failure_ipv6():
    event = parse_auth_line(log_line(
        "Failed password for invalid user admin from 2001:0db8:0:0::1 port 22 ssh2 [preauth]"
    ))
    assert event["username"] == "admin"
    assert event["source_ip"] == "2001:db8::1"


@pytest.mark.parametrize("message", [
    "Accepted password for alice from 192.0.2.1 port 54321 ssh2",
    "Invalid user admin from 192.0.2.1 port 54321",
    "Connection closed by authenticating user alice 192.0.2.1 port 54321 [preauth]",
    "Disconnected from invalid user admin 192.0.2.1 port 54321 [preauth]",
    "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1 user=alice",
    "Failed publickey for alice from 192.0.2.1 port 54321 ssh2",
    "Failed password for alice from invalid-ip port 54321 ssh2",
    "Failed password for alice from fe80::1%eth0 port 22 ssh2",
    "Failed password for alice from 192.0.2.1 port 0 ssh2",
    "Failed password for alice from 192.0.2.1 port 65536 ssh2",
    "Failed password for alice from 192.0.2.1",
    "Failed password for alice from 192.0.2.1 port 22 ssh2 unexpected suffix",
    "user-supplied text: Failed password for alice from 192.0.2.1 port 22 ssh2",
])
def test_nonfailures_and_malformed_messages_are_skipped(message):
    assert parse_auth_line(log_line(message)) is None


@pytest.mark.parametrize("service", ["sudo[1234]", "app[1234]", "fake-sshd[1234]", "sshd", "sshd[x]"])
def test_service_identity_is_required(service):
    assert parse_auth_line(log_line(service=service)) is None


@pytest.mark.parametrize("line", [None, "", "nonsense", [], 42,
    "Oct 22 15:00:00 server-a sshd[1234]: Failed password for alice from 192.0.2.1 port 22 ssh2",
])
def test_invalid_or_yearless_log_is_skipped(line):
    assert parse_auth_line(line) is None


@pytest.mark.parametrize("timestamp", ["2026-02-30T12:00:00Z", "2026-10-22T12:00:00", "2026-10-22T12:00:00+99:00",
    "0001-01-01T12:00:00Z", "1000-01-01T00:00:00+03:00"])
def test_bad_or_ambiguous_timestamp_is_skipped(timestamp):
    assert parse_auth_line(log_line(time=timestamp)) is None


def test_same_event_offset_and_line_ending_do_not_change_hash():
    first = parse_auth_line(log_line())
    second = parse_auth_line(log_line(time="2026-10-22T12:00:00.123456Z").replace("\n", "\r\n"))
    assert first["event_hash"] == second["event_hash"]


def test_distinct_pid_or_target_host_changes_hash():
    first = parse_auth_line(log_line())
    assert parse_auth_line(log_line(service="sshd[9999]"))["event_hash"] != first["event_hash"]
    assert parse_auth_line(log_line(host="server-b"))["event_hash"] != first["event_hash"]


def test_companion_messages_count_as_one_attempt():
    messages = [
        "Invalid user admin from 192.0.2.1 port 22",
        "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1 user=admin",
        "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2",
        "Connection closed by invalid user admin 192.0.2.1 port 22 [preauth]",
    ]
    assert sum(parse_auth_line(log_line(message)) is not None for message in messages) == 1


@pytest.mark.parametrize("process", ["sshd", "sshd-session", "sshd-auth"])
def test_openssh_process_names_normalize_to_existing_detection_service(process):
    line = log_line(service=f"{process}[1234]")
    event = parse_auth_line(line)
    assert event is not None
    assert event["service"] == "sshd"
    assert event["event_time"] == datetime(2026, 10, 22, 12, 0, 0, 123456)
    assert event["raw_message"] == line.rstrip("\n")
    assert event["event_hash"] == parse_auth_line(log_line())["event_hash"]


@pytest.mark.parametrize("process", ["fake-sshd-auth", "sshd-auth-extra", "sshd-session-extra"])
def test_unrecognized_process_names_are_still_rejected(process):
    assert parse_auth_line(log_line(service=f"{process}[1234]")) is None
