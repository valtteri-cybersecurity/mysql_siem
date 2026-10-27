from datetime import datetime, timezone

import pytest

from ingestion.auth.parser import AuthParseError, parse_auth_line


def log_line(message="Failed password for alice from 192.0.2.1 port 54321 ssh2", **changes):
    parts = {"time": "2026-10-22T15:00:00.123456+03:00", "host": "server-a", "service": "sshd[1234]"}
    parts.update(changes)
    return f"{parts['time']} {parts['host']} {parts['service']}: {message}\n"


def syslog_context(start="2026-01-01T00:00:00+00:00", end="2027-01-01T00:00:00+00:00", zone="UTC"):
    return {"syslog_start": datetime.fromisoformat(start), "syslog_end": datetime.fromisoformat(end),
            "syslog_timezone": zone}


def test_normal_failure_and_original_timestamp():
    event = parse_auth_line(log_line())
    assert event["event_time"] == datetime(2026, 10, 22, 12, 0, 0, 123456)
    assert event["hostname"] == "server-a"
    assert event["source_ip"] == "192.0.2.1"
    assert event["source_port"] == 54321
    assert event["auth_method"] == "password"
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


@pytest.mark.parametrize("method", ["password", "publickey"])
@pytest.mark.parametrize("result,event_type", [("Accepted", "SSH_LOGIN_SUCCESS"), ("Failed", "SSH_AUTH_FAILURE")])
@pytest.mark.parametrize("process", ["sshd", "sshd-session", "sshd-auth"])
def test_ssh_results_and_methods(method, result, event_type, process):
    event = parse_auth_line(log_line(
        f"{result} {method} for alice from 2001:db8::1 port 22 ssh2", service=f"{process}[1234]"
    ))
    assert event["event_type"] == event_type
    assert event["auth_method"] == method
    assert event["service"] == "sshd"
    assert event["source_port"] == 22


@pytest.mark.parametrize("result", ["Accepted", "Failed"])
def test_publickey_fingerprint_and_certificate_id_are_not_stored(result):
    event = parse_auth_line(log_line(
        f"{result} publickey for alice from 192.0.2.1 port 22 ssh2: ED25519-CERT SHA256:public "
        "ID private-certificate-label (serial 1) CA ED25519 SHA256:authority"
    ))
    assert event["raw_message"].endswith("port 22 ssh2")
    assert "private-certificate-label" not in event["raw_message"]
    assert "SHA256" not in event["raw_message"]
    assert event["auth_method"] == "publickey"


@pytest.mark.parametrize("message", [
    "Invalid user admin from 192.0.2.1 port 54321",
    "Connection closed by authenticating user alice 192.0.2.1 port 54321 [preauth]",
    "Disconnected from invalid user admin 192.0.2.1 port 54321 [preauth]",
    "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1 user=alice",
    "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)",
    "Partial publickey for alice from 192.0.2.1 port 22 ssh2",
    "user-supplied text: Failed password for alice from 192.0.2.1 port 22 ssh2",
])
def test_companion_messages_are_skipped(message):
    assert parse_auth_line(log_line(message)) is None


@pytest.mark.parametrize("message", [
    "Failed password for alice from invalid-ip port 54321 ssh2",
    "Failed password for alice from fe80::1%eth0 port 22 ssh2",
    "Failed password for alice from 192.0.2.1 port 0 ssh2",
    "Failed password for alice from 192.0.2.1 port 65536 ssh2",
    "Failed password for alice from 192.0.2.1 port bad ssh2",
    "Failed password for alice from 192.0.2.1",
    "Accepted password for alice port 22 ssh2",
    "Failed password for alice from 192.0.2.1 port 22 ssh2 unexpected suffix",
])
def test_supported_malformed_messages_stop_collection(message):
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(message))


@pytest.mark.parametrize("service", ["sudo[1234]", "app[1234]", "fake-sshd[1234]"])
def test_service_identity_is_required(service):
    assert parse_auth_line(log_line(service=service)) is None


@pytest.mark.parametrize("line", [None, "", "nonsense", [], 42])
def test_unrelated_or_invalid_input_is_skipped(line):
    assert parse_auth_line(line) is None


@pytest.mark.parametrize("timestamp", ["2026-02-30T12:00:00Z", "2026-10-22T12:00:00", "2026-10-22T12:00:00+99:00",
    "0001-01-01T12:00:00Z", "1000-01-01T00:00:00+03:00", "nonsense"])
def test_bad_or_ambiguous_timestamp_stops_collection(timestamp):
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(time=timestamp))


def test_same_event_offset_and_line_ending_do_not_change_hash():
    first = parse_auth_line(log_line())
    second = parse_auth_line(log_line(time="2026-10-22T12:00:00.123456Z").replace("\n", "\r\n"))
    assert first["event_hash"] == second["event_hash"]


def test_legacy_password_hash_is_unchanged():
    import hashlib
    import json

    identity = ["2026-10-22T12:00:00.123456", "server-a", "1234",
                "Failed password for alice from 192.0.2.1 port 54321 ssh2"]
    expected = hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()
    assert parse_auth_line(log_line())["event_hash"] == expected


def test_distinct_attempts_with_same_user_and_ip_keep_distinct_hashes():
    first = parse_auth_line(log_line())
    assert parse_auth_line(log_line(service="sshd[9999]"))["event_hash"] != first["event_hash"]
    assert parse_auth_line(log_line(host="server-b"))["event_hash"] != first["event_hash"]
    assert parse_auth_line(log_line(time="2026-10-22T12:00:01.123456Z"))["event_hash"] != first["event_hash"]
    different_port = log_line("Failed password for alice from 192.0.2.1 port 54322 ssh2")
    assert parse_auth_line(different_port)["event_hash"] != first["event_hash"]


def test_companion_messages_count_as_one_attempt():
    messages = [
        "Invalid user admin from 192.0.2.1 port 22",
        "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1 user=admin",
        "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2",
        "Connection closed by invalid user admin 192.0.2.1 port 22 [preauth]",
    ]
    events = 0
    for message in messages:
        if parse_auth_line(log_line(message)) is not None:
            events += 1
    assert events == 1


@pytest.mark.parametrize("process", ["sshd", "sshd-session", "sshd-auth"])
def test_openssh_process_names_normalize_to_existing_detection_service(process):
    line = log_line(service=f"{process}[1234]")
    event = parse_auth_line(line)
    assert event["service"] == "sshd"
    assert event["raw_message"] == line.rstrip("\n")
    assert event["event_hash"] == parse_auth_line(log_line())["event_hash"]


@pytest.mark.parametrize("process", ["fake-sshd-auth", "sshd-auth-extra", "sshd-session-extra"])
def test_unrecognized_process_names_are_still_rejected(process):
    assert parse_auth_line(log_line(service=f"{process}[1234]")) is None


@pytest.mark.parametrize("message,username", [("LOGIN ON tty1 BY alice", "alice"),
    ("ROOT LOGIN ON tty1", "root"), ("LOGIN ON ttyS0 BY bob", "bob")])
def test_local_tty_success_without_source_ip(message, username):
    event = parse_auth_line(log_line(message, service="login[1234]"))
    assert event["event_type"] == "LOCAL_LOGIN_SUCCESS"
    assert event["username"] == username
    assert event["source_ip"] is None
    assert event["source_port"] is None
    assert event["auth_method"] is None
    assert event["service"] == "login"


def test_local_pam_authentication_failure_without_ip():
    message = ("pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 "
               "tty=/dev/tty1 ruser= rhost=  user=alice")
    event = parse_auth_line(log_line(message, service="login[1234]"))
    assert event["event_type"] == "LOCAL_LOGIN_FAILURE"
    assert event["username"] == "alice"
    assert event["source_ip"] is None
    assert event["auth_method"] == "pam"


def test_local_pam_failure_can_have_no_username():
    event = parse_auth_line(log_line("pam_unix(login:auth): authentication failure; "
                                    "logname= uid=0 euid=0 tty=tty1 ruser= rhost=", service="login[1234]"))
    assert event["event_type"] == "LOCAL_LOGIN_FAILURE"
    assert event["username"] is None


@pytest.mark.parametrize("service,message", [
    ("login", "pam_unix(login:session): session opened for user alice(uid=1000) by (uid=0)"),
    ("login", "pam_unix(remote:session): session opened for user alice by (uid=0)"),
    ("cron", "pam_unix(cron:session): session opened for user root by (uid=0)"),
    ("sudo", "pam_unix(sudo:session): session opened for user root by alice(uid=1000)"),
    ("su", "pam_unix(su:session): session opened for user root by alice(uid=1000)"),
    ("login", "LOGIN ON pts/0 BY alice FROM server-b"),
    ("login", "LOGIN ON tty1 BY alice FROM server-b"),
    ("login", "ROOT LOGIN ON tty1 FROM server-b"),
    ("login", "pam_unix(login:auth): authentication failure; tty=/dev/tty1 rhost=192.0.2.1 user=alice"),
    ("login", "pam_unix(login:auth): authentication failure; tty=ssh rhost= user=alice"),
    ("login", "FAILED LOGIN 1 FROM tty1 FOR alice, Authentication failure"),
])
def test_unproven_sessions_remote_login_and_local_companions_are_not_counted(service, message):
    assert parse_auth_line(log_line(message, service=f"{service}[1234]")) is None


def test_syslog_without_confirmed_context_cannot_be_consumed():
    with pytest.raises(AuthParseError, match="confirmed source interval"):
        parse_auth_line(log_line(time="Oct 22 15:00:00"))


def test_syslog_with_confirmed_year_and_zone():
    event = parse_auth_line(log_line(time="Oct 22 15:00:00"),
                            **syslog_context(zone="Europe/Helsinki"))
    assert event["event_time"] == datetime(2026, 10, 22, 12)
    expected = parse_auth_line(log_line(time="2026-10-22T12:00:00Z"))
    assert event["event_hash"] == expected["event_hash"]


def test_syslog_single_digit_day_and_timezone_object():
    event = parse_auth_line(log_line(time="Jan  2 15:00:00"), **syslog_context(zone=timezone.utc))
    assert event["event_time"] == datetime(2026, 1, 2, 15)


def test_syslog_year_rollover_uses_confirmed_interval():
    context = syslog_context("2026-12-30T00:00:00+00:00", "2027-01-02T00:00:00+00:00")
    december = parse_auth_line(log_line(time="Dec 31 23:59:59"), **context)
    january = parse_auth_line(log_line(time="Jan  1 00:00:01"), **context)
    assert december["event_time"] == datetime(2026, 12, 31, 23, 59, 59)
    assert january["event_time"] == datetime(2027, 1, 1, 0, 0, 1)


@pytest.mark.parametrize("timestamp", ["Mar 29 03:30:00", "Oct 25 03:30:00"])
def test_syslog_nonexistent_or_ambiguous_dst_time_is_rejected(timestamp):
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(time=timestamp), **syslog_context(zone="Europe/Helsinki"))


@pytest.mark.parametrize("timestamp", ["Foo 22 15:00:00", "Feb 30 15:00:00", "Oct 22 25:00:00"])
def test_invalid_syslog_timestamp_is_rejected(timestamp):
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(time=timestamp), **syslog_context())


@pytest.mark.parametrize("changes", [
    {"syslog_timezone": None}, {"syslog_timezone": "Not/A_Zone"},
    {"syslog_start": datetime(2026, 1, 1)}, {"syslog_end": datetime(2026, 1, 1)},
    {"syslog_end": datetime(2028, 1, 1, tzinfo=timezone.utc)},
    {"syslog_end": datetime(2025, 1, 1, tzinfo=timezone.utc)},
])
def test_unconfirmed_or_invalid_syslog_context_is_rejected(changes):
    context = syslog_context()
    context.update(changes)
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(time="Oct 22 15:00:00"), **context)


def test_syslog_time_outside_confirmed_interval_is_rejected():
    context = syslog_context("2026-10-23T00:00:00+00:00", "2026-10-24T00:00:00+00:00")
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(time="Oct 22 15:00:00"), **context)


@pytest.mark.parametrize("message", [
    "Failed password for ali\udcffce from 192.0.2.1 port 22 ssh2",
    "Accepted password for ali\x00ce from 192.0.2.1 port 22 ssh2",
    "Accepted password for " + "a" * 256 + " from 192.0.2.1 port 22 ssh2",
])
def test_supported_events_with_invalid_text_are_rejected_without_exposing_values(message):
    with pytest.raises(AuthParseError) as error:
        parse_auth_line(log_line(message))
    assert "alice" not in str(error.value)
    assert "192.0.2.1" not in str(error.value)


@pytest.mark.parametrize("service", ["sshd", "sshd[x]", "sshd[]", "sshd-auth[bad]"])
def test_supported_event_with_malformed_process_header_is_not_silently_consumed(service):
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(service=service))


def test_a_logged_message_cannot_impersonate_the_source_header():
    message = "user-supplied text host sshd[1234]: Accepted password for alice from 192.0.2.1 port 22 ssh2"
    assert parse_auth_line(log_line(message, service="app[1234]")) is None


def test_a_huge_port_is_rejected_as_a_safe_parser_error():
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line("Failed password for alice from 192.0.2.1 port " + "9" * 5000 + " ssh2"))


def test_local_failure_requires_an_explicit_empty_remote_host():
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line("pam_unix(login:auth): authentication failure; tty=tty1 user=alice",
                                 service="login[1234]"))


def test_publickey_redaction_preserves_hostname_and_username_named_ssh2():
    event = parse_auth_line(log_line("Accepted publickey for ssh2 from 192.0.2.1 port 22 ssh2: ED25519 SHA256:key",
                                     host="ssh2"))
    assert event["hostname"] == "ssh2"
    assert event["username"] == "ssh2"
    assert event["raw_message"].endswith("sshd[1234]: Accepted publickey for ssh2 from 192.0.2.1 port 22 ssh2")


def test_syslog_fold_in_another_year_outside_interval_does_not_hide_valid_event():
    context = syslog_context("2025-10-27T00:00:00+02:00", "2026-10-27T00:00:00+02:00", "Europe/Helsinki")
    event = parse_auth_line(log_line(time="Oct 26 03:30:00"), **context)
    assert event["event_time"] == datetime(2026, 10, 26, 1, 30)


@pytest.mark.parametrize("message", [
    "LOGIN ON tty1 BY", "ROOT LOGIN ON tty1 unexpected suffix",
    "pam_unix(login:auth): authentication failure",
    "pam_unix(login:auth): authentication failure; tty=tty1 rhost= password=private",
])
def test_supported_local_records_with_invalid_data_stop_collection(message):
    with pytest.raises(AuthParseError):
        parse_auth_line(log_line(message, service="login[1234]"))


def test_local_login_and_pam_session_companion_count_once():
    messages = ["pam_unix(login:session): session opened for user alice(uid=1000) by (uid=0)",
                "LOGIN ON tty1 BY alice"]
    recognized = 0
    for message in messages:
        if parse_auth_line(log_line(message, service="login[1234]")) is not None:
            recognized += 1
    assert recognized == 1


@pytest.mark.parametrize("message", [
    "Accepted keyboard-interactive/pam for alice from 192.0.2.1 port 22 ssh2",
    "Failed changed-format for alice from 192.0.2.1 port 22 ssh2",
])
def test_unrecognized_ssh_auth_outcome_is_a_visible_gap(message):
    with pytest.raises(AuthParseError, match="unsupported method or format"):
        parse_auth_line("2026-10-22T12:00:00Z server sshd[12]: " + message)
