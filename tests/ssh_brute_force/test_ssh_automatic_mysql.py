"""Crash recovery, late arrivals and ID commit ordering on the private server."""

import json
from datetime import datetime, timedelta

import pymysql
import pytest

from detection.common.alerts import AlertStorageError
from detection.ssh_brute_force.runner import run_automatic
from ingestion.auth.collector import (
    AUTH_WRITER_LOCK,
    AuthCollectionBusy,
    collect_auth_events,
)
from ingestion.auth.db import save_event
from ingestion.auth.parser import parse_auth_line

START = datetime(2026, 10, 22, 12)
CONFIG = {"batch_size": 1000, "late_seconds": 600, "max_buffer_events": 10000}


@pytest.fixture
def automatic_mysql(mysql, apply_migration):
    for name in ("003_detection_alerts.sql", "004_detection_state.sql", "008_ssh_brute_force_rule.sql"):
        apply_migration(mysql, name)
    return mysql


def insert_events(connection, count=5, *, start=START, step=5, hostname="server-a", source_ip="192.0.2.1", first_pid=100):
    with connection.cursor() as cursor:
        for index in range(count):
            timestamp = (start + timedelta(seconds=index * step)).isoformat(timespec="microseconds")
            event = parse_auth_line(f"{timestamp}Z {hostname} sshd[{first_pid + index}]: "
                                    f"Failed password for user{index} from {source_ip} port 54321 ssh2")
            assert save_event(cursor, event) == 1
    connection.commit()


def read_state(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT s.last_event_id, s.state_data FROM detection_state s "
                       "JOIN detection_rules r ON r.id = s.rule_id WHERE r.rule_key = %s",
                       ("SSH_BRUTE_FORCE_001",))
        row = cursor.fetchone()
    return None if row is None else (row[0], json.loads(row[1]))


def current_schema(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        return cursor.fetchone()[0]


def counts(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM detection_alerts")
        alerts = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alert_evidence")
        return alerts, cursor.fetchone()[0]


def test_failure_count_and_state_persist_across_batches(automatic_mysql):
    insert_events(automatic_mysql)
    config = dict(CONFIG, batch_size=2)
    first = run_automatic(automatic_mysql, config, now=START)
    assert first["new_alerts_saved"] == 0 and read_state(automatic_mysql)[0] == 2
    second = run_automatic(automatic_mysql, config, now=START + timedelta(seconds=60))
    assert second["new_alerts_saved"] == 0 and read_state(automatic_mysql)[0] == 4
    third = run_automatic(automatic_mysql, config, now=START + timedelta(seconds=120))
    assert third["new_alerts_saved"] == 1 and read_state(automatic_mysql)[0] == 5
    assert counts(automatic_mysql) == (1, 5)


def test_calendar_minute_example_from_requirements(automatic_mysql):
    insert_events(automatic_mysql, 2, start=START + timedelta(seconds=45), step=1)
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))["detections_found"] == 0
    insert_events(automatic_mysql, 3, start=START + timedelta(seconds=70), step=1)
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=120))["new_alerts_saved"] == 1
    assert counts(automatic_mysql) == (1, 5)


def test_late_event_with_larger_id_and_older_time_is_not_skipped(automatic_mysql):
    insert_events(automatic_mysql, 4, start=START + timedelta(seconds=20))
    run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))
    insert_events(automatic_mysql, 1, start=START + timedelta(seconds=5), first_pid=900)
    summary = run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=600))
    assert summary["new_events_fetched"] == 1
    assert summary["new_alerts_saved"] == 1
    assert read_state(automatic_mysql)[0] == 5


def test_expired_context_is_not_retained_forever(automatic_mysql):
    insert_events(automatic_mysql, 4)
    run_automatic(automatic_mysql, CONFIG, now=START)
    run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=661))
    assert read_state(automatic_mysql)[1]["events"] == []
    insert_events(automatic_mysql, 1, start=START + timedelta(seconds=25), first_pid=900)
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=700))["new_alerts_saved"] == 0
    assert read_state(automatic_mysql)[0] == 5


def test_new_connection_recovers_tail_without_duplicate_alert(automatic_mysql, private_server):
    insert_events(automatic_mysql, 4)
    run_automatic(automatic_mysql, CONFIG, now=START)
    insert_events(automatic_mysql, 1, start=START + timedelta(seconds=25), first_pid=900)
    with pymysql.connect(unix_socket=private_server, user="root", database=current_schema(automatic_mysql),
                         charset="utf8mb4", autocommit=False) as restarted:
        assert run_automatic(restarted, CONFIG, now=START + timedelta(seconds=60))["new_alerts_saved"] == 1
    automatic_mysql.rollback()
    result = run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=120))
    assert result["new_events_fetched"] == 0
    assert result["existing_alerts_skipped"] == 1
    assert counts(automatic_mysql) == (1, 5)


def test_continuous_attack_across_batches_extends_one_alert(automatic_mysql):
    insert_events(automatic_mysql)
    run_automatic(automatic_mysql, CONFIG, now=START)
    insert_events(automatic_mysql, 5, start=START + timedelta(seconds=25), first_pid=200)
    summary = run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))
    assert summary["alerts_updated"] == 1
    assert counts(automatic_mysql) == (1, 10)


def test_separate_episodes_generate_distinct_alerts(automatic_mysql):
    insert_events(automatic_mysql)
    run_automatic(automatic_mysql, CONFIG, now=START)
    insert_events(automatic_mysql, 5, start=START + timedelta(seconds=180))
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=240))["new_alerts_saved"] == 1
    assert counts(automatic_mysql) == (2, 10)


@pytest.mark.parametrize("changes", [{"hostname": "server-b"}, {"source_ip": "2001:db8::1"}])
def test_hosts_and_ips_do_not_combine_automatically(automatic_mysql, changes):
    insert_events(automatic_mysql, 4)
    insert_events(automatic_mysql, 1, **changes)
    assert run_automatic(automatic_mysql, CONFIG, now=START)["new_alerts_saved"] == 0
    assert read_state(automatic_mysql)[0] == 5


def test_disabled_rule_preserves_pending_ids_until_reenabled(automatic_mysql):
    insert_events(automatic_mysql, 2)
    run_automatic(automatic_mysql, CONFIG, now=START)
    before = read_state(automatic_mysql)
    insert_events(automatic_mysql, 3, start=START + timedelta(seconds=15), first_pid=200)
    with automatic_mysql.cursor() as cursor:
        cursor.execute("UPDATE detection_rules SET enabled = FALSE WHERE rule_key = %s", ("SSH_BRUTE_FORCE_001",))
    automatic_mysql.commit()
    assert not run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))["state_updated"]
    assert read_state(automatic_mysql) == before
    with automatic_mysql.cursor() as cursor:
        cursor.execute("UPDATE detection_rules SET enabled = TRUE WHERE rule_key = %s", ("SSH_BRUTE_FORCE_001",))
    automatic_mysql.commit()
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=120))["new_alerts_saved"] == 1


@pytest.mark.parametrize("failure", ["evidence", "state", "commit"])
def test_automatic_failure_rolls_back_all_alerts_and_checkpoint(automatic_mysql, monkeypatch, failure):
    insert_events(automatic_mysql, 5)
    insert_events(automatic_mysql, 5, hostname="server-b")
    original_commit = automatic_mysql.commit
    if failure == "commit":
        def fail_commit():
            raise pymysql.OperationalError(2013, "test")
        monkeypatch.setattr(automatic_mysql, "commit", fail_commit)
    else:
        with automatic_mysql.cursor() as cursor:
            if failure == "evidence":
                cursor.execute("""CREATE TRIGGER fail_auto BEFORE INSERT ON alert_evidence FOR EACH ROW
                    BEGIN IF NEW.event_id = 10 THEN
                        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure';
                    END IF; END""")
            else:
                cursor.execute("""CREATE TRIGGER fail_auto BEFORE INSERT ON detection_state FOR EACH ROW
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'""")
    with pytest.raises((pymysql.MySQLError, AlertStorageError)):
        run_automatic(automatic_mysql, CONFIG, now=START)
    assert counts(automatic_mysql) == (0, 0)
    assert read_state(automatic_mysql) is None
    if failure == "commit":
        monkeypatch.setattr(automatic_mysql, "commit", original_commit)
    else:
        with automatic_mysql.cursor() as cursor:
            cursor.execute("DROP TRIGGER fail_auto")
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))["new_alerts_saved"] == 2
    assert read_state(automatic_mysql)[0] == 10
    assert counts(automatic_mysql) == (2, 10)


def test_existing_checkpoint_survives_failed_extension(automatic_mysql):
    insert_events(automatic_mysql)
    run_automatic(automatic_mysql, CONFIG, now=START)
    before = read_state(automatic_mysql)
    insert_events(automatic_mysql, 1, start=START + timedelta(seconds=25), first_pid=900)
    with automatic_mysql.cursor() as cursor:
        cursor.execute("""CREATE TRIGGER fail_state_update BEFORE UPDATE ON detection_state FOR EACH ROW
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'""")
    with pytest.raises(pymysql.MySQLError):
        run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))
    assert read_state(automatic_mysql) == before
    assert counts(automatic_mysql) == (1, 5)
    with automatic_mysql.cursor() as cursor:
        cursor.execute("DROP TRIGGER fail_state_update")
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=120))["alerts_updated"] == 1
    assert counts(automatic_mysql) == (1, 6)


def test_ssh_state_cannot_overwrite_port_scan_state(automatic_mysql):
    with automatic_mysql.cursor() as cursor:
        cursor.execute("INSERT INTO detection_state (rule_id, last_event_id, state_data) "
                       "SELECT id, 17, %s FROM detection_rules WHERE rule_key = %s",
                       ('{"version":1,"events":[]}', "PORT_SCAN_001"))
    automatic_mysql.commit()
    insert_events(automatic_mysql)
    run_automatic(automatic_mysql, CONFIG, now=START)
    with automatic_mysql.cursor() as cursor:
        cursor.execute("SELECT last_event_id FROM detection_state s JOIN detection_rules r ON r.id = s.rule_id "
                       "WHERE r.rule_key = %s", ("PORT_SCAN_001",))
        assert cursor.fetchone() == (17,)
    assert read_state(automatic_mysql)[0] == 5


def test_irrelevant_event_id_advances_checkpoint_without_alert(automatic_mysql):
    insert_events(automatic_mysql, 1)
    with automatic_mysql.cursor() as cursor:
        cursor.execute("UPDATE auth_events SET event_type = %s", ("SSH_AUTH_SUCCESS",))
    automatic_mysql.commit()
    result = run_automatic(automatic_mysql, CONFIG, now=START)
    assert result["new_events_fetched"] == 1 and result["events_analyzed"] == 0
    assert read_state(automatic_mysql) == (1, {"version": 1, "events": []})


def test_global_writer_lock_prevents_out_of_order_collector_commits(automatic_mysql, private_server, tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_text("2026-10-22T12:00:01Z server-a sshd[200]: Failed password for bob from 192.0.2.1 port 22 ssh2\n")
    with pymysql.connect(unix_socket=private_server, user="root", database=current_schema(automatic_mysql),
                         autocommit=False) as writer:
        with writer.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0)", (AUTH_WRITER_LOCK,))
            assert cursor.fetchone() == (1,)
        writer.begin()
        with writer.cursor() as cursor:
            save_event(cursor, parse_auth_line("2026-10-22T12:00:00Z server-a sshd[100]: Failed password for alice from 192.0.2.1 port 22 ssh2"))
        with pytest.raises(AuthCollectionBusy):
            collect_auth_events(automatic_mysql, logfile, collector_id="different-host")
        # Detection has its own lock and sees no prematurely committed higher ID.
        assert run_automatic(automatic_mysql, CONFIG, now=START)["new_events_fetched"] == 0
        assert read_state(automatic_mysql)[0] == 0
        writer.commit()
        with writer.cursor() as cursor:
            cursor.execute("SELECT RELEASE_LOCK(%s)", (AUTH_WRITER_LOCK,))
    assert collect_auth_events(automatic_mysql, logfile, collector_id="different-host")["inserted"] == 1
    assert run_automatic(automatic_mysql, CONFIG, now=START + timedelta(seconds=60))["new_events_fetched"] == 2
    assert read_state(automatic_mysql)[0] == 2


def test_bounded_collection_counts_and_resumes_without_loss(automatic_mysql, tmp_path):
    logfile = tmp_path / "auth.log"
    lines = []
    for index in range(3):
        lines.append(
            f"2026-10-22T12:00:0{index}Z server-a sshd[{100 + index}]: "
            "Failed password for alice from 192.0.2.1 port 22 ssh2\n"
        )
    logfile.write_text("".join(lines))
    stats = {}
    assert collect_auth_events(automatic_mysql, logfile, collector_id="test", stats=stats, max_lines=2)["inserted"] == 2
    assert stats["lines_read"] == 2
    assert stats["failures_recognized"] == 2
    assert stats["duplicates"] == 0
    assert stats["successes_recognized"] == 0
    assert stats["local_logins_recognized"] == 0
    assert stats["budget_exhausted"] is True
    assert stats["remaining_bytes"] == len(lines[2].encode())
    assert collect_auth_events(automatic_mysql, logfile, collector_id="test", stats=stats, max_lines=2)["inserted"] == 1
    assert stats["lines_read"] == 1
    assert stats["failures_recognized"] == 1
    assert stats["budget_exhausted"] is False
    assert stats["remaining_bytes"] == 0
    replay = tmp_path / "replayed-auth.log"
    replay.write_bytes(logfile.read_bytes())
    assert collect_auth_events(automatic_mysql, replay, collector_id="test", stats=stats)["inserted"] == 0
    assert stats["lines_read"] == 3
    assert stats["failures_recognized"] == 3
    assert stats["duplicates"] == 3
    assert stats["unrecognized_lines"] == 0
    assert stats["invalid_lines"] == 0
    assert stats["remaining_bytes"] == 0
    assert stats["budget_exhausted"] is False
    assert stats["elapsed_seconds"] >= 0
