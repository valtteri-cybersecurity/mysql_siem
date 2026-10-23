"""Cross-model API v1 checks; raw JSON ingress remains a separate prerequisite."""

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.v1.batch import EventBatchRequest
from contracts.v1.responses import EventBatchResponse


@pytest.fixture
def six_type_batch():
    timestamp = "2026-10-23T12:00:00.000000Z"
    samples = [
        ("ufw.event", {"event_time": timestamp, "action": None, "src_ip": None, "dst_ip": None,
                       "protocol": None, "src_port": 0, "dst_port": 0, "raw_line": "original",
                       "event_hash": hashlib.sha256(b"original").hexdigest(), "reported_hostname": None}),
        ("ssh.auth_event", {"event_time": timestamp, "hostname": "mint", "source_ip": "::1",
                            "username": None, "event_type": "SSH_AUTH_FAILURE", "service": "sshd",
                            "raw_message": "original", "event_hash": "a" * 64}),
        ("dns.query", {"event_time": timestamp, "raw_timestamp": "2026-10-23T12:00:00.000000001Z",
                       "client_ip": None, "domain": "example.org", "query_type": "A", "response_code": None,
                       "filtering_result": "allowed", "filtering_reason": None, "upstream": None,
                       "elapsed_ms": "0.000000001", "cached": None, "dedup_key": "b" * 64}),
        ("system.metrics", {"timestamp": timestamp, "uptime_hours": None, "cpuload1": None,
                            "cpuload5": None, "cpuload15": None, "cpu_usage": None, "cpu_temperature": None,
                            "ram_free_mb": None, "disk_used": None, "disk_free": None, "disk_usage": None}),
        ("filesystem.metrics", {"metric_date": "2026-10-23", "observed_at": timestamp,
                                "modified_last_day": "0", "total_files": "1", "revision": "1"}),
        ("security.metrics", {"date": timestamp, "uptime": "1.00", "blocks": "0", "failed_logins": "0",
                              "unique_ips": "0", "metric_day": "2026-10-23", "revision": "1"}),
    ]
    messages = []
    for index, (kind, payload) in enumerate(samples, start=1):
        messages.append({"message_id": f"00000000-0000-4000-8000-{index:012d}", "message_type": kind,
                         "payload_version": 1, "source_key": "source." + str(index),
                         "created_at": timestamp, "payload": payload})
    return {"protocol_version": 1, "messages": messages}


def test_six_type_batch_roundtrip_and_acknowledgement_contract(six_type_batch):
    original = copy.deepcopy(six_type_batch)
    parsed = EventBatchRequest.model_validate_json(json.dumps(six_type_batch))
    assert parsed.model_dump() == original == six_type_batch
    results = []
    for index, message in enumerate(parsed.messages):
        results.append({"index": index, "message_id": message.message_id, "status": "accepted"})
        assert message.model_config["strict"] is True
        assert message.model_config["extra"] == "forbid"
        for field in type(message).model_fields.values():
            assert field.is_required()
        for field in type(message.payload).model_fields.values():
            assert field.is_required()
    response = {"protocol_version": 1, "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "collector_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "received_at": "2026-10-23T12:00:01.000000Z",
                "committed": True, "results": results}
    assert EventBatchResponse.model_validate_json(json.dumps(response)).model_dump() == response


@pytest.mark.parametrize("index,field,value", [
    (0, "dst_port", None), (1, "source_ip", "fe80::1%eth0"),
    (2, "event_time", "2026-10-23T12:00:00.000001Z"),
    (3, "timestamp", "2026-10-23T12:00:00.000001Z"),
    (4, "revision", "0"), (5, "metric_day", "2026-10-22"),
])
def test_invalid_payload_at_each_position_rejects_entire_six_type_batch(six_type_batch, index, field, value):
    six_type_batch["messages"][index]["payload"][field] = value
    with pytest.raises(ValidationError):
        EventBatchRequest.model_validate(six_type_batch)
    with pytest.raises(ValidationError):
        EventBatchRequest.model_validate_json(json.dumps(six_type_batch))


def test_clean_imports_have_no_database_network_process_or_write_side_effects():
    script = '''
import pathlib
import sys

def audit(event, args):
    if event in ("socket.connect", "socket.bind", "subprocess.Popen", "os.system"):
        raise RuntimeError("Forbidden import side effect")
    if event == "open":
        mode, flags = args[1:3]
        if (isinstance(mode, str) and any(char in mode for char in "wax+")) or flags & 67:
            raise RuntimeError("Forbidden file write")
    if event == "import" and args[0].split(".")[0] in ("pymysql", "database", "metrics", "requests"):
        raise RuntimeError("Unexpected runtime dependency")

sys.addaudithook(audit)
import importlib
for path in pathlib.Path("contracts/v1").glob("*.py"):
    importlib.import_module("contracts.v1." + path.stem)
'''
    result = subprocess.run([sys.executable, "-B", "-c", script],
                            check=False, cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
