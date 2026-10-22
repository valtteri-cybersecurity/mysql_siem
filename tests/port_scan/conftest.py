from datetime import datetime, timedelta

import pytest

from detection.port_scan.detector import detect_port_scans
from detection.port_scan.main import build_alert


@pytest.fixture
def sample_events():
    events = []
    for index in range(10):
        events.append(
            {
                "id": index + 1,
                "event_time": datetime(2026, 10, 22, 12) + timedelta(seconds=index),
                "action": ("BLOCK", "AUDIT", "ALLOW")[index % 3],
                "src_ip": "192.0.2.1",
                "dst_ip": "198.51.100.1",
                "protocol": "TCP",
                "dst_port": 1000 + index,
            }
        )
    return events


@pytest.fixture
def finding(sample_events):
    return detect_port_scans(sample_events)[0]


@pytest.fixture
def alert(finding):
    return build_alert(finding)[0]
