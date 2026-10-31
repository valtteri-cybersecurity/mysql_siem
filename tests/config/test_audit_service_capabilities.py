from pathlib import Path


def test_audit_unit_capabilities():
    root = Path(__file__).resolve().parents[2]
    path = root / "config/systemd/mysql-siem-audit.service"

    lines = path.read_text(encoding="utf-8").splitlines()

    assert (
        "CapabilityBoundingSet="
        "CAP_AUDIT_CONTROL CAP_SETUID CAP_SETGID"
    ) in lines

    assert "AmbientCapabilities=CAP_SETUID" in lines
    assert "NoNewPrivileges=true" in lines
    assert "RestrictSUIDSGID=true" in lines

    assert lines.count("AmbientCapabilities=CAP_SETUID") == 1
