from unittest.mock import Mock

import pytest

from ingestion.audit import main
from ingestion.audit.parser import parse_events


def test_default_summary_does_not_print_events(monkeypatch, capsys, event_text):
    event = parse_events(event_text())["events"][0]
    monkeypatch.setattr(main, "collect", Mock(return_value={
        "events": [event], "issues": [], "checkpoint": {}, "coverage": "anchor_available",
    }))
    assert main.main([]) == 0
    output = capsys.readouterr()
    assert "Audit events: 1" in output.out
    assert "/etc/passwd" not in output.out
    assert "checkpoint not saved" in output.out


def test_development_output_is_limited(monkeypatch, capsys, event_text):
    event = parse_events(event_text())["events"][0]
    monkeypatch.setattr(main, "collect", Mock(return_value={
        "events": [event] * 5, "issues": [], "checkpoint": {}, "coverage": "anchor_available",
    }))
    assert main.main(["--show-events", "--limit", "2"]) == 0
    output = capsys.readouterr().out
    assert len(output.splitlines()) == 3
    assert "DO_NOT_RETAIN" not in output
    assert "proctitle" not in output
    assert "+00:00" in output


@pytest.mark.parametrize("error,code", [
    (FileNotFoundError, 1), (PermissionError, 1), (TimeoutError, 1),
    (ValueError, 1), (RuntimeError, 1), (KeyboardInterrupt, 130),
])
def test_safe_failure_and_interruption_codes(monkeypatch, capsys, error, code):
    monkeypatch.setattr(main, "collect", Mock(side_effect=error("SECRET must not be printed")))
    assert main.main([]) == code
    output = capsys.readouterr()
    assert "SECRET" not in output.err + output.out
    assert "checkpoint" in output.err


def test_incomplete_collection_is_failure(monkeypatch, capsys):
    monkeypatch.setattr(main, "collect", Mock(return_value={"events": [], "issues": [
        {"reason": "incomplete_paths"}], "checkpoint": None}))
    assert main.main([]) == 1
    assert "no checkpoint" in capsys.readouterr().err


def test_display_limit_validated_before_collection(monkeypatch):
    collector = Mock()
    monkeypatch.setattr(main, "collect", collector)
    with pytest.raises(SystemExit):
        main.main(["--limit", "21"])
    collector.assert_not_called()
