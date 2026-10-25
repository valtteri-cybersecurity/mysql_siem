import json
import os
from types import SimpleNamespace

import pytest

from config import installation_state as journal
from config import service_installation as service


@pytest.fixture
def layout(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, 'trusted_state', lambda path: None)
    monkeypatch.setattr(journal, 'require_install_lock', lambda: None)
    monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
    monkeypatch.setattr(service, 'deployment_paths', lambda *args: None)
    monkeypatch.setattr(service, 'restore_missing_staged_settings', lambda *args: None)
    root = tmp_path / 'root'
    root.mkdir()
    stage = root / 'stage'
    stage.mkdir()
    target = root / 'service'
    stable = root / 'python'
    state = root / 'state'
    state.mkdir()
    record = {
        'version': 1,
        'stage': str(stage), 'target': str(target), 'stable': str(stable),
        'user': 'mysql_siem', 'candidate': None, 'phase': 'staged',
        'identity': {}, 'publication': None, 'database_started': True,
        'cron_digest': None, 'checkpoint_transition': None,
    }
    journal.write_file(state / 'deployment.json', json.dumps(record) + '\n')
    return SimpleNamespace(root=root, stage=stage, target=target, stable=stable,
                           state=state, record=record)


def test_legacy_journal_is_accepted_without_being_rewritten(layout):
    before = (layout.state / 'deployment.json').read_bytes()
    record = journal.read_deployment(layout.state)
    assert record['database_started'] is True
    assert record['database_started_current'] is False
    assert (layout.state / 'deployment.json').read_bytes() == before


def test_new_journal_is_valid_and_keeps_recovery_information(layout):
    record = journal.read_deployment(layout.state)
    record['database_started_current'] = True
    journal.save_deployment(layout.state, record)
    result = journal.read_deployment(layout.state)
    assert result['database_started_current'] is True
    assert result['database_started'] is True
    assert result['stage'] == str(layout.stage)


@pytest.mark.parametrize('value', [None, 1, 'true', [], {}])
def test_per_attempt_flag_requires_bool(layout, value):
    record = journal.read_deployment(layout.state)
    record['database_started_current'] = value
    journal.save_deployment(layout.state, record)
    with pytest.raises(journal.InstallationStateError, match='progress metadata'):
        journal.read_deployment(layout.state)


def test_per_attempt_flag_cannot_claim_database_without_sticky_marker(layout):
    record = journal.read_deployment(layout.state)
    record['database_started'] = False
    record['database_started_current'] = True
    journal.save_deployment(layout.state, record)
    with pytest.raises(journal.InstallationStateError, match='progress metadata'):
        journal.read_deployment(layout.state)


def test_unknown_extra_fields_still_fail_closed(layout):
    record = journal.read_deployment(layout.state)
    record['unexpected'] = True
    journal.save_deployment(layout.state, record)
    with pytest.raises(journal.InstallationStateError, match='Invalid deployment recovery journal'):
        journal.read_deployment(layout.state)


@pytest.mark.parametrize('current', [False, True])
def test_discard_preserves_database_started_recovery_and_reports_attempt(layout, capsys, current):
    record = journal.read_deployment(layout.state)
    record['database_started_current'] = current
    journal.save_deployment(layout.state, record)
    service.discard_deployment(layout.state)
    output = capsys.readouterr().err
    assert ('during this installation attempt' if current
            else 'during an earlier interrupted installation attempt') in output
    assert layout.stage.is_dir()
    assert journal.read_deployment(layout.state)['database_started'] is True


def test_retry_with_existing_stage_keeps_sticky_marker_and_resets_current(layout):
    record = journal.read_deployment(layout.state)
    record['database_started_current'] = True
    journal.save_deployment(layout.state, record)
    result = service.prepare_deployment(layout.root, layout.target, 'mysql_siem',
                                        None, layout.stable, layout.state, reset=False)
    assert result == layout.stage
    saved = journal.read_deployment(layout.state)
    assert saved['database_started'] is True
    assert saved['database_started_current'] is False
    assert saved['stage'] == str(layout.stage)
    assert layout.stage.exists()


def test_reset_retry_keeps_historical_marker_but_resets_attempt(layout, monkeypatch):
    record = journal.read_deployment(layout.state)
    record['database_started_current'] = True
    journal.save_deployment(layout.state, record)
    next_stage = layout.root / 'next_stage'
    next_stage.mkdir()
    monkeypatch.setattr(service, 'stage_service', lambda *args, **kwargs: next_stage)
    monkeypatch.setattr(service.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    result = service.prepare_deployment(layout.root, layout.target, 'mysql_siem',
                                        None, layout.stable, layout.state, reset=True)
    saved = journal.read_deployment(layout.state)
    assert result == next_stage
    assert saved['database_started'] is True
    assert saved['database_started_current'] is False
    assert saved['stage'] == str(next_stage)
    assert layout.stage.exists()


def test_first_attempt_starts_with_both_flags_false(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, 'trusted_state', lambda path: None)
    monkeypatch.setattr(journal, 'require_install_lock', lambda: None)
    monkeypatch.setattr(service, 'trusted_directory', lambda path: None)
    root = tmp_path / 'root'
    root.mkdir()
    state = root / 'state'
    stage = root / 'stage'
    stage.mkdir()
    monkeypatch.setattr(service, 'stage_service', lambda *args, **kwargs: stage)
    monkeypatch.setattr(service.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    service.prepare_deployment(root, root / 'app', 'mysql_siem', None, root / 'python', state, reset=True)
    saved = journal.read_deployment(state)
    assert saved['database_started'] is False
    assert saved['database_started_current'] is False


def test_database_started_action_marks_both_flags(layout, monkeypatch):
    monkeypatch.setattr(journal, 'require_maintenance', lambda state: None)
    monkeypatch.setattr(journal, 'STATE_DIR', layout.state)
    record = journal.read_deployment(layout.state)
    assert record['database_started_current'] is False
    service.main(['database-started'])
    saved = journal.read_deployment(layout.state)
    assert saved['database_started'] is True
    assert saved['database_started_current'] is True


def test_legacy_journal_still_preserved_when_discarded(layout, capsys):
    service.discard_deployment(layout.state)
    assert 'earlier interrupted installation attempt' in capsys.readouterr().err
    assert (layout.state / 'deployment.json').exists()
    assert layout.stage.exists()


def test_discard_without_any_database_start_removes_only_uncommitted_stage(layout):
    record = journal.read_deployment(layout.state)
    record['database_started'] = False
    record['database_started_current'] = False
    journal.save_deployment(layout.state, record)
    service.discard_deployment(layout.state)
    assert not layout.stage.exists()
    assert not (layout.state / 'deployment.json').exists()

