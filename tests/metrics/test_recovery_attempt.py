"""Journal compatibility and per-attempt progress, using temporary files only."""

import json
import os
from types import SimpleNamespace
from unittest.mock import Mock

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


@pytest.mark.parametrize('historical,current', [(False, False), (True, False), (True, True)])
def test_new_journal_is_valid_and_keeps_recovery_information(layout, historical, current):
    record = journal.read_deployment(layout.state)
    record['database_started'] = historical
    record['database_started_current'] = current
    journal.save_deployment(layout.state, record)
    before = (layout.state / 'deployment.json').read_bytes()
    result = journal.read_deployment(layout.state)
    assert result['database_started_current'] is current
    assert result['database_started'] is historical
    assert (layout.state / 'deployment.json').read_bytes() == before
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


def test_retry_with_existing_stage_keeps_sticky_marker_and_resets_current(layout, monkeypatch):
    record = journal.read_deployment(layout.state)
    record['database_started_current'] = True
    journal.save_deployment(layout.state, record)
    next_stage = layout.root / 'next_stage'
    next_stage.mkdir()
    copy = Mock(return_value=next_stage)
    monkeypatch.setattr(service, 'stage_service', copy)
    monkeypatch.setattr(service.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    result = service.prepare_deployment(layout.root, layout.target, 'mysql_siem',
                                        None, layout.stable, layout.state, reset=False)
    assert result == next_stage
    assert copy.call_args.kwargs['settings_source'] == layout.stage
    assert copy.call_args.args[0] == layout.root
    saved = journal.read_deployment(layout.state)
    assert saved['database_started'] is True
    assert saved['database_started_current'] is False
    assert saved['stage'] == str(next_stage)
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



@pytest.mark.parametrize('fault', [
    'legacy-extra', 'current-extra', 'missing-stage', 'mistyped-current',
    'contradictory', 'version', 'invalid-json', 'list', 'mistyped-history',
])
def test_invalid_recovery_state_preserves_all_evidence(layout, monkeypatch, fault):
    record = dict(layout.record)
    if fault == 'legacy-extra':
        record['unknown'] = True
    elif fault == 'current-extra':
        record.update(database_started_current=True, unknown=True)
    elif fault == 'missing-stage':
        record.pop('stage')
    elif fault == 'mistyped-current':
        record['database_started_current'] = 'false'
    elif fault == 'contradictory':
        record.update(database_started=False, database_started_current=True)
    elif fault == 'version':
        record['version'] = 2
    elif fault == 'mistyped-history':
        record['database_started'] = 1
    raw = json.dumps(record)
    if fault == 'invalid-json':
        raw = '{unfinished'
    elif fault == 'list':
        raw = '[]'
    journal_path = layout.state / 'deployment.json'
    journal.write_file(journal_path, raw)
    settings = layout.stage / 'mysql.env'
    settings.write_bytes(b'synthetic retained settings')
    receipt = layout.state / 'receipt.json'
    receipt.write_bytes(b'synthetic retained receipt')
    before = journal_path.read_bytes(), settings.read_bytes(), receipt.read_bytes()
    stage = Mock(side_effect=AssertionError('Invalid journals must never be replaced'))
    monkeypatch.setattr(service, 'stage_service', stage)
    with pytest.raises((journal.InstallationStateError, ValueError)):
        service.prepare_deployment(layout.root, layout.target, 'mysql_siem',
                                   None, layout.stable, layout.state, reset=False)
    with pytest.raises((journal.InstallationStateError, ValueError)):
        service.discard_deployment(layout.state)
    stage.assert_not_called()
    assert (journal_path.read_bytes(), settings.read_bytes(), receipt.read_bytes()) == before
    assert not (layout.state / 'maintenance').exists()
    assert layout.stage.is_dir()
