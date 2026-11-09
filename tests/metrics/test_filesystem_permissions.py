import os
from datetime import datetime, timezone
from operator import attrgetter

import pytest

from database.identity import EventIdentity
from metrics.filesystem import inventory, permissions
from metrics.filesystem.file_integrity import FileDigest
from metrics.filesystem.fim import FileState

OBSERVED = datetime(2026, 11, 9, 10, 0, 0, 123456, tzinfo=timezone.utc)
SSH = b'/etc/ssh/sshd_config'
SUDOERS = b'/etc/sudoers'
CUSTOM = b'/etc/security/tool'
CONFIG = b'c' * 32


def file(path, mode, uid=0, gid=0):
    metadata = inventory.FileMetadata(10, uid, gid, mode, 0)
    return inventory.InventoryEntry(path, 'FOUND', OBSERVED, 'regular', metadata, FileDigest('DISABLED'))


def directory(path, mode):
    metadata = inventory.FileMetadata(0, 0, 0, mode, 0)
    return inventory.InventoryEntry(path, 'SCANNED', OBSERVED, 'directory', metadata)


def observed(*entries):
    return inventory.InventoryResult(entries, CONFIG, OBSERVED)


def state(mode, uid=0, gid=0):
    return FileState(None, 10, uid, gid, mode, OBSERVED.replace(tzinfo=None))


def custom_rule(**options):
    return permissions.PermissionRule('custom', paths=(CUSTOM,), **options)


def kinds(assessment):
    return list(map(attrgetter('kind'), assessment.findings))


def test_new_suid_file_is_reported_with_scope_and_utc_time():
    result = permissions.analyze_permissions(observed(file(CUSTOM, 0o4755)), previous={},
                                             identity=EventIdentity(3, 4, 5), rules=(custom_rule(),))
    finding, = result.findings
    assert (finding.kind, finding.severity, finding.rule_id) == ('SUID', 'HIGH', 'custom')
    assert (finding.host_id, finding.source_id, finding.path, finding.observed_at) == (3, 4, CUSTOM, OBSERVED)
    assert finding.current == permissions.PermissionState(0o4755, 0, 0) and finding.previous is None
    assert 'new' in finding.reason


@pytest.mark.parametrize('mode,old_mode,kind,severity', [
    (0o2755, 0o755, 'SGID', 'HIGH'),
    (0o2700, 0o700, 'SGID', 'LOW'),
    (0o755, 0o4755, 'SUID', 'LOW'),
])
def test_special_permission_changes_compare_to_the_baseline(mode, old_mode, kind, severity):
    result = permissions.analyze_permissions(observed(file(CUSTOM, mode)), previous={CUSTOM: state(old_mode)},
                                             rules=(custom_rule(),))
    finding, = result.findings
    assert (finding.kind, finding.severity) == (kind, severity)
    assert finding.previous.mode == old_mode


@pytest.mark.parametrize('previous', [None, {CUSTOM: state(0o4755)}])
def test_existing_suid_bit_alone_is_not_a_finding(previous):
    result = permissions.analyze_permissions(observed(file(CUSTOM, 0o4755)), previous=previous, rules=(custom_rule(),))
    assert result.findings == ()


def test_world_writable_critical_file_has_one_finding_and_prior_mode():
    result = permissions.analyze_permissions(observed(file(SSH, 0o646)), previous={SSH: state(0o644)})
    finding, = result.findings
    assert (finding.kind, finding.severity) == ('WORLD_WRITABLE', 'HIGH')
    assert finding.previous.mode == 0o644 and finding.current.mode == 0o646
    assert 'previously protected' in finding.reason


def test_sticky_bit_depends_on_object_type_and_scope():
    temporary = b'/tmp'
    cron = b'/etc/cron.d'
    rules = permissions.DEFAULT_RULES + (permissions.PermissionRule('temporary', paths=(temporary,)),)
    result = permissions.analyze_permissions(observed(directory(temporary, 0o1777), directory(cron, 0o1757),
                                                      file(SSH, 0o1646)), rules=rules)
    assert list(map(attrgetter('path'), result.findings)) == [cron, SSH]
    assert kinds(result) == ['WORLD_WRITABLE', 'WORLD_WRITABLE']
    assert 'sticky bit' in result.findings[0].reason


def test_directory_sgid_is_not_treated_as_executable_privilege():
    cron = b'/etc/cron.d'
    result = permissions.analyze_permissions(observed(directory(cron, 0o2755)), previous={})
    assert result.findings == ()


def test_real_inventory_provides_directory_permissions(tmp_path):
    path = tmp_path / 'critical'
    path.mkdir()
    path.chmod(0o777)
    config = inventory.InventoryConfig(files=(), directories=(path,), hash_content=False)
    collected = inventory.collect_inventory(config)
    result = permissions.analyze_permissions(collected, rules=(permissions.PermissionRule('site', paths=(path,), critical=True),))
    finding, = result.findings
    assert finding.path == os.fsencode(path)
    assert finding.kind == 'WORLD_WRITABLE' and finding.current.mode == 0o777
    assert finding.current.owner_uid == os.getuid() and finding.previous is None


def test_wrong_owner_and_owner_change_are_distinct():
    invalid = permissions.analyze_permissions(observed(file(SUDOERS, 0o440, uid=1000)),
                                              previous={SUDOERS: state(0o440)})
    finding, = invalid.findings
    assert (finding.kind, finding.severity) == ('OWNER_MISMATCH', 'HIGH')
    assert finding.previous.owner_uid == 0 and finding.current.owner_uid == 1000
    rule = custom_rule(allowed_uids=(0,), allowed_gids=(10, 11))
    allowed = permissions.analyze_permissions(observed(file(CUSTOM, 0o644, gid=11)),
                                              previous={CUSTOM: state(0o644, gid=10)}, rules=(rule,))
    assert kinds(allowed) == ['OWNER_CHANGED']
    wrong_group = permissions.analyze_permissions(observed(file(CUSTOM, 0o644, gid=12)), rules=(rule,))
    assert kinds(wrong_group) == ['OWNER_MISMATCH']


def test_ssh_group_write_and_site_specific_mode_masks():
    unsafe = permissions.analyze_permissions(observed(file(SSH, 0o664)))
    assert kinds(unsafe) == ['UNSAFE_MODE']
    site = custom_rule(allowed_mode=0o640, forbidden_mode=0o040)
    assert kinds(permissions.analyze_permissions(observed(file(CUSTOM, 0o640)), rules=(site,))) == ['UNSAFE_MODE']
    assert kinds(permissions.analyze_permissions(observed(file(CUSTOM, 0o604)), rules=(site,))) == ['UNSAFE_MODE']


def test_safe_default_modes_allow_distribution_specific_group_ids():
    result = permissions.analyze_permissions(observed(file(SSH, 0o644, gid=100), file(SUDOERS, 0o440, gid=10),
                                                      file(b'/etc/crontab', 0o600),
                                                      file(b'/etc/systemd/system/service.service', 0o644)))
    assert result.findings == ()


def test_missing_and_unobserved_rules_have_explicit_coverage():
    missing = inventory.InventoryEntry(SSH, 'MISSING', OBSERVED)
    result = permissions.analyze_permissions(observed(missing))
    assert result.findings == ()
    assert dict(result.unassessed)[SSH] == 'MISSING'
    assert dict(result.unassessed)[SUDOERS] == 'NOT_OBSERVED'


@pytest.mark.parametrize('partial', [True, False])
def test_unreliable_inventory_withholds_all_findings(partial):
    failed = inventory.InventoryEntry(SUDOERS, 'DENIED', OBSERVED, 'regular')
    entries = (failed,)
    if partial:
        entries += (file(SSH, 0o666),)
    result = permissions.analyze_permissions(observed(*entries), previous={})
    assert result.findings == ()
    assert dict(result.unassessed)[SUDOERS] == 'DENIED'
    if partial:
        assert result.inventory_status == 'PARTIAL'
        assert dict(result.unassessed)[SSH] == 'INCOMPLETE_INVENTORY'
    else:
        assert result.inventory_status == 'FAILED'


def test_directory_without_metadata_is_not_treated_as_safe():
    cron = b'/etc/cron.d'
    old_inventory = observed(inventory.InventoryEntry(cron, 'SCANNED', OBSERVED, 'directory'))
    result = permissions.analyze_permissions(old_inventory)
    assert result.findings == ()
    assert dict(result.unassessed)[cron] == 'METADATA_UNAVAILABLE'


def test_special_exception_is_limited_to_the_approved_path_and_bit():
    other = b'/etc/security/other'
    rule = permissions.PermissionRule('site', directories=('/etc/security',), forbidden_mode=0o6000,
                                      special_exceptions=((CUSTOM, 0o4000),))
    allowed = permissions.analyze_permissions(observed(file(CUSTOM, 0o4755)), previous={}, rules=(rule,))
    assert allowed.findings == ()
    report = permissions.analyze_permissions(observed(file(CUSTOM, 0o6757), file(other, 0o4755)),
                                            previous={}, rules=(rule,))
    assert kinds(report) == ['WORLD_WRITABLE', 'SGID', 'SUID']
    assert report.findings[1].severity == 'CRITICAL'


def test_multiple_independent_risks_without_duplicate_findings():
    tree = permissions.PermissionRule('general', directories=('/etc',), critical=True)
    selected = custom_rule(allowed_uids=(0,), forbidden_mode=0o4022, critical=True)
    report = permissions.analyze_permissions(observed(file(CUSTOM, 0o4777, uid=1000)), previous={},
                                            rules=(tree, selected))
    assert kinds(report) == ['WORLD_WRITABLE', 'SUID', 'UNSAFE_MODE', 'OWNER_MISMATCH']
    assert set(map(attrgetter('rule_id'), report.findings)) == {'custom'}
    assert '0o0020' in report.findings[2].reason


def test_disabled_exact_rule_excludes_path_from_tree_rule():
    tree = permissions.PermissionRule('tree', directories=('/etc/security',))
    result = permissions.analyze_permissions(observed(file(CUSTOM, 0o666)),
                                             rules=(tree, custom_rule(enabled=False)))
    assert result.findings == ()


@pytest.mark.parametrize('rules', [
    (permissions.PermissionRule('invalid', paths=('relative',)),),
    (permissions.PermissionRule('invalid', paths=(CUSTOM,), allowed_uids=(-1,)),),
    (permissions.PermissionRule('invalid', paths=(CUSTOM,), forbidden_mode=0o10000),),
    (permissions.PermissionRule('invalid', paths=(CUSTOM,), special_exceptions=((b'/etc/other', 0o4000),)),),
    (permissions.PermissionRule('invalid', paths=(CUSTOM,), special_exceptions=((CUSTOM, 0o200),)),),
    (custom_rule(), permissions.PermissionRule('duplicate', paths=(CUSTOM,))),
])
def test_invalid_rule_definitions_are_rejected(rules):
    with pytest.raises(ValueError):
        permissions.analyze_permissions(observed(file(CUSTOM, 0o644)), rules=rules)
