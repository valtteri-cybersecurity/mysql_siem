"""Assess Unix modes and ownership from an existing FIM inventory."""

import re
import stat
from dataclasses import dataclass
from datetime import datetime

from metrics.filesystem.file_integrity import approved_path
from metrics.filesystem.fim import FileState, prepare_inventory
from metrics.filesystem.inventory import FileMetadata, InventoryResult

MODE_BITS = 0o7777
SPECIAL_BITS = stat.S_ISUID | stat.S_ISGID
EXECUTE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
UNTRUSTED_WRITE = stat.S_IWGRP | stat.S_IWOTH


@dataclass(frozen=True)
class PermissionRule:
    rule_id: str
    paths: tuple[str, ...] = ()
    directories: tuple[str, ...] = ()
    allowed_uids: tuple[int, ...] = ()
    allowed_gids: tuple[int, ...] = ()
    allowed_mode: int = MODE_BITS
    forbidden_mode: int = 0
    special_exceptions: tuple[tuple[str, int], ...] = ()
    critical: bool = False
    enabled: bool = True


# Distribution-specific group and exact mode requirements belong in site rules.
DEFAULT_RULES = (
    PermissionRule('ssh-config', paths=('/etc/ssh/sshd_config',), directories=('/etc/ssh/sshd_config.d',),
                   allowed_uids=(0,), forbidden_mode=UNTRUSTED_WRITE, critical=True),
    PermissionRule('sudoers', paths=('/etc/sudoers',), directories=('/etc/sudoers.d',),
                   allowed_uids=(0,), forbidden_mode=UNTRUSTED_WRITE, critical=True),
    PermissionRule('cron', paths=('/etc/crontab',), directories=('/etc/cron.d',),
                   allowed_uids=(0,), forbidden_mode=UNTRUSTED_WRITE, critical=True),
    PermissionRule('systemd', directories=('/etc/systemd/system',),
                   allowed_uids=(0,), forbidden_mode=UNTRUSTED_WRITE, critical=True),
    PermissionRule('system-config', paths=('/etc/passwd', '/etc/group', '/etc/fstab'),
                   allowed_uids=(0,), forbidden_mode=UNTRUSTED_WRITE, critical=True),
)


@dataclass(frozen=True)
class PermissionState:
    mode: int
    owner_uid: int
    group_gid: int


@dataclass(frozen=True)
class PermissionFinding:
    path: bytes
    kind: str
    severity: str
    current: PermissionState
    previous: PermissionState | None
    observed_at: datetime
    reason: str
    rule_id: str
    host_id: int | None
    source_id: int | None


@dataclass(frozen=True)
class PermissionAssessment:
    inventory_status: str
    findings: tuple[PermissionFinding, ...]
    unassessed: tuple[tuple[bytes, str], ...]


def index_rules(rules):
    if not isinstance(rules, (tuple, list)) or len(rules) > 128:
        raise ValueError('Invalid permission rule list.')
    ids = set()
    exact = {}
    trees = {}
    exceptions = {}
    for rule in rules:
        if (not isinstance(rule, PermissionRule) or not isinstance(rule.rule_id, str)
                or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', rule.rule_id)
                or rule.rule_id in ids):
            raise ValueError('Invalid or duplicate permission rule ID.')
        ids.add(rule.rule_id)
        if type(rule.enabled) is not bool or type(rule.critical) is not bool:
            raise ValueError('Invalid permission rule flags.')
        for mode in (rule.allowed_mode, rule.forbidden_mode):
            if type(mode) is not int or not 0 <= mode <= MODE_BITS:
                raise ValueError('Invalid permission mode mask.')
        for owners in (rule.allowed_uids, rule.allowed_gids):
            if not isinstance(owners, (tuple, list)):
                raise TypeError('Allowed owners require an ID list.')
            for identifier in owners:
                if type(identifier) is not int or not 0 <= identifier < 2**32:
                    raise ValueError('Invalid allowed owner ID.')
        if not rule.paths and not rule.directories:
            raise ValueError('A permission rule requires a target.')
        for targets, index in ((rule.paths, exact), (rule.directories, trees)):
            if not isinstance(targets, (tuple, list)):
                raise TypeError('Permission targets require a path list.')
            for target in targets:
                path = approved_path(target)
                if path in index:
                    raise ValueError('Duplicate permission target.')
                index[path] = rule
        for path, mode in rule.special_exceptions:
            path = approved_path(path)
            key = (rule.rule_id, path)
            if type(mode) is not int or not mode or mode & ~SPECIAL_BITS or key in exceptions:
                raise ValueError('Invalid or duplicate SUID/SGID exception.')
            exceptions[key] = mode
    for (rule_id, path) in exceptions:
        rule = matching_rule(path, exact, trees)
        if rule is None or rule.rule_id != rule_id:
            raise ValueError('SUID/SGID exception is outside its rule scope.')
    return exact, trees, exceptions


def matching_rule(path, exact, trees):
    rule = exact.get(path)
    if rule is not None:
        return rule
    while path:
        rule = trees.get(path)
        if rule is not None:
            return rule
        path = path.rpartition(b'/')[0]
    return None


def _permission_state(metadata):
    for value, maximum in ((metadata.mode, MODE_BITS), (metadata.owner_uid, 2**32 - 1),
                           (metadata.group_gid, 2**32 - 1)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Invalid permissions or ownership in the inventory or baseline.')
    return PermissionState(metadata.mode, metadata.owner_uid, metadata.group_gid)


def _special_risks(current, before, baseline_known, allowed, forbidden, critical):
    risks = []
    old_mode = 0
    if before is not None:
        old_mode = before.mode
    for bit, kind, owner, execute in ((stat.S_ISUID, 'SUID', current.owner_uid, EXECUTE_BITS),
                                      (stat.S_ISGID, 'SGID', current.group_gid, stat.S_IXGRP)):
        if current.mode & bit:
            if forbidden & bit:
                reason = f'The {kind} bit is forbidden by the permission rule.'
            elif baseline_known and not old_mode & bit and not allowed & bit:
                reason = f'The {kind} bit was added since the verified baseline.'
                if before is None:
                    reason = f'A file carrying the {kind} bit is new to the verified inventory.'
            else:
                continue
            severity = 'LOW'
            if current.mode & execute:
                severity = 'MEDIUM'
                if owner == 0 or critical:
                    severity = 'HIGH'
                if owner == 0 and current.mode & stat.S_IWOTH:
                    severity = 'CRITICAL'
            risks.append((kind, severity, reason))
            forbidden &= ~bit
        elif old_mode & bit and not allowed & bit:
            risks.append((kind, 'LOW', f'The {kind} bit was removed since the verified baseline.'))
    return risks, forbidden


def permission_risks(rule, current, before, *, directory, baseline_known, allowed):
    forbidden = current.mode & (rule.forbidden_mode | (MODE_BITS & ~rule.allowed_mode))
    risks = []
    severity = 'MEDIUM'
    if rule.critical:
        severity = 'HIGH'
    sticky_directory = directory and bool(current.mode & stat.S_ISVTX)
    if current.mode & stat.S_IWOTH and (rule.critical or not sticky_directory):
        reason = 'Other users have write permission.'
        if sticky_directory:
            reason = 'Other-write permission remains set on this critical directory despite the sticky bit.'
        elif before is not None and not before.mode & stat.S_IWOTH:
            reason = 'The previously protected file became writable by other users.'
        risks.append(('WORLD_WRITABLE', severity, reason))
        forbidden &= ~stat.S_IWOTH
    if not directory:
        forbidden &= ~allowed
        special, forbidden = _special_risks(current, before, baseline_known, allowed, forbidden, rule.critical)
        risks.extend(special)
    if forbidden:
        risks.append(('UNSAFE_MODE', severity, f'The file mode contains forbidden bits ({forbidden:#06o}).'))
    if ((rule.allowed_uids and current.owner_uid not in rule.allowed_uids)
            or (rule.allowed_gids and current.group_gid not in rule.allowed_gids)):
        risks.append(('OWNER_MISMATCH', severity, 'The owner UID or GID is outside the approved list.'))
    elif before is not None and (before.owner_uid, before.group_gid) != (current.owner_uid, current.group_gid):
        owner_severity = 'LOW'
        if rule.critical:
            owner_severity = 'MEDIUM'
        risks.append(('OWNER_CHANGED', owner_severity, 'The owner UID or GID changed since the verified baseline.'))
    return risks


def analyze_permissions(inventory, *, previous=None, identity=None, rules=DEFAULT_RULES):
    """Assess a completed inventory. Previous state must be a verified, matching FIM scope."""
    exact, trees, exceptions = index_rules(rules)
    if not isinstance(inventory, InventoryResult):
        raise TypeError('A file inventory result is required.')
    status = inventory.status
    if not inventory.entries:
        status = 'FAILED'
    if status == 'SUCCESS':
        prepare_inventory(inventory)
    host_id = source_id = None
    if identity is not None:
        host_id, source_id = identity.host_id, identity.source_id
    findings = []
    unassessed = {}
    observed = set()
    for entry in inventory.entries:
        path = entry.path
        observed.add(path)
        rule = matching_rule(path, exact, trees)
        if rule is None or not rule.enabled:
            continue
        if entry.status not in ('FOUND', 'SCANNED'):
            unassessed[path] = entry.status
            continue
        if status != 'SUCCESS':
            unassessed[path] = 'INCOMPLETE_INVENTORY'
            continue
        if not isinstance(entry.metadata, FileMetadata):
            unassessed[path] = 'METADATA_UNAVAILABLE'
            continue
        directory = entry.file_type == 'directory'
        if entry.file_type not in ('regular', 'directory') or directory != (entry.status == 'SCANNED'):
            unassessed[path] = 'UNSUPPORTED'
            continue
        current = _permission_state(entry.metadata)
        before = None
        if previous is not None and not directory and path in previous:
            state = previous[path]
            if not isinstance(state, FileState):
                raise ValueError('Invalid verified FIM file state.')
            before = _permission_state(state)
        allowed = exceptions.get((rule.rule_id, path), 0)
        for kind, severity, reason in permission_risks(rule, current, before, directory=directory,
                                                      baseline_known=previous is not None, allowed=allowed):
            findings.append(PermissionFinding(path, kind, severity, current, before, entry.observed_at,
                                              reason, rule.rule_id, host_id, source_id))
    for path in exact.keys() | trees.keys():
        rule = matching_rule(path, exact, trees)
        if path not in observed and rule.enabled:
            unassessed[path] = 'NOT_OBSERVED'
    return PermissionAssessment(status, tuple(findings), tuple(sorted(unassessed.items())))
