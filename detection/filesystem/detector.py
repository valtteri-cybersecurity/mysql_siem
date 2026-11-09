"""Confirm stored FIM transitions and select evidence-backed alerts."""

import json
import re
from datetime import datetime

from database.identity import EventIdentity, validate_id
from detection.common.alerts import make_alert_fingerprint
from metrics.filesystem.file_integrity import approved_path
from metrics.filesystem.fim import FileState, detect_changes
from metrics.filesystem.permissions import (
    PermissionState,
    matching_rule,
    permission_risks,
)

CRITICAL_RULE = 'FIM_CRITICAL_CHANGE_001'
PERMISSION_RULE = 'FIM_PERMISSION_RISK_001'
RULE_KEYS = (CRITICAL_RULE, PERMISSION_RULE)
EVIDENCE_TYPE = 'FIM'
CRITICAL_FILES = ('/etc/ssh/sshd_config', '/etc/sudoers')
CRITICAL_DIRECTORIES = ('/etc/ssh/sshd_config.d', '/etc/sudoers.d', '/etc/systemd/system')


class FimDetectionError(RuntimeError):
    """Detection cannot safely advance its checkpoint."""


def _state(raw, observed_at):
    if raw is None:
        return None, None
    data = json.loads(raw)
    if not isinstance(data, dict) or data.keys() != {'content_sha256', 'size_bytes', 'owner_uid', 'group_gid', 'mode'}:
        raise ValueError('Unexpected FIM state fields.')
    digest = data['content_sha256']
    if digest is not None:
        if not isinstance(digest, str) or re.fullmatch(r'[a-f0-9]{64}', digest) is None:
            raise ValueError('Invalid FIM digest.')
        digest = bytes.fromhex(digest)
    for key, maximum in (('size_bytes', 2**64 - 1), ('owner_uid', 2**32 - 1),
                         ('group_gid', 2**32 - 1), ('mode', 0o7777)):
        if type(data[key]) is not int or not 0 <= data[key] <= maximum:
            raise ValueError('Invalid FIM metadata.')
    return FileState(digest, data['size_bytes'], data['owner_uid'], data['group_gid'], data['mode'], observed_at), data


def confirm_event(row):
    event_id, host, source, collector, sender, path, kind, previous, current, stamp, source_type = row
    try:
        validate_id(event_id)
        identity = EventIdentity(host, source, collector, sender)
        if source_type != 'filesystem' or not isinstance(stamp, datetime) or stamp.tzinfo is not None or stamp.year < 1000:
            raise ValueError('Invalid FIM event scope or timestamp.')
        path = approved_path(path)
        before, old = _state(previous, stamp)
        after, new = _state(current, stamp)
        earlier, later = {}, {}
        if before is not None:
            earlier[path] = before
        if after is not None:
            later[path] = after
        if (path, kind, before, after) not in detect_changes(earlier, later, {path: 'MISSING'}):
            raise ValueError('FIM event does not describe its declared change.')
    except (ValueError, TypeError):
        raise FimDetectionError('Invalid FIM evidence. Checkpoint unchanged.') from None
    return event_id, identity, path, kind, before, after, stamp, old, new


def _significant_risks(path, kind, before, after, policy):
    if kind not in ('CREATED', 'PERMISSION_CHANGED', 'OWNER_CHANGED'):
        return []
    exact, trees, exceptions = policy
    rule = matching_rule(path, exact, trees)
    if rule is None or not rule.enabled:
        return []
    allowed = exceptions.get((rule.rule_id, path), 0)
    current = PermissionState(after.mode, after.owner_uid, after.group_gid)
    previous = None
    previous_kinds = set()
    if before is not None:
        previous = PermissionState(before.mode, before.owner_uid, before.group_gid)
        for risk, _, _ in permission_risks(rule, previous, None, directory=False, baseline_known=False, allowed=allowed):
            previous_kinds.add(risk)
    findings = []
    for risk, severity, reason in permission_risks(rule, current, previous, directory=False,
                                                   baseline_known=True, allowed=allowed):
        if severity not in ('HIGH', 'CRITICAL'):
            continue
        if kind == 'PERMISSION_CHANGED' and (risk in previous_kinds or risk.startswith('OWNER_')):
            continue
        if kind == 'OWNER_CHANGED' and risk != 'OWNER_MISMATCH':
            continue
        findings.append({'kind': risk, 'severity': severity, 'reason': reason, 'rule_id': rule.rule_id})
    return findings


def build_alert(rule_key, event, critical_files, critical_directories, policy):
    if rule_key not in RULE_KEYS:
        raise FimDetectionError('Unknown FIM detection rule.')
    event_id, identity, path, kind, before, after, stamp, old, new = event
    details = {'host_id': identity.host_id, 'source_id': identity.source_id, 'path': path.decode('utf-8', 'backslashreplace'),
               'path_hex': path.hex(), 'event_type': kind, 'previous_state': old, 'current_state': new}
    if rule_key == CRITICAL_RULE:
        critical = path in critical_files
        for directory in critical_directories:
            if path.startswith(directory + b'/'):
                critical = True
                break
        if not critical:
            return None
        title = 'Critical filesystem change'
        description = 'A protected file changed in a verified FIM inventory.'
    else:
        risks = _significant_risks(path, kind, before, after, policy)
        if not risks:
            return None
        details['risks'] = risks
        title = 'Filesystem permission risk'
        description = 'A verified FIM transition introduced a significant permissions or ownership risk.'
    fingerprint = make_alert_fingerprint(rule_key, [identity.host_id, identity.source_id, event_id])
    return {'rule_key': rule_key, 'host_id': identity.host_id, 'title': title, 'description': description,
            'first_seen': stamp, 'last_seen': stamp, 'details': details, 'alert_fingerprint': fingerprint}
