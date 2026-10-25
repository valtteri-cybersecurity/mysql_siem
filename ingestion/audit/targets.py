"""Watch definitions, separate from collection and parsing."""

import posixpath
import re

DEFAULT_TARGETS = [
    {"name": "passwd", "files": ["/etc/passwd"], "directories": [], "executables": []},
    {"name": "shadow", "files": ["/etc/shadow"], "directories": [], "executables": []},
    {"name": "sudoers", "files": ["/etc/sudoers"],
     "directories": ["/etc/sudoers.d"], "executables": []},
]


def validate_targets(targets):
    """Validate administrator-supplied definitions before reading or rule loading."""
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64:
        raise ValueError('Audit requires 1..64 approved target groups.')
    names = set()
    keys = set()
    count = 0
    for target in targets:
        if not isinstance(target, dict) or set(target) != {
            'name', 'audit_key', 'files', 'directories', 'executables',
        }:
            raise ValueError('Invalid Audit target definition.')
        name, key = target['name'], target['audit_key']
        if (not isinstance(name, str) or re.fullmatch(r'[a-z][a-z0-9_]{0,31}', name) is None
                or not isinstance(key, str) or re.fullmatch(r'siem_[a-z0-9_]{1,26}', key) is None
                or name in names or key in keys):
            raise ValueError('Invalid or duplicate Audit target name/key.')
        names.add(name)
        keys.add(key)
        for kind in ('files', 'directories', 'executables'):
            paths = target[kind]
            if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
                raise ValueError('Audit target paths must be unique lists.')
            if len(paths) != len(set(paths)):
                raise ValueError('Duplicate Audit target path.')
            for path in paths:
                if (not isinstance(path, str) or len(path) > 4096 or path == '/'
                        or re.fullmatch(r'/[a-zA-Z0-9_./+-]+', path) is None
                        or path != posixpath.normpath(path) or path.endswith('/')):
                    raise ValueError('Audit targets require canonical absolute paths without whitespace.')
                count += 1
        if not target['files'] and not target['directories'] and not target['executables']:
            raise ValueError('An Audit target group cannot be empty.')
    if count > 128:
        raise ValueError('Too many Audit target paths.')
    return targets


def match_targets(path, executable=None, targets=None):
    """Match lexical paths only; never follow paths supplied by an audit record."""
    if targets is None:
        targets = DEFAULT_TARGETS
    matches = []
    for target in targets:
        matched = path in target["files"]
        for directory in target["directories"]:
            directory = directory.rstrip("/")
            if path == directory or path.startswith(directory + "/"):
                matched = True
        if executable is not None and executable in target.get("executables", []):
            matched = True
        if matched:
            matches.append(target["name"])
    return matches
