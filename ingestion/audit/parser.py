"""Parse uninterpreted ausearch records, retaining only approved metadata.

PATH item counts establish structural completeness; EOE is optional in disk
logs. PROCTITLE, EXECVE, syscall arguments and raw records are never returned.
An observed write is a file operation, not proof of an account change.
"""

import hashlib
import json
import posixpath
import re
from datetime import datetime, timedelta, timezone

from ingestion.audit.targets import match_targets

HEADER = re.compile(
    r'^(?:node=(?P<node>[^\s]{1,255}) )?type=(?P<type>[A-Z0-9_]+) '
    r'msg=audit\((?P<seconds>[0-9]{1,12})\.(?P<fraction>[0-9]{1,6}):'
    r'(?P<serial>[0-9]{1,20})\):\s*(?P<body>.*)$'
)
FIELD = re.compile(r'''([a-zA-Z0-9_]+)=("[^"\n]*"|'[^'\n]*'|[^\s]+)''')

# Raw syscall numbers depend on architecture. Unknown pairs remain unknown.
SYSCALLS = {
    "c000003e": {
        1: "write", 2: "open", 18: "pwrite64", 20: "writev", 76: "truncate",
        77: "ftruncate", 82: "rename", 85: "creat", 87: "unlink", 90: "chmod",
        91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown", 132: "utime",
        188: "setxattr", 189: "lsetxattr", 190: "fsetxattr", 197: "removexattr",
        198: "lremovexattr", 199: "fremovexattr", 235: "utimes", 257: "openat",
        260: "fchownat", 261: "futimesat", 263: "unlinkat", 264: "renameat",
        268: "fchmodat", 280: "utimensat", 296: "pwritev", 316: "renameat2",
        328: "pwritev2", 437: "openat2", 452: "fchmodat2",
    },
    "40000003": {
        4: "write", 5: "open", 8: "creat", 10: "unlink", 15: "chmod",
        16: "lchown", 38: "rename", 92: "truncate", 93: "ftruncate",
        94: "fchmod", 95: "fchown", 146: "writev", 181: "pwrite64",
        182: "chown", 212: "chown", 295: "openat", 298: "fchownat",
        301: "unlinkat", 302: "renameat", 306: "fchmodat", 353: "renameat2",
        437: "openat2", 452: "fchmodat2",
    },
    "c00000b7": {
        5: "setxattr", 6: "lsetxattr", 7: "fsetxattr", 14: "removexattr",
        15: "lremovexattr", 16: "fremovexattr", 35: "unlinkat", 38: "renameat",
        45: "truncate", 46: "ftruncate", 52: "fchmod", 53: "fchmodat",
        54: "fchownat", 55: "fchown", 56: "openat", 64: "write", 66: "writev",
        68: "pwrite64", 70: "pwritev", 88: "utimensat", 276: "renameat2",
        287: "pwritev2", 437: "openat2", 452: "fchmodat2",
    },
}


def fields_from(body):
    fields = {}
    position = 0
    # ENRICHED logs append interpreted data after ASCII GS; use raw data only.
    body = body.split("\x1d", 1)[0]
    for match in FIELD.finditer(body):
        if body[position:match.start()].strip() or match[1] in fields:
            raise ValueError("Malformed audit fields.")
        fields[match[1]] = match[2]
        position = match.end()
    if body[position:].strip():
        raise ValueError("Malformed audit fields.")
    return fields


def text_field(value):
    if value is None or value in ("(null)", '"(null)"'):
        return None
    if value.startswith(('"', "'")):
        value = value[1:-1]
    else:
        value = bytes.fromhex(value).decode("utf-8")
    if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid audit text.")
    return value


def integer_field(fields, name):
    value = fields.get(name)
    if value is None:
        return None
    if not re.fullmatch(r"-?[0-9]{1,20}", value):
        raise ValueError("Invalid audit integer.")
    number = int(value)
    if name == "auid" and number in (-1, 4294967295):
        return None
    return number


def operation_for(syscall, fields):
    if syscall in ("open", "openat"):
        value = fields.get("a1" if syscall == "open" else "a2")
        if value is None:
            return "open"
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", value):
            raise ValueError("Invalid open flags.")
        if int(value, 16) & (1 | 2 | 64 | 512):
            return "write_open"
        return "read_open"
    if syscall in ("write", "writev", "pwrite64", "pwritev", "pwritev2", "truncate", "ftruncate"):
        return "write"
    if syscall in ("chmod", "fchmod", "fchmodat", "fchmodat2"):
        return "permissions"
    if syscall in ("chown", "fchown", "lchown", "fchownat"):
        return "ownership"
    if syscall in ("rename", "renameat", "renameat2"):
        return "rename"
    if syscall in ("unlink", "unlinkat"):
        return "delete"
    if syscall == "creat":
        # creat also truncates existing files; PATH CREATE proves a new name.
        return "write_open"
    if syscall in ("setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr",
                   "fremovexattr", "utime", "utimes", "futimesat", "utimensat"):
        return "attributes"
    return "unknown"


def parse_group(group, source_id, targets):
    syscalls = []
    paths = []
    cwd = None
    for record_type, body in group["records"]:
        if record_type == "SYSCALL":
            syscalls.append(fields_from(body))
        elif record_type == "PATH":
            paths.append(fields_from(body))
        elif record_type == "CWD":
            value = text_field(fields_from(body).get("cwd"))
            if cwd is not None and cwd != value:
                raise ValueError("Conflicting CWD records.")
            cwd = value
    if len(syscalls) != 1:
        return None, "missing_or_duplicate_syscall"
    fields = syscalls[0]
    count = integer_field(fields, "items")
    if count is None or not 0 <= count <= 1024:
        return None, "missing_or_invalid_items"
    items = [integer_field(path, "item") for path in paths]
    if len(paths) != count or set(items) != set(range(count)):
        return None, "incomplete_paths"
    if "syscall" not in fields or "arch" not in fields:
        return None, "missing_syscall_identity"
    syscall_number = integer_field(fields, "syscall")
    arch = fields["arch"].lower()
    syscall = SYSCALLS.get(arch, {}).get(syscall_number)
    operation = operation_for(syscall, fields)
    success = None
    if "success" in fields:
        if fields["success"] not in ("yes", "no"):
            raise ValueError("Invalid syscall result.")
        success = fields["success"] == "yes"
    exit_code = integer_field(fields, "exit")
    if success is not None and exit_code is not None and success != (exit_code >= 0):
        raise ValueError("Conflicting syscall result.")
    executable = text_field(fields.get("exe"))
    changed_paths = []
    target_names = []
    for path in paths:
        name = text_field(path.get("name"))
        if name is None:
            return None, "missing_path_name"
        if not name.startswith("/"):
            if cwd is None or not cwd.startswith("/"):
                return None, "missing_cwd"
            directory_args = []
            if syscall in ("openat", "openat2", "unlinkat", "fchmodat", "fchmodat2",
                           "fchownat", "utimensat", "futimesat"):
                directory_args = ["a0"]
            elif syscall in ("renameat", "renameat2"):
                directory_args = ["a0", "a2"]
            for argument in directory_args:
                # A relative name uses CWD only with AT_FDCWD, not an arbitrary FD.
                if fields.get(argument, "").lower() not in ("ffffff9c", "ffffffffffffff9c"):
                    return None, "unresolved_directory_fd"
            name = posixpath.join(cwd, name)
        name = posixpath.normpath("/" + name.lstrip("/"))
        if path.get("nametype") == "PARENT":
            continue
        matches = match_targets(name, executable, targets)
        if not matches:
            continue
        for target in matches:
            if target not in target_names:
                target_names.append(target)
        changed_paths.append({
            "path": name, "targets": matches, "nametype": path.get("nametype"),
            "inode": integer_field(path, "inode"), "device": path.get("dev"),
            "deletion_confirmed": operation == "delete" and success is True
            and path.get("nametype") == "DELETE",
        })
    if not changed_paths or operation == "read_open":
        return None, None
    if operation in ("write_open", "create") and any(path["nametype"] == "CREATE" for path in changed_paths):
        operation = "create"
    if operation == "rename":
        for path in changed_paths:
            if path["nametype"] == "CREATE" and any(
                old["path"] == path["path"] and old["nametype"] == "DELETE" for old in changed_paths
            ):
                operation = "replace"
                break
    return {
        "source_id": source_id, "node": group["node"], "event_id": group["event_id"],
        "serial": group["serial"], "event_time": group["event_time"],
        "event_hash": group["event_hash"], "targets": target_names, "paths": changed_paths,
        "auid": integer_field(fields, "auid"), "uid": integer_field(fields, "uid"),
        "euid": integer_field(fields, "euid"), "pid": integer_field(fields, "pid"),
        "ppid": integer_field(fields, "ppid"), "program": text_field(fields.get("comm")),
        "executable": executable, "arch": arch, "syscall_number": syscall_number,
        "syscall": syscall, "operation": operation, "success": success,
        "exit_code": exit_code, "rule_key": text_field(fields.get("key")),
    }, None


def parse_events(output, *, source_id="local", targets=None, max_events=1000):
    """Return events, safe diagnostics and anchors for all complete syscalls.

    A batch with issues must not advance a durable checkpoint. Missing optional
    metadata is None. Identity includes the caller's trusted source scope.
    """
    if not isinstance(output, str) or len(output.encode("utf-8")) > 8 * 1024 * 1024:
        raise ValueError("Invalid or excessive audit output.")
    if not isinstance(source_id, str) or not source_id or len(source_id) > 255:
        raise ValueError("Invalid audit source identity.")
    if type(max_events) is not int or not 1 <= max_events <= 10000:
        raise ValueError("Invalid audit event limit.")
    groups = {}
    issues = []
    for line in output.split("\n"):
        line = line.rstrip("\r")
        if not line.strip() or line == "----" or line.startswith("time->"):
            continue
        match = HEADER.fullmatch(line)
        if match is None:
            issues.append({"event_id": None, "reason": "invalid_record"})
            continue
        event_id = f'{match["seconds"]}.{match["fraction"]}:{match["serial"]}'
        key = (match["node"], event_id)
        if key not in groups:
            if len(groups) >= max_events:
                raise ValueError("Audit event limit exceeded; use a smaller time window.")
            try:
                event_time = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=int(match["seconds"]), microseconds=int(match["fraction"].ljust(6, "0")),
                )
            except OverflowError:
                issues.append({"event_id": event_id, "reason": "invalid_time"})
                continue
            identity = json.dumps([source_id, match["node"], event_id], separators=(",", ":"))
            groups[key] = {
                "node": match["node"], "event_id": event_id, "serial": int(match["serial"]),
                "event_time": event_time, "event_hash": hashlib.sha256(identity.encode()).hexdigest(),
                "records": [],
            }
        # Sensitive record bodies are not retained even while grouping.
        if match["type"] in ("SYSCALL", "PATH", "CWD"):
            record = (match["type"], match["body"])
            if record not in groups[key]["records"]:
                groups[key]["records"].append(record)
    events = []
    anchors = []
    for group in groups.values():
        try:
            event, reason = parse_group(group, source_id, targets)
        except (ValueError, UnicodeError):
            event, reason = None, "invalid_fields"
        if reason is not None:
            issues.append({"event_id": group["event_id"], "reason": reason})
            continue
        anchors.append({"event_id": group["event_id"], "node": group["node"],
                        "event_time": group["event_time"].isoformat()})
        if event is not None:
            events.append(event)
    return {"events": events, "issues": issues, "anchors": anchors}
