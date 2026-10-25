"""Read bounded UTC windows using read-only auditctl/ausearch commands.

No ausearch --checkpoint file is used: its automatic position can include
records outside search filters. The returned candidate is never persisted here.
"""

import hashlib
import json
import math
import os
import re
import selectors
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ingestion.audit.parser import HEADER, parse_events

MAX_BYTES = 4 * 1024 * 1024
SETTLE_SECONDS = 10
OVERLAP_SECONDS = 2
LOG_OWNER = 0


def run_command(command, *, deadline, max_bytes):
    """Bound both pipes while reading, and reap the child even on interruption."""
    environment = os.environ.copy()
    environment.update(LC_ALL="C", TZ="UTC")
    if time.monotonic() >= deadline:
        raise TimeoutError("Audit collection timed out.")
    # Callers use fixed command names and argument arrays, never a shell.
    process = subprocess.Popen(  # nosec B603
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment,
    )
    output = {"stdout": bytearray(), "stderr": bytearray()}
    size = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Audit collection timed out.")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("Audit output limit exceeded; use a smaller window.")
                    output[key.data].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Audit collection timed out.")
        return_code = process.wait(timeout=remaining)
        return return_code, output["stdout"].decode("utf-8"), output["stderr"].decode("utf-8")
    except subprocess.TimeoutExpired:
        raise TimeoutError("Audit collection timed out.") from None
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


def source_status(deadline):
    code, output, error = run_command(["/usr/sbin/auditctl", "-s"], deadline=deadline, max_bytes=16384)
    if code != 0 or error.strip():
        raise RuntimeError("Audit status is unavailable; check privileges and installation.")
    values = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("enabled", "pid", "lost", "backlog"):
            if parts[0] in values or not parts[1].isascii() or not parts[1].isdigit():
                raise ValueError("Invalid audit status.")
            values[parts[0]] = int(parts[1])
    if set(values) != {"enabled", "pid", "lost", "backlog"}:
        raise ValueError("Incomplete audit status.")
    if values["enabled"] not in (1, 2) or values["pid"] == 0:
        raise RuntimeError("Auditing is disabled or auditd is not running.")
    if values["lost"] != 0:
        raise RuntimeError("Kernel reports lost audit records; recovery review required.")
    if values["backlog"] != 0:
        raise RuntimeError("Audit queue is not drained; retry without advancing checkpoint.")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if re.fullmatch(r"[0-9a-f-]{36}", boot_id) is None:
        raise ValueError("Invalid boot identity.")
    return {"lost": values["lost"], "boot_id": boot_id, "daemon_pid": values["pid"]}


def utc_time(value):
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Audit times must include a timezone.")
    return value.astimezone(timezone.utc)


def validate_checkpoint(checkpoint, source_id):
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "version", "source_id", "until", "anchor", "lost", "boot_id",
    }:
        raise ValueError("Invalid audit checkpoint.")
    if type(checkpoint["version"]) is not int or checkpoint["version"] != 1:
        raise ValueError("Unsupported audit checkpoint version.")
    if checkpoint["source_id"] != source_id or checkpoint["lost"] != 0:
        raise ValueError("Audit checkpoint source or loss counter changed.")
    if not isinstance(checkpoint["boot_id"], str) or re.fullmatch(
        r"[0-9a-f-]{36}", checkpoint["boot_id"]
    ) is None:
        raise ValueError("Invalid checkpoint boot identity.")
    until = utc_time(datetime.fromisoformat(checkpoint["until"]))
    if until.microsecond:
        raise ValueError("Checkpoint boundary must be a whole second.")
    anchor = checkpoint["anchor"]
    if anchor is not None:
        if not isinstance(anchor, dict) or set(anchor) != {"event_id", "node", "event_time"}:
            raise ValueError("Invalid audit anchor.")
        if not isinstance(anchor["event_id"], str) or re.fullmatch(
            r"[0-9]{1,12}\.[0-9]{1,6}:[0-9]{1,20}", anchor["event_id"]
        ) is None:
            raise ValueError("Invalid audit anchor identity.")
        if anchor["node"] is not None and not isinstance(anchor["node"], str):
            raise ValueError("Invalid audit anchor node.")
        anchor_time = utc_time(datetime.fromisoformat(anchor["event_time"]))
        if anchor_time >= until:
            raise ValueError("Audit anchor exceeds checkpoint boundary.")
    return until


def search(start, end, *, deadline, max_bytes, serial=None):
    command = ["/usr/sbin/ausearch", "--input-logs", "--message", "SYSCALL", "--debug",
               "--start", start.strftime("%m/%d/%Y"), start.strftime("%H:%M:%S"),
               "--end", end.strftime("%m/%d/%Y"), end.strftime("%H:%M:%S")]
    if serial is not None:
        command.extend(["--event", serial])
    # Keep the default uninterpreted format: unlike --raw it emits an explicit
    # no-matches marker. Status 1 alone also means argument or file read errors.
    code, output, error = run_command(command, deadline=deadline, max_bytes=max_bytes)
    if code == 1 and not output.strip() and error.strip() == "<no matches>":
        return ""
    if code != 0 or error.strip():
        raise RuntimeError("Ausearch failed or reported diagnostics; checkpoint unchanged.")
    return output


def read_batch(*, checkpoint=None, source_id="local", start=None, now=None,
               window_seconds=60, max_events=1000, max_bytes=MAX_BYTES, timeout=10):
    """Return raw output and a provisional checkpoint, with no durable writes.

    On first use read only the latest settled window, unless start is supplied.
    Resume overlaps two seconds: storage must deduplicate event_hash. A retained
    anchor detects rotation past committed data. Without an anchor, retention
    coverage cannot be proven; the result explicitly reports that limitation.
    """
    if type(window_seconds) is not int or not 3 <= window_seconds <= 300:
        raise ValueError("Audit window must be within 3..300 seconds.")
    if type(max_events) is not int or not 1 <= max_events <= 10000:
        raise ValueError("Invalid audit event limit.")
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 8 * 1024 * 1024:
        raise ValueError("Invalid audit byte limit.")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("Audit timeout must be within 0..60 seconds.")
    if not isinstance(source_id, str) or not source_id or len(source_id) > 255:
        raise ValueError("Invalid audit source identity.")
    now = utc_time(now if now is not None else datetime.now(timezone.utc))
    settled = (now - timedelta(seconds=SETTLE_SECONDS)).replace(microsecond=0)
    if checkpoint is not None:
        if start is not None:
            raise ValueError("Specify a start or a checkpoint, not both.")
        until = validate_checkpoint(checkpoint, source_id)
        if until > settled:
            raise ValueError("Audit clock moved backwards; checkpoint unchanged.")
        start = until - timedelta(seconds=OVERLAP_SECONDS)
    elif start is None:
        start = settled - timedelta(seconds=window_seconds)
    start = utc_time(start).replace(microsecond=0)
    end = min(start + timedelta(seconds=window_seconds), settled)
    if start >= end:
        raise ValueError("Audit start must precede the settled boundary.")
    deadline = time.monotonic() + timeout
    before = source_status(deadline)
    anchor = None
    if checkpoint is not None:
        if before["boot_id"] != checkpoint["boot_id"]:
            raise RuntimeError("Audit source rebooted; recovery review required.")
        anchor = checkpoint["anchor"]
        if anchor is not None:
            instant = utc_time(datetime.fromisoformat(anchor["event_time"]))
            output = search(instant.replace(microsecond=0), instant.replace(microsecond=0),
                            deadline=deadline, max_bytes=max_bytes, serial=anchor["event_id"].split(":")[1])
            parsed = parse_events(output, source_id=source_id, max_events=max_events)
            if parsed["issues"] or anchor not in parsed["anchors"]:
                raise RuntimeError("Audit anchor missing or incomplete; possible rotation data loss.")
    output = search(start, end, deadline=deadline, max_bytes=max_bytes)
    after = source_status(deadline)
    if before != after:
        raise RuntimeError("Audit source changed during collection; checkpoint unchanged.")
    return {
        "output": output, "start": start, "end": end, "anchor": anchor,
        "source_id": source_id, "status": after, "max_events": max_events,
    }


def log_inventory(logfile):
    """Numbered uncompressed auditd rotations, oldest first; never glob log data."""
    logfile = Path(logfile)
    rotations = []
    for path in logfile.parent.iterdir():
        prefix = logfile.name + '.'
        suffix = path.name[len(prefix):] if path.name.startswith(prefix) else ''
        if suffix.isascii() and suffix.isdigit():
            rotations.append((int(suffix), path))
    if len(rotations) > 256:
        raise ValueError('Too many Audit rotations; collection budget exceeded.')
    rotations.sort(reverse=True)
    paths = [path for _, path in rotations] + [logfile]
    inventory = []
    for path in paths:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != LOG_OWNER
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise ValueError('Unsafe Audit log ownership, mode or file type.')
        inventory.append({'path': path, 'device': info.st_dev, 'inode': info.st_ino,
                          'size': info.st_size})
    return inventory


def log_fingerprint(infile, offset):
    saved = infile.tell()
    infile.seek(max(0, offset - 256))
    value = hashlib.sha256(infile.read(min(offset, 256))).hexdigest()
    infile.seek(saved)
    return value


def open_log_source(item):
    descriptor = os.open(item['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != LOG_OWNER
                or info.st_mode & 0o022 or (info.st_dev, info.st_ino) != (item['device'], item['inode'])):
            raise ValueError('Audit source changed or is unsafe; retry without advancing.')
        return os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise


def runtime_health():
    """The fixed root launcher supplies a fresh status, then permanently drops UID."""
    raw = os.environ.get('SIEM_AUDIT_HEALTH', '')
    if len(raw) > 1024:
        raise ValueError('Invalid Audit launcher status.')
    health = json.loads(raw)
    if not isinstance(health, dict) or set(health) != {'lost', 'boot_id', 'daemon_pid', 'observed_at'}:
        raise ValueError('Audit must run through its protected launcher.')
    if (type(health['lost']) is not int or health['lost'] != 0
            or type(health['daemon_pid']) is not int or health['daemon_pid'] <= 0
            or not isinstance(health['boot_id'], str)
            or re.fullmatch(r'[0-9a-f-]{36}', health['boot_id']) is None
            or type(health['observed_at']) not in (int, float)
            or not math.isfinite(health['observed_at'])
            or not 0 <= time.time() - health['observed_at'] <= 90):
        raise ValueError('Audit status is stale or reports a source failure.')
    return health


def validate_log_position(checkpoint, source_id):
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        'version', 'source_id', 'device', 'inode', 'offset', 'fingerprint',
        'reader_boot_id', 'initial_started_at', 'history_policy',
    }:
        raise ValueError('Invalid Audit file checkpoint; maintenance required.')
    if (type(checkpoint['version']) is not int or checkpoint['version'] != 2
            or checkpoint['source_id'] != source_id
            or checkpoint['history_policy'] != 'retained_uncompressed'):
        raise ValueError('Unsupported or foreign Audit file checkpoint.')
    for name in ('device', 'inode', 'offset'):
        if type(checkpoint[name]) is not int or not 0 <= checkpoint[name] < 2**64:
            raise ValueError('Invalid Audit file position.')
    if (not isinstance(checkpoint['fingerprint'], str)
            or re.fullmatch(r'[0-9a-f]{64}', checkpoint['fingerprint']) is None):
        raise ValueError('Invalid Audit position fingerprint.')
    utc_time(datetime.fromisoformat(checkpoint['initial_started_at']))


def read_log_batch(*, logfile='/var/log/audit/audit.log', checkpoint=None, source_id,
                   health, targets=None, now=None, max_bytes=MAX_BYTES, max_events=1000, timeout=40):
    """Read a byte-bounded prefix, replaying any group crossing its boundary.

    The version-2 position is a proposed file device/inode/offset and fingerprint.
    It is never written to a checkpoint file. Recent or split groups stay before
    the proposed offset. Complete events interleaved with them are replayed too.
    Appended records are read by position even if their audit timestamp is old.
    """
    if (type(max_bytes) is not int or not 65536 <= max_bytes <= 8 * 1024 * 1024
            or type(max_events) is not int or not 1 <= max_events <= 10000
            or type(timeout) not in (float, int) or not math.isfinite(timeout) or not 0 < timeout <= 50):
        raise ValueError('Invalid Audit read budget.')
    if not isinstance(source_id, str) or not source_id or len(source_id) > 255:
        raise ValueError('Invalid Audit source scope.')
    now = utc_time(now if now is not None else datetime.now(timezone.utc))
    settled = now - timedelta(seconds=SETTLE_SECONDS)
    deadline = time.monotonic() + timeout
    inventory = log_inventory(logfile)
    first = 0
    if checkpoint is not None:
        validate_log_position(checkpoint, source_id)
        first = -1
        for index, item in enumerate(inventory):
            if (item['device'], item['inode']) == (checkpoint['device'], checkpoint['inode']):
                first = index
                break
        if first == -1:
            raise RuntimeError('Audit checkpoint file disappeared; possible rotation data loss.')
    # A missing numeric rotation between the cursor and the active log is a gap.
    for left, right in zip(inventory[first:-1], inventory[first + 1:]):
        number = int(left['path'].name.rsplit('.', 1)[1])
        following = 0 if right['path'] == Path(logfile) else int(right['path'].name.rsplit('.', 1)[1])
        if number != following + 1:
            raise RuntimeError('Missing or compressed intermediate Audit rotation; recovery required.')
    groups = {}
    lines_read = 0
    bytes_read = 0
    limited = False
    pending = False
    boundary = None
    end_position = None
    for index in range(first, len(inventory)):
        item = inventory[index]
        with open_log_source(item) as infile:
            size = os.fstat(infile.fileno()).st_size
            offset = checkpoint['offset'] if checkpoint is not None and index == first else 0
            if offset > size:
                raise RuntimeError('Audit log was truncated; checkpoint unchanged.')
            if checkpoint is not None and index == first:
                if log_fingerprint(infile, offset) != checkpoint['fingerprint']:
                    raise RuntimeError('Audit checkpoint bytes changed; possible truncation or corruption.')
                if offset:
                    infile.seek(offset - 1)
                    if infile.read(1) != b'\n':
                        raise ValueError('Audit checkpoint is not a record boundary.')
            infile.seek(offset)
            end_position = {'device': item['device'], 'inode': item['inode'], 'offset': offset}
            while infile.tell() < size:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Audit file read timed out; checkpoint unchanged.')
                before = {'device': item['device'], 'inode': item['inode'], 'offset': infile.tell()}
                remaining = max_bytes - bytes_read
                if remaining <= 0:
                    limited = True
                    break
                raw = infile.readline(min(65537, remaining + 1, size - infile.tell()))
                if len(raw) > remaining:
                    limited = True
                    break
                if len(raw) > 65536:
                    raise ValueError('Audit record exceeds the supported line size.')
                if not raw.endswith(b'\n'):
                    if index != len(inventory) - 1:
                        raise RuntimeError('Incomplete record in a rotated Audit log.')
                    pending = True
                    break
                bytes_read += len(raw)
                line = raw.decode('utf-8').rstrip('\r\n')
                match = HEADER.fullmatch(line)
                if match is None:
                    raise ValueError('Malformed Audit record; checkpoint unchanged.')
                if match['type'] in ('SYSCALL', 'PATH', 'CWD'):
                    key = (match['node'], match['seconds'], match['fraction'], match['serial'])
                    if key not in groups:
                        if len(groups) >= max_events:
                            limited = True
                            break
                        groups[key] = {'lines': [], 'first': lines_read, 'last': lines_read,
                                       'position': before}
                    groups[key]['lines'].append(line)
                    groups[key]['last'] = lines_read
                lines_read += 1
                end_position = {'device': item['device'], 'inode': item['inode'], 'offset': infile.tell()}
            if index != len(inventory) - 1 and os.fstat(infile.fileno()).st_size != size:
                raise RuntimeError('Rotated Audit log is still changing; retry.')
        if limited or pending:
            break
    # Find the first group that cannot yet be committed. Never split interleaved groups.
    for group in groups.values():
        parsed = parse_events('\n'.join(group['lines']), source_id=source_id, targets=targets, max_events=1)
        old_enough = bool(parsed['anchors']) and datetime.fromisoformat(parsed['anchors'][0]['event_time']) <= settled
        if parsed['issues']:
            header = HEADER.fullmatch(group['lines'][0])
            instant = datetime.fromtimestamp(int(header['seconds']), timezone.utc)
            incomplete = all(issue['reason'] in (
                'incomplete_paths', 'missing_or_duplicate_syscall', 'missing_cwd',
            ) for issue in parsed['issues'])
            if not incomplete or (not limited and instant <= settled):
                raise ValueError('Invalid or incomplete historical Audit event; recovery required.')
        if parsed['issues'] or not old_enough:
            pending = True
            if boundary is None or group['first'] < boundary['first']:
                boundary = group
    changed = True
    while changed and boundary is not None:
        changed = False
        for group in groups.values():
            if group['first'] < boundary['first'] <= group['last']:
                boundary = group
                changed = True
    output = []
    for group in groups.values():
        if boundary is None or group['first'] < boundary['first']:
            output.extend(group['lines'])
    position = dict(boundary['position'] if boundary is not None else end_position)
    # Re-find the inode after parsing: a rotation may have renamed its pathname.
    retained = None
    for item in log_inventory(logfile):
        if (item['device'], item['inode']) == (position['device'], position['inode']):
            retained = item
            break
    if retained is None:
        raise RuntimeError('Audit log disappeared during collection; no checkpoint proposed.')
    with open_log_source(retained) as infile:
        if os.fstat(infile.fileno()).st_size < position['offset']:
            raise RuntimeError('Audit log truncated during collection.')
        position['fingerprint'] = log_fingerprint(infile, position['offset'])
    if limited and checkpoint is not None and all(position[key] == checkpoint[key] for key in ('device', 'inode', 'offset')):
        raise ValueError('One Audit group exceeds the read budget; manual recovery required.')
    position.update(version=2, source_id=source_id, reader_boot_id=health['boot_id'],
                    initial_started_at=checkpoint['initial_started_at'] if checkpoint else now.isoformat(),
                    history_policy='retained_uncompressed')
    return {'output': '\n'.join(output), 'checkpoint': position, 'limited': limited,
            'pending': pending, 'bytes_read': bytes_read, 'initial': checkpoint is None}
