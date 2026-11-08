"""Verify active Auth checkpoints and adopt explicitly approved legacy file generations."""

import json
import os
import time
from pathlib import Path

from config import installation_state as journal
from database.local_identity import database_key, read_settings, ssh_settings
from database.migration_steps import columns
from ingestion.auth.collector import get_logfiles, open_logfile, position_hash
from ingestion.auth.identity import AuthCollectionError, finish, hashes, start

TABLE = 'auth_ingestion_state'
ORIGIN = ('generation_key', 'prefix_sha', 'observed_size', 'observed_sha', 'file_mtime_ns')
APPROVAL = 'auth-checkpoint-approval.json'
ACKNOWLEDGEMENT = 'ADOPT LEGACY AUTH CHECKPOINTS'


def approved_snapshot(connection, state: Path, key: tuple, position: int, digest: str) -> tuple:
    scope = key[3]
    evidence = [scope, *key[:3], position, digest]
    path = state / APPROVAL
    instructions = (
        f'Legacy Auth checkpoint has no verified file generation. Checkpoint {json.dumps(evidence)}. '
        'Keep the checkpoint and logs. Recover an independently verified backup that pairs this exact '
        'committed checkpoint with its original log. If verified, create ' + str(path)
        + ' as a root-owned 0600 JSON file with keys database, server (MySQL server_uuid), '
        'approve (value "' + ACKNOWLEDGEMENT + '") and checkpoints (a list of the displayed arrays, '
        'each extended with the original file size in bytes, original mtime in nanoseconds since Unix epoch, '
        'and lowercase SHA-256 of the entire paired backup log, in that order). '
        'A digest taken only from the current log is insufficient. Retry the same upgrade.'
    )
    if not path.exists() and not path.is_symlink():
        raise AuthCollectionError(instructions)
    journal.trusted_state(state)
    try:
        approval = json.loads(journal.read_file(path))
        database, server = database_key(connection)
        if (approval['approve'] != ACKNOWLEDGEMENT or approval['database'] != database
                or approval['server'] != server or not isinstance(approval['checkpoints'], list)):
            raise ValueError
        matching = []
        for entry in approval['checkpoints']:
            if isinstance(entry, list) and json.dumps(entry[:6]) == json.dumps(evidence):
                matching.append(entry)
        if len(matching) != 1 or len(matching[0]) != 9:
            raise ValueError
        size, mtime, snapshot_sha = matching[0][6:]
        if type(size) is not int or size < position or type(mtime) is not int or mtime < 0:
            raise ValueError
        if not isinstance(snapshot_sha, str) or len(snapshot_sha) != 64 or bytes.fromhex(snapshot_sha).hex() != snapshot_sha:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise AuthCollectionError('Invalid or unmatched Auth recovery approval. ' + instructions) from None
    return size, mtime, snapshot_sha


def sources(logfile: str) -> dict:
    files = {}
    for filename in get_logfiles(logfile, include_gzip=False):
        try:
            info = os.lstat(filename)
        except FileNotFoundError:
            continue
        files[filename] = (info.st_dev, info.st_ino)
    return files


def verify_position(infile, position: int, digest: str, size: int) -> None:
    if not 0 < position <= size:
        raise AuthCollectionError('Auth checkpoint offset is outside its source; manual recovery required.')
    infile.seek(position - 1)
    if infile.read(1) != b'\n' or position_hash(infile, position) != digest:
        raise AuthCollectionError('Auth checkpoint boundary or fingerprint differs; manual recovery required.')


def verify_file(connection, state: Path, filename: str, key: tuple, checkpoint: tuple,
                deadline: float, allow_approval: bool) -> tuple | None:
    position, digest, generation, prefix_sha, size, observed_sha, mtime_ns = checkpoint
    with open_logfile(filename) as infile:
        info = os.fstat(infile.fileno())
        if (info.st_dev, info.st_ino) != key[1:3]:
            raise AuthCollectionError('Auth source rotated during verification; retry the upgrade.')
        if position != 0:
            verify_position(infile, position, digest, info.st_size)
        if generation is not None:
            stats = {'source_resets': 0, 'coverage_gaps': 0}
            actual, prefix, observed = start(infile, info, checkpoint, stats, deadline)
            if actual != generation or infile.tell() != position:
                raise AuthCollectionError('Auth checkpoint generation no longer matches its source; manual recovery required.')
            finish(infile, info, prefix, observed, deadline)
            return None
        if (prefix_sha, size, observed_sha, mtime_ns) != (None, None, None, None):
            raise AuthCollectionError('Partial Auth generation metadata; manual recovery required.')
        if position == 0:
            return None
        if not allow_approval:
            raise AuthCollectionError('Active legacy Auth checkpoint has not been migrated; keep collection paused.')
        size, mtime, expected = approved_snapshot(connection, state, key, position, digest)
        if size > info.st_size or (size == info.st_size and mtime != info.st_mtime_ns):
            raise AuthCollectionError('Auth source metadata differs from the independently approved snapshot; manual recovery required.')
        verified = hashes(infile, (position, size, info.st_size), deadline)
        if verified[size].hexdigest() != expected:
            raise AuthCollectionError('Auth source content differs from the independently approved snapshot; manual recovery required.')
        prefix = verified[position]
        observed = verified[info.st_size].hexdigest()
        infile.seek(position)
        mtime = finish(infile, info, prefix, observed, deadline)
        return prefix.hexdigest(), info.st_size, observed, mtime


def verify_checkpoints(connection, project: Path, user: str, *, state: Path = journal.STATE_DIR,
                       allow_approval: bool = False) -> list:
    """Read the configured reader's current plain logs. Retired inodes keep their rows."""
    reader, configured = ssh_settings(project, user)
    source = Path(configured)
    if not source.is_absolute():
        raise AuthCollectionError('Use an absolute SSH_AUTH_LOGFILE to verify active Auth checkpoints.')
    logfile = str(source.resolve())
    settings = read_settings(project / 'config/identity.env')
    scope = settings.get('SIEM_AUTH_SOURCE_ID', 0)
    deadline = time.monotonic() + 30
    inventory = sources(logfile)
    changes = []
    with connection.cursor() as cursor:
        fields = columns(cursor, TABLE)
        if not fields:
            return changes
        selected = ['last_position', 'position_hash']
        for name in ORIGIN:
            if name in fields:
                selected.append(name)
            else:
                selected.append('NULL')
        query = ('SELECT ' + ','.join(selected) + ' FROM ' + TABLE
                 + ' WHERE collector_id=%s AND file_device=%s AND file_inode=%s')
        if 'source_scope' in fields:
            query += ' AND source_scope=%s'
        for filename, (device, inode) in inventory.items():
            if time.monotonic() >= deadline:
                raise AuthCollectionError('Auth checkpoint verification exceeded its time budget; retry the upgrade.')
            key = (reader, device, inode, scope)
            params = key
            if 'source_scope' not in fields:
                params = key[:3]
            cursor.execute(query, params)
            checkpoint = cursor.fetchone()
            if checkpoint is None:
                continue
            origin = verify_file(connection, state, filename, key, checkpoint, deadline, allow_approval)
            if origin is not None:
                changes.append((key, checkpoint[:2], origin))
    if str(source.resolve()) != logfile or sources(logfile) != inventory:
        raise AuthCollectionError('Auth sources rotated during verification; retry the upgrade.')
    return changes


def save_origin(cursor, key: tuple, checkpoint: tuple, origin: tuple) -> None:
    cursor.execute('UPDATE auth_ingestion_state SET generation_key=%s,prefix_sha=%s,observed_size=%s,'
                   'observed_sha=%s,file_mtime_ns=%s WHERE collector_id=%s AND file_device=%s AND file_inode=%s '
                   'AND source_scope=%s AND last_position=%s AND position_hash=%s AND generation_key IS NULL '
                   'AND prefix_sha IS NULL AND observed_size IS NULL AND observed_sha IS NULL AND file_mtime_ns IS NULL',
                   origin + key + checkpoint)
    if cursor.rowcount != 1:
        raise AuthCollectionError('Auth checkpoint changed during recovery; no checkpoint transition was committed.')
