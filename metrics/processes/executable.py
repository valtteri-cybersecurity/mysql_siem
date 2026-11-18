"""Observe Linux executable metadata through the process's procfs link."""

import os
import stat

import psutil

STAT_FIELDS = {'executable_device': 'st_dev', 'executable_inode': 'st_ino',
               'executable_uid': 'st_uid', 'executable_gid': 'st_gid', 'executable_mode': 'st_mode',
               'executable_size': 'st_size', 'executable_mtime_ns': 'st_mtime_ns'}
METADATA_FIELDS = tuple(STAT_FIELDS) + ('executable_deleted',)
STATE_FIELDS = ('executable_path', 'executable_identity_status') + METADATA_FIELDS
LAST_KNOWN = 'last_known_executable'


def display_path(value):
    if not value or '\0' in value:
        return None
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return None
    return value


def unverified(path=None):
    path = display_path(path)
    status = 'UNKNOWN'
    if path is not None:
        status = 'PATH_ONLY'
    observation = dict.fromkeys(METADATA_FIELDS)
    observation.update(executable_path=path, executable_identity_status=status)
    return observation


def read_executable(proc_link):
    # O_PATH pins the object without opening it for content I/O. Follow only the procfs magic link.
    descriptor = os.open(proc_link, os.O_PATH | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None
        path = os.readlink(f'/proc/self/fd/{descriptor}')
        live = os.stat(proc_link)
        if info.st_ctime_ns != live.st_ctime_ns or info.st_nlink != live.st_nlink:
            return None
        observation = {}
        for field, attribute in STAT_FIELDS.items():
            value = getattr(info, attribute, None)
            if value != getattr(live, attribute, None):
                return None
            observation[field] = value

        deleted = False
        if info.st_nlink == 0:
            path = path.removesuffix(' (deleted)')
            deleted = True
            # memfd and O_TMPFILE objects can be anonymous from creation.
            if path.startswith('/memfd:') or path.rsplit('/', 1)[-1] == f'#{info.st_ino}':
                deleted = None
        elif path.endswith(' (deleted)'):
            # A literal suffix and an unlinked name with other hard links are indistinguishable here.
            deleted = None
        observation.update(executable_path=display_path(path), executable_deleted=deleted,
                           executable_identity_status='VERIFIED')
        return observation
    finally:
        os.close(descriptor)


def observe(process, reported_path):
    try:
        if not process.is_running():
            return unverified()
        proc_link = os.path.join(psutil.PROCFS_PATH, str(process.pid), 'exe')
        try:
            observation = read_executable(proc_link)
        except OSError:
            observation = unverified(reported_path)
        if process.is_running() and observation is not None:
            return observation
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return unverified()
    return unverified()


def last_observation(state):
    if state.get('executable_identity_status') == 'VERIFIED':
        return state
    if LAST_KNOWN in state:
        return state[LAST_KNOWN]
    return state


def set_observation(state, previous, observation):
    state.pop(LAST_KNOWN, None)
    state.update(observation)
    status = observation['executable_identity_status']
    if status == 'VERIFIED':
        return
    last = last_observation(previous)
    if last.get('executable_identity_status') == 'VERIFIED' or (status == 'UNKNOWN' and last.get('executable_path')):
        known = {}
        for field in STATE_FIELDS:
            if field in last:
                known[field] = last[field]
        state[LAST_KNOWN] = known


def changed(before, after):
    last = last_observation(before)
    old_status = last.get('executable_identity_status', 'PATH_ONLY')
    new_status = after.get('executable_identity_status', 'PATH_ONLY')
    if old_status == new_status == 'VERIFIED':
        fields = ('executable_device', 'executable_inode', 'executable_uid', 'executable_gid',
                  'executable_mode', 'executable_deleted', 'executable_path')
    elif old_status == new_status == 'PATH_ONLY':
        fields = ('executable_path',)
    else:
        return False
    for field in fields:
        old_value = last.get(field)
        new_value = after.get(field)
        if field == 'executable_path':
            old_value = display_path(old_value)
            new_value = display_path(new_value)
        if old_value is not None and new_value is not None and old_value != new_value:
            return True
    return False
