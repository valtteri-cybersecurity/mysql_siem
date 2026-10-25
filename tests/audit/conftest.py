"""Synthetic audit records only; never read or change monitored system files."""

import pytest


def audit_event(path="/etc/passwd", *, serial=12, seconds=1792886390,
                syscall=257, arch="c000003e", success="yes", exit_code=3,
                nametype="NORMAL", extra_paths=None, node=None, extra=""):
    prefix = f"node={node} " if node else ""
    identity = f"{seconds}.123:{serial}"
    paths = [(path, nametype)] + (extra_paths or [])
    lines = [
        "----", "time->Sun Oct 25 00:00:00 2026",
        (f'{prefix}type=SYSCALL msg=audit({identity}): arch={arch} syscall={syscall} '
        f'success={success} exit={exit_code} a0=ffffff9c a1=1234 a2=241 items={len(paths)} '
        f'ppid=10 pid=20 auid=1000 uid=0 euid=0 comm="test-editor" '
        f'exe="/usr/bin/test-editor" key="account_files" {extra}'),
        f'{prefix}type=CWD msg=audit({identity}): cwd="/etc"',
    ]
    for item, (name, kind) in enumerate(paths):
        lines.append(f'{prefix}type=PATH msg=audit({identity}): item={item} name="{name}" '
                     f'inode={200 + item} dev=08:01 nametype={kind}')
    lines.extend([
        f'{prefix}type=PROCTITLE msg=audit({identity}): proctitle=7465737400736563726574',
        f'{prefix}type=EXECVE msg=audit({identity}): argc=2 a0="test" a1="DO_NOT_RETAIN"',
    ])
    return "\n".join(lines) + "\n"


@pytest.fixture
def event_text():
    return audit_event
