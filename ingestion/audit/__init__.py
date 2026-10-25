"""Linux Audit collection without database or system configuration changes.

Development usage (run at the repository root):
    python -m ingestion.audit.main
    python -m ingestion.audit.main --show-events --limit 5 --window-seconds 30

API:
    from ingestion.audit.main import collect
    result = collect(source_id="trusted-source-id", checkpoint=previous_state)

The API returns Python dictionaries and UTC-aware datetimes. Only the selected
event metadata may be stored; do not persist the raw reader output. Exit codes
are 0 for a successful batch (including empty), 1 for failure and 130 for Ctrl-C.
An issue-bearing batch has checkpoint=None and must not advance storage state.

The initial default window is the latest 60 seconds ending 10 seconds ago. An
explicit timezone-aware start can select an older starting point. Each resumed
window overlaps two seconds. Limits default to 1000 source syscall events, 4 MiB
of output per command and a shared 10-second command deadline. Overflow fails
the batch: retry the same checkpoint with a smaller window, never skip forward.

Phase 2 requirements (not implemented here):
* Persist events and the returned checkpoint in the SAME MySQL transaction.
  Deduplicate event_hash under a trusted, stable source identity and serialize
  writers. Convert UTC-aware times to UTC-naive only at the MySQL boundary.
* Verify that the required audit rules, privileges and auditd disk flushing are
  configured externally. No events is not proof that watches are installed.
* Define an explicit first-start/recovery policy. Earlier history is deliberately
  excluded by default. A missing retained anchor or a reboot requires recovery;
  the collector never automatically resets progress. Kernel lost>0 also blocks
  collection rather than silently accepting a known gap.
* A retained event anchor detects loss through ordinary sequential rotation.
  Without an anchor, retention coverage is unverified. It cannot prove that
  individual records were not removed, or that missing intermediate rotations
  exist. Add durable file/inode coverage and retention monitoring in phase 2.
* Time windows cannot guarantee capture of arbitrarily delayed disk writes,
  clock jumps or records arriving after the overlap. Confirm settle/overlap
  against the deployment, and add durable log positions/replay in phase 2.
* PATH item counts prove structural completeness, not arrival of every optional
  record. EOE is optional. Relative paths use recorded CWD lexically; aliases,
  symlinks and directory-FD-relative paths without sufficient PATH information
  need deployment validation. Unknown syscall/architecture pairs stay unknown;
  openat2 flags are a pointer and are never guessed from syscall arguments.

No checkpoint files, database calls, audit rules, installations or schedules
are created. Audit tools must already be installed. Live audit behavior must
be verified separately on a disposable configured Linux audit host.

Reader semantics were checked against the upstream sources:
https://github.com/linux-audit/audit-userspace/blob/master/docs/ausearch.8
https://github.com/linux-audit/audit-userspace/blob/master/src/ausearch.c
https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8
"""
