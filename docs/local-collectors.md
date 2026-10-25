# Local Processes, Services and Audit collectors

These collectors use the local Server identity registry. Remote Collector delivery
is not implemented. Source code and isolated tests do not demonstrate a successful
installation on a real host; use the installation checks below before acceptance.

| Collector | Trigger | Persistent data | Initial collection |
| --- | --- | --- | --- |
| Processes | Managed cron, every minute | Migration 018: `process_state`, `process_events`, shared `collector_snapshots` | Save a baseline; subsequent snapshots produce changes |
| Services | Managed cron, every minute | Migration 019: `service_state`, `service_events`, shared `collector_snapshots` | Save a baseline; subsequent snapshots produce changes |
| Audit | `mysql-siem-audit.timer`, 60 seconds after each completed invocation | Migration 020: `audit_events`, `audit_checkpoints`, `audit_targets` | Read retained, uncompressed audit logs from the oldest available file in bounded batches |

All three require an active host, enabled source and collector, and an approved
collector/source binding. The installed environment supplies `SIEM_COLLECTOR_ID`
and `SIEM_PROCESSES_SOURCE_ID`, `SIEM_SERVICES_SOURCE_ID`, `SIEM_AUDIT_SOURCE_ID`.
The source identity comes from configuration and the registry, not event text.
A named MySQL lock serializes each source's writer. Events and state/checkpoints
commit together; failures roll back. History tables are append-only for the runtime
account. State tables have only the additional permissions their writer needs.

Processes compares PID plus creation time and selected process metadata. It does
not collect full command lines. Services queries systemd inventory and unit
properties using read-only `systemctl` commands. Neither collector changes
processes or service states. Snapshot collection cannot observe changes that
begin and end between samples. A failed collection preserves the last baseline.

## Installation and upgrade

The standard installer downloads the official `main` commit. Uncommitted changes
in a development checkout are not installed by running that checkout's installer.
Publish/review the intended commit before testing that release through this path.

For a fresh disposable host, follow the README's Server installation. For an
existing installation whose history must be preserved, use:

```bash
sudo bash install.sh --upgrade --role server
```

Do not use reset mode to test a history-preserving upgrade. The default installer
can permanently reset an existing database after explicit `RESET` confirmation.
Back up database history and protected configuration before any installation test.
The upgrade stops if pre-017 UFW history lacks verified UTC interpretation; resolve
that history offline rather than bypassing the check.

Preparation holds the installation maintenance barrier while applying migrations,
registering identities, preparing permissions and publishing code/configuration.
Audit preparation runs before maintenance is released. Activation enables only the
owned timer after publication. Failed activation restores maintenance. A failed
installation can leave prepared configuration, rules or staged files for recovery;
review the specific error and rerun the same operation after correcting it.

Audit needs Linux kernel Audit support, auditd and its tools, systemd, supported
kernel ABI configuration, root-owned log files and compatible auditd disk logging.
The read-only preflight reports PASS/FAIL/UNKNOWN prerequisites:

```bash
.venv/bin/python -m config.audit_setup check
```

Some status checks require administrator privileges. Run the same command through
an approved administrator environment to distinguish missing privilege from a
missing prerequisite; it does not install or modify configuration.

Default targets are `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` and `/etc/sudoers.d`.
Missing optional sudo targets are reported as `NOT_INSTALLED`; they are not watched.
If those paths are installed later, repeat approved preparation/installation and
verify active rules. Merely creating a path does not add the missing watch.
Adding database targets also requires corresponding approved rule preparation.

The installer owns `/etc/audit/rules.d/50-mysql-siem.rules`, two systemd units and
`config/audit-runtime.json` in the installed tree. It preserves unrelated rules,
does not delete all kernel rules, and checks that its expected rules are active.
If Audit is immutable and required rules are absent, persistent rules can be
prepared but activation requires administrator review and an approved reboot.
An incompatible existing log group or configuration stops preparation.

The service starts a fixed root launcher for Audit status/rule verification. It
drops supplementary groups and permanently changes all UIDs/GIDs to `mysql_siem`
before running the database worker. Audit logs become readable by that account;
the account is not granted sudo or permission to write audit logs or change rules.
Operational logs are bounded and stored under `/var/log/mysql_siem/{processes,services,audit}`.

## Audit collection and recovery

Automatic collection uses inode/device/byte-offset positions and a short preceding
byte fingerprint captured from the original read. Every read range is also hashed
and reread for comparison before accepting the batch, within the same time budget.
Rewriting a read range rejects the batch without advancing its stored checkpoint.
File rotation is followed in numbered, uncompressed order.
Missing checkpoint files, intermediate rotation gaps, truncation, changed anchor
bytes, malformed historical events or nonzero kernel loss stop collection. No
checkpoint is advanced on a failed transaction. A busy writer exits 75 and leaves
collection to the existing writer.

Each default batch reads at most 4 MiB and 1000 syscall groups with a 40-second
reader deadline. Recent events wait for a ten-second settling period; incomplete
and interleaved groups are replayed from their safe boundary. Large retained
history may require many timer invocations. Ensure ingestion catches up before
retention removes unread files. Monitor both last successful progress and pending
backlog: a running timer alone does not prove current coverage.

The first collection proves only what is in the available uncompressed files.
Compressed history, previously deleted records and earlier history are outside
that coverage. The fingerprint is an integrity check around the saved position,
not a complete forensic proof of all log contents. `reader_boot_id` records the
reader's boot; it does not establish a historical event's boot identity.

Store only selected metadata: timestamps, identity, paths, syscall/result and
approved process/user attributes. Raw execution arguments and file contents are
excluded. Unknown syscall/ABI combinations remain unknown; relative paths and
rename/atomic-replacement behavior need validation on the target host.

On a gap or invalid checkpoint, keep maintenance/recovery evidence and investigate
retention, source identity, log ownership and database health. Restore the required
unaltered logs where possible. Do not delete checkpoints or silently restart at
the newest log: any operator-approved new baseline must explicitly document its
coverage gap. Never edit checksummed migration files to force an upgrade.

The separate development preview (`python -m ingestion.audit.main --show-events`)
uses `ausearch` time windows, prints limited metadata and saves nothing. Its
version-1 checkpoint cannot resume automatic version-2 file-position collection.

## Acceptance test on a disposable host

Use a disposable VM with the supported Oracle MySQL 8.0/8.4 and target Linux
version. Kernel Audit and systemd must work; unit-test mocks are insufficient.
Record the exact installed commit and repeat on each supported deployment target.

1. Test a fresh install and a separate `--upgrade` installation with seeded old
   history and identities. Compare old row IDs, timestamps, hashes, checkpoints,
   settings and unrelated cron entries before/after upgrade. Repeat the upgrade;
   verify migrations 018–020 are `APPLIED` without duplicate identities or jobs.
2. Verify the application user can read its settings and required Audit logs but
   cannot change service code, rules, audit logs, registry rows or history rows.
   Inspect actual worker UIDs, GIDs and capabilities. Confirm root is dropped
   before opening the database. Verify systemd confinement allows collection.
3. Check `systemctl status mysql-siem-audit.timer`, the service journal and all
   three bounded collector logs. Verify the maintenance barrier blocks jobs and
   that a successful install clears it. Check activation failure restores it.
4. Start/stop a harmless process and create a disposable service. Compare baseline
   and subsequent process/service events against the controlled changes. Never
   use critical production processes/services for these checks.
5. Configure approved disposable Audit targets and generate known writes, chmod,
   ownership, rename, deletion and atomic replacement. Verify expected metadata,
   target mapping and multi-PATH grouping, with no content or raw arguments stored.
   Repeat atomic replacement followed by another write to verify watch continuity.
   Avoid modifying the real password/shadow/sudo configuration solely for testing.
6. Exercise real auditd rotation, restart and reboot; verify continuous checkpoint
   progress and replay deduplication. Simulate missing rotation, unreadable logs,
   kernel loss and oversized/incomplete events on the disposable host. Collection
   must fail visibly without silently skipping history or moving its checkpoint.
7. Interrupt the worker around database writes and run overlapping writers. Verify
   atomic event/checkpoint persistence, rollback, source isolation and safe retry.
   Check failure/recovery leaves unrelated Audit rules and host services intact.

Integration acceptance requires these host-level results in addition to passing
unit tests and private MySQL integration tests. Until then, installation readiness
means ready for a controlled test, not a validated production installation.
