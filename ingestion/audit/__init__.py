"""Linux Audit metadata collection and local MySQL integration.

Automatic collection uses ``collect_to_mysql`` in ``ingestion.audit.main``.
Migration 020 supplies audit_events, audit_checkpoints and audit_targets. An
approved local Audit identity and a source-scoped MySQL named lock are required.
Events and the version-2 file-position checkpoint commit in one transaction;
errors roll back both. Duplicate source/event hashes do not create extra rows.

The installer prepares owned Audit rules, read access and a protected manifest.
The systemd timer invokes a fixed launcher which verifies rules and auditd
health, then permanently drops root before database collection. The worker
reads retained, uncompressed audit.log rotations by device/inode/byte offset.
Missing rotations, truncation, malformed history and kernel lost events stop
collection without advancing the checkpoint. First start covers only retained
uncompressed history; it cannot prove coverage before that history.

Default automatic limits are 4 MiB, 1000 syscall groups and 40 seconds per batch.
Recent or incomplete groups remain pending; the default settling delay is ten
seconds. Stored data contains selected event metadata, never file contents,
password hashes or raw PROCTITLE/EXECVE arguments.

Development preview is a separate, nonpersistent time-window reader:
    python -m ingestion.audit.main --show-events --limit 5 --window-seconds 30
    from ingestion.audit.main import collect

Its default window is the latest 60 seconds ending ten seconds ago, with a
resumed two-second overlap and a shared ten-second command deadline. Its
version-1 checkpoint is not interchangeable with automatic file positions.
Preview does not save events or checkpoints, install rules or schedule jobs.
Exit codes are 0 for success, 1 for failure and 130 for interruption. Automatic
collection additionally returns 75 when another writer owns the source lock.

Deployment prerequisites, validation and recovery: docs/local-collectors.md.
Real auditd rules, rotation, systemd confinement and privileges require an
installation test on a disposable Linux host before deployment acceptance.
"""
