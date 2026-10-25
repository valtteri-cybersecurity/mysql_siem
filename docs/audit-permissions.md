# Audit log access with the private mysql_siem group

The Audit collector requires `log_group = mysql_siem` in auditd.conf. A numeric
GID resolving to the same private group is also accepted. The mysql_siem account
must have that group as its primary group; neither UID nor GID may be root.

The installer and launcher do not edit auditd.conf, chmod/chown Audit logs, modify
ACLs or grant adm membership to the Audit worker. The launcher clears all
supplementary groups and permanently drops real, effective and saved UIDs/GIDs
before reading. It checks the active log and every retained numbered rotation.
Only the application's own output log remains writable in the systemd service.
The privileged launcher still needs Audit status/rule access before the UID drop.

Required metadata:

| Object | Owner/group | Mode |
| --- | --- | --- |
| Dedicated Audit log directory | root:mysql_siem | 0750 |
| Active log | root:mysql_siem | 0640 (0440 is also readable) |
| Every retained uncompressed rotation | root:mysql_siem | 0440 or 0640 |

Symlinks, nonregular log files, hard links, incorrect owners/groups and other
modes fail validation. Parent directory safety checks still apply. No write
permissions are needed on input logs. The default `/var/log/audit` path retains
the existing narrowly validated `root:syslog 0775` parent exception; `/var/log`
is never modified by this code.

The read-only preflight first validates metadata, then uses setpriv with the
private UID/GID and `--clear-groups`. A fixed isolated Python program independently
opens the same inode with O_NOFOLLOW and reads one byte, without printing data.
No root-opened file descriptor is passed to that process. Thus mode bits alone
are not mistaken for effective access: ACLs or mandatory access controls may
still deny the read. This probe requires root; a non-root preflight reports that
it could not verify the complete privilege drop. The launcher repeats read checks
after permanently dropping privileges, without any ACL repair.

## Existing root:adm installation: manual, approved transition

**Stop here unless the administrator has approved the effect on existing readers.**
Changing the owning group can remove existing adm users' Audit access. This code
will refuse an old root:adm configuration; it will not migrate it automatically.
Do not interpret a failed preflight as permission to loosen access.

1. Record the installed version and arrange an approved maintenance window.
   Pause mysql_siem collection using the existing maintenance procedure. Preserve
   the database, identity.env, deployment/recovery records, Audit rules and all
   retained logs. Do not run a RESET or delete checkpoints for this transition.
2. Inventory auditd.conf, the active log, every retained rotation and directory
   ownership/modes. Record access/default ACLs, for example with getfacl, and back
   up configuration and permission metadata securely. Audit logs can contain
   sensitive raw arguments; do not copy them into reports. Reject unexpected
   symlinks, hard links or unrelated files rather than following or deleting them.
3. Identify all existing adm readers, administrators and other log consumers.
   Obtain approval for the intended reader policy. If their access must remain,
   the administrator must arrange and validate that policy separately, or stop
   the transition. Do not add other readers to the private mysql_siem group:
   that group also protects application code/configuration. The application does
   not add, remove or maintain other readers' ACL entries.
4. The administrator manually changes only the relevant auditd setting:

   ```ini
   log_group = mysql_siem
   ```

   Preserve unrelated settings and follow the distribution's approved auditd
   configuration reload procedure. This application never performs that change
   or reload to establish log permissions. Confirm the effective configuration;
   editing the file alone does not prove that the running daemon applied it.
5. **Handle old rotations separately.** Do not assume that auditd changes every
   old file's group during reload. Under the approved policy, the administrator
   verifies each retained inode and prepares its owner/group/mode to match the
   table above. Preserve file contents, inodes and names so existing checkpoints
   remain usable. Never use a recursive chmod/chown over `/var/log`, and never
   remove all ACLs with `setfacl -b`. Existing ACLs can affect both group masks and
   named-user access; changes require a separate review of other readers' effective
   permissions. Verify the base group entry and effective access as well as mode
   bits. This implementation deliberately leaves existing ACLs untouched.
6. Run the read-only preflight using THIS version's protected staged or installed
   project. An old ACL-based release's preflight is not sufficient. The example
   below assumes the installed project already contains this group-based version:

   ```bash
   cd /usr/local/lib/mysql_siem
   sudo /opt/mysql_siem-venv/bin/python -B -m config.audit_setup check
   ```

   The new installer also runs this check from its protected staged copy before
   database setup. Do not run a default RESET installation just to migrate log
   permissions; an existing database must use the separately approved upgrade
   procedure. Require all checks to pass, including all old rotations. A failing file must
   be reviewed individually; never skip unread files or reset collection progress.
7. In the separate acceptance environment, verify a real auditd rotation and a
   daemon restart. Check the new active file AND the renamed old file, actual
   mysql_siem UID/GID, an empty supplementary group list, checkpoint progress,
   denial of input writes and continued access for all approved other readers.
   Resume normal collection only after these checks and maintenance completion.

Ubuntu 24.04's auditd 3.1.2 documents log_group and sets the configured group when
opening the active log and closing it for rotation. This does not guarantee that
all older rotations have their group updated. External logrotate scripts must
also preserve the selected policy. Compressed archives are outside this reader's
supported retained history and must not be silently skipped.

Sources reviewed before implementation:
- [Ubuntu 24.04 auditd.conf manual](https://manpages.ubuntu.com/manpages/noble/man5/auditd.conf.5.html)
- [auditd 3.1.2 log opening and rotation](https://github.com/linux-audit/audit-userspace/blob/v3.1.2/src/auditd-event.c)

This document describes a manual transition and acceptance procedure. It does not
claim a successful Ubuntu, Debian or Mint installation test. All collectors still
share the mysql_siem UID; this change does not create per-collector UID isolation.

## Read-only checks before database setup

The installer runs `config.audit_setup check --operation reset` or
`--operation upgrade` before setting `DATABASE_SETUP_STARTED` or calling either
database operation. The snapshot log check follows at the same boundary. Neither
check changes Audit settings, rules, permissions or database contents.

RESET predicts the exact defaults seeded by migration 020. Upgrade reads the
existing Audit target registry and migration 020 status using SELECT only. An
already applied migration uses the enabled current definitions, including custom
targets. When 020 is pending, the check also predicts its default insertions,
preserving existing names, unique keys and disabled entries. Failure to read or
validate the scope blocks preparation; it does not fall back to guesses.

The same rule planner is used by the check and actual preparation. It inspects
target presence/types, kernel ABIs, active rules and immutable status. Conflicting
mysql_siem keys and never/task or never/exit suppressors fail. Missing rules in
immutable mode fail before any persistent rule write or database operation; an
administrator must provision the rules and arrange an approved reboot. Immutable
mode with all expected rules already active is accepted. A foreign managed-rule
filename or unsafe destination directory also fails before database setup. Kernel
health, the private log group and actual group-cleared reads remain mandatory.

`READY FOR PREPARATION` means these read-only prerequisites passed. Mutable mode
may still require adding missing rules during preparation. A read-only check
cannot prove that a later auditctl add will succeed, reserve kernel resources,
prove future filesystem writes or prevent configuration/target changes between
checks. Actual preparation repeats validation and verifies installed active rules;
only later activation completes integration. Optional absent target paths are
reported and omitted using the existing preparation policy. Real auditd rotation,
service activation and the complete installation still require acceptance tests.

The real snapshot-log open tests are explicitly enabled with
`SIEM_TEST_LOG_ACCESS=1` in a root test run with an existing mysql_siem account.
They create only a temporary tree under /run, test umasks 077/022/002 and repeated
preparation, and open all three collectors' logs as that user for reading and
writing. They do not create accounts or run an installation. Ordinary unprivileged
runs skip these tests and use isolated filesystem/metadata regression tests.

The installer bootstrap downloads the official GitHub main commit into a protected
checkout; it does not install uncommitted changes from the current working tree.
Local unit tests exercise these changes, but an installer acceptance test will
exercise them only after the approved version is published to the official branch.
Do not bypass bootstrap origin, commit or directory checks to test local changes.
