# Automatic Audit permission preparation

Use the normal Server installer on Ubuntu 24.04, Debian 13, or a supported
Ubuntu-based Linux Mint release:

```bash
sudo bash install.sh --role server
```

The installer verifies its private account, prepares trusted code and a Python
environment, then checks recovery state, MySQL and snapshot-log prerequisites.
It inventories Audit configuration, all numbered logs and their access/default
ACLs before proposing changes. All unrelated Audit/kernel/rule/unit checks must
pass first. A separate `AUDIT` confirmation approves Audit system changes.
The final database `RESET` confirmation comes after successful Audit preparation
and full Audit postflight. Upgrade never becomes RESET automatically. Declining
RESET does not reverse an independently approved, verified Audit migration.

Only log_group is changed to mysql_siem. Other auditd.conf text, owner, group,
mode and extended attributes are preserved through atomic replacement. A private
configuration/permission backup is written before mutation. Logs are modified
through pinned descriptors: root:mysql_siem, directory 0750, active log 0640,
numbered rotations 0440. Their contents, names and inodes are preserved. There
is no recursive chmod/chown, rule deletion or supplementary-group workaround.
The runtime launcher clears supplementary groups and permanently drops UID/GID;
it never changes ACLs or repairs permissions.

## Reader policy and masks

The previous owning group's effective access is retained as a named numeric-group
ACL on each inode. Existing named users/groups retain effective permissions,
including explicit user denials overriding adm membership. Hidden permissions are
normalized before masks change, so previously masked writes cannot be activated.
No other user is added to the private mysql_siem group. Existing local readers are
identified from their ACLs and group memberships and tested through independent
opens before/after migration, without printing log data. Group-ID policies also
preserve the access of readers resolved through NSS. The Audit worker is separately
verified with all supplementary groups removed. Other collectors' existing general
system-log policy is unchanged; Audit itself does not use adm membership.

Default ACLs preserve the original future-file policy and auditd creation mode.
Without an original default ACL, a named permission on one old file does not grant
that user new access to every future file. Transitional defaults preserve reader
policy both before and after auditd changes its group. Final defaults retain
reader access through auditd chmod(0640/0440) and future rotation. Named denied
adm members remain denied. Non-root writers, world access and unexpected layouts
require separate review rather than automatic broadening or removal of access.

## Verified reload and interruption recovery

The installer uses a Linux pidfd to send HUP to the verified auditd executable.
Success requires a new DAEMON_CONFIG success record identifying this sender,
healthy kernel status, unchanged inode inventory, verified permissions and a full
Audit postflight. A successful signal call alone does not establish success.
See the documented [auditd SIGHUP interface](https://raw.githubusercontent.com/linux-audit/audit-userspace/v3.1.2/docs/auditd.8).

Recovery metadata is stored in
`/usr/local/lib/.mysql_siem-local/audit-permissions.json`, root-only mode 0600.
It contains original configuration and permission metadata, never copied Audit
events or MySQL credentials. Earlier completed backups are archived before a new
migration is approved. Keep backups private.

The exclusive runtime lock, public audit-permissions.pending marker and original
maintenance marker block collection during mutation. The maintenance marker also
protects already installed wrappers that predate this feature. Audit preparation
never removes a pre-existing identity-maintenance marker. Its own maintenance
marker is removed only after durable verified completion while holding the lock.

After a partial failure or process termination, retry the same installer command.
It validates the saved plan, original inode identities and recognized intermediate
ACL states, then completes forward without another approval for that saved plan.
It never blindly restores old permissions onto actively changing logs. Database
contents, receipts, identities and checkpoints are not rewritten by this phase.

Unknown files, compressed rotations, links, unsafe owners/modes, changed metadata,
inconsistent backups or rotation-inventory changes stop preparation. A rotation
conflict during a partial migration requires administrative review with the backup
and markers intact; the installer does not guess the policy for unknown inodes.
Transitional defaults retain prior readers during that conflict. Do not delete
barriers or copy another host's recovery data to force continuation.

## Real Ubuntu 24.04 and Debian 13 VM acceptance protocol

These VM tests have not been executed by the development task. The ordinary test
suite uses temporary files and simulated auditd reloads; its real Linux ACL xattr
checks do not prove full distribution compatibility. No VM runner is available in
the current environment. Run the following protocol separately on snapshot-restorable
Ubuntu 24.04 and Debian 13 VMs, never on a development or production machine.

Use an approved version published to official main and a clean checkout. The
installer bootstrap downloads official main, not uncommitted local changes.
Record application commit, OS release, kernel, auditd and Oracle MySQL versions.
Both images need the existing supported MySQL/socket prerequisites, a running
healthy auditd, and the ordinary root:adm configuration. Retention must leave
spare slots for test rotation. Restore the baseline snapshot between fault cases.

Prepare test-image fixtures with at least two retained logs and three readers:

- One named ACL reader outside adm, with corresponding default ACLs.
- One reader authorized only through adm.
- One adm member with a named zero-permission file/default ACL. Give it directory
  traversal so file-ACL denial is actually tested.

Fixture preparation establishes the starting policy for tests; it is not a manual
permission-repair step required in normal product deployment.

| Case | Action | Required result |
| --- | --- | --- |
| Fresh install | Run the normal Server command and approve AUDIT | No manual permission commands; correct private group; full postflight succeeds |
| Decline AUDIT | Reject the Audit prompt | Original config/ACLs and database remain unchanged |
| Existing test DB | Accept AUDIT, then decline RESET | Audit transition verified; no database DROP; no identity/checkpoint rewrite |
| Reader policy | Open all logs as each fixture user before/after | Both original readers succeed; named denied adm member fails |
| Private worker | Independently open every log after permanent UID/GID drop with groups cleared | All opens succeed; no inherited root FD |
| Retained logs | Compare inode/device and hashes of the original byte prefixes | No replacement/truncation; appended daemon records are allowed |
| Future rotation | Request a normal auditd rotation, then repeat reader/worker probes | New active and retained logs preserve intended access and modes |
| Real event | Create/remove a harmless comment-only file in the watched sudoers directory | A bounded collector run stores the matching event in MySQL |
| Upgrade | Re-run with --upgrade, without RESET input | Same receipt and identities; historical events retained and checkpoints continue without reset; no redundant permission mutation |
| Reload failure | In a restored disposable snapshot, reject/fail HUP acknowledgement | Pending and maintenance remain; no database reset |
| Abrupt stop | Terminate setup before config update, after update, after reload and at completion | Saved metadata remains; no premature collection; verified same-command recovery |
| Concurrent rotation | Rotate during a partial migration | Known readers retain policy; conflicting inventory remains blocked for review |
| Reboot | Reboot an interrupted and a completed snapshot | Interrupted setup stays blocked; completed private worker resumes safely |

Use metadata, prefix hashes and aggregate database counts as evidence. Do not export
raw Audit events, configuration backups or credentials into test reports. Confirm
service/timer state and actual MySQL ingestion; enabled timer status alone is not
an end-to-end acceptance result.
