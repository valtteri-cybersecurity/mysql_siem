# MySQL SIEM

A Python-based security monitoring project designed to collect, analyze, and detect suspicious activity in Linux environments.

The project combines Linux system monitoring, firewall logs, and DNS activity into a MySQL database. Its goal is to explore how Security Information and Event Management (SIEM) systems work and develop practical skills in cybersecurity, backend development, and security monitoring.

**Status:** Work in progress — an educational Blue Team project, not a production-ready SIEM.

## Features

- **System Monitoring** — Collects CPU, memory, disk usage, uptime, and filesystem metrics.
- **Firewall Monitoring** — Collects and analyzes UFW firewall events, blocked connections, and network activity.
- **DNS Monitoring** — Integrates with AdGuard Home to collect and analyze DNS queries, with configurable filtering and data retention.
- **Port Activity Analysis** — Summarizes UFW activity by destination device, port, protocol and historical interval. See [usage and migration](#ufw-port-activity-analysis).
- **Source IP Analysis** — Stores interval-based UFW activity summaries, including internal and IPv6 sources, for future behavior analysis. See [usage and migration](#ufw-source-ip-analysis).
- **SSH Brute Force Detection** — Collects SSH password failures and supports scheduled SOC detection with durable checkpoints. See [configuration and deployment](#ssh-brute-force-detection).
- **Threat Detection** — Detects potential port-scanning activity and stores security alerts with supporting event data.
- **Automated Collection** — Uses scheduled background tasks to collect and process data.

## Technologies

- Python
- MySQL
- Linux (Ubuntu / Linux Mint)
- Bash
- SQL
- UFW
- AdGuard Home
- Git

## Project Architecture

The application is organized into separate components:

| Component | Purpose |
|---|---|
| Ingestion | Collects system logs and network activity |
| Database | Stores collected events and monitoring data |
| Analysis | Processes data and identifies activity patterns |
| Anomaly Detection | Planned detection of deviations from normal behavior |
| Detection | Identifies suspicious activity and generates alerts |
| Configuration | Manages application settings and scheduled tasks |

This modular structure allows new monitoring sources and detection methods to be added as the project develops.

## Installation

The project is primarily developed and tested on Ubuntu-based Linux systems.

Clone the repository:

`git clone https://github.com/valtteri-cybersecurity/mysql_siem.git`

Enter the project directory:

`cd mysql_siem`

Run the installation script in a dedicated test environment after reviewing it:

`sudo bash install.sh`

The installation script prepares the database, required dependencies, and scheduled monitoring tasks.

Additional configuration is required for integrations such as AdGuard Home.

## UFW Source IP Analysis

`analysis/ufw/main.py` is the shared entry point for UFW analysis. `source_ips.py` describes activity without labeling sources as attackers. Detection
applies security rules and produces SOC alerts; this analysis produces neither alerts
nor anomaly scores. Daily counts, SSH and port scan logic remain independent. Port summaries are
provided by the separate `ports.py` analysis in the same entry point.

For each valid source IP and explicit interval, `analysis_source_ips` stores:

- Total events and separate BLOCK, ALLOW and AUDIT counts.
- Unique destination ports and destination IPs.
- First/last event times and separate TCP/UDP counts.

All fields come from `ufw_log`; its raw schema is unchanged. Private, loopback,
link-local and IPv6 sources are included. IP spellings are normalized. Missing or
invalid sources are skipped. Unknown actions/protocols still contribute to totals;
only the named counters are selective. Missing/invalid destinations do not discard
the source event, but do not contribute to distinct counts. Port 0 means missing.

### Manual runs and stored results

Run from the project root after schema preparation:

```bash
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main \
  --start '2026-10-21 00:00:00' --end '2026-10-22 00:00:00'
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --recent-hours 2
```

Intervals use `start <= event_time < end`. Supply naive timestamps in the **existing
UFW `event_time` time basis**, without UTC conversion or an offset. This differs
from the UTC convention used by SSH. Automatic runs use the host's naive clock;
ensure it matches the UFW timestamps before scheduling. The API accepts any valid
historical interval, including hourly, daily, 7/30/90-day and calendar-month ranges,
without a current-day or 30-day cutoff:

```python
from analysis.ufw.source_ips import analyze_source_ips, run_source_ip_analysis

# Use the project's get_connection() and naive datetime bounds.
metrics = analyze_source_ips(connection, start_time, end_time)  # Read-only dictionaries.
summary = run_source_ip_analysis(connection, start_time, end_time)  # Save atomically.
```

The read-only caller owns its transaction; saving requires a dedicated connection.
Queries stream only the necessary fields from the indexed raw time range. Python
keeps counters and sets of distinct destinations. The default safety limit is
100,000 raw rows per interval, including invalid-source rows; exceeding it fails
without saving a partial result. Split large intervals or set `--max-events`
within 1..1000000. No full-history backfill runs automatically.

The primary key is `(period_start, period_end, source_ip)`. Each successful save
replaces **only the exact interval** in one transaction, including removing stale
sources or clearing an interval that is now empty. Other periods and raw events
remain unchanged. A named MySQL lock serializes analysis runs; contention reports
`SKIPPED`. Failed writes roll back. Detection locks/state are independent.

```sql
SELECT source_ip, total_events, blocked_events, allowed_events, audited_events,
       unique_destination_ports, unique_destination_ips, first_seen, last_seen,
       tcp_events, udp_events
FROM analysis_source_ips
WHERE period_start = '2026-10-21 00:00:00'
  AND period_end = '2026-10-22 00:00:00'
ORDER BY total_events DESC, source_ip;
```

The source-history index supports comparisons over time. Use one consistent
interval size for future baselines; overlapping hourly/daily summaries describe
some of the same events. Distinct counts cannot be summed to obtain a larger
interval's distinct count: recompute that interval from raw events. Missing raw
history cannot be reconstructed from summaries.

### Migration and scheduling

On an existing installation, apply [migration 009](database/migrations/009_analysis_source_ips.sql)
and then [migration 010](database/migrations/010_drop_top_attacking_ips.sql) before
switching the deployed code and managed cron job:

```bash
sudo mysql mysql_siem < database/migrations/009_analysis_source_ips.sql
sudo mysql mysql_siem < database/migrations/010_drop_top_attacking_ips.sql
```

Migration 009 creates the new `analysis_source_ips` table and indexes. Migration
010 **permanently deletes `top_attacking_ips` and its old history**. No legacy
summaries are copied. Both migrations can be repeated; existing new summaries
and UFW raw events are preserved. Rebuild any desired historical intervals from
retained raw events using the manual command above. MySQL DDL commits implicitly;
inspect pre-existing definitions or a partially applied migration before retrying.
Do not import `database/schema.sql` as an upgrade: it is for new databases only.

After schema preparation, an installer run provisions table-scoped
SELECT/INSERT/DELETE permissions and replaces the old `analysis/attacking_ips/main.py`
job in this installation's managed cron block. Other user jobs are preserved;
review any manually added legacy job outside that block separately. Existing
passwords and already granted permissions are preserved. The installer requires
legacy-table cleanup, gives no grants on that table and never creates it on new
installations. New empty databases receive migration 009 during installation.
Existing installations require the migration commands above; the installer does
not automatically run those migrations on an existing database. Current installers
also require the Port Activity migration described below.

The shared job runs **every five minutes** with `--all --recent-hours 3`, refreshing
the current provisional hour and two previous hours for both analyses.
`--recent-hours` supports 1..24. The original command without a selection flag
still runs Source IP Analysis only and defaults to 2 hours; `--ports` and `--all`
default to 3 hours. Delayed events outside those buckets
need an explicit historical rerun. The job uses the project directory, environment
loader, `/usr/bin/python3`, `PYTHONPATH` and `umask 077`. Logs go to
`analysis/ufw/cron.log` with 1 MB rotation and three backups. They include interval,
source/event counts, status and start/finish times. Use `--log-file PATH` for manual
file output; set `umask 077`. Exit codes are 0 for success/expected skip, 1 for
operational failure and 2 for invalid arguments. `--help` needs no database.

### History and future analysis

The future project retention target is **at least six calendar months** of DNS,
UFW and SSH raw events, and **at least 12 months** of analysis summaries. This
analysis adds no raw-event purge or rolling historical cutoff. No runtime UFW-history deletion was
found in the current code. DNS retains its existing mechanism (30 days by default),
so it does not yet meet the new target. A common retention policy, bounded history
backfill, daily/longer-term scheduling, normal-behavior models and anomaly scoring
remain separate future work.

## UFW Port Activity Analysis

`analysis/ufw/ports.py` describes activity for each **destination IP, destination
port, protocol and explicit time interval**. It replaces `analysis/targeted_ports/`
and `top_targeted_ports`. TCP and UDP on the same port, and different destination
devices, remain separate. It stores total/BLOCK/ALLOW/AUDIT event counts, unique
source IPs and first/last event times in `analysis_ufw_ports`.

Accepted targets have a valid IPv4/IPv6 address, a port in 1..65535 and the recorded
protocol TCP or UDP. Port 0 is the raw table's missing-port marker. Missing/invalid
targets, missing ports and unsupported protocols are skipped; no sentinel IP or
NULL is put in the unique key. All actions contribute to totals, including unknown
actions. Missing/invalid source IPs count as target activity but not as unique
sources. Valid source IPs include private addresses; equivalent IP spellings merge.
The existing UFW raw schema and its naive time basis are unchanged.

Run from the project root with the usual environment loader:

```bash
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --ports
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --source-ips
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --all --recent-hours 6
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --ports \
  --start '2026-10-21 00:00:00' --end '2026-10-22 00:00:00'
```

`aggregate_ports(events, start_time, end_time)` is the pure function;
`analyze_ports(connection, start_time, end_time)` returns read-only dictionaries;
`run_port_analysis(connection, start_time, end_time)` atomically saves them with a
dedicated connection. Bounds are `[start, end)`. Streaming, raw-row limits and
historical-range support follow Source IP Analysis. A save replaces only the exact
interval, including removing vanished groups on empty/corrected reruns. Port runs
have their own MySQL lock. `--all` saves analyses/intervals separately: completed
intervals remain committed if a later one fails. No SOC alerts or anomaly scores
are produced; Port Scan Detection continues reading raw UFW events independently.

The unique key is `(period_start, period_end, destination_ip, destination_port,
protocol)`. A port/protocol/destination/time index supports history lookups. The
numeric `id` is internal and can change on recomputation. Explicit period bounds
allow hourly, daily, 7/30/90/180-day and longer comparisons with at least 12 months
of stored history; no rolling deletion is added. Compare one consistent interval
size. **Do not sum hourly `unique_source_ips` to obtain daily unique sources**;
recompute the required interval from raw events instead.

### Existing installation upgrade

1. Disable the old targeted_ports cron line, including any manually added copy,
   and wait for its running process to finish. Keep unrelated jobs running. If
   Source IP migration 009/010 has not been applied, complete that upgrade first.
2. Apply [migration 011](database/migrations/011_analysis_ufw_ports.sql) using the
   MySQL client and an account with DDL/routine privileges:

   ```bash
   sudo mysql mysql_siem < database/migrations/011_analysis_ufw_ports.sql
   ```

3. Deploy the updated files and run the reviewed installer as the existing app
   owner through sudo. It grants SELECT/INSERT/DELETE on the new table, replaces
   its managed UFW job with `--all --recent-hours 3`, and removes its old port job.
   Unrelated cron entries and the daily-count job are preserved.

The migration creates and validates the replacement's columns, engine, keys and
constraints **before permanently dropping `top_targeted_ports`**. A wrong existing
replacement aborts without changing its data or retiring the old table. Inspect
and correct that schema before retrying. MySQL DDL commits implicitly; the whole
migration cannot be undone with rollback. Old aggregates are not copied and are
irrecoverable without a prior backup or corresponding raw events. Repeated runs
preserve existing new results and raw UFW/Source IP data. Only the explicitly
replaced old table is dropped. A fresh installation contains only the new port
table and does not execute this destructive upgrade. Never import the bootstrap
`database/schema.sql` into an existing database.

Logs share `analysis/ufw/cron.log` (1 MB, three backups), with analysis name, period,
accepted-event/group counts and status. The default three-hour refresh revisits
late events in those buckets only. Older late arrivals require an explicit manual
range; increase `--recent-hours` up to 24 when needed. No automatic long-history
backfill runs. Inspect a specific interval without mixing aggregation sizes:

```sql
SELECT destination_ip, destination_port, protocol, total_events,
       blocked_events, allowed_events, audited_events, unique_source_ips,
       first_seen, last_seen
FROM analysis_ufw_ports
WHERE period_start = '2026-10-21 12:00:00'
  AND period_end = '2026-10-21 13:00:00'
ORDER BY total_events DESC;
```

## SSH Brute Force Detection

`SSH_BRUTE_FORCE_001` detects at least **five failed SSH password attempts from the same source IP to the same hostname in an inclusive 60-second sliding window**. Different usernames count together. Overlapping qualifying windows form one episode; separate episodes form separate alerts. The original detection algorithm is shared by manual and automatic runs.

### Event source and normalization

The collector reads `/var/log/auth.log` by default. Supported lines have a full ISO timestamp with a UTC offset or `Z`, a hostname, and `sshd[PID]: Failed password for ... from IP port N ssh2`. The `invalid user` password-failure variant and an optional `[preauth]` suffix are supported. IPv4 and IPv6 addresses are validated. Accepted logins, standalone `Invalid user` notices, PAM companion messages and disconnects do not count as extra failures.

`auth_events` stores the original event time as UTC `DATETIME(6)`, hostname, source IP, username, normalized `SSH_AUTH_FAILURE` type, `sshd` service, raw message and a unique event hash. Raw logs are not copied into alert JSON. Yearless syslog timestamps, `sshd-session`, other authentication methods, journald input and compressed archives are currently unsupported.

`auth_ingestion_state` tracks each collector's file device/inode, byte position and checkpoint-content hash. Numbered, uncompressed rotations are drained oldest first. Complete lines, new events and read positions commit together; failures roll them back. Incomplete final lines wait for a later run. Each pass reads at most 5,000 lines across all files; `--max-lines` can change this within 1..100000. File truncation/replacement triggers replay, with hashes preventing duplicate inserts. Completely indistinguishable messages with the same timestamp, host and PID deduplicate. Logs removed before collection and copytruncate races cannot be recovered.

### Configuration and deployment

Review deployment separately before applying database or cron changes. The installer provisions migrations `003_detection_alerts.sql`, `004_detection_state.sql`, `007_auth_events.sql` and `008_ssh_brute_force_rule.sql` for a new, empty database. Existing installations require explicit, reviewed migration application; the installer does not automatically apply these detection/auth migrations to an existing database. SSH jobs require both auth tables, the SSH rule and the shared detection schema.

For an existing installation, inspect the current schema and apply the required additive migrations after approval:

```bash
sudo mysql mysql_siem < database/migrations/003_detection_alerts.sql
sudo mysql mysql_siem < database/migrations/004_detection_state.sql
sudo mysql mysql_siem < database/migrations/007_auth_events.sql
sudo mysql mysql_siem < database/migrations/008_ssh_brute_force_rule.sql
```

Rule registration is repeatable and preserves existing rule settings. The default is `SSH Brute Force Attempt`, severity `HIGH`, enabled. An enabled SSH rule with another severity is rejected in this version.

After approved schema preparation, a reviewed installer run grants table-scoped permissions and updates its existing managed cron block without duplicating jobs or removing unrelated entries. Existing MySQL passwords are preserved. Auth collection needs SELECT/INSERT on `auth_events` and SELECT/INSERT/UPDATE on `auth_ingestion_state`; detection also needs the existing SOC and `detection_state` permissions. No SSH server is installed, started or reconfigured.

The installer creates `config/ssh.env` from [the example](config/ssh.env.example) only when absent. Keep the collector ID stable; leaving it empty uses the local hostname. Settings are read literally by `config/run_with_env.sh --ssh`, without executing shell expressions. SSH settings are independent of DNS and port scan settings.

| Setting | Default | Purpose |
|---|---|---|
| `SSH_AUTH_LOGFILE` | `/var/log/auth.log` | Supported rsyslog auth source |
| `SSH_AUTH_COLLECTOR_ID` | Local hostname | Identity of the machine reading the file |
| `SSH_BRUTE_FORCE_BATCH_SIZE` | `1000` | New database IDs per automatic pass |
| `SSH_BRUTE_FORCE_LATE_SECONDS` | `600` | Additional processing-time retention for late arrivals |
| `SSH_BRUTE_FORCE_MAX_BUFFER_EVENTS` | `10000` | Maximum persisted event-buffer size |

The application user must be able to read the source through the existing log-access model. The installer warns about missing sources or insufficient access; it does not change group membership, sudoers, SSH settings or source-file permissions. With `--allow-missing-source`, a missing auth log produces `SKIPPED` without advancing collection state or creating events. Collection starts when the file appears. An unreadable existing source is a failure. Machines without an SSH server require no fabricated events or alerts.

### Automatic state, late arrivals and deduplication

SSH uses its own rule-keyed row in the shared `detection_state` table. It stores `last_event_id` and a versioned JSON buffer of event dictionaries with their first detection-visit time. Port scan state is separate. The next pass reads all larger IDs, including unsupported types so they can be visited without repeatedly blocking progress. Event timestamps do not determine the checkpoint.

The auth collector holds the common MySQL writer lock from before ID allocation through commit, even across different collector IDs. This makes ID order safe for the checkpoint. All writers must use the updated collector or respect that same lock; uncoordinated external inserts can commit IDs out of order. SSH detection uses its own named run lock, also shared with manual SSH runs. These follow the existing port scan locking pattern and do not block UFW/DNS jobs. Locks release when the database session closes; overlapping runs report `SKIPPED`.

Buffered events retain their original event timestamps for detection. They remain available for `60 + late_seconds` after their first detection visit: 660 seconds by default. Thus two failures at 12:00:45 and three at 12:01:10 can be combined across separate minute runs. A newly committed ID with an older event timestamp is still examined. After a restart, the saved tail is processed once before expiry. Companions already expired from the buffer are not guaranteed to match later arrivals; this is a bounded lateness policy, not unlimited historical replay.

A full buffer or backwards processing-clock movement fails without advancing the checkpoint. Size settings may need tuning for sustained full batches or backlogs; the buffer must hold at least one batch. Source events are not automatically deleted, and must remain available for evidence validation and alert extension.

SOC alerts use the shared SHA-256 fingerprint and `AUTH` evidence references to `auth_events.id`. Replays skip existing alerts; windows sharing source events extend one alert and count the union of evidence IDs. Alert identity and operator status are preserved. If late data would join multiple already-saved alerts, the run reports a review-required error and leaves its checkpoint unchanged rather than partially merging history.

Every automatic pass commits its alerts, evidence and SSH checkpoint in one transaction. A failed write rolls them all back for retry. Manual time-range runs keep the existing per-alert transactions and do not update the automatic checkpoint.

### Cron, logging and manual use

Both jobs are prepared in the installer's managed cron block **once per minute**, independently. Their completion order is irrelevant: later commits are visited on the next detection pass. Jobs use `/usr/bin/python3`, the project working directory, `PYTHONPATH`, the `--ssh` environment loader and `umask 077`. [The inactive cron example](config/ssh.cron.example) shows both commands; copying it does not activate scheduling.

| Job | Log |
|---|---|
| Auth collection | `ingestion/auth/cron.log` |
| Automatic detection | `detection/ssh_brute_force/cron.log` |

Each Python log rotates at 1 MB with three backups. Installer-created logs/settings have mode 0600. Collection logs line/failure counts, inserts, duplicates and state outcome; detection logs fetched/analyzed counts, episodes, created/updated/skipped alerts and checkpoint outcome. Both include status and start/finish times, without passwords or full auth messages. Inspect `FAILED`, `SKIPPED` and state-update lines; for failures before Python starts, check cron output and run the command manually. Exit codes are 0 for success or an expected skip, 1 for operational failure, and 2 for invalid arguments.

Run from the project root after deployment approval and database preparation:

```bash
bash config/run_with_env.sh --ssh /usr/bin/python3 -m ingestion.auth.main --allow-missing-source
bash config/run_with_env.sh --ssh /usr/bin/python3 -m detection.ssh_brute_force.main --automatic
bash config/run_with_env.sh --ssh /usr/bin/python3 -m detection.ssh_brute_force.main \
  --start '2026-10-22 12:00:00' --end '2026-10-22 12:10:00'
```

Use `--log-file PATH` for rotating file output; otherwise summaries go to the console. For manual file logs, set `umask 077`. Manual ranges use UTC without an offset, with an inclusive start and exclusive end. Include at least 60 seconds of overlapping context between manual ranges. Use `--help` for argument details without connecting to MySQL.

Inspect recent SSH alerts:

```sql
SELECT a.id, a.severity, a.status, a.source_ip,
       JSON_UNQUOTE(JSON_EXTRACT(a.details, '$.hostname')) AS hostname,
       JSON_EXTRACT(a.details, '$.failure_count') AS failure_count,
       a.first_seen, a.last_seen, a.detected_at
FROM detection_alerts a
JOIN detection_rules r ON r.id = a.rule_id
WHERE r.rule_key = 'SSH_BRUTE_FORCE_001'
ORDER BY a.id DESC LIMIT 20;
```

Enable or disable detection explicitly; collection remains independent:

```sql
UPDATE detection_rules SET enabled = FALSE WHERE rule_key = 'SSH_BRUTE_FORCE_001';
-- Set enabled = TRUE to resume from the saved checkpoint.
```

## Testing

Analysis and SSH tests use synthetic events. Optional MySQL tests start private servers with temporary data directories, Unix sockets and networking disabled; they do not use the collection database or perform real SSH attacks.

```bash
.venv/bin/python -m pytest -q
ANALYSIS_TEST_MYSQL=1 SSH_TEST_MYSQL=1 PORT_SCAN_TEST_MYSQL=1 .venv/bin/python -m pytest -q
.venv/bin/ruff check --no-cache detection/ssh_brute_force ingestion/auth config/run_logging.py analysis/ufw tests/ssh_brute_force tests/analysis
```

The suite covers source-IP/port/protocol metrics, migration schema guards and retirement, historical interval boundaries, repeatable recomputation, legacy-table removal and raw-data preservation, installer cron replacement, parser/rotation behavior, bounded collection, cross-run windows, late IDs, restart recovery, atomic rollback, lock contention, rule isolation, repeatable installer cron generation and port scan regressions. Installer tests execute isolated sections with substituted database/cron commands; they never run a real installation.

## Development Roadmap

The long-term goal is to build a more complete Linux security monitoring platform.

Planned improvements include:

- Additional security detection rules
- Network behavior analysis and anomaly detection
- Learning normal DNS and network activity patterns
- REST API for accessing monitoring data
- Web-based dashboard for visualizing security events
- Improved alert management and reporting

## About the Project

MySQL SIEM is a personal learning project focused on Python software development, Linux administration, networking, and Blue Team cybersecurity.

The project is developed incrementally, with an emphasis on understanding security monitoring concepts, writing maintainable code, and building practical detection capabilities.

It is not intended to replace professional SIEM solutions.
