# MySQL SIEM

An educational Python project for collecting Linux security events, analyzing
network activity and detecting suspicious behavior with MySQL.

**Work in progress — not a production-ready SIEM.**

## Features

- UFW firewall logs, SSH password-failure events and AdGuard Home DNS queries.
- CPU, memory, disk, uptime and filesystem metrics.
- Historical UFW summaries by source IP and destination port.
- Port scan and SSH brute force detection with shared SOC alerts.

Analysis describes activity; detection applies rules and creates alerts.
Anomaly detection is planned.

## Installation

Requires an Ubuntu-based Linux system, Python 3.10+ and MySQL 8.
Run the installer through sudo as the intended application owner.

### New installation

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
sudo bash install.sh
```

The installer prepares dependencies, the database, permissions and cron jobs.
Review it before use. DNS requires additional configuration.

### Update an existing installation

Run from the project root with the updated files available:

1. Disable old `attacking_ips` and `targeted_ports` cron jobs and wait for any
   running instances to finish. Keep unrelated jobs running.
2. Apply the analysis migrations in order. Do not continue after an error:

   ```bash
   sudo mysql mysql_siem < database/migrations/009_analysis_source_ips.sql &&
   sudo mysql mysql_siem < database/migrations/010_drop_top_attacking_ips.sql &&
   sudo mysql mysql_siem < database/migrations/011_analysis_ufw_ports.sql
   ```

3. Run `sudo bash install.sh` to update permissions and managed cron jobs.

These migrations can be repeated. **010 and 011 permanently delete the old
aggregate tables and their history**; raw events and existing new summaries are
preserved. Migration 011 checks the replacement schema before deleting the old
table. MySQL DDL commits implicitly and cannot be undone with rollback.

**Never import `database/schema.sql` into an existing database.** Older deployments
may also need detection/auth migrations 003, 004, 007 and 008; inspect the current
schema and [migration files](database/migrations) first. The installer preserves
existing configuration, passwords and unrelated cron entries.

## Configuration

| File | Purpose |
|---|---|
| `config/mysql.env` | Shared database connection; created by the installer |
| [config/ssh.env.example](config/ssh.env.example) | SSH log source and detection limits |
| [config/port_scan.env.example](config/port_scan.env.example) | Port scan processing limits |
| [config/adguard.env.example](config/adguard.env.example) | Optional AdGuard Home integration |

Use the examples as templates for the matching `.env` files. The installer
creates SSH and port scan defaults when absent. Keep credentials out of Git. The installer expects local MySQL, database
`mysql_siem` and application user `pythonuser`. It does not install or configure
an SSH server. SSH collection skips a missing auth log until it becomes available.

## UFW analysis

| Analysis | Results |
|---|---|
| Source IP | Event/action/protocol counts, unique destination ports/IPs, first/last seen |
| Port activity | Counts and unique sources per destination IP, port and TCP/UDP protocol, first/last seen |

Results are stored in `analysis_source_ips` and `analysis_ufw_ports`.
Source analysis includes private IPv4/IPv6 addresses. Port analysis requires a
valid destination IP and port 1–65535; missing targets, port 0 and non-TCP/UDP
traffic are excluded.

Run both analyses, or replace `--all` with `--source-ips` or `--ports`:

```bash
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --all --recent-hours 3
```

Recalculate a historical interval:

```bash
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --ports \
  --start '2026-10-21 00:00:00' --end '2026-10-22 00:00:00'
```

Bounds are `start <= event_time < end`. Use timestamps in the existing UFW time
basis, without an offset or UTC conversion; the host clock must match that basis.
Reruns atomically replace only the exact interval. Each analysis/interval commits
separately. Distinct IP/port counts cannot be summed across hours to get daily
unique counts.

The default limit is 100,000 raw rows per interval; use shorter intervals or
`--max-events` up to 1,000,000 for larger datasets. Inspect results with:

```sql
SELECT period_start, destination_ip, destination_port, protocol, total_events
FROM analysis_ufw_ports
ORDER BY period_start DESC, total_events DESC
LIMIT 10;
```

## Detection

Run from the project root:

```bash
bash config/run_with_env.sh --port-scan /usr/bin/python3 -m detection.port_scan.main
bash config/run_with_env.sh --ssh /usr/bin/python3 -m ingestion.auth.main --allow-missing-source
bash config/run_with_env.sh --ssh /usr/bin/python3 -m detection.ssh_brute_force.main --automatic
```

SSH detects at least five password failures from the same source IP to the same
host in 60 seconds. Its collector supports ISO-timestamped `sshd` password-failure
lines in `auth.log`; manual SSH ranges use UTC without an offset. Collection and
detection maintain separate checkpoints. Use each module's `--help` for options.

## Scheduling and logs

| Schedule | Jobs |
|---|---|
| Every minute | UFW/SSH collection, port scan and SSH detection |
| Every five minutes | System/filesystem/security metrics, configured DNS collection |
| Every five minutes | Both UFW analyses: current hour and two previous hours |
| Daily at 13:02 | Daily UFW counts, covering the day so far |

UFW analysis uses `--all --recent-hours 3`. Increase the window up to 24 hours or
run a historical interval to include older late events; no full-history backfill
runs automatically. Cron times use the host's timezone.

```bash
crontab -l
tail -n 50 analysis/ufw/cron.log
```

Analysis, SSH and port scan logs rotate at 1 MB with three backups. Look for
`SUCCESS`, `SKIPPED` or `FAILED`; inspect the relevant module's `cron.log` on errors.

## History and planned work

The retention target is six calendar months of raw DNS/UFW/SSH events and twelve
months of analysis summaries. A shared retention policy and anomaly models are
not implemented yet. DNS retains its existing 30-day default; UFW analysis adds
no raw-data deletion or rolling history cutoff.

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
ANALYSIS_TEST_MYSQL=1 SSH_TEST_MYSQL=1 PORT_SCAN_TEST_MYSQL=1 .venv/bin/python -m pytest -q
```

Optional MySQL tests start private temporary servers with networking disabled;
they do not use the collection database. Installer tests use fake database/cron
commands. No real installation is run by the tests.
