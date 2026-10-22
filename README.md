# MySQL SIEM

An educational Python project for collecting Linux security events, analyzing
network activity and detecting suspicious behavior with MySQL.

**Work in progress — not a production-ready SIEM.**

## Features

- UFW firewall logs, SSH password-failure events and AdGuard Home DNS queries.
- CPU, memory, disk, uptime and filesystem metrics.
- Historical UFW Source IP, Port Activity and Traffic Analysis.
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

Run the updated installer from the project root:

```bash
sudo bash install.sh
```

The installer creates missing UFW Analysis tables from the current schema and
validates them before granting permissions and scheduling jobs. No manual
analysis migrations are required. Existing data, rule settings, configuration,
passwords and unrelated cron entries are preserved. Incompatible existing tables
stop setup for inspection; they are never replaced automatically. Stop any old
analysis processes before updating. Do not manually import `database/schema.sql`
into an existing database; let the installer select the missing definitions.

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

UFW Analysis provides historical source IP, destination port and firewall traffic
statistics. Hourly and daily summaries support network monitoring, trend analysis
and future anomaly detection. Counts describe logged events, not connections.

```bash
bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --all --recent-hours 3
```

Select `--source-ips`, `--ports` or `--traffic` individually. Use `--start` and
`--end` for historical correction (`start <= event_time < end`). Traffic refreshes
whole hours and days intersecting the range; daily distinct counts use raw data.
Use the existing naive local UFW timestamps, without offset conversion. The
host clock must match that basis; repeated DST hours cannot be distinguished by
the existing raw timestamps. Source/port row limits remain available via `--help`.
Traffic periods remain of unknown ingestion coverage, including empty closed
periods, because the collector has no health history. Open periods are provisional.

```text
analysis/ufw/
├── __init__.py
├── source_ips.py
├── ports.py
├── traffic.py
└── main.py
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
| Every five minutes | All three UFW analyses: current hour and two previous hours; traffic daily summaries |

UFW analysis uses `--all --recent-hours 3`; traffic also refreshes today and yesterday. Increase the window up to 24 hours or
run a historical interval to include older late events; no full-history backfill
runs automatically. Cron times use the host's timezone.

UFW collection processes at most 5,000 complete log lines per pass with a
20-second processing budget. Use `--max-lines` and `--max-seconds` on the
collector to adjust these limits; unfinished work resumes on the next run.

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
