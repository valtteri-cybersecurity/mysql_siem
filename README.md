# mysql_siem

A Python and MySQL Blue Team lab for collecting Linux security telemetry,
analyzing firewall activity and detecting possible port scans. It combines
UFW events, host metrics and AdGuard Home DNS query logs in one database.

Collection, SQL-based summaries and stateful port-scan detection are implemented.
The project is built for learning Python, backend development and SOC workflows.

## Features

- Incremental UFW log ingestion with file-position tracking and duplicate handling.
- CPU, memory, disk usage, uptime, filesystem and authentication-failure metrics.
- SQL summaries of blocked source addresses, destination ports and daily UFW actions.
- AdGuard Home DNS collection over verified HTTPS, with pagination, checkpoints,
  replay handling and configurable retention, defaulting to 30 days.
- Port-scan detection using a 60-second sliding window and distinct destination ports.
- Shared SOC alerts with original-event evidence, stable alert identities and
  transactional checkpoint updates.
- Minute-based detection jobs, overlap protection and rotating detection logs.
- Pytest coverage for detection, persistence, recovery and cron configuration,
  including optional isolated MySQL integration tests.

## Installation

Designed for Ubuntu and Linux Mint with Python 3.10+ and local MySQL 8.
UFW and authentication metrics require readable `/var/log/ufw.log` and
`/var/log/auth.log`; configure logging and access for the collection user.

### New installation

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
sudo bash install.sh
```

The installer installs dependencies, starts services, creates the local
`mysql_siem` database and application account, provisions collection and detection
tables, and adds jobs to the installing user's crontab. Port-scan detection runs
once per minute. Existing configuration files and account passwords are preserved.

Database credentials are stored in `config/mysql.env`. Optional settings are in
`config/port_scan.env` and `config/adguard.env`. These local configuration files
are excluded from Git. Keep credentials private.

### Upgrade an existing installation

Existing telemetry must be retained. Apply the additive detection migrations
before rerunning the installer:

```bash
sudo mysql mysql_siem < database/migrations/003_detection_alerts.sql
sudo mysql mysql_siem < database/migrations/004_detection_state.sql
sudo bash install.sh
```

If migration 003 is already applied, only 004 is new. Both migrations are
repeatable and preserve existing rule settings. The installer then grants the
required application permissions and updates its managed cron block without
duplicating jobs or removing unrelated entries.

The installer applies detection migrations automatically only to a new database.
**Never import `database/schema.sql` over an existing database**: it is a base
schema dump containing destructive statements. Review [migration 003](database/migrations/003_detection_alerts.sql) and
[migration 004](database/migrations/004_detection_state.sql) before upgrading.

## Port-scan detection

The implemented rule, **`PORT_SCAN_001` — Possible Port Scanning**, detects:

| Condition | Value |
| --- | --- |
| Grouping | Same source IP, destination IP and protocol |
| Protocols | TCP and UDP, evaluated separately |
| Firewall actions | BLOCK, AUDIT and ALLOW |
| Threshold | At least 10 distinct destination ports |
| Time window | At most 60 seconds, including the exact boundary |
| Initial severity | HIGH |

Repeated attempts to the same port count once. The window slides across calendar
minutes. Qualifying windows sharing events form one finding, so a continuous
scan can last longer than 60 seconds without producing repeated alerts.

```text
UFW logs -> ufw_log -> Port Scan Detector -> detection_alerts -> alert_evidence
                             |
                       detection_state
```

Automatic passes read bounded batches of new UFW IDs instead of repeatedly
scanning the full history. A persisted event buffer connects consecutive runs
and accommodates delayed arrivals. By default, a pass reads up to 1,000 new
rows and retains buffered events for 660 seconds from their first detection
read: the 60-second window plus a 600-second delay allowance.

Later findings sharing original evidence extend the existing alert while
preserving its fingerprint, severity and investigation status. Automatic alert
changes, evidence and the processing checkpoint commit together; a failed
transaction rolls them back. A MySQL named lock prevents overlapping command-line
runs without interfering with the UFW collector's separate lock.

The shared tables are `detection_rules`, `detection_alerts`, `alert_evidence`
and `detection_state`. Limits can be adjusted using
[config/port_scan.env.example](config/port_scan.env.example).

### Run and verify

Run one automatic processing pass from the project root:

```bash
bash config/run_with_env.sh --port-scan /usr/bin/python3 -m detection.port_scan.main
```

Inspect an explicit time range without advancing the automatic checkpoint.
The start is inclusive and the end exclusive; use the same timezone-naive time
basis as `ufw_log.event_time`:

```bash
bash config/run_with_env.sh /usr/bin/python3 -m detection.port_scan.main \
  --start "2026-10-22 12:00:00" --end "2026-10-22 13:00:00"
```

Check scheduled runs and stored alerts:

```bash
crontab -l
tail -n 40 detection/port_scan/cron.log
sudo mysql mysql_siem -e "
SELECT id, severity, status, source_ip, first_seen, last_seen
FROM detection_alerts ORDER BY id DESC LIMIT 10;
"
```

A successful automatic pass reports `Status: SUCCESS` and
`Detection state updated: YES`. A disabled rule or an occupied lock produces
`SKIPPED`; failures return a nonzero exit code. Cron uses `--log-file` to rotate
the detection log at approximately 1 MB and keep three backups.

To disable the rule without removing its saved alerts or checkpoint:

```bash
sudo mysql mysql_siem -e "
UPDATE detection_rules SET enabled = FALSE WHERE rule_key = 'PORT_SCAN_001';
"
```

Set `enabled = TRUE` to resume processing. If a run fails, check database
permissions, migration status and the configured buffer limits. Processing
resumes from the last committed checkpoint; do not reset the event ID to bypass
an error. The standalone Python detector also works without a MySQL connection.

## Connect AdGuard Home

The DNS collector currently supports AdGuard Home. Configure its connection
before installation, or before rerunning the installer for an existing setup.

### 1. Configure your server

```bash
test -f config/adguard.env || cp config/adguard.env.example config/adguard.env
chmod 600 config/adguard.env
nano config/adguard.env
```

Set your HTTPS management URL, credentials and source name:

```ini
ADGUARD_URL=https://adguard.example.org
ADGUARD_USERNAME=your-user
ADGUARD_PASSWORD=your-password
ADGUARD_SOURCE_NAME=adguard-home
```

Use literal values without shell quotes. For a private CA or self-signed
certificate, also set `ADGUARD_CA_BUNDLE` to the absolute path of the trusted
public PEM certificate. TLS verification remains enabled. AdGuard query logging
must be enabled and its HTTPS interface reachable from the collector.

### 2. Install the integration

For an existing database, complete any required detection migrations described
above before rerunning:

```bash
sudo bash install.sh
```

With `config/adguard.env` present, the installer registers the source and adds a
five-minute DNS job alongside the other collectors. New sources are disabled
until explicitly enabled; existing enablement is preserved.

### 3. Enable the source and test collection

For the default source name configured above:

```bash
sudo mysql mysql_siem -e "
SELECT source_name, base_url, enabled FROM dns_sources;
"
```

Confirm the registered URL is your server, then enable the source and run once:

```bash
sudo mysql mysql_siem -e "
UPDATE dns_sources SET enabled = TRUE WHERE source_name = 'adguard-home';
"
bash config/run_with_env.sh --dns /usr/bin/python3 -m ingestion.dns.main
```

Check stored events and subsequent scheduled runs:

```bash
sudo mysql mysql_siem -e "SELECT COUNT(*) AS dns_events FROM dns_events;"
crontab -l
tail -n 20 ingestion/dns/cron.log
```

A successful run reports `DNS collection complete`. DNS replay handling is best
effort: the API does not provide an event identity used by this collector, so
perfect duplicate detection and lossless collection are not guaranteed.

## Project structure

| Directory | Purpose |
| --- | --- |
| `ingestion/` | UFW ingestion and the modular DNS collector |
| `metrics/` | System, filesystem and security measurements |
| `analysis/` | SQL-based summaries |
| `detection/port_scan/` | Standalone detector, database reads and stateful execution |
| `detection/common/` | Shared SOC alert and evidence storage |
| `database/` | Shared connection, base schema and additive migrations |
| `config/` | Environment loader, configuration and cron examples |
| `tests/` | Unit tests and optional isolated integration tests |

## Development and tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Tests use synthetic events and simulated database dependencies. Optional MySQL
integration tests require `mysqld` and create their own temporary servers with
networking disabled; they do not use the collection database. Enable them
explicitly:

```bash
PORT_SCAN_TEST_MYSQL=1 .venv/bin/python -m pytest tests/port_scan/test_port_scan_mysql.py
DNS_TEST_MYSQL=1 .venv/bin/python -m pytest tests/dns/test_mysql.py
```

Port-scan tests cover sliding-window boundaries, grouping, delayed events,
cross-run continuity, restart recovery, alert updates, transaction rollback,
locking and repeatable cron generation. Cron tests simulate configuration
changes rather than installing real scheduled jobs.

## Current limitations

This is a lab project, not a production-ready SIEM. A port-scan finding indicates
suspicious activity, not proof of an attack.

- Detection has bounded batch and buffer sizes; arbitrarily delayed events may
  no longer have enough retained context to complete or extend a finding.
- ID-based progress relies on the existing collector's serialized writes.
- Previously separate alerts are not automatically merged if late evidence
  later connects them; incident correlation is outside the current scope.
- The detector favors clear Python over optimization and is not intended for
  unrestricted high-volume log streams.
- Older collectors still need more consistent parsing and error handling.
  Log rotation and retention outside DNS and the detection log require separate
  configuration.

There is no dashboard, HTTP API, external alert notification or automatic
firewall blocking. Port-scan detection is the only implemented detection rule.
