# mysql_siem

A Python and MySQL project for collecting Linux security telemetry and exploring
SQL-based analysis. It combines UFW firewall events, host metrics and AdGuard
Home DNS query logs in one database.

Built as a hands-on Blue Team project. Collection and basic summaries are
implemented; detection and operational hardening are still under development.

## Features

- Incremental UFW log ingestion with file-position tracking and duplicate handling.
- System metrics: CPU, memory, disk usage and uptime.
- Filesystem and security metrics, including authentication-failure counts.
- Summaries of blocked source addresses, destination ports and daily UFW actions.
- AdGuard Home integration using the official `/control/querylog` API over verified HTTPS.
- Separate DNS adapter and storage layers, with pagination, checkpoints and replay handling.
- Configurable DNS retention, defaulting to 30 days.
- Cron-based collection managed by the installation script.

Only the AdGuard Home DNS adapter is currently implemented. There is no dashboard,
API or complete detection and alerting pipeline yet.

## Installation

Designed for Ubuntu and Linux Mint with Python 3.10+ and local MySQL 8.

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
sudo bash install.sh
```

The installer installs dependencies, configures the local `mysql_siem` database
and `pythonuser` account, creates the tables, and adds collection jobs to the
installing user's crontab. Existing configuration files are preserved.

The installer changes services, database account settings and its managed cron
block. Review it before running on a shared host. UFW and authentication metrics
also require readable `/var/log/ufw.log` and `/var/log/auth.log` files; their logging
and access permissions must be configured for the collection user.

Database settings are stored in `config/mysql.env`. Keep credentials private and
never import `database/schema.sql` over data you want to retain.

## Connect AdGuard Home

### 1. Configure your server

Before installation, or before rerunning the installer for an existing setup:

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
| `detection/` | Early detection experiments |
| `database/` | Shared connection, schema and migrations |
| `config/` | Environment loader and configuration examples |
| `tests/` | Automated tests, primarily for DNS and its integration |

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Optional MySQL integration tests use a temporary isolated server and require
`mysqld` to be available:

```bash
DNS_TEST_MYSQL=1 .venv/bin/python -m pytest tests/dns/test_mysql.py
```

## Current limitations

This is a lab project, not a production-ready SIEM. Older collectors still need
more consistent parsing, error handling and database access. Log rotation and
retention outside DNS require separate configuration. Blocked traffic alone is
not proof of an attack, and detection experiments do not yet generate alerts.
