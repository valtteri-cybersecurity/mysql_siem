# MySQL SIEM

**Linux Security Monitoring & Intrusion Detection**

MySQL SIEM is an open-source security monitoring and intrusion detection project built with Python, MySQL and Linux.

It collects security events, monitors system activity, analyzes network traffic and detects potentially suspicious behavior.

The project combines log collection, system monitoring, security analysis and threat detection into a single platform.

## Features

### Network Security

- UFW firewall log collection, including rotated and compressed logs
- Source IP, network port and traffic analysis
- Port scan detection
- Optional DNS monitoring through AdGuard Home

The UFW collector includes incremental processing, persistent checkpoints, duplicate detection and quarantine handling for malformed events.

Collection continuity is monitored to help identify missing or changed log sources.

Optional filtering can reduce repetitive localhost MySQL AUDIT events. Filtering is disabled by default to preserve security visibility.

### Authentication Monitoring

- SSH authentication event collection
- Successful and failed SSH login monitoring
- Local login activity
- SSH brute-force detection

Authentication events are stored in MySQL for security analysis and historical investigation.

### System Monitoring

- CPU, memory, disk and uptime metrics
- Filesystem monitoring
- Running process monitoring and change detection
- systemd service monitoring and change history
- Security-related system metrics

### Security Auditing

Linux Audit integration provides monitoring of security-relevant system activity and configuration changes.

Default monitoring targets include:

- User and group configuration
- Sensitive account files
- SSH configuration and activity
- Cron configuration
- MySQL-related activity

Additional monitoring targets can be configured.

### Data Storage and Automation

- MySQL database for events, metrics and security alerts
- Automated collection, analysis and detection tasks
- Persistent collection state and duplicate protection
- Versioned database migrations
- Database-preserving upgrade procedures
- Verified backups and recovery checks
- Dedicated service account and restricted runtime permissions

## Supported Linux Distributions

Installation has been tested on:

| Distribution | Version |
|---|---|
| Debian | 13 |
| Ubuntu | 24.04 LTS |
| Ubuntu | 26.04 LTS |
| Linux Mint | 22.3 |

**Requirements:**

- Python 3
- Oracle MySQL 8.0 or 8.4
- Linux system with supported log sources
- Administrator privileges for installation

On Debian 13, Oracle MySQL Server and Client must already be installed. On Ubuntu and Linux Mint, the installer can install the required MySQL packages.

MariaDB is not currently supported.

Successful installation does not guarantee that every optional collector is available on every system. Some features depend on the operating system, installed services and log permissions.

## Installation

Clone the repository:

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
```

Review the revision you intend to install:

```bash
git log -1 --format='%H %s'
```

Start a fresh server installation using an explicitly approved full 40-character commit SHA:

```bash
sudo bash install.sh --role server --reset --revision APPROVED_COMMIT_SHA
```

Replace `APPROVED_COMMIT_SHA` with the full commit identifier you have reviewed and approved.

The installer prepares the application environment, database, dependencies, service account and automated monitoring tasks.

Follow the installation instructions and review any reported prerequisites.

**Important:** RESET is intended for fresh installations. If an existing MySQL SIEM database is present, the installer requires explicit confirmation before deleting its data.

## Updating MySQL SIEM

MySQL SIEM includes a database-preserving upgrade process.

The upgrade procedure is designed to preserve existing events, alerts, identities and collection checkpoints while applying supported database migrations.

Currently, upgrades require an explicitly approved commit:

```bash
sudo bash install.sh --role server --upgrade --revision APPROVED_COMMIT_SHA
```

The upgrade process includes database compatibility checks, verified backups, recovery checks and deployment validation.

Automatic version selection is not yet enabled. The installer does not automatically trust the latest GitHub `main` commit.

Some older installations may require additional migration work when historical data cannot be safely verified. In these cases, the upgrade stops rather than modifying uncertain historical records.

**Never use RESET to resolve a failed data-preserving upgrade.** Preserve the database, backups and recovery information for investigation.

A signed release channel for secure automatic upgrades is planned.

## Project Status

MySQL SIEM is under active development.

The current implementation operates as a **local SIEM server** with automated log collection, system monitoring, security analysis and intrusion detection.

Recent development has focused on:

- More reliable UFW ingestion and log rotation handling
- Compressed UFW log processing
- Improved event validation and collection continuity
- Optional, controlled UFW event filtering
- Database migration safety and historical data preservation
- Verified backups and safer upgrades
- Process, service and Linux Audit monitoring

### Planned Development

Upcoming work focuses on reliability, performance, testing and centralized monitoring.

The long-term architecture separates the system into two roles:

**SIEM Server:** Central event storage, security analysis, detection and monitoring.

**SIEM Collector:** Lightweight Linux agent that securely delivers events to the central server.

Remote collector registration and HTTPS event delivery are not yet implemented. The collector installation role is therefore not currently available.

Automatic signed releases and broader integration testing are also planned.

## Development and Testing

The repository includes automated Python tests covering collection, database operations, migrations, security analysis and intrusion detection.

Testing includes unit tests and MySQL integration tests. Some integration and performance tests require a separate test environment.

The project remains experimental. New versions should be validated in a test environment before deployment to systems containing important historical data.

## Documentation

Additional information about UFW collection, compressed log handling, quarantine and upgrade requirements is available in:

[UFW Collector Operations](docs/ufw-phase2-operations.md)

## Technologies

Python · MySQL · Linux · Bash · SQL · Linux Audit · Git

---

**MySQL SIEM is an educational and experimental security software project. It is not intended to replace a production-grade SIEM platform.**
