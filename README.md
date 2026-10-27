# mysql_siem

**Linux Security Monitoring & Intrusion Detection**

mysql_siem is an open-source security monitoring project built with Python and MySQL.

It collects security events, monitors Linux system activity, analyzes network traffic and detects potentially suspicious behavior.

The project combines log collection, host monitoring, security analysis and threat detection into a single system.

## Features

**Network Security**
- UFW firewall log collection and traffic analysis
- Source IP and network port analysis
- Port scan detection
- Optional DNS monitoring through AdGuard Home

**Authentication Monitoring**
- SSH login attempts and authentication events
- Successful and failed SSH logins
- Local login activity
- SSH brute-force detection

**System Monitoring**
- System performance and resource metrics
- Filesystem and security metrics
- Running process monitoring and change detection
- systemd service monitoring and change history

**Security Auditing**
- Linux Audit integration
- Monitoring of sensitive system configuration files
- Detection of changes to user account and sudo configurations

**Data Storage & Automation**
- MySQL database for collected events, metrics and security alerts
- Automated collection and detection tasks
- Incremental log processing and persistent collection state
- Database migrations for version upgrades

## Supported Linux Distributions

Installation has been successfully tested on:

- Debian 13
- Ubuntu 24.04 LTS
- Ubuntu 26.04 LTS
- Linux Mint 22.3 

The application uses Python 3 and MySQL 8.0 or 8.4.

**Note:** Debian 13 requires an existing Oracle MySQL server and client installation. On Ubuntu and Linux Mint, the installer can install MySQL when needed. MariaDB is not currently supported.

## Installation

Clone the repository:

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
```

Start the installation:

```bash
sudo bash install.sh --role server
```

The installer retrieves the latest version from the official main branch and prepares the application environment, database, dependencies and automated monitoring tasks.

Follow the installation prompts. Certain monitoring features require the corresponding Linux services and log sources to be available.

DNS monitoring requires separate AdGuard Home configuration.

## Updating mysql_siem

Existing installations can be upgraded without intentionally deleting stored events, metrics or alerts.

```bash
cd mysql_siem
sudo bash install.sh --upgrade --role server
```

The upgrade preserves the existing database and collection history while applying supported database migrations.

**Important:** Running the installer without `--upgrade` on an existing installation uses the reset installation path. If a database already exists, the installer requires explicit `RESET` confirmation before deleting its data.

Back up important data before installation or upgrades.

## Project Status

mysql_siem is under active development.

The current version operates as a local SIEM server with automated collection, monitoring, analysis and detection capabilities.

Development is moving toward a centralized architecture where multiple Linux machines can report security events to a central server.

Remote collector registration and HTTPS event delivery are not yet available.

This is an educational and experimental cybersecurity project, not a replacement for a production-grade SIEM platform.

## Technologies

Python · MySQL · Linux · Bash · SQL · Linux Audit · Git


