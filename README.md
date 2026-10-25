# mysql_siem

mysql_siem is a Python-based security monitoring application for Linux. It collects local events and system metrics, stores them in MySQL, and analyzes them for suspicious activity.

The project is actively evolving into a **centralized security monitoring service** for multiple Linux machines. Local Server installation is available today; remote Collector registration and HTTPS event delivery are still under development.

## Features

- UFW firewall event collection and traffic analysis
- SSH authentication monitoring and brute-force detection
- Port scan detection
- DNS event collection through AdGuard Home
- System, filesystem and security metrics
- Process and systemd service snapshots with change history
- Linux Audit metadata collection for passwd, shadow and sudo configuration
- MySQL event history, security alerts and automated cron jobs

## Installation

Installation has been tested on **Debian 13, Ubuntu 24.04/26.04 and Linux Mint 22.3**. The current automatic installer recognizes Debian 13, Ubuntu and Linux Mint.

Clone the project and start the Server installation:

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
sudo bash install.sh --role server
```

The installer downloads the current official `main` branch and shows its commit. Confirm the Server role when prompted. The installer creates the service account, installs dependencies, prepares an isolated Python environment and configures collection and analysis jobs. You can run it from a private home directory without moving the clone or opening access to your home.

- Service code: `/usr/local/lib/mysql_siem`
- Python environment: `/opt/mysql_siem-venv`
- Machine settings: `/usr/local/lib/mysql_siem/config/*.env`

**Development reset installer:** if `mysql_siem` already exists, installation requires typing `RESET` and permanently deletes its events, metrics, alerts and database configuration. A fresh schema and local identities are created. File-based settings and logs are retained; the original Git clone and local changes stay untouched. Back up anything you want to keep before reinstalling. A failed reset installation keeps collection paused until a successful retry.

To preserve an existing database, use `sudo bash install.sh --upgrade --role server`.
The upgrade validates existing history and applies additive migrations. See the
[local collector installation and acceptance checks](docs/local-collectors.md)
for Processes, Services and Audit prerequisites, recovery and remaining host-level
validation. Earlier platform installation tests do not establish acceptance of
these new collectors.

**Debian 13 requires a preinstalled Oracle MySQL 8.0 or 8.4 server and client**, with local administrative socket access. On Ubuntu and Mint, the installer can install MySQL when needed. MariaDB is not supported. Optional AdGuard Home integration requires separate configuration.

The `collector` installation role is reserved for future development and currently stops before making system changes.

## Project status

This is an actively developed learning project focused on Python, MySQL, Linux administration and cybersecurity. It is not a replacement for a production-grade SIEM. The centralized architecture is being built incrementally while retaining the existing local collectors and detection capabilities.
