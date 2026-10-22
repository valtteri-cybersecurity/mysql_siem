# MySQL SIEM

A Python-based security monitoring project designed to collect, analyze, and detect suspicious activity in Linux environments.

The project combines Linux system monitoring, firewall logs, and DNS activity into a MySQL database. Its goal is to explore how Security Information and Event Management (SIEM) systems work and develop practical skills in cybersecurity, backend development, and security monitoring.

**Status:** Work in progress — an educational Blue Team project, not a production-ready SIEM.

## Features

- **System Monitoring** — Collects CPU, memory, disk usage, uptime, and filesystem metrics.
- **Firewall Monitoring** — Collects and analyzes UFW firewall events, blocked connections, and network activity.
- **DNS Monitoring** — Integrates with AdGuard Home to collect and analyze DNS queries, with configurable filtering and data retention.
- **Security Analysis** — Uses Python and SQL to identify patterns in collected security events.
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
