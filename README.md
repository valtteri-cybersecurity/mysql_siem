# MySQL SIEM

A Python and MySQL project for collecting Linux host metrics and firewall events, exploring SQL-based analysis, and developing security detection logic.

**Work in progress.** This is an educational Blue Team project, not a complete or production-ready SIEM. The current version provides collection and aggregation scripts with an Ubuntu installation script. Detection, portability, testing, and operational hardening remain under development.

## Current features

- UFW ingestion from /var/log/ufw.log: event time, action, source and destination addresses, protocol, ports, raw log line, and SHA-256 event hash.
- Incremental ingestion using a saved file position and a unique event-hash constraint.
- System metrics: uptime, CPU usage and load averages, CPU temperature where available, available memory, and root filesystem usage.
- Filesystem metrics: file counts under /home and recently modified files under /etc.
- Security metrics: authentication-failure counts from /var/log/auth.log, UFW block counts, unique blocked source addresses, and uptime.
- Aggregations for blocked source IPs, targeted destination ports, and daily UFW actions.
- An initial detection entry point that retrieves today's BLOCK and AUDIT events. It does not yet implement an operational port-scan detector or alert pipeline.

Process monitoring, service monitoring, DNS integration, sudo-command ingestion, an API, and a GUI are not included in the current source snapshot. They may exist in separate local work or be added later.

## Structure

| Path | Responsibility |
| --- | --- |
| ingestion/ | UFW parsing and incremental ingestion |
| metrics/system/ | System measurements |
| metrics/filesystem/ | Filesystem counts |
| metrics/security/ | Authentication and firewall counters |
| analysis/ | Source-IP, destination-port, and daily aggregations |
| detection/port_scan/ | Preliminary event retrieval for future detection |
| database/connection.py | Shared environment-based MySQL connection |
| database/schema.sql | Database schema dump |
| install.sh | Ubuntu installation and cron configuration |

## Requirements

The installer targets Ubuntu with apt, systemd, and local MySQL root authentication through /run/mysqld/mysqld.sock.

It installs Python 3, the distribution's PyMySQL package, MySQL Server, rsyslog, cron, CA certificates, and OpenSSL. Collectors also depend on normal Linux facilities such as /proc, /sys, and find.

The host must provide readable /var/log/ufw.log and /var/log/auth.log files for the corresponding collectors. Installing rsyslog does not by itself guarantee that both files exist or that the scheduled user can read them. Configure logging and appropriate read permissions separately. Do not make sensitive logs world-readable.

## Installation

Use a disposable VM or dedicated lab host first. Read install.sh and the cautions below before running it.

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
sudo bash install.sh
```

The installer:

1. Installs dependencies and enables MySQL, cron, and rsyslog.
2. Creates config/mysql.env if absent, using a randomly generated database password.
3. Restricts that file to mode 600 and assigns ownership to the installation user.
4. Creates the local ufw_monitor database and imports the schema if it contains no tables.
5. Creates or updates pythonuser@localhost and grants table-specific SELECT, INSERT, and UPDATE privileges as needed.
6. Generates a path-independent config/run_with_env.sh wrapper.
7. Checks Python syntax and writes a marked block into the installation user's crontab.
8. Checks the application database connection.

Installation success does not establish that every collector has working log access or that analysis results are correct.

### Installation cautions

- Names are currently fixed: DB_HOST=localhost, DB_NAME=ufw_monitor, and DB_USER=pythonuser.
- The installer changes the password of an existing pythonuser@localhost account. This can break other applications using that account. Prefer a dedicated project account in a future revision and avoid running this installer against a shared account.
- Existing privileges on that account are not revoked. Table-specific grants do not remove privileges previously assigned elsewhere.
- The installer rejects nonempty databases whose table-name set differs from the expected eight tables. It does not verify existing column definitions or migrate schemas.
- database/schema.sql contains DROP TABLE IF EXISTS statements. Do not import it directly into a database containing data you need to keep. The installer only imports it when the database has no tables.
- config/mysql.env is sourced as shell code, including during privileged installation. Treat it and the project directory as trusted input; do not use configuration from an untrusted source.
- Installation changes services, file ownership, and cron configuration. It is not an atomic deployment or migration process.

## Configuration

The shared Python connection helper reads environment variables; it does not load configuration files automatically.

```text
DB_HOST=localhost
DB_USER=pythonuser
DB_PASSWORD=<private password generated during installation>
DB_NAME=ufw_monitor
```

Keep config/mysql.env, config/adguard.env, logs, and local credentials out of Git. Never paste real passwords into documentation.

## Manual execution

Run from the repository root after installation:

```bash
bash config/run_with_env.sh /usr/bin/python3 -m metrics.system.main
bash config/run_with_env.sh /usr/bin/python3 -m metrics.filesystem.main
bash config/run_with_env.sh /usr/bin/python3 -m metrics.security.main
bash config/run_with_env.sh /usr/bin/python3 -m ingestion.ufw_to_mysql
bash config/run_with_env.sh /usr/bin/python3 -m analysis.attacking_ips.main
```

The targeted-port scripts currently rely on local imports. Their scheduled entry point runs from analysis/targeted_ports rather than using a package-qualified module command.

## Scheduled collection

The installer manages only the block between its mysql_siem cron markers and preserves other crontab entries.

| Job | Schedule |
| --- | --- |
| UFW ingestion | Every minute |
| System, filesystem, and security metrics | Every five minutes |
| Source-IP aggregation | Every five minutes |
| Daily UFW counts | Daily at 13:02 |
| Targeted-port aggregation | Daily at 13:03 |

Times follow the host's cron configuration. Output is appended to cron.log files beside the corresponding scripts. Log rotation, retention, and prevention of overlapping jobs are not configured by the installer.

Inspect the current user's jobs with:

```bash
crontab -l
```

## Database tables

The supplied schema defines filesystem_metrics, security_metrics, system_metrics, top_attacking_ips, top_targeted_ports, ufw_daily_actions_counts, ufw_log, and ufw_state.

UFW event values are inserted with parameterized SQL. The unique event_hash index supports duplicate suppression. Aggregated blocked traffic is not proof of an attack, despite the historical top_attacking_ips table name.

## Known limitations

- Detection currently retrieves events only; there is no complete detector, alert delivery, API, or dashboard.
- The UFW parser treats the first whitespace-separated field as a timestamp. Traditional syslog formats need additional parsing.
- Log rotation is handled only by resetting the saved offset when the current file becomes smaller. File replacement and rotated-log recovery require more work.
- INSERT IGNORE can suppress database warnings as well as duplicates; malformed input needs stronger validation.
- Authentication-failure matching depends on date format and case-sensitive message strings.
- Daily counting opens matching rotated UFW files as plain text, including potential compressed files. Its seven-day average covers days represented by BLOCK rows, not necessarily seven calendar days including zero-event days.
- Source-IP exclusions contain environment-specific address prefixes.
- Filesystem metrics are counts, not file-integrity monitoring.
- Some scripts still have inconsistent import and connection patterns. Errors are often printed without a nonzero exit status.
- Automated tests, retention policies, schema migrations, robust scheduling, and production security hardening remain incomplete.

## Development priorities

- Use an isolated project database account without modifying shared credentials.
- Improve parser validation, timestamps, log rotation, and failure reporting.
- Standardize module imports and database access.
- Add automated tests and schema migration support.
- Implement and validate detection rules.
- Integrate DNS data, starting with AdGuard Home and potentially Unbound.
- Introduce an API and user interface after collection and analysis are established.

This roadmap describes future work, not completed functionality.
