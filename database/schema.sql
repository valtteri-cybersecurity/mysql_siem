-- Immutable pre-registry baseline for migration 013. No data replacement.
-- Initialize/upgrade through: python -m database.migrate apply
-- Migration 014 adds the registry; 015/016 add identities and scoped keys.
-- Preserve existing rule IDs, operator settings, events and checkpoints.

CREATE TABLE `filesystem_metrics` (
  `metric_date` date NOT NULL,
  `modified_last_day` bigint unsigned NOT NULL DEFAULT '0',
  `total_files` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`metric_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `security_metrics` (
  `date` datetime NOT NULL,
  `uptime` decimal(10,2) NOT NULL,
  `blocks` bigint unsigned NOT NULL DEFAULT '0',
  `failed_logins` bigint unsigned NOT NULL DEFAULT '0',
  `unique_ips` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `system_metrics` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `uptime_hours` decimal(12,2) DEFAULT NULL,
  `cpuload1` decimal(10,2) DEFAULT NULL,
  `cpuload5` decimal(10,2) DEFAULT NULL,
  `cpuload15` decimal(10,2) DEFAULT NULL,
  `cpu_usage` decimal(10,2) DEFAULT NULL,
  `cpu_temperature` decimal(10,2) DEFAULT NULL,
  `ram_free_mb` decimal(14,2) DEFAULT NULL,
  `disk_used` decimal(14,2) DEFAULT NULL,
  `disk_free` decimal(14,2) DEFAULT NULL,
  `disk_usage` decimal(10,2) DEFAULT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS analysis_ufw_ports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    period_start DATETIME(6) NOT NULL,
    period_end DATETIME(6) NOT NULL,
    destination_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    destination_port SMALLINT UNSIGNED NOT NULL,
    protocol VARCHAR(3) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    unique_source_ips BIGINT UNSIGNED NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_ufw_ports_period (period_start, period_end, destination_ip, destination_port, protocol),
    KEY idx_ufw_ports_history (destination_port, protocol, destination_ip, period_start, period_end),
    CONSTRAINT chk_ufw_ports_period CHECK (period_start < period_end),
    CONSTRAINT chk_ufw_ports_seen CHECK (
        first_seen >= period_start AND first_seen <= last_seen AND last_seen < period_end
    ),
    CONSTRAINT chk_ufw_ports_port CHECK (destination_port BETWEEN 1 AND 65535),
    CONSTRAINT chk_ufw_ports_protocol CHECK (protocol IN ('TCP', 'UDP'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS analysis_ufw_traffic (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    period_start DATETIME(6) NOT NULL,
    period_end DATETIME(6) NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    other_events BIGINT UNSIGNED NOT NULL,
    tcp_events BIGINT UNSIGNED NOT NULL,
    udp_events BIGINT UNSIGNED NOT NULL,
    unique_source_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ports BIGINT UNSIGNED NOT NULL,
    first_seen DATETIME(6) NULL,
    last_seen DATETIME(6) NULL,
    period_status VARCHAR(6) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    coverage_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UNKNOWN',
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_traffic_period (period_start, period_end),
    CONSTRAINT chk_analysis_ufw_traffic_status CHECK (period_status IN ('OPEN', 'CLOSED')),
    CONSTRAINT chk_analysis_ufw_traffic_hour CHECK (TIMESTAMPDIFF(SECOND, period_start, period_end) = 3600
        AND MINUTE(period_start) = 0 AND SECOND(period_start) = 0 AND MICROSECOND(period_start) = 0),
    CONSTRAINT chk_analysis_ufw_traffic_seen CHECK (
        (total_events = 0 AND first_seen IS NULL AND last_seen IS NULL) OR
        (total_events > 0 AND first_seen IS NOT NULL AND last_seen IS NOT NULL
         AND first_seen >= period_start AND first_seen <= last_seen AND last_seen < period_end))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS analysis_ufw_traffic_daily (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    analysis_date DATE NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    other_events BIGINT UNSIGNED NOT NULL,
    tcp_events BIGINT UNSIGNED NOT NULL,
    udp_events BIGINT UNSIGNED NOT NULL,
    unique_source_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ports BIGINT UNSIGNED NOT NULL,
    period_status VARCHAR(6) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    coverage_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UNKNOWN',
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_traffic_period (analysis_date),
    CONSTRAINT chk_analysis_ufw_traffic_daily_status CHECK (period_status IN ('OPEN', 'CLOSED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `ufw_log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `event_time` datetime DEFAULT NULL,
  `action` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_ip` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dst_ip` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `protocol` varchar(10) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_port` int unsigned NOT NULL DEFAULT '0',
  `dst_port` int unsigned NOT NULL DEFAULT '0',
  `raw_line` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `event_hash` char(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ufw_event_hash` (`event_hash`),
  KEY `idx_event_time` (`event_time`),
  KEY `idx_src_ip` (`src_ip`),
  KEY `idx_dst_ip` (`dst_ip`),
  KEY `idx_action` (`action`),
  KEY `idx_dst_port` (`dst_port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ufw_state` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `logfile` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `last_position` bigint unsigned NOT NULL DEFAULT '0',
  `file_device` bigint unsigned DEFAULT NULL,
  `file_inode` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ufw_state_file` (`file_device`,`file_inode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS analysis_source_ips (
    period_start DATETIME(6) NOT NULL,
    period_end DATETIME(6) NOT NULL,
    source_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    unique_destination_ports BIGINT UNSIGNED NOT NULL,
    unique_destination_ips BIGINT UNSIGNED NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    tcp_events BIGINT UNSIGNED NOT NULL,
    udp_events BIGINT UNSIGNED NOT NULL,
    analyzed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (period_start, period_end, source_ip),
    KEY idx_analysis_source_history (source_ip, period_start, period_end),
    CONSTRAINT chk_source_analysis_period CHECK (period_start < period_end),
    CONSTRAINT chk_source_analysis_seen CHECK (
        first_seen >= period_start AND first_seen <= last_seen AND last_seen < period_end
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dns_sources (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_name VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    base_url VARCHAR(2048) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_dns_source_name (source_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dns_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_id BIGINT UNSIGNED NOT NULL,
    event_time DATETIME(6) NOT NULL COMMENT 'UTC',
    raw_timestamp VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45) DEFAULT NULL,
    domain VARCHAR(1024) NOT NULL,
    query_type VARCHAR(32) NOT NULL,
    response_code VARCHAR(64) DEFAULT NULL,
    filtering_result VARCHAR(32) NOT NULL,
    filtering_reason VARCHAR(128) DEFAULT NULL,
    upstream VARCHAR(2048) DEFAULT NULL,
    elapsed_ms DECIMAL(20,9) DEFAULT NULL,
    cached BOOLEAN DEFAULT NULL,
    dedup_key BINARY(32) DEFAULT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_dns_replay (source_id, dedup_key),
    KEY idx_dns_source_time (source_id, event_time),
    KEY idx_dns_event_time (event_time),
    CONSTRAINT fk_dns_events_source FOREIGN KEY (source_id) REFERENCES dns_sources (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dns_collection_state (
    source_id BIGINT UNSIGNED NOT NULL,
    state_data JSON NOT NULL,
    updated_at DATETIME(6) NOT NULL COMMENT 'UTC',
    PRIMARY KEY (source_id),
    CONSTRAINT fk_dns_state_source FOREIGN KEY (source_id) REFERENCES dns_sources (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS detection_rules (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(255) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_detection_rule_key (rule_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS detection_alerts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id BIGINT UNSIGNED NOT NULL,
    severity VARCHAR(10) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'NEW',
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    source_ip VARCHAR(45) DEFAULT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    detected_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    alert_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    details JSON NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alert_fingerprint (alert_fingerprint),
    KEY idx_alert_rule (rule_id),
    CONSTRAINT fk_alert_rule FOREIGN KEY (rule_id) REFERENCES detection_rules (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS alert_evidence (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alert_event (alert_id, event_type, event_id),
    KEY idx_evidence_event (event_type, event_id),
    CONSTRAINT fk_evidence_alert FOREIGN KEY (alert_id)
        REFERENCES detection_alerts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS detection_state (
    rule_id BIGINT UNSIGNED NOT NULL,
    last_event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    state_data JSON NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (rule_id),
    CONSTRAINT fk_detection_state_rule FOREIGN KEY (rule_id)
        REFERENCES detection_rules (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dns_client_filters (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_id BIGINT UNSIGNED NOT NULL,
    client_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    hide_from_query_log BOOLEAN NOT NULL DEFAULT FALSE,
    exclude_from_collection BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_dns_client_filter (source_id, client_ip),
    CONSTRAINT fk_dns_client_filter_source FOREIGN KEY (source_id)
        REFERENCES dns_sources (id),
    CONSTRAINT chk_dns_client_filter_hide CHECK (hide_from_query_log IN (0, 1)),
    CONSTRAINT chk_dns_client_filter_exclude CHECK (exclude_from_collection IN (0, 1)),
    CONSTRAINT chk_dns_client_filter_enabled CHECK (enabled IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE dns_domain_filters (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_id BIGINT UNSIGNED NOT NULL,
    domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_dns_domain_filter (source_id, domain),
    CONSTRAINT fk_dns_domain_filter_source FOREIGN KEY (source_id)
        REFERENCES dns_sources (id),
    CONSTRAINT chk_dns_domain_filter_enabled CHECK (enabled IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS auth_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_time DATETIME(6) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    username VARCHAR(255) DEFAULT NULL,
    event_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    service VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    raw_message TEXT NOT NULL,
    event_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_auth_event_hash (event_hash),
    KEY idx_auth_event_time (event_time),
    KEY idx_auth_detection (hostname, source_ip, event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS auth_ingestion_state (
    collector_id VARCHAR(255) NOT NULL,
    file_device BIGINT UNSIGNED NOT NULL,
    file_inode BIGINT UNSIGNED NOT NULL,
    logfile TEXT NOT NULL,
    last_position BIGINT UNSIGNED NOT NULL,
    position_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (collector_id, file_device, file_inode)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO detection_rules (rule_key, name, severity, enabled)
VALUES ('PORT_SCAN_001', 'Possible Port Scanning', 'HIGH', TRUE)
ON DUPLICATE KEY UPDATE rule_key = detection_rules.rule_key;

INSERT INTO detection_rules (rule_key, name, severity, enabled)
VALUES ('SSH_BRUTE_FORCE_001', 'SSH Brute Force Attempt', 'HIGH', TRUE)
ON DUPLICATE KEY UPDATE rule_key = detection_rules.rule_key;
