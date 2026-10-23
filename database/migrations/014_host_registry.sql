-- Phase 2: registry identities are assigned explicitly by an administrator.
CREATE TABLE IF NOT EXISTS hosts (
    host_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    administrative_name VARCHAR(255) NOT NULL,
    reported_hostname VARCHAR(255) NULL,
    current_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NULL,
    os_name VARCHAR(255) NULL,
    os_version VARCHAR(255) NULL,
    enrollment_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (host_id),
    KEY idx_host_hostname (reported_hostname),
    CONSTRAINT chk_host_enrollment CHECK (enrollment_status IN ('PENDING', 'ACTIVE', 'DISABLED', 'RETIRED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS host_groups (
    group_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    group_name VARCHAR(128) NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (group_id),
    UNIQUE KEY uq_host_group_name (group_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS host_group_members (
    group_id BIGINT UNSIGNED NOT NULL,
    host_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (group_id, host_id),
    KEY idx_members_host (host_id),
    FOREIGN KEY (group_id) REFERENCES host_groups (group_id),
    FOREIGN KEY (host_id) REFERENCES hosts (host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS log_sources (
    source_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_name VARCHAR(128) NOT NULL,
    source_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (source_id),
    UNIQUE KEY uq_source_host_name (host_id, source_name),
    UNIQUE KEY uq_source_host (source_id, host_id),
    FOREIGN KEY (host_id) REFERENCES hosts (host_id),
    CONSTRAINT chk_source_type CHECK (source_type IN ('ufw', 'auth', 'dns', 'system', 'filesystem', 'security'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS collectors (
    collector_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    collector_name VARCHAR(128) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (collector_id),
    UNIQUE KEY uq_collector_name (collector_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS collector_sources (
    collector_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (collector_id, source_id),
    FOREIGN KEY (collector_id) REFERENCES collectors (collector_id),
    FOREIGN KEY (source_id) REFERENCES log_sources (source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS sender_identities (
    sender_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    identity_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    identity_value VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (sender_id),
    UNIQUE KEY uq_sender_identity (identity_type, identity_value),
    UNIQUE KEY uq_sender_host (sender_id, host_id),
    FOREIGN KEY (host_id) REFERENCES hosts (host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS sender_sources (
    sender_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (sender_id, source_id),
    FOREIGN KEY (sender_id) REFERENCES sender_identities (sender_id),
    FOREIGN KEY (source_id) REFERENCES log_sources (source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS sender_certificates (
    certificate_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    sender_id BIGINT UNSIGNED NOT NULL,
    sha256_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    serial_number VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    valid_from DATETIME(6) NOT NULL COMMENT 'UTC',
    valid_until DATETIME(6) NOT NULL COMMENT 'UTC',
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    revoked_at DATETIME(6) NULL COMMENT 'UTC',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (certificate_id),
    UNIQUE KEY uq_certificate_fingerprint (sha256_fingerprint),
    KEY idx_certificate_sender (sender_id, status),
    FOREIGN KEY (sender_id) REFERENCES sender_identities (sender_id),
    CONSTRAINT chk_certificate_dates CHECK (valid_from < valid_until),
    CONSTRAINT chk_certificate_status CHECK (status IN ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'REPLACED')),
    CONSTRAINT chk_certificate_fingerprint CHECK (sha256_fingerprint REGEXP '^[0-9a-f]{64}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS alert_hosts (
    alert_id BIGINT UNSIGNED NOT NULL,
    host_id BIGINT UNSIGNED NOT NULL,
    host_role VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'TARGET',
    PRIMARY KEY (alert_id, host_id, host_role),
    KEY idx_alert_hosts_host (host_id, alert_id),
    FOREIGN KEY (alert_id) REFERENCES detection_alerts (id),
    FOREIGN KEY (host_id) REFERENCES hosts (host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
