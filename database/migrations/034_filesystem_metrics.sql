CREATE TABLE IF NOT EXISTS filesystem_mount_metrics (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    measured_at DATETIME(6) NOT NULL COMMENT 'UTC measurement time',
    mount_point VARBINARY(4096) NOT NULL,
    path_sha256 BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(mount_point, 256))) STORED NOT NULL,
    filesystem_type VARCHAR(64) NOT NULL,
    total_bytes BIGINT UNSIGNED NOT NULL,
    available_bytes BIGINT UNSIGNED NOT NULL,
    total_inodes BIGINT UNSIGNED NOT NULL,
    free_inodes BIGINT UNSIGNED NOT NULL,
    read_only BOOLEAN NOT NULL,
    mount_options TEXT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_filesystem_mount_history (host_id, source_id, measured_at, id),
    KEY idx_filesystem_mount_path_history (host_id, source_id, path_sha256, measured_at, id),
    CONSTRAINT chk_filesystem_mount_path CHECK (LEFT(mount_point, 1) = X'2F' AND INSTR(mount_point, X'00') = 0),
    CONSTRAINT chk_filesystem_mount_capacity CHECK (available_bytes <= total_bytes AND free_inodes <= total_inodes),
    CONSTRAINT chk_filesystem_mount_read_only CHECK (read_only IN (FALSE, TRUE)),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS filesystem_file_state (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    file_path VARBINARY(4096) NOT NULL,
    path_sha256 BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(file_path, 256))) STORED NOT NULL,
    content_sha256 VARBINARY(32) NULL COMMENT 'Raw SHA-256 digest when available',
    size_bytes BIGINT UNSIGNED NOT NULL,
    owner_uid INT UNSIGNED NOT NULL,
    group_gid INT UNSIGNED NOT NULL,
    mode SMALLINT UNSIGNED NOT NULL COMMENT 'Permission and special bits',
    observed_at DATETIME(6) NOT NULL COMMENT 'UTC observation time',
    PRIMARY KEY (id),
    UNIQUE KEY uq_filesystem_file_state_path (host_id, source_id, path_sha256),
    CONSTRAINT chk_filesystem_file_state_path CHECK (LEFT(file_path, 1) = X'2F' AND INSTR(file_path, X'00') = 0),
    CONSTRAINT chk_filesystem_file_state_digest CHECK (OCTET_LENGTH(content_sha256) = 32),
    CONSTRAINT chk_filesystem_file_state_mode CHECK (mode <= 4095),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS filesystem_file_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    file_path VARBINARY(4096) NOT NULL,
    path_sha256 BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(file_path, 256))) STORED NOT NULL,
    event_type VARCHAR(18) COLLATE utf8mb4_0900_bin NOT NULL,
    previous_state JSON NULL,
    current_state JSON NULL,
    observed_at DATETIME(6) NOT NULL COMMENT 'UTC observation time, may differ from actual change time',
    PRIMARY KEY (id),
    KEY idx_filesystem_file_history (host_id, source_id, observed_at, id),
    KEY idx_filesystem_file_path_history (host_id, source_id, path_sha256, observed_at, id),
    CONSTRAINT chk_filesystem_file_event_path CHECK (LEFT(file_path, 1) = X'2F' AND INSTR(file_path, X'00') = 0),
    CONSTRAINT chk_filesystem_file_event_state CHECK (
        (previous_state IS NULL OR JSON_TYPE(previous_state) = 'OBJECT')
        AND (current_state IS NULL OR JSON_TYPE(current_state) = 'OBJECT')
        AND (
            (event_type = 'CREATED' AND previous_state IS NULL AND current_state IS NOT NULL)
            OR (event_type = 'DELETED' AND previous_state IS NOT NULL AND current_state IS NULL)
            OR (event_type IN ('CONTENT_CHANGED', 'PERMISSION_CHANGED', 'OWNER_CHANGED')
                AND previous_state IS NOT NULL AND current_state IS NOT NULL)
        )
    ),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS filesystem_scan_state (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    last_successful_scan_at DATETIME(6) NULL COMMENT 'UTC time of the last fully successful inventory',
    config_sha256 VARBINARY(32) NOT NULL COMMENT 'Raw SHA-256 digest of the monitoring configuration',
    baseline_complete BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (host_id, source_id),
    CONSTRAINT chk_filesystem_scan_config CHECK (OCTET_LENGTH(config_sha256) = 32),
    CONSTRAINT chk_filesystem_scan_baseline CHECK (
        baseline_complete IN (FALSE, TRUE) AND (baseline_complete = FALSE OR last_successful_scan_at IS NOT NULL)
    ),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
