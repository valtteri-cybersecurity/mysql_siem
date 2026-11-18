CREATE TABLE IF NOT EXISTS collector_health (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    collector_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    generation BIGINT UNSIGNED NOT NULL,
    last_attempt_at DATETIME(6) NOT NULL COMMENT 'UTC, when the attempt finished or was skipped',
    status VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    error_code VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    consecutive_failures INT UNSIGNED NOT NULL,
    duration_ms BIGINT UNSIGNED NOT NULL,
    observed_count INT UNSIGNED NULL,
    added_count INT UNSIGNED NULL,
    changed_count INT UNSIGNED NULL,
    removed_count INT UNSIGNED NULL,
    unchanged_count INT UNSIGNED NULL,
    coverage JSON NOT NULL,
    transitions JSON NOT NULL,
    PRIMARY KEY (host_id, source_id, collector_type),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    CONSTRAINT chk_collector_health_type CHECK (collector_type IN ('processes', 'services')),
    CONSTRAINT chk_collector_health_status CHECK (status IN ('SUCCESS', 'PARTIAL', 'FAILED', 'SKIPPED')),
    CONSTRAINT chk_collector_health_error CHECK (
        (status = 'SUCCESS' AND error_code IS NULL)
        OR (status <> 'SUCCESS' AND error_code IS NOT NULL AND error_code IN (
            'SOURCE_UNAVAILABLE', 'PERMISSION_DENIED', 'OBSERVATION_TIMEOUT', 'INCOMPLETE_OBSERVATION',
            'INVALID_OBSERVATION', 'DATABASE_ERROR', 'IDENTITY_ERROR', 'COLLECTION_BUSY', 'UNKNOWN_ERROR'
        ))
    ),
    CONSTRAINT chk_collector_health_payload CHECK (
        JSON_TYPE(coverage) = 'OBJECT' AND JSON_TYPE(transitions) = 'ARRAY' AND JSON_LENGTH(transitions) <= 16
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
