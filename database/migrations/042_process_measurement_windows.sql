CREATE TABLE IF NOT EXISTS process_measurement_windows (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    window_start DATETIME NOT NULL COMMENT 'UTC, inclusive',
    window_end DATETIME NOT NULL COMMENT 'UTC, exclusive',
    first_observed_at DATETIME(6) NOT NULL,
    last_observed_at DATETIME(6) NOT NULL,
    sample_count INT UNSIGNED NOT NULL,
    metrics JSON NOT NULL,
    executables JSON NOT NULL,
    parent_child JSON NOT NULL,
    PRIMARY KEY (host_id, source_id, window_start),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    CONSTRAINT chk_process_window_time CHECK (
        MOD(MINUTE(window_start), 5) = 0 AND SECOND(window_start) = 0
        AND TIMESTAMPDIFF(SECOND, window_start, window_end) = 300
        AND first_observed_at >= window_start AND first_observed_at <= last_observed_at
        AND last_observed_at < window_end
    ),
    CONSTRAINT chk_process_window_payload CHECK (
        sample_count > 0 AND JSON_TYPE(metrics) = 'OBJECT'
        AND JSON_TYPE(executables) = 'OBJECT' AND JSON_LENGTH(executables) <= 64
        AND JSON_TYPE(parent_child) = 'OBJECT' AND JSON_LENGTH(parent_child) <= 64
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
