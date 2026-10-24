-- Additive snapshot tables. Existing history is never rewritten.
CREATE TABLE IF NOT EXISTS collector_snapshots (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    source_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    observed_at DATETIME(6) NOT NULL COMMENT 'UTC, last committed complete observation',
    PRIMARY KEY (host_id, source_type),
    CONSTRAINT chk_snapshot_kind CHECK (source_type IN ('processes', 'services')),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS process_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    process_key VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_type VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_time DATETIME(6) NOT NULL COMMENT 'UTC observation time, not exact transition time',
    previous_state JSON NULL,
    current_state JSON NULL,
    PRIMARY KEY (id),
    KEY idx_process_host_history (host_id, source_id, process_key, event_time, id),
    KEY idx_process_retention (event_time, id),
    CONSTRAINT chk_process_event CHECK (event_type IN ('STARTED', 'STOPPED', 'CHANGED')),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS process_state (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    process_key VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    state JSON NOT NULL,
    observed_at DATETIME(6) NOT NULL COMMENT 'UTC',
    PRIMARY KEY (host_id, process_key),
    KEY idx_process_source (host_id, source_id),
    CONSTRAINT chk_process_state CHECK (JSON_TYPE(state) = 'OBJECT'),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
