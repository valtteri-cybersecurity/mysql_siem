-- Additive snapshot tables. Existing history is never rewritten.
CREATE TABLE IF NOT EXISTS service_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    service_name VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_type VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_time DATETIME(6) NOT NULL COMMENT 'UTC observation time, not exact transition time',
    previous_state JSON NULL,
    current_state JSON NULL,
    PRIMARY KEY (id),
    KEY idx_service_host_history (host_id, source_id, service_name, event_time, id),
    KEY idx_service_retention (event_time, id),
    CONSTRAINT chk_service_event CHECK (event_type IN ('APPEARED', 'REMOVED', 'STARTED', 'STOPPED', 'FAILED', 'CHANGED')),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS service_state (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    service_name VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    state JSON NOT NULL,
    observed_at DATETIME(6) NOT NULL COMMENT 'UTC',
    PRIMARY KEY (host_id, service_name),
    KEY idx_service_source (host_id, source_id),
    CONSTRAINT chk_service_state CHECK (JSON_TYPE(state) = 'OBJECT'),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
