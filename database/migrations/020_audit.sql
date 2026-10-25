-- Additive Linux Audit integration. Existing history and checkpoints are retained.
CREATE TABLE IF NOT EXISTS audit_targets (
    target_name VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    audit_key VARCHAR(31) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    definition JSON NOT NULL,
    enabled TINYINT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (target_name),
    UNIQUE KEY uq_audit_target_key (audit_key),
    CONSTRAINT chk_audit_target_enabled CHECK (enabled IN (0, 1)),
    CONSTRAINT chk_audit_target_definition CHECK (JSON_TYPE(definition) = 'OBJECT')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    target_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_path VARCHAR(4096) NOT NULL,
    audit_key VARCHAR(255) NOT NULL,
    event_time DATETIME(6) NOT NULL COMMENT 'UTC audit timestamp',
    audit_event_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_hash VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    boot_id VARCHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    auid BIGINT UNSIGNED NULL,
    uid BIGINT UNSIGNED NULL,
    euid BIGINT UNSIGNED NULL,
    pid BIGINT UNSIGNED NULL,
    ppid BIGINT UNSIGNED NULL,
    executable VARCHAR(4096) NULL,
    operation VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    success TINYINT UNSIGNED NULL,
    metadata JSON NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_audit_source_event (source_id, event_hash),
    KEY idx_audit_host_history (host_id, source_id, event_time, id),
    KEY idx_audit_target_history (host_id, target_type, event_time, id),
    KEY idx_audit_retention (event_time, id),
    CONSTRAINT chk_audit_success CHECK (success IS NULL OR success IN (0, 1)),
    CONSTRAINT chk_audit_metadata CHECK (JSON_TYPE(metadata) = 'OBJECT'),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    host_id BIGINT UNSIGNED NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL,
    collector_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NULL,
    position JSON NOT NULL,
    updated_at DATETIME(6) NOT NULL COMMENT 'UTC commit observation',
    PRIMARY KEY (host_id, source_id),
    CONSTRAINT chk_audit_position CHECK (JSON_TYPE(position) = 'OBJECT'),
    FOREIGN KEY (source_id, host_id) REFERENCES log_sources (source_id, host_id),
    FOREIGN KEY (collector_id, source_id) REFERENCES collector_sources (collector_id, source_id),
    FOREIGN KEY (sender_id, host_id) REFERENCES sender_identities (sender_id, host_id),
    FOREIGN KEY (sender_id, source_id) REFERENCES sender_sources (sender_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
