-- Phase 1: manual, additive migration for MySQL 8. Never applied by the collector.
-- Apply only after approval. DDL commits implicitly; inspect definitions if rerun.
-- event_time uses UTC, preserving the source timestamp's microsecond precision.

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

-- This tracks ingestion only; no detection checkpoints are added in phase 1.
CREATE TABLE IF NOT EXISTS auth_ingestion_state (
    collector_id VARCHAR(255) NOT NULL,
    file_device BIGINT UNSIGNED NOT NULL,
    file_inode BIGINT UNSIGNED NOT NULL,
    logfile TEXT NOT NULL,
    last_position BIGINT UNSIGNED NOT NULL,
    position_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (collector_id, file_device, file_inode)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
