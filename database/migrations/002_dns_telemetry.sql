-- DNS telemetry schema for mysql_siem. Applied once by install.sh when absent.
-- For an existing installation, it can also be applied manually, once.
-- No database creation, grants, source registration or collection activation.
-- MySQL DDL commits implicitly; inspect partial failures before retrying.

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
    -- Reserved for collector-generated replay keys in phase 4. NULL preserves
    -- all occurrences; this is not a provider event ID or identity guarantee.
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
    -- Opaque versioned collector state; paging semantics belong to phase 4.
    state_data JSON NOT NULL,
    updated_at DATETIME(6) NOT NULL COMMENT 'UTC',
    PRIMARY KEY (source_id),
    CONSTRAINT fk_dns_state_source FOREIGN KEY (source_id) REFERENCES dns_sources (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
