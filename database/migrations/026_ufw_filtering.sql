CREATE TABLE IF NOT EXISTS ufw_filter_rules (
 source_id BIGINT UNSIGNED NOT NULL,
 host_id BIGINT UNSIGNED NOT NULL,
 rule_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 rule_version INT UNSIGNED NOT NULL,
 definition JSON NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 audit_id BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY (source_id,rule_key),
 FOREIGN KEY (source_id,host_id) REFERENCES log_sources(source_id,host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_filter_audit (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 source_id BIGINT UNSIGNED NOT NULL,
 host_id BIGINT UNSIGNED NOT NULL,
 rule_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 rule_version INT UNSIGNED NOT NULL,
 definition JSON NOT NULL,
 enabled BOOLEAN NOT NULL,
 actor VARCHAR(255) NOT NULL,
 reason VARCHAR(512) NOT NULL,
 changed_at DATETIME(6) NOT NULL,
 FOREIGN KEY (source_id,host_id) REFERENCES log_sources(source_id,host_id),
 KEY ix_ufw_filter_audit_source (source_id,rule_key,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_filter_seen (
 source_id BIGINT UNSIGNED NOT NULL,
 event_hash BINARY(32) NOT NULL,
 host_id BIGINT UNSIGNED NOT NULL,
 rule_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 rule_version INT UNSIGNED NOT NULL,
 event_time DATETIME(6) NOT NULL,
 recorded_at DATETIME(6) NOT NULL,
 PRIMARY KEY (source_id,event_hash),
 KEY ix_ufw_filter_seen_time (event_time,host_id),
 FOREIGN KEY (source_id,host_id) REFERENCES log_sources(source_id,host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_filter_stats (
 source_id BIGINT UNSIGNED NOT NULL,
 host_id BIGINT UNSIGNED NOT NULL,
 rule_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 rule_version INT UNSIGNED NOT NULL,
 period_start DATETIME(6) NOT NULL,
 period_end DATETIME(6) NOT NULL,
 filtered_count BIGINT UNSIGNED NOT NULL,
 first_event_time DATETIME(6) NOT NULL,
 last_event_time DATETIME(6) NOT NULL,
 recorded_at DATETIME(6) NOT NULL,
 PRIMARY KEY (source_id,rule_key,rule_version,period_start),
 FOREIGN KEY (source_id,host_id) REFERENCES log_sources(source_id,host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
