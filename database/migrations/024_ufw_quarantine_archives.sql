CREATE TABLE IF NOT EXISTS ufw_quarantine (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 source_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
 raw_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 raw_bytes MEDIUMBLOB NOT NULL,
 reason VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 received_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 host_id BIGINT UNSIGNED NULL,
 source_id BIGINT UNSIGNED NULL,
 collector_id BIGINT UNSIGNED NULL,
 UNIQUE KEY uq_ufw_quarantine (source_scope,raw_sha),
 FOREIGN KEY (source_id,host_id) REFERENCES log_sources(source_id,host_id),
 FOREIGN KEY (collector_id,source_id) REFERENCES collector_sources(collector_id,source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_quarantine_origins (
 source_scope BIGINT UNSIGNED NOT NULL,
 file_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 byte_position BIGINT UNSIGNED NOT NULL,
 quarantine_id BIGINT UNSIGNED NOT NULL,
 filename TEXT NOT NULL,
 file_device BIGINT UNSIGNED NOT NULL,
 file_inode BIGINT UNSIGNED NOT NULL,
 archive_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 PRIMARY KEY (source_scope,file_key,byte_position,quarantine_id),
 FOREIGN KEY (quarantine_id) REFERENCES ufw_quarantine(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_archives (
 source_scope BIGINT UNSIGNED NOT NULL,
 archive_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 filename TEXT NOT NULL,
 file_device BIGINT UNSIGNED NOT NULL,
 file_inode BIGINT UNSIGNED NOT NULL,
 logical_position BIGINT UNSIGNED NOT NULL DEFAULT 0,
 status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'PENDING',
 checked_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
 PRIMARY KEY (source_scope,archive_sha)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS ufw_archive_failures (
 source_scope BIGINT UNSIGNED NOT NULL,
 source_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 filename TEXT NOT NULL,
 reason VARCHAR(64) NOT NULL,
 detected_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY (source_scope,source_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
