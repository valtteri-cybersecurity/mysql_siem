CREATE TABLE IF NOT EXISTS ufw_file_checkpoints (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 source_scope BIGINT UNSIGNED NOT NULL,
 file_device BIGINT UNSIGNED NOT NULL,
 file_inode BIGINT UNSIGNED NOT NULL,
 filename TEXT NOT NULL,
 byte_position BIGINT UNSIGNED NOT NULL,
 prefix_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 observed_size BIGINT UNSIGNED NOT NULL,
 observed_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 checked_at DATETIME(6) NOT NULL,
 KEY ix_ufw_file_identity (source_scope,file_device,file_inode,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_collection_gaps (
 source_scope BIGINT UNSIGNED NOT NULL,
 gap_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 checkpoint_id BIGINT UNSIGNED NOT NULL,
 reason VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 detected_at DATETIME(6) NOT NULL,
 resolved BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY (source_scope,gap_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_archive_proofs (
 source_scope BIGINT UNSIGNED NOT NULL,
 archive_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 expanded_size BIGINT UNSIGNED NOT NULL,
 expanded_sha CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 PRIMARY KEY (source_scope,archive_sha,expanded_size)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ufw_collection_health (
 source_scope BIGINT UNSIGNED NOT NULL PRIMARY KEY,
 last_success DATETIME(6) NULL,
 last_failure DATETIME(6) NULL,
 error_class VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 active_state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pending_archives BIGINT UNSIGNED NOT NULL,
 stop_reason VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 active_lines BIGINT UNSIGNED NOT NULL,
 archive_lines BIGINT UNSIGNED NOT NULL,
 pass_number BIGINT UNSIGNED NOT NULL DEFAULT 0,
 plain_backlog BOOLEAN NOT NULL DEFAULT FALSE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
