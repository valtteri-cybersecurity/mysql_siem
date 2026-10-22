-- DNS client filter management. Apply after 002_dns_telemetry.sql.
-- Additive only: no existing telemetry, source or collection state is changed.
-- Applied once by install.sh when absent; existing rules are preserved.
-- MySQL DDL commits implicitly; inspect partial failures before retrying.

CREATE TABLE dns_client_filters (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_id BIGINT UNSIGNED NOT NULL,
    client_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    hide_from_query_log BOOLEAN NOT NULL DEFAULT FALSE,
    exclude_from_collection BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_dns_client_filter (source_id, client_ip),
    CONSTRAINT fk_dns_client_filter_source FOREIGN KEY (source_id)
        REFERENCES dns_sources (id),
    CONSTRAINT chk_dns_client_filter_hide CHECK (hide_from_query_log IN (0, 1)),
    CONSTRAINT chk_dns_client_filter_exclude CHECK (exclude_from_collection IN (0, 1)),
    CONSTRAINT chk_dns_client_filter_enabled CHECK (enabled IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
