-- Exact-domain collection exclusions. Apply after 002_dns_telemetry.sql.
-- Additive only: no DNS events, client rules or checkpoints are changed.
-- Applied once by install.sh when absent; existing rules are preserved.
-- MySQL DDL commits implicitly; inspect partial failures before retrying.

CREATE TABLE dns_domain_filters (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_id BIGINT UNSIGNED NOT NULL,
    domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_dns_domain_filter (source_id, domain),
    CONSTRAINT fk_dns_domain_filter_source FOREIGN KEY (source_id)
        REFERENCES dns_sources (id),
    CONSTRAINT chk_dns_domain_filter_enabled CHECK (enabled IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
