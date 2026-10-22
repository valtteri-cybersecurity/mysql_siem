-- Additive MySQL 8 migration. Existing raw events and summaries are retained.
-- No coverage guarantee: collector file offsets cannot prove a complete period.
-- Unique period keys support at least twelve months; no automatic deletion.

CREATE TABLE IF NOT EXISTS analysis_ufw_traffic (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    period_start DATETIME(6) NOT NULL,
    period_end DATETIME(6) NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    other_events BIGINT UNSIGNED NOT NULL,
    tcp_events BIGINT UNSIGNED NOT NULL,
    udp_events BIGINT UNSIGNED NOT NULL,
    unique_source_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ports BIGINT UNSIGNED NOT NULL,
    first_seen DATETIME(6) NULL,
    last_seen DATETIME(6) NULL,
    period_status VARCHAR(6) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    coverage_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UNKNOWN',
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_traffic_period (period_start, period_end),
    CONSTRAINT chk_analysis_ufw_traffic_status CHECK (period_status IN ('OPEN', 'CLOSED')),
    CONSTRAINT chk_analysis_ufw_traffic_hour CHECK (TIMESTAMPDIFF(SECOND, period_start, period_end) = 3600
        AND MINUTE(period_start) = 0 AND SECOND(period_start) = 0 AND MICROSECOND(period_start) = 0),
    CONSTRAINT chk_analysis_ufw_traffic_seen CHECK (
        (total_events = 0 AND first_seen IS NULL AND last_seen IS NULL) OR
        (total_events > 0 AND first_seen IS NOT NULL AND last_seen IS NOT NULL
         AND first_seen >= period_start AND first_seen <= last_seen AND last_seen < period_end))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS analysis_ufw_traffic_daily (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    analysis_date DATE NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    other_events BIGINT UNSIGNED NOT NULL,
    tcp_events BIGINT UNSIGNED NOT NULL,
    udp_events BIGINT UNSIGNED NOT NULL,
    unique_source_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ips BIGINT UNSIGNED NOT NULL,
    unique_destination_ports BIGINT UNSIGNED NOT NULL,
    period_status VARCHAR(6) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    coverage_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UNKNOWN',
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_traffic_period (analysis_date),
    CONSTRAINT chk_analysis_ufw_traffic_daily_status CHECK (period_status IN ('OPEN', 'CLOSED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
