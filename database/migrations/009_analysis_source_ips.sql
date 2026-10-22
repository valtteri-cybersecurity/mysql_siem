-- Source IP Analysis for MySQL 8. Apply manually after review on existing installs.
-- Additive: no raw data or legacy top_attacking_ips rows are changed or copied.
-- Period times retain ufw_log.event_time's existing naive time basis.
-- DDL commits implicitly; inspect definitions after a partial error or prior table.

CREATE TABLE IF NOT EXISTS analysis_source_ips (
    period_start DATETIME(6) NOT NULL,
    period_end DATETIME(6) NOT NULL,
    source_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    unique_destination_ports BIGINT UNSIGNED NOT NULL,
    unique_destination_ips BIGINT UNSIGNED NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    tcp_events BIGINT UNSIGNED NOT NULL,
    udp_events BIGINT UNSIGNED NOT NULL,
    analyzed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (period_start, period_end, source_ip),
    KEY idx_analysis_source_history (source_ip, period_start, period_end),
    CONSTRAINT chk_source_analysis_period CHECK (period_start < period_end),
    CONSTRAINT chk_source_analysis_seen CHECK (
        first_seen >= period_start AND first_seen <= last_seen AND last_seen < period_end
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
