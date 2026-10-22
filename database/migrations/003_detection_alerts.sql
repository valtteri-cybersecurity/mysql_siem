-- Shared SOC alerts for MySQL 8. Apply manually to the selected database.
-- Additive and repeatable: existing telemetry and rule settings are preserved.
-- DDL commits implicitly. Inspect existing table definitions after partial errors.

CREATE TABLE IF NOT EXISTS detection_rules (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(255) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_detection_rule_key (rule_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS detection_alerts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id BIGINT UNSIGNED NOT NULL,
    severity VARCHAR(10) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'NEW',
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    source_ip VARCHAR(45) DEFAULT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    detected_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    alert_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    details JSON NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alert_fingerprint (alert_fingerprint),
    KEY idx_alert_rule (rule_id),
    CONSTRAINT fk_alert_rule FOREIGN KEY (rule_id) REFERENCES detection_rules (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS alert_evidence (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alert_event (alert_id, event_type, event_id),
    CONSTRAINT fk_evidence_alert FOREIGN KEY (alert_id)
        REFERENCES detection_alerts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO detection_rules (rule_key, name, severity, enabled)
VALUES ('PORT_SCAN_001', 'Possible Port Scanning', 'HIGH', TRUE)
ON DUPLICATE KEY UPDATE rule_key = detection_rules.rule_key;
