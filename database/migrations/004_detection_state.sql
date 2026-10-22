-- Apply after 003. Additive and repeatable; no telemetry is changed.
CREATE TABLE IF NOT EXISTS detection_state (
    rule_id BIGINT UNSIGNED NOT NULL,
    last_event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    state_data JSON NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (rule_id),
    CONSTRAINT fk_detection_state_rule FOREIGN KEY (rule_id)
        REFERENCES detection_rules (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Evidence lookup is now used on each automatic pass; the alert-first unique
-- index from 003 cannot efficiently find alerts by their original event IDs.
SET @evidence_index_sql = IF(
    EXISTS(SELECT 1 FROM information_schema.statistics
           WHERE table_schema = DATABASE() AND table_name = 'alert_evidence'
             AND index_name = 'idx_evidence_event'),
    'SELECT 1',
    'ALTER TABLE alert_evidence ADD INDEX idx_evidence_event (event_type, event_id)'
);
PREPARE evidence_index_statement FROM @evidence_index_sql;
EXECUTE evidence_index_statement;
DEALLOCATE PREPARE evidence_index_statement;
