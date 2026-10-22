-- Phase 2: apply manually, only after approval, to the selected MySQL database.
-- Prerequisites: 003_detection_alerts.sql and 007_auth_events.sql.
-- Register only the SSH rule; preserve existing rule IDs and operator settings.
-- No new alert tables, telemetry changes or detection checkpoints.

INSERT INTO detection_rules (rule_key, name, severity, enabled)
VALUES ('SSH_BRUTE_FORCE_001', 'SSH Brute Force Attempt', 'HIGH', TRUE)
ON DUPLICATE KEY UPDATE rule_key = detection_rules.rule_key;
