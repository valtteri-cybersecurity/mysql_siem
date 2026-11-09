INSERT INTO detection_rules (rule_key, name, severity, enabled)
VALUES ('FIM_CRITICAL_CHANGE_001', 'Critical Filesystem Change', 'HIGH', TRUE),
       ('FIM_PERMISSION_RISK_001', 'Filesystem Permission Risk', 'HIGH', TRUE)
ON DUPLICATE KEY UPDATE rule_key = detection_rules.rule_key;
