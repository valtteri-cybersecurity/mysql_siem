-- MySQL 8: create and validate Port Activity Analysis, then retire its predecessor.
-- Stop/remove the old targeted_ports cron job and wait for its running process
-- to finish BEFORE applying this migration. Use an account with DDL/routine rights.
-- Old aggregates are permanently deleted, not copied. Raw UFW events are retained.
-- DDL commits implicitly: this is NOT a transactionally reversible migration.
-- A pre-existing incompatible replacement table is left unchanged; retirement stops.
-- On validation failure, inspect the schema. A rerun replaces any leftover helper.

CREATE TABLE IF NOT EXISTS analysis_ufw_ports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    period_start DATETIME(6) NOT NULL,
    period_end DATETIME(6) NOT NULL,
    destination_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    destination_port SMALLINT UNSIGNED NOT NULL,
    protocol VARCHAR(3) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    total_events BIGINT UNSIGNED NOT NULL,
    blocked_events BIGINT UNSIGNED NOT NULL,
    allowed_events BIGINT UNSIGNED NOT NULL,
    audited_events BIGINT UNSIGNED NOT NULL,
    unique_source_ips BIGINT UNSIGNED NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_ufw_ports_period (period_start, period_end, destination_ip, destination_port, protocol),
    KEY idx_ufw_ports_history (destination_port, protocol, destination_ip, period_start, period_end),
    CONSTRAINT chk_ufw_ports_period CHECK (period_start < period_end),
    CONSTRAINT chk_ufw_ports_seen CHECK (
        first_seen >= period_start AND first_seen <= last_seen AND last_seen < period_end
    ),
    CONSTRAINT chk_ufw_ports_port CHECK (destination_port BETWEEN 1 AND 65535),
    CONSTRAINT chk_ufw_ports_protocol CHECK (protocol IN ('TCP', 'UDP'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- A temporary migration helper validates BEFORE retiring the old table. SIGNAL
-- also protects the old table if a client continues after an SQL error.
DROP PROCEDURE IF EXISTS mysql_siem_migrate_ufw_ports;
DELIMITER //
CREATE PROCEDURE mysql_siem_migrate_ufw_ports()
BEGIN
    DECLARE valid_columns INT DEFAULT 0;
    DECLARE valid_indexes INT DEFAULT 0;
    DECLARE valid_checks INT DEFAULT 0;

    IF (SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'analysis_ufw_ports'
          AND table_type = 'BASE TABLE' AND engine = 'InnoDB'
          AND table_collation = 'utf8mb4_bin') <> 1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'analysis_ufw_ports: wrong table type or engine; legacy table retained';
    END IF;

    SELECT COUNT(*) INTO valid_columns FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'analysis_ufw_ports' AND is_nullable = 'NO'
      AND (
        (column_name = 'id' AND column_type = 'bigint unsigned' AND extra = 'auto_increment' AND column_default IS NULL)
        OR (column_name IN ('period_start', 'period_end', 'first_seen', 'last_seen')
            AND column_type = 'datetime(6)' AND extra = '' AND column_default IS NULL)
        OR (column_name = 'destination_ip' AND column_type = 'varchar(45)' AND collation_name = 'ascii_bin'
            AND extra = '' AND column_default IS NULL)
        OR (column_name = 'destination_port' AND column_type = 'smallint unsigned' AND extra = '' AND column_default IS NULL)
        OR (column_name = 'protocol' AND column_type = 'varchar(3)' AND collation_name = 'ascii_bin'
            AND extra = '' AND column_default IS NULL)
        OR (column_name IN ('total_events', 'blocked_events', 'allowed_events', 'audited_events', 'unique_source_ips')
            AND column_type = 'bigint unsigned' AND extra = '' AND column_default IS NULL)
        OR (column_name = 'updated_at' AND column_type = 'timestamp(6)'
            AND LOWER(column_default) = 'current_timestamp(6)'
            AND LOWER(extra) = 'default_generated on update current_timestamp(6)')
      );
    IF valid_columns <> 14 OR (SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'analysis_ufw_ports') <> 14 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'analysis_ufw_ports: column mismatch; legacy table retained';
    END IF;

    SELECT COUNT(*) INTO valid_indexes FROM (
        SELECT index_name, non_unique, index_type, is_visible, COUNT(*) AS column_count,
               GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ',') AS columns_in_order,
               SUM(sub_part IS NOT NULL) AS prefix_columns
        FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = 'analysis_ufw_ports'
        GROUP BY index_name, non_unique, index_type, is_visible
    ) AS indexes_found
    WHERE index_type = 'BTREE' AND is_visible = 'YES' AND prefix_columns = 0 AND (
        (index_name = 'PRIMARY' AND non_unique = 0 AND column_count = 1 AND columns_in_order = 'id')
        OR (index_name = 'uq_ufw_ports_period' AND non_unique = 0 AND column_count = 5
            AND columns_in_order = 'period_start,period_end,destination_ip,destination_port,protocol')
        OR (index_name = 'idx_ufw_ports_history' AND non_unique = 1 AND column_count = 5
            AND columns_in_order = 'destination_port,protocol,destination_ip,period_start,period_end')
    );
    IF valid_indexes <> 3 OR (SELECT COUNT(DISTINCT index_name) FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = 'analysis_ufw_ports') <> 3 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'analysis_ufw_ports: index mismatch; legacy table retained';
    END IF;

    SELECT COUNT(*) INTO valid_checks FROM (
        SELECT tc.constraint_name,
            REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(LOWER(cc.check_clause),
                '`', ''), ' ', ''), '(', ''), ')', ''), '_ascii', ''), '_utf8mb4', ''), CHAR(92), '') AS clause
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.check_constraints AS cc
          ON cc.constraint_schema = tc.constraint_schema AND cc.constraint_name = tc.constraint_name
        WHERE tc.table_schema = DATABASE() AND tc.table_name = 'analysis_ufw_ports'
          AND tc.constraint_type = 'CHECK' AND tc.enforced = 'YES'
    ) AS checks_found
    WHERE (constraint_name = 'chk_ufw_ports_period' AND clause = 'period_start<period_end')
       OR (constraint_name = 'chk_ufw_ports_seen'
           AND clause = 'first_seen>=period_startandfirst_seen<=last_seenandlast_seen<period_end')
       OR (constraint_name = 'chk_ufw_ports_port' AND clause = 'destination_portbetween1and65535')
       OR (constraint_name = 'chk_ufw_ports_protocol' AND clause = 'protocolin''tcp'',''udp''');
    IF valid_checks <> 4 OR (SELECT COUNT(*) FROM information_schema.table_constraints
        WHERE table_schema = DATABASE() AND table_name = 'analysis_ufw_ports') <> 6 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'analysis_ufw_ports: constraint mismatch; legacy table retained';
    END IF;

    -- Only this explicitly replaced table is retired. No raw rows are changed.
    DROP TABLE IF EXISTS top_targeted_ports;
END//
DELIMITER ;
CALL mysql_siem_migrate_ufw_ports();
DROP PROCEDURE mysql_siem_migrate_ufw_ports;
