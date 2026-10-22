-- MySQL dump 10.13  Distrib 8.4.11, for Linux (x86_64)
--
-- Host: localhost    Database: mysql_siem
-- ------------------------------------------------------
-- Server version	8.4.11-0ubuntu0.26.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `filesystem_metrics`
--

DROP TABLE IF EXISTS `filesystem_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `filesystem_metrics` (
  `metric_date` date NOT NULL,
  `modified_last_day` bigint unsigned NOT NULL DEFAULT '0',
  `total_files` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`metric_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `security_metrics`
--

DROP TABLE IF EXISTS `security_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `security_metrics` (
  `date` datetime NOT NULL,
  `uptime` decimal(10,2) NOT NULL,
  `blocks` bigint unsigned NOT NULL DEFAULT '0',
  `failed_logins` bigint unsigned NOT NULL DEFAULT '0',
  `unique_ips` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `system_metrics`
--

DROP TABLE IF EXISTS `system_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_metrics` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `uptime_hours` decimal(12,2) DEFAULT NULL,
  `cpuload1` decimal(10,2) DEFAULT NULL,
  `cpuload5` decimal(10,2) DEFAULT NULL,
  `cpuload15` decimal(10,2) DEFAULT NULL,
  `cpu_usage` decimal(10,2) DEFAULT NULL,
  `cpu_temperature` decimal(10,2) DEFAULT NULL,
  `ram_free_mb` decimal(14,2) DEFAULT NULL,
  `disk_used` decimal(14,2) DEFAULT NULL,
  `disk_free` decimal(14,2) DEFAULT NULL,
  `disk_usage` decimal(10,2) DEFAULT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `analysis_ufw_ports`
--

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

--
-- Table structure for table `ufw_daily_actions_counts`
--

DROP TABLE IF EXISTS `ufw_daily_actions_counts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ufw_daily_actions_counts` (
  `day` date NOT NULL,
  `audit_count` bigint unsigned NOT NULL DEFAULT '0',
  `allow_count` bigint unsigned NOT NULL DEFAULT '0',
  `block_count` bigint unsigned NOT NULL DEFAULT '0',
  `total_count` bigint unsigned NOT NULL DEFAULT '0',
  `total_average_week` decimal(12,2) NOT NULL DEFAULT '0.00',
  PRIMARY KEY (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ufw_log`
--

DROP TABLE IF EXISTS `ufw_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ufw_log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `event_time` datetime DEFAULT NULL,
  `action` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_ip` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dst_ip` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `protocol` varchar(10) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_port` int unsigned NOT NULL DEFAULT '0',
  `dst_port` int unsigned NOT NULL DEFAULT '0',
  `raw_line` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `event_hash` char(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ufw_event_hash` (`event_hash`),
  KEY `idx_event_time` (`event_time`),
  KEY `idx_src_ip` (`src_ip`),
  KEY `idx_dst_ip` (`dst_ip`),
  KEY `idx_action` (`action`),
  KEY `idx_dst_port` (`dst_port`)
) ENGINE=InnoDB AUTO_INCREMENT=1623 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ufw_state`
--

DROP TABLE IF EXISTS `ufw_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ufw_state` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `logfile` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `last_position` bigint unsigned NOT NULL DEFAULT '0',
  `file_device` bigint unsigned DEFAULT NULL,
  `file_inode` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ufw_state_file` (`file_device`,`file_inode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-10-09 12:45:28
