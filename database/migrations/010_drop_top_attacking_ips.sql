-- Retire the replaced Source IP summary table and permanently discard its history.
-- Apply 009_analysis_source_ips.sql first to create the replacement table.
-- UFW raw events and analysis_source_ips are not modified.
-- MySQL DDL commits implicitly. This operation cannot be rolled back.

DROP TABLE IF EXISTS top_attacking_ips;
