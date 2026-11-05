ALTER TABLE analysis_source_ips ADD INDEX idx_analysis_time_basis (time_basis);
ALTER TABLE analysis_ufw_ports ADD INDEX idx_analysis_time_basis (time_basis);
ALTER TABLE analysis_ufw_traffic ADD INDEX idx_analysis_time_basis (time_basis);
ALTER TABLE analysis_ufw_traffic_daily ADD INDEX idx_analysis_time_basis (time_basis);
