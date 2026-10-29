ALTER TABLE analysis_source_ips DROP PRIMARY KEY, ADD PRIMARY KEY (period_start,period_end,source_ip,host_scope,time_basis);
ALTER TABLE analysis_ufw_ports DROP INDEX uq_ufw_ports_period, ADD UNIQUE KEY uq_ufw_ports_period (period_start,period_end,destination_ip,destination_port,protocol,host_scope,time_basis);
ALTER TABLE analysis_ufw_traffic DROP INDEX uq_traffic_period, ADD UNIQUE KEY uq_traffic_period (period_start,period_end,host_scope,time_basis);
ALTER TABLE analysis_ufw_traffic_daily DROP INDEX uq_traffic_period, ADD UNIQUE KEY uq_traffic_period (analysis_date,host_scope,time_basis);
