/*
 * Copyright (c) 2023 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package prometheus

// Metric names for the core exporter. Every metric registered in
// prometheus.go takes its name from here so naming stays consistent and
// renames happen in one place. All names carry the loxilb_ namespace;
// counters end in _total. The REST /metrics/* JSON keys are a separate,
// unchanged surface (see prometheus_sm.go shared-metric keys).
const (
	// Connection tracking metrics
	MetricActiveConntrackCount = "loxilb_active_conntrack_entries"
	MetricConntrackMaxEntries  = "loxilb_conntrack_max_entries"
	MetricActiveFlowCountTCP   = "loxilb_active_flow_count_tcp"
	MetricActiveFlowCountUDP   = "loxilb_active_flow_count_udp"
	MetricActiveFlowCountSCTP  = "loxilb_active_flow_count_sctp"
	MetricNewFlowCount         = "loxilb_new_flows"

	// Load balancer metrics
	MetricLBRuleCount             = "loxilb_lb_rules"
	MetricTotalRequests           = "loxilb_requests_total"
	MetricTotalRequestsPerService = "loxilb_service_requests_total"
	MetricTotalErrors             = "loxilb_errors_total"
	MetricTotalErrorsPerService   = "loxilb_service_errors_total"

	// Endpoint health metrics
	MetricHealthyEndpointsCount   = "loxilb_healthy_endpoints"
	MetricUnhealthyEndpointsCount = "loxilb_unhealthy_endpoints"

	// Firewall metrics
	MetricTotalFwDrops        = "loxilb_fw_drop_packets_total"
	MetricTotalFwDropsPerRule = "loxilb_fw_rule_drop_packets_total"
	MetricFirewallRulesCount  = "loxilb_firewall_rules"

	// System utilization metrics (percentage [0-100])
	MetricSystemCPUUtilization    = "loxilb_system_cpu_utilization_percent"
	MetricSystemMemoryUtilization = "loxilb_system_memory_utilization_percent"
	MetricSystemDiskUtilization   = "loxilb_system_disk_utilization_percent"

	// Security rate limiting metrics
	MetricSecuritySYNBlocked      = "loxilb_security_syn_blocked_total"
	MetricSecuritySYNPassed       = "loxilb_security_syn_passed_total"
	MetricSecuritySYNCookies      = "loxilb_security_syn_cookies_total"
	MetricSecurityConnBlocked     = "loxilb_security_conn_blocked_total"
	MetricSecurityConnPassed      = "loxilb_security_conn_passed_total"
	MetricSecurityUniqueIPs       = "loxilb_security_unique_ips"
	MetricSecurityUDPBlocked      = "loxilb_security_udp_blocked_total"
	MetricSecurityUDPPassed       = "loxilb_security_udp_passed_total"
	MetricSecurityUDPBytesBlocked = "loxilb_security_udp_bytes_blocked_total"
	MetricSecurityUDPBytesPassed  = "loxilb_security_udp_bytes_passed_total"

	// IP filter metrics
	MetricIPFilterBlacklistPackets = "loxilb_ipfilter_blacklist_packets_total"
	MetricIPFilterBlacklistBytes   = "loxilb_ipfilter_blacklist_bytes_total"
	MetricIPFilterWhitelistPackets = "loxilb_ipfilter_whitelist_packets_total"
	MetricIPFilterWhitelistBytes   = "loxilb_ipfilter_whitelist_bytes_total"
	MetricIPFilterTotalRules       = "loxilb_ipfilter_rules"

	// Traffic processing metrics
	MetricProcessedBytesTotal   = "loxilb_processed_bytes_total"
	MetricProcessedPacketsTotal = "loxilb_processed_packets_total"

	MetricProcessedTCPBytes    = "loxilb_processed_tcp_bytes_total"
	MetricProcessedUDPBytes    = "loxilb_processed_udp_bytes_total"
	MetricProcessedSCTPBytes   = "loxilb_processed_sctp_bytes_total"
	MetricProcessedTCPPackets  = "loxilb_processed_tcp_packets_total"
	MetricProcessedUDPPackets  = "loxilb_processed_udp_packets_total"
	MetricProcessedSCTPPackets = "loxilb_processed_sctp_packets_total"

	// Per-rule interaction metrics
	MetricLBRuleInteractionBytes   = "loxilb_lb_rule_interaction_bytes_total"
	MetricLBRuleInteractionPackets = "loxilb_lb_rule_interaction_packets_total"

	// Traffic distribution metrics
	MetricServiceTrafficBytes   = "loxilb_service_traffic_bytes_total"
	MetricServiceTrafficPackets = "loxilb_service_traffic_packets_total"
	MetricEndpointTrafficBytes  = "loxilb_endpoint_traffic_bytes_total"
	MetricClientTrafficPackets  = "loxilb_client_traffic_packets_total"
)
