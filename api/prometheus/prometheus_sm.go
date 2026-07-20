/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Shared-metrics (SM) subsystem carried from upstream loxilb prometheus.go.

package prometheus

import (
	"fmt"
	"strings"
	"sync"

	tk "github.com/loxilb-io/loxilib"
)

var (
	// Shared metrics
	sharedMetrics = struct {
		sync.RWMutex
		data map[string]SharedMetric
	}{data: make(map[string]SharedMetric)}

	enableSharedMetrics = true
)

// Define the struct for the metrics
type DipMetric struct {
	Dip   string  `json:"dip"`
	Value float64 `json:"value"`
	Ratio float64 `json:"ratio"`
}

// Define the map type for the outer object
type DipMetrics map[string][]DipMetric

// Define the struct for the metrics
type ServiceDistMetric struct {
	Value float64 `json:"value"`
	Ratio float64 `json:"ratio"`
}

// Define the map type for the outer object
type ServiceDistMetrics map[string]ServiceDistMetric

// Define the struct for the service metrics
type ServiceMetric struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// Define the map type for the outer object
type RequestMetrics struct {
	TotalRequests           float64         `json:"total_requests"`
	TotalRequestsPerService []ServiceMetric `json:"total_requests_per_service"`
}

// Define the struct for the error metrics
type ErrorMetrics struct {
	TotalErrors           float64         `json:"total_errors"`
	TotalErrorsPerService []ServiceMetric `json:"total_errors_per_service"`
}

// Define the struct for the interaction metrics
type InteractionMetric struct {
	Service string  `json:"service"`
	Sip     string  `json:"sip"`
	Dip     string  `json:"dip"`
	Value   float64 `json:"value"`
}

// Define the map type for the outer object
type ProcessedTrafficMetrics struct {
	LbRuleInteractionBytes   []InteractionMetric `json:"lb_rule_interaction_bytes"`
	LbRuleInteractionPackets []InteractionMetric `json:"lb_rule_interaction_packets"`
}

// Define the struct for the firewall drop metrics per rule
type FwDropMetric struct {
	FwRule string  `json:"fw_rule"`
	Value  float64 `json:"value"`
}

// Define the struct for the firewall drop metrics
type FwDropsMetrics struct {
	TotalFwDrops        float64        `json:"total_fw_drops"`
	TotalFwDropsPerRule []FwDropMetric `json:"total_fw_drops_per_rule"`
}

// Define the Node structure
type Node struct {
	ID            string  `json:"id"`
	Title         string  `json:"title"`
	Subtitle      string  `json:"subtitle"`
	Mainstat      float64 `json:"mainstat"`
	Secondarystat float64 `json:"secondarystat,omitempty"`
	Color         string  `json:"color"`
	Icon          string  `json:"icon"`
	NodeRadius    int     `json:"nodeRadius"`
}

// Define the Edge structure
type Edge struct {
	ID            string  `json:"id"`
	Source        string  `json:"source"`
	Target        string  `json:"target"`
	Mainstat      float64 `json:"mainstat"`
	Secondarystat float64 `json:"secondarystat,omitempty"`
	Thickness     int     `json:"thickness"`
	Color         string  `json:"color"`
}

// Define the Nodegraph structure
type NodeGraphSchema struct {
	SchemaVersion int `json:"schemaVersion"`
	Meta          struct {
		PreferredVisualisationType string `json:"preferredVisualisationType"`
	} `json:"meta"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type SharedMetric struct {
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
	Labels map[string]string `json:"labels,omitempty"` // Optional labels
}

// Helper functions for shared metrics
func SetSharedMetric(name string, value float64) {
	sharedMetrics.Lock()
	defer sharedMetrics.Unlock()
	sharedMetrics.data[name] = SharedMetric{Name: name, Value: value}
}

func AddSharedMetric(name string, increment float64) {
	sharedMetrics.Lock()
	defer sharedMetrics.Unlock()
	if metric, exists := sharedMetrics.data[name]; exists {
		metric.Value += increment
		sharedMetrics.data[name] = metric
	} else {
		sharedMetrics.data[name] = SharedMetric{Name: name, Value: increment}
	}
}

func AddLabeledMetric(name string, labels map[string]string, increment float64) {
	sharedMetrics.Lock()
	defer sharedMetrics.Unlock()
	labelsKey := generateLabelsKey(name, labels)
	if metric, exists := sharedMetrics.data[labelsKey]; exists {
		metric.Value += increment
		sharedMetrics.data[labelsKey] = metric
	} else {
		sharedMetrics.data[labelsKey] = SharedMetric{Name: name, Value: increment, Labels: labels}
	}
}

// SetLabeledMetric overwrites a labeled metric with an absolute value
// (gauge semantics, as opposed to AddLabeledMetric's counter semantics).
func SetLabeledMetric(name string, labels map[string]string, value float64) {
	sharedMetrics.Lock()
	defer sharedMetrics.Unlock()
	labelsKey := generateLabelsKey(name, labels)
	sharedMetrics.data[labelsKey] = SharedMetric{Name: name, Value: value, Labels: labels}
}

// DeleteLabeledMetric removes a labeled metric entry (e.g. when the underlying
// rule or endpoint has been deleted).
func DeleteLabeledMetric(name string, labels map[string]string) {
	sharedMetrics.Lock()
	defer sharedMetrics.Unlock()
	delete(sharedMetrics.data, generateLabelsKey(name, labels))
}

// Helper function to retrieve specific metrics from shared metrics
func metricJSON(metricNames []string) map[string]float64 {
	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	metrics := make(map[string]float64)
	for _, name := range metricNames {
		if value, exists := sharedMetrics.data[name]; exists {
			metrics[name] = float64(value.Value)
		} else {
			tk.LogIt(tk.LogDebug, "Metric %s not found\n", name)
		}
	}
	return metrics
}

// Function to get labeled metrics
func GetLabeledMetrics() []SharedMetric {
	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	metrics := make([]SharedMetric, 0, len(sharedMetrics.data))
	for _, metric := range sharedMetrics.data {
		metrics = append(metrics, metric)
	}
	return metrics
}

func GetFlowCountSM() map[string]float64 {
	// API URL : /metrics/flowcount
	metricNames := []string{
		"active_conntrack_count",
		"active_flow_count_tcp",
		"active_flow_count_udp",
		"active_flow_count_sctp",
		"inactive_flow_count",
	}
	return metricJSON(metricNames)
}

func GetHostCountSM() map[string]float64 {
	// API URL : /metrics/hostcount
	metricNames := []string{
		"healthy_host_count",
		"unhealthy_host_count",
	}
	return metricJSON(metricNames)
}

func GetLBRuleCountSM() map[string]float64 {
	// API URL : /metrics/lbrulecount
	metricNames := []string{
		"lb_rule_count",
	}
	return metricJSON(metricNames)
}

func GetNetFlowCountSM() map[string]float64 {
	// API URL : /metrics/newflowcount
	metricNames := []string{
		"new_flow_count",
	}
	return metricJSON(metricNames)
}

func GetReqCountSM() RequestMetrics {
	metricNames := []string{
		"total_requests",
	}

	metrics := RequestMetrics{}
	metrics.TotalRequests = metricJSON(metricNames)["total_requests"]

	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	totalRequestsPerService := make([]ServiceMetric, 0)
	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "total_requests_per_service") {
			service, ok := metric.Labels["service"]
			if !ok || service == "" {
				service = "default"
			}
			totalRequestsPerService = append(totalRequestsPerService, ServiceMetric{
				Name:  service,
				Value: float64(metric.Value),
			})
		}
	}
	metrics.TotalRequestsPerService = totalRequestsPerService

	return metrics
}

func GetErrCountSM() ErrorMetrics {
	metricNames := []string{
		"total_errors",
	}

	metrics := ErrorMetrics{}
	metrics.TotalErrors = metricJSON(metricNames)["total_errors"]

	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	totalErrorsPerService := make([]ServiceMetric, 0)
	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "total_errors_per_service") {
			service, ok := metric.Labels["service"]
			if !ok || service == "" {
				service = "default"
			}
			totalErrorsPerService = append(totalErrorsPerService, ServiceMetric{
				Name:  service,
				Value: float64(metric.Value),
			})
		}
	}

	metrics.TotalErrorsPerService = totalErrorsPerService

	return metrics
}

func GetProcessedTrafficVecSM() map[string]float64 {
	metricNames := []string{
		"processed_bytes",
		"processed_tcp_bytes",
		"processed_sctp_bytes",
		"processed_udp_bytes",
		"processed_packets",
	}
	return metricJSON(metricNames)
}

func GetLBProcessedTrafficVecSM() ProcessedTrafficMetrics {
	metrics := ProcessedTrafficMetrics{
		LbRuleInteractionBytes:   make([]InteractionMetric, 0),
		LbRuleInteractionPackets: make([]InteractionMetric, 0),
	}

	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	for key, metric := range sharedMetrics.data {
		service, ok := metric.Labels["service"]
		if !ok || service == "" {
			service = "default"
		}

		interactionMetric := InteractionMetric{
			Service: service,
			Sip:     metric.Labels["sip"],
			Dip:     metric.Labels["dip"],
			Value:   float64(metric.Value),
		}

		if strings.HasPrefix(key, "lb_rule_interaction_bytes") {
			metrics.LbRuleInteractionBytes = append(metrics.LbRuleInteractionBytes, interactionMetric)
		} else if strings.HasPrefix(key, "lb_rule_interaction_packets") {
			metrics.LbRuleInteractionPackets = append(metrics.LbRuleInteractionPackets, interactionMetric)
		}
	}

	return metrics
}

func GetEpDistTrafficVecSM() DipMetrics {
	// API URL : /metrics/epdisttraffic
	serviceTraffic := make(map[string]float64)
	serviceDipTraffic := make(map[string]map[string]float64)

	// Read lock to ensure thread-safe access to sharedMetrics.data
	sharedMetrics.RLock()
	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "lb_rule_interaction_bytes") {
			service, ok := metric.Labels["service"]
			if !ok || service == "" || service == "-" {
				service = "default"
			}
			dip := metric.Labels["dip"]

			if _, exists := serviceTraffic[service]; !exists {
				serviceTraffic[service] = 0
				serviceDipTraffic[service] = make(map[string]float64)
			}

			serviceTraffic[service] += metric.Value
			serviceDipTraffic[service][dip] += metric.Value
		}
	}
	sharedMetrics.RUnlock()

	// Calculate distribution ratio
	metrics := make(DipMetrics)
	for service, totalTraffic := range serviceTraffic {
		distribution := make([]DipMetric, 0)
		for dip, dipTraffic := range serviceDipTraffic[service] {
			// Guard against NaN (JSON marshal fails on NaN) when total is zero
			ratio := 0.0
			if totalTraffic > 0 {
				ratio = float64(dipTraffic) / float64(totalTraffic)
			}
			distribution = append(distribution, DipMetric{
				Dip:   dip,
				Value: dipTraffic,
				Ratio: ratio,
			})
		}
		metrics[service] = distribution
	}

	return metrics
}

func GetServiceDistTrafficVecSM() ServiceDistMetrics {
	// API URL : /metrics/servicedisttraffic
	serviceTraffic := make(map[string]float64)

	// Read lock to ensure thread-safe access to sharedMetrics.data
	sharedMetrics.RLock()
	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "lb_rule_interaction_bytes") {
			service, ok := metric.Labels["service"]
			if !ok || service == "" || service == "-" {
				service = "default"
			}

			if _, exists := serviceTraffic[service]; !exists {
				serviceTraffic[service] = 0
			}

			serviceTraffic[service] += metric.Value
		}
	}
	sharedMetrics.RUnlock()

	// Calculate distribution ratio
	metrics := make(ServiceDistMetrics)
	totalTraffic := 0.0
	for _, traffic := range serviceTraffic {
		totalTraffic += traffic
	}

	for service, traffic := range serviceTraffic {
		// Guard against NaN (JSON marshal fails on NaN) when total is zero
		ratio := 0.0
		if totalTraffic > 0 {
			ratio = traffic / totalTraffic
		}
		metrics[service] = ServiceDistMetric{
			Value: traffic,
			Ratio: ratio,
		}
	}

	return metrics
}

func GetFwDropsSM() FwDropsMetrics {
	metricNames := []string{
		"total_fw_drops",
	}

	metrics := FwDropsMetrics{}
	metrics.TotalFwDrops = metricJSON(metricNames)["total_fw_drops"]

	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	totalDropsPerRule := make([]FwDropMetric, 0)
	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "total_fw_drops_per_rule") {
			totalDropsPerRule = append(totalDropsPerRule, FwDropMetric{
				FwRule: metric.Labels["fw_rule"],
				Value:  float64(metric.Value),
			})
		}
	}
	metrics.TotalFwDropsPerRule = totalDropsPerRule

	return metrics
}

func GetReqCountPerClientSM() map[string]float64 {
	clientRequests := make(map[string]float64)

	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "lb_rule_interaction_packets") {
			// EXTRACT CLIENT IP(ip) FROM LABELS
			clientIP := metric.Labels["sip"]
			if _, exists := clientRequests[clientIP]; !exists {
				clientRequests[clientIP] = 0
			}
			clientRequests[clientIP] += float64(metric.Value)
		}
	}

	resp := make(map[string]float64)
	for clientIP, count := range clientRequests {
		resp[clientIP] = count
	}

	return resp
}

func GetNodeGraphSM() NodeGraphSchema {
	return generateNodeGraphSchema("")
}

func GetNodeGraphServiceSM(service string) NodeGraphSchema {
	return generateNodeGraphSchema(service)
}

func generateNodeGraphSchema(service string) NodeGraphSchema {
	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()

	// Define temp data
	tmpData := make([]map[string]interface{}, 0, len(sharedMetrics.data))

	for key, metric := range sharedMetrics.data {
		if strings.HasPrefix(key, "lb_rule_interaction_bytes") && (service == "" || metric.Labels["service"] == service) {
			svc := metric.Labels["service"]
			if svc == "" || svc == "-" {
				svc = "default"
				continue // Skip appending to tmpData
			}
			dip := metric.Labels["dip"]
			if dip == "" {
				dip = "na"
			}
			sip := metric.Labels["sip"]
			if sip == "" {
				sip = "na"
			}
			value := float64(metric.Value)
			tmpData = append(tmpData, map[string]interface{}{
				"service": svc,
				"dip":     dip,
				"sip":     sip,
				"value":   value,
			})
		}
	}

	// Generate Node data
	nodeMap := make(map[string]Node)
	for _, data := range tmpData {
		dip := data["dip"].(string)
		sip := data["sip"].(string)
		value := data["value"].(float64)
		service := data["service"].(string)

		if node, exists := nodeMap[service]; exists {
			node.Mainstat += value
			nodeMap[service] = node
		} else {
			nodeMap[service] = Node{
				ID:       service,
				Title:    service,
				Mainstat: value,
				Color:    "blue",
			}
		}

		if node, exists := nodeMap[dip]; exists {
			node.Mainstat += value
			nodeMap[dip] = node
		} else {
			nodeMap[dip] = Node{
				ID:       dip,
				Title:    dip,
				Mainstat: value,
				Color:    "green",
			}
		}

		if node, exists := nodeMap[sip]; exists {
			node.Mainstat += value
			nodeMap[sip] = node
		} else {
			nodeMap[sip] = Node{
				ID:       sip,
				Title:    sip,
				Mainstat: value,
				Color:    "yellow",
			}
		}
	}

	nodes := make([]Node, 0, len(nodeMap))
	for _, node := range nodeMap {
		nodes = append(nodes, node)
	}

	edges := make([]Edge, 0, len(tmpData)*2)
	for _, data := range tmpData {
		dip := data["dip"].(string)
		sip := data["sip"].(string)
		service := data["service"].(string)
		value := data["value"].(float64)

		edges = append(edges, Edge{
			ID:        fmt.Sprintf("%s-%s", sip, service),
			Source:    sip,
			Target:    service,
			Mainstat:  value,
			Thickness: 4,
			Color:     "cyan",
		})

		edges = append(edges, Edge{
			ID:        fmt.Sprintf("%s-%s", service, dip),
			Source:    service,
			Target:    dip,
			Mainstat:  value,
			Thickness: 4,
			Color:     "orange",
		})
	}

	return NodeGraphSchema{
		SchemaVersion: 37,
		Meta: struct {
			PreferredVisualisationType string `json:"preferredVisualisationType"`
		}{
			PreferredVisualisationType: "nodeGraph",
		},
		Nodes: nodes,
		Edges: edges,
	}
}

// NOTE: The legacy collection goroutines (RunHostCount, RunProcessedStatistic,
// RunFwStatistic) that used to live here were removed: they ran in parallel with
// the optimized pipeline in prometheus.go, double-counting the shared Prometheus
// counters and racing on prevConntrackStats under a different lock. The single
// pipeline in prometheus.go now also feeds the shared-metrics store consumed by
// the /metrics/* REST endpoints.
