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

import "time"

// MetricPriority defines the collection and storage priority for different metrics
type MetricPriority int

const (
	CRITICAL_REALTIME  MetricPriority = iota // 10s collection, always in memory
	IMPORTANT_NEARTIME                       // 30s collection, 1-min aggregation
	OPERATIONAL                              // 2-min collection, 5-min aggregation
	HISTORICAL                               // 5-min collection, 15-min aggregation
)

// MetricConfig defines configuration for metric collection and storage
type MetricConfig struct {
	Priority           MetricPriority // Collection priority
	CollectionInterval time.Duration  // How often to collect this metric
	AggregationWindow  time.Duration  // Time window for aggregation
	RetentionPeriod    time.Duration  // How long to keep the data
	InMemoryOnly       bool           // Whether to keep only in memory
	DeltaThreshold     float64        // Minimum change threshold for storage
	MaxMemoryEntries   int            // Maximum entries to keep in memory
}

// MetricCategory represents different categories of metrics in loxilb
type MetricCategory string

const (
	Critical    MetricCategory = "critical"
	Important   MetricCategory = "important"
	Operational MetricCategory = "operational"
	Historical  MetricCategory = "historical"
)

const (
	COLLECTION_BASIS             = 10
	CRITICAL_COLLECTION_RATIO    = 1
	IMPORTANT_COLLECTION_RATIO   = 3
	OPERATIONAL_COLLECTION_RATIO = 12
	HISTORICAL_COLLECTION_RATIO  = 24
	DB_COLLECTION_RATIO          = 120
)

// DefaultMetricConfigs provides default configurations for all metric categories
var DefaultMetricConfigs = map[MetricCategory]MetricConfig{
	// CRITICAL_REALTIME metrics - Always in memory, 10s collection
	Critical: {
		Priority:           CRITICAL_REALTIME,
		CollectionInterval: COLLECTION_BASIS * CRITICAL_COLLECTION_RATIO * time.Second,
		AggregationWindow:  time.Minute,
		RetentionPeriod:    24 * time.Hour,
		InMemoryOnly:       true,
		DeltaThreshold:     1.0,  // Always store changes
		MaxMemoryEntries:   1440, // 24 hours worth
	},
	// IMPORTANT_NEARTIME metrics - 30s collection, 1-min aggregation
	Important: {
		Priority:           IMPORTANT_NEARTIME,
		CollectionInterval: COLLECTION_BASIS * IMPORTANT_COLLECTION_RATIO * time.Second,
		AggregationWindow:  time.Minute,
		RetentionPeriod:    7 * 24 * time.Hour,
		InMemoryOnly:       false,
		DeltaThreshold:     10.0, // Always store endpoint health changes
		MaxMemoryEntries:   480,  // 4 hours worth
	},
	// OPERATIONAL metrics - 2-min collection, 5-min aggregation
	Operational: {
		Priority:           OPERATIONAL,
		CollectionInterval: COLLECTION_BASIS * OPERATIONAL_COLLECTION_RATIO * time.Second,
		AggregationWindow:  5 * time.Minute,
		RetentionPeriod:    30 * 24 * time.Hour,
		InMemoryOnly:       false,
		DeltaThreshold:     100000.0, // 1 RPS change threshold
		MaxMemoryEntries:   144,      // 12 hours worth
	},
	// HISTORICAL metrics - 5-min collection, 15-min aggregation
	Historical: {
		Priority:           HISTORICAL,
		CollectionInterval: COLLECTION_BASIS * HISTORICAL_COLLECTION_RATIO * time.Second,
		AggregationWindow:  15 * time.Minute,
		RetentionPeriod:    365 * 24 * time.Hour,
		InMemoryOnly:       false,
		DeltaThreshold:     0.0, // Always store for historical analysis
		MaxMemoryEntries:   96,  // 24 hours worth
	},
}

// GetMetricConfig returns the configuration for a specific metric category
func GetMetricConfig(metricCategory MetricCategory) (MetricConfig, bool) {
	config, exists := DefaultMetricConfigs[metricCategory]
	return config, exists
}

// GetMetricsByPriority returns all metrics of a specific priority level
func GetMetricsByPriority(priority MetricPriority) []MetricCategory {
	var metrics []MetricCategory
	for metricCategory, config := range DefaultMetricConfigs {
		if config.Priority == priority {
			metrics = append(metrics, metricCategory)
		}
	}
	return metrics
}

// IsRealTimeMetric checks if a metric requires real-time processing
func IsRealTimeMetric(metricCategory MetricCategory) bool {
	if config, exists := DefaultMetricConfigs[metricCategory]; exists {
		return config.Priority == CRITICAL_REALTIME
	}
	return false
}

// ShouldStoreInMemoryOnly checks if a metric should only be stored in memory
func ShouldStoreInMemoryOnly(metricCategory MetricCategory) bool {
	if config, exists := DefaultMetricConfigs[metricCategory]; exists {
		return config.InMemoryOnly
	}
	return false
}

// GetCollectionInterval returns the collection interval for a metric
func GetCollectionInterval(metricCategory MetricCategory) time.Duration {
	if config, exists := DefaultMetricConfigs[metricCategory]; exists {
		return config.CollectionInterval
	}
	return time.Minute // Default fallback
}

// GetDeltaThreshold returns the delta threshold for a metric
func GetDeltaThreshold(metricCategory MetricCategory) float64 {
	if config, exists := DefaultMetricConfigs[metricCategory]; exists {
		return config.DeltaThreshold
	}
	return 0.0 // Default: store all changes
}
