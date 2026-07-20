/*
 * Copyright (c) 2025 NetLOX Inc
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

package loxinet

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Parse call counters
	parseCallsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_parser_calls_total",
			Help: "Total number of parser calls",
		},
		[]string{"protocol", "status"}, // status: success, error, timeout, panic
	)

	// Parse latency histogram
	parseLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_parser_duration_seconds",
			Help:    "Parser execution duration",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}, // 1ms to 5s
		},
		[]string{"protocol"},
	)

	// Body size histogram
	parsedBodySize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_parser_body_size_bytes",
			Help:    "Size of parsed HTTP bodies",
			Buckets: []float64{100, 512, 1024, 4096, 16384, 65536, 262144, 1048576}, // 100B to 1MB
		},
		[]string{"protocol"},
	)

	// Attributes extracted counter
	attributesExtracted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_parser_attributes_extracted_total",
			Help: "Total number of attributes extracted by parsers",
		},
		[]string{"protocol"},
	)
)

// RecordParseCall records a parser invocation with status
func RecordParseCall(protocol string, status string, durationSeconds float64) {
	parseCallsTotal.WithLabelValues(protocol, status).Inc()
	parseLatency.WithLabelValues(protocol).Observe(durationSeconds)
}

// RecordParsedBodySize records the size of a parsed body
func RecordParsedBodySize(protocol string, sizeBytes int) {
	parsedBodySize.WithLabelValues(protocol).Observe(float64(sizeBytes))
}

// RecordAttributesExtracted records the number of attributes extracted
func RecordAttributesExtracted(protocol string, count int) {
	if count <= 0 {
		return
	}
	attributesExtracted.WithLabelValues(protocol).Add(float64(count))
}
