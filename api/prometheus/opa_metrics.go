/*
 * Copyright (c) 2025 LoxiLB Authors
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

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ============================================================================
// OPA L4 WATCHER METRICS - Policy sync and circuit breaker monitoring
// ============================================================================
// These metrics are populated by the OPA watcher in pkg/opa/watcher.go during
// each sync cycle. They track sync operations, duration, rule counts, and
// circuit breaker state.
// ============================================================================

var (
	// opaWatcherSyncsTotal counts sync operations by outcome.
	opaWatcherSyncsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_opa_watcher_syncs_total",
			Help: "Total OPA L4 watcher sync operations by status.",
		},
		[]string{"status"}, // "success" or "failure"
	)

	// opaSyncDurationSeconds tracks the duration of each sync cycle.
	opaSyncDurationSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "loxilb_opa_sync_duration_seconds",
			Help:    "OPA L4 watcher sync duration in seconds.",
			Buckets: []float64{0.1, 0.5, 1, 5, 10},
		},
	)

	// opaFirewallRules tracks the current number of OPA-managed firewall rules.
	opaFirewallRules = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_opa_firewall_rules",
			Help: "Current number of OPA-managed firewall rules.",
		},
	)

	// opaCircuitBreakerState tracks the circuit breaker state as a numeric gauge.
	opaCircuitBreakerState = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_opa_circuit_breaker_state",
			Help: "OPA circuit breaker state (0=CLOSED, 1=OPEN, 2=HALF_OPEN).",
		},
	)
)

// RecordOPASyncResult increments the sync counter for the given status.
func RecordOPASyncResult(status string) {
	opaWatcherSyncsTotal.WithLabelValues(status).Inc()
}

// ObserveOPASyncDuration records a sync cycle duration observation.
func ObserveOPASyncDuration(seconds float64) {
	opaSyncDurationSeconds.Observe(seconds)
}

// SetOPAFirewallRulesTotal sets the gauge to the current number of OPA-managed rules.
func SetOPAFirewallRulesTotal(count float64) {
	opaFirewallRules.Set(count)
}

// SetOPACircuitBreakerState sets the gauge to the current circuit breaker state value.
func SetOPACircuitBreakerState(state float64) {
	opaCircuitBreakerState.Set(state)
}
