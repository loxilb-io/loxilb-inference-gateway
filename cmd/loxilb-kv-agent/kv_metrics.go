/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * kv_metrics.go -- Prometheus metrics for the KV cache pipeline.
 *
 * All metrics live in the kv-agent binary (package main).
 * Collection calls llb_kv_pipeline_get_stats via CGO bridge
 * in kv_bridge.go. The loxilb process does NOT link libloxilb_kv.a;
 * it exposes its own poll-based loxilb_kv_agent_up gauge via /kv/health
 * (pkg/loxinet/kv_agent_client.go) — health is deliberately NOT exported
 * from this binary, since an in-process constant cannot observe its own
 * pipeline dying.
 */
package main

import (
	"sync"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

// ============================================================================
// KV PIPELINE PROMETHEUS METRICS
// ============================================================================
// 4 metrics covering: fetch sessions, fetch errors, evictions, and pipeline
// throughput — exactly the counters the C stats struct actually carries.
// Pattern follows api/prometheus/ai_metrics.go (promauto registration).
// ============================================================================

var (
	// kvFetchTotal counts total KV fetch sessions started.
	kvFetchTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "loxilb_kv_fetch_total",
		Help: "Total KV cache fetch sessions started",
	})

	// kvFetchErrors counts fetch errors. The C stats struct carries only an
	// aggregate error count, so there is no per-type breakdown (plain counter;
	// an error_type label can return when C carries one).
	kvFetchErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "loxilb_kv_fetch_errors_total",
		Help: "Total KV cache fetch errors",
	})

	// kvBytesTransferred counts total decompressed bytes delivered through the
	// pipeline (post-decompress payload volume, not raw DMA bytes).
	kvBytesTransferred = promauto.NewCounter(prometheus.CounterOpts{
		Name: "loxilb_kv_bytes_transferred_total",
		Help: "Total bytes transferred through KV pipeline (decompressed)",
	})

	// kvEvictions counts sessions evicted due to priority preemption.
	kvEvictions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "loxilb_kv_evictions_total",
		Help: "Total sessions evicted due to priority preemption",
	})
)

// prevStats holds the previous collection's counters for delta computation.
var prevStats struct {
	mu        sync.Mutex
	fetches   uint64
	errors    uint64
	evictions uint64
	bytes     uint64
}

// RegisterKVMetrics is called once at kv-agent startup as an init checkpoint.
// promauto handles actual Prometheus registration; this function only logs
// metric readiness.
func RegisterKVMetrics() {
	log.Info("kv pipeline metrics registered (4 metrics)")
}

// CollectKVMetrics is called every 10 seconds (PrometheusDefaultPeriod) to
// read C-side pipeline counters via CGO and update Prometheus metrics.
// Uses the delta pattern from ai_metrics.go: current - previous = increment.
func CollectKVMetrics(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}

	stats := pipelineGetStats(ctx)

	prevStats.mu.Lock()
	defer prevStats.mu.Unlock()

	// Delta computation: only increment counters by the difference
	if stats.Fetches >= prevStats.fetches {
		delta := stats.Fetches - prevStats.fetches
		if delta > 0 {
			kvFetchTotal.Add(float64(delta))
		}
	}

	if stats.Errors >= prevStats.errors {
		delta := stats.Errors - prevStats.errors
		if delta > 0 {
			kvFetchErrors.Add(float64(delta))
		}
	}

	if stats.Evictions >= prevStats.evictions {
		delta := stats.Evictions - prevStats.evictions
		if delta > 0 {
			kvEvictions.Add(float64(delta))
		}
	}

	if stats.Bytes >= prevStats.bytes {
		delta := stats.Bytes - prevStats.bytes
		if delta > 0 {
			kvBytesTransferred.Add(float64(delta))
		}
	}

	// Save current as previous for next collection cycle
	prevStats.fetches = stats.Fetches
	prevStats.errors = stats.Errors
	prevStats.evictions = stats.Evictions
	prevStats.bytes = stats.Bytes
}

// StartMetricsCollector launches a background goroutine that calls
// CollectKVMetrics every 10 seconds (matching PrometheusDefaultPeriod).
func StartMetricsCollector(ctx unsafe.Pointer, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				CollectKVMetrics(ctx)
			case <-stopCh:
				return
			}
		}
	}()
}
