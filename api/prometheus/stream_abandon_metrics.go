/*
 * Copyright (c) 2026 NetLOX Inc
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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// Streams that ended before their terminator
// ============================================================================
// A streamed inference either delivers its terminator to the client or is
// torn down with the stream open. The data plane
// (loxilb-ebpf/common/sockproxy_abandon.h) records the second case by
// reason, with the stream's age at the end:
//
//   client_gone   the client closed or reset mid-stream; the backend leg is
//                 shut in the same teardown and the engine aborts
//   backend_died  the engine leg ended first
//   stall_abort   the client stopped reading and the gateway ended the
//                 stream after LLB_SSE_STALL_ABORT_SEC (default off)
//
// Every unfinished stream is GPU work whose remaining tokens nobody reads;
// these families say how often that happens, why, and how deep into the
// generation. Same construction as the half-close families (cumulative le
// buckets on the C side, const metrics on scrape, torn reads clamped, never
// going backwards). Label values are enum abandon_reason's order.
// ============================================================================

const abandonReasons = 3

var abandonReasonLabels = [abandonReasons]string{"client_gone", "backend_died", "stall_abort"}

// abandonAgeBounds are the age-at-end bucket upper bounds in SECONDS; they
// must match abandon_age_bounds_s in sockproxy_abandon.h.
var abandonAgeBounds = [kvBounds]float64{1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1800, 3600}

// streamAbandonSnapshot is the unfinished-stream state taken from one C
// snapshot. The age histograms reuse kvHist (12 bounds, sum already in the
// exported unit).
type streamAbandonSnapshot struct {
	total         [abandonReasons]uint64
	age           [abandonReasons]kvHist
	stallAbortSec uint64
}

// mergeStreamAbandon sanitizes next and merges it into prev; counters only
// need to not go backwards, the knob gauge is taken as read.
func mergeStreamAbandon(prev, next streamAbandonSnapshot) streamAbandonSnapshot {
	m := next
	for r := range m.total {
		m.total[r] = maxU64(prev.total[r], next.total[r])
		m.age[r] = mergeKvHist(prev.age[r], sanitizeKvHist(next.age[r]))
	}
	return m
}

var (
	streamAbandonStoreMutex sync.Mutex
	streamAbandonStore      streamAbandonSnapshot
)

// updateStreamAbandonStore merges a raw snapshot into the store. Called once
// per collection cycle by RunSockproxyMetrics.
func updateStreamAbandonStore(raw streamAbandonSnapshot) {
	streamAbandonStoreMutex.Lock()
	streamAbandonStore = mergeStreamAbandon(streamAbandonStore, raw)
	streamAbandonStoreMutex.Unlock()
}

var streamAbandonedDesc = prometheus.NewDesc(
	"loxilb_proxy_stream_abandoned_total",
	"Streamed responses that ended before their terminator, by reason (client_gone: the client left and the backend leg was shut with it; backend_died: the engine leg ended first; stall_abort: the gateway ended a stream its client stopped reading).",
	[]string{"reason"}, nil,
)

var streamAbandonAgeDesc = prometheus.NewDesc(
	"loxilb_proxy_stream_abandon_age_seconds",
	"Age of a streamed response when it ended before its terminator, by reason: how deep into the generation the stream was lost.",
	[]string{"reason"}, nil,
)

var streamStallAbortSecDesc = prometheus.NewDesc(
	"loxilb_proxy_sse_stall_abort_seconds",
	"The stalled-client window in force (LLB_SSE_STALL_ABORT_SEC): a stream whose client has not drained its relay cache for this long is ended; 0 = off.",
	nil, nil,
)

// streamAbandonCollector emits the unfinished-stream families from the
// store on every scrape. Every series is present from the start, at zero.
type streamAbandonCollector struct{}

// Describe implements prometheus.Collector.
func (streamAbandonCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- streamAbandonedDesc
	ch <- streamAbandonAgeDesc
	ch <- streamStallAbortSecDesc
}

// Collect implements prometheus.Collector.
func (streamAbandonCollector) Collect(ch chan<- prometheus.Metric) {
	streamAbandonStoreMutex.Lock()
	s := streamAbandonStore
	streamAbandonStoreMutex.Unlock()

	for r := 0; r < abandonReasons; r++ {
		ch <- prometheus.MustNewConstMetric(streamAbandonedDesc, prometheus.CounterValue,
			float64(s.total[r]), abandonReasonLabels[r])
		h := s.age[r]
		ch <- prometheus.MustNewConstHistogram(streamAbandonAgeDesc, h.count, h.sum,
			kvBucketMap(abandonAgeBounds, h), abandonReasonLabels[r])
	}
	ch <- prometheus.MustNewConstMetric(streamStallAbortSecDesc, prometheus.GaugeValue,
		float64(s.stallAbortSec))
}

func init() {
	datapathRegisterer{}.MustRegister(streamAbandonCollector{})
}
