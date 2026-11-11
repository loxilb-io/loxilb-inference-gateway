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
// P/D occupancy: the admission units held now, and the parked connections
// ============================================================================
// A P/D request holds one admission unit on its prefill endpoint and one on
// its decode endpoint from admission until its cleanup
// (pd_ep_loads[].active_conns in loxilb-ebpf/common/sockproxy.h), summed
// over every P/D pool; a connection waiting for a unit is PARKED. All three
// are read as they are at the snapshot: when the load is gone they return
// to zero, whatever the session cache still maps.
// ============================================================================

// pdOccupancySnapshot is the occupancy taken from one C snapshot.
type pdOccupancySnapshot struct {
	prefill uint64
	decode  uint64
	parked  uint64
}

var (
	pdOccupancyMutex sync.Mutex
	pdOccupancyStore pdOccupancySnapshot
)

// updatePdOccupancyStore replaces the store with a snapshot: all three are
// gauges. Called once per collection cycle by RunSockproxyMetrics.
func updatePdOccupancyStore(raw pdOccupancySnapshot) {
	pdOccupancyMutex.Lock()
	pdOccupancyStore = raw
	pdOccupancyMutex.Unlock()
}

var pdPrefillInflightDesc = prometheus.NewDesc(
	"loxilb_pd_prefill_inflight",
	"P/D admission units held on prefill endpoints, from admission until the request's cleanup, summed over the P/D pools. Not the engine's prefill jobs.",
	nil, nil,
)

var pdDecodeInflightDesc = prometheus.NewDesc(
	"loxilb_pd_decode_inflight",
	"P/D admission units held on decode endpoints, from admission until the request's cleanup, summed over the P/D pools.",
	nil, nil,
)

var pdParkedConnectionsDesc = prometheus.NewDesc(
	"loxilb_pd_parked_connections",
	"Client connections parked on a prefill endpoint's admission queue (no P/D unit was free), summed over the P/D pools. The capacity gate's queue is loxilb_ai_admission_queued.",
	nil, nil,
)

// pdOccupancyCollector emits the occupancy families from the store on every
// scrape.
type pdOccupancyCollector struct{}

// Describe implements prometheus.Collector.
func (pdOccupancyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- pdPrefillInflightDesc
	ch <- pdDecodeInflightDesc
	ch <- pdParkedConnectionsDesc
}

// Collect implements prometheus.Collector.
func (pdOccupancyCollector) Collect(ch chan<- prometheus.Metric) {
	pdOccupancyMutex.Lock()
	s := pdOccupancyStore
	pdOccupancyMutex.Unlock()

	ch <- prometheus.MustNewConstMetric(pdPrefillInflightDesc, prometheus.GaugeValue, float64(s.prefill))
	ch <- prometheus.MustNewConstMetric(pdDecodeInflightDesc, prometheus.GaugeValue, float64(s.decode))
	ch <- prometheus.MustNewConstMetric(pdParkedConnectionsDesc, prometheus.GaugeValue, float64(s.parked))
}

func init() {
	datapathRegisterer{}.MustRegister(pdOccupancyCollector{})
}
