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
// Pools: how many the proxy holds, how many it has freed
// ============================================================================
// A pool is the data plane's state of one rule's endpoint set
// (loxilb-ebpf/common/sockproxy_pool.h). A deleted pool is freed once the
// last connection, HTTP/2 session or capacity permit that holds it lets go,
// after a grace period. Under rule churn, live returns to the number of
// rules once the connections of the deleted ones are gone, and freed counts
// every pool that went; a live count that only grows is a pool kept by a
// holder that never let go.
// ============================================================================

// poolSnapshot is the pool state taken from one C snapshot.
type poolSnapshot struct {
	live  uint64
	freed uint64
}

// mergePool merges next into prev: the freed counter does not go backwards,
// the live gauge is taken as read.
func mergePool(prev, next poolSnapshot) poolSnapshot {
	return poolSnapshot{live: next.live, freed: maxU64(prev.freed, next.freed)}
}

var (
	poolStoreMutex sync.Mutex
	poolStore      poolSnapshot
)

// updatePoolStore merges a raw snapshot into the store. Called once per
// collection cycle by RunSockproxyMetrics.
func updatePoolStore(raw poolSnapshot) {
	poolStoreMutex.Lock()
	poolStore = mergePool(poolStore, raw)
	poolStoreMutex.Unlock()
}

var poolsLiveDesc = prometheus.NewDesc(
	"loxilb_proxy_pools_live",
	"Rule pools the proxy holds: one per rule, plus each deleted rule's pool until the last connection, HTTP/2 session or capacity permit that holds it is gone.",
	nil, nil,
)

var poolsFreedDesc = prometheus.NewDesc(
	"loxilb_proxy_pools_freed_total",
	"Rule pools freed after their rule was deleted and their last holder let go.",
	nil, nil,
)

// poolCollector emits the pool families from the store on every scrape.
type poolCollector struct{}

// Describe implements prometheus.Collector.
func (poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- poolsLiveDesc
	ch <- poolsFreedDesc
}

// Collect implements prometheus.Collector.
func (poolCollector) Collect(ch chan<- prometheus.Metric) {
	poolStoreMutex.Lock()
	s := poolStore
	poolStoreMutex.Unlock()

	ch <- prometheus.MustNewConstMetric(poolsLiveDesc, prometheus.GaugeValue, float64(s.live))
	ch <- prometheus.MustNewConstMetric(poolsFreedDesc, prometheus.CounterValue, float64(s.freed))
}

func init() {
	datapathRegisterer{}.MustRegister(poolCollector{})
}
