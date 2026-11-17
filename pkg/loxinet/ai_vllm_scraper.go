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

// ai_vllm_scraper.go — THIN SHIM over the shared pkg/aimetrics collector
// core (96-05 extraction, CTRL-02 substrate).
//
// The poll loop, in-flight dedup, LastUpdate stamping, and the narrow
// 3-series lineparser (incl. the num_gpu_blocks label tolerance)
// moved verbatim to pkg/aimetrics so the CGO_ENABLED=0 global AI controller
// can reuse them. What stays here is exactly the loxilb-side Sink: the three
// cgo bridge calls (queue depth + advertised KV capacity + decode KV-cache
// pressure) and the Go-side WorkerMetrics bookkeeping. Behavior-identical for
// loxilb: same series, same cgo sinks, same staleness stamping.
//
// Two-decoder split (locked): this shim consumes the NARROW lineparser via
// aimetrics.Poller — it must never switch to the controller-only
// full-family decoder (aimetrics.DecodeFamilies).
package loxinet

/*
#include <stdint.h>

extern void llb_ai_update_ep_queue_depth(uint32_t service_ip, uint16_t service_port,
                                         int ep_index, uint32_t queued_requests);
extern void llb_ai_update_ep_capacity(uint32_t service_ip, uint16_t service_port,
                                      int ep_index, uint32_t num_gpu_blocks);
extern void llb_ai_update_ep_kv_usage(uint32_t service_ip, uint16_t service_port,
                                      int ep_index, uint32_t kv_usage_pct);
*/
import "C"

import (
	"context"
	"net"
	"time"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// VllmScraper polls vLLM /metrics endpoints to extract queue depth and GPU cache
// utilization metrics for queue-depth-aware Tier 2 EP selection (COMP-07).
// It is a shim over aimetrics.Poller with a cgo-backed Sink.
type VllmScraper struct {
	// endpoints maps EP index to "ip:port" for each vLLM backend.
	endpoints map[int]string

	// Service identification for C-side queue depth updates.
	serviceIP   uint32
	servicePort uint16

	// updateFn stores scraped metrics into the Go-side WorkerMetrics map.
	updateFn func(endpointIP string, metrics WorkerMetrics)

	// poller is the shared collector core (poll loop + dedup + lineparser).
	poller *aimetrics.Poller
}

// tkScraperLogger adapts tk.LogIt to the aimetrics.Logger surface so the
// extracted core keeps emitting the identical log lines/levels it did
// before the move (pkg/aimetrics itself cannot import loxilib — it must
// stay darwin/CGO_ENABLED=0 buildable for the controller).
type tkScraperLogger struct{}

func (tkScraperLogger) Infof(format string, args ...interface{}) {
	tk.LogIt(tk.LogInfo, format, args...)
}

func (tkScraperLogger) Warnf(format string, args ...interface{}) {
	tk.LogIt(tk.LogWarning, format, args...)
}

func (tkScraperLogger) Debugf(format string, args ...interface{}) {
	tk.LogIt(tk.LogDebug, format, args...)
}

// NewVllmScraper creates a scraper for the given vLLM endpoints.
//
// Parameters:
//
//	endpoints:   map of EP index to "ip:port" address
//	serviceIP:   VIP for the LB service (network byte order)
//	servicePort: port for the LB service (host byte order)
//	interval:    scrape interval (default 10s)
//	updateFn:    callback to update WorkerMetrics in the Go-side sync.Map
func NewVllmScraper(endpoints map[int]string, serviceIP uint32, servicePort uint16,
	interval time.Duration, updateFn func(string, WorkerMetrics)) *VllmScraper {

	s := &VllmScraper{
		endpoints:   endpoints,
		serviceIP:   serviceIP,
		servicePort: servicePort,
		updateFn:    updateFn,
	}

	// Densify the EP-index map into the slice shape the shared poller
	// takes; empty slots (sparse indices) are skipped by the poller.
	maxIdx := -1
	for idx := range endpoints {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	eps := make([]string, maxIdx+1)
	for idx, addr := range endpoints {
		if idx >= 0 {
			eps[idx] = addr
		}
	}

	s.poller = aimetrics.NewPoller(eps, interval, (*vllmScraperSink)(s))
	s.poller.SetLogger(tkScraperLogger{})
	return s
}

// sameEndpoints reports whether the scraper polls exactly these endpoints.
func (s *VllmScraper) sameEndpoints(eps map[int]string) bool {
	if len(eps) != len(s.endpoints) {
		return false
	}
	for i, a := range eps {
		if s.endpoints[i] != a {
			return false
		}
	}
	return true
}

// Run starts the scraper loop. It blocks until ctx is cancelled.
func (s *VllmScraper) Run(ctx context.Context) {
	s.poller.Run(ctx)
}

// Stop cancels the scraper goroutine.
func (s *VllmScraper) Stop() {
	s.poller.Stop()
}

// vllmScraperSink is the loxinet-side aimetrics.Sink: it performs exactly
// the two pre-extraction cgo bridge calls per sample plus the decode
// KV-pressure call, and the Go-side WorkerMetrics bookkeeping. It is invoked
// from per-EP scrape goroutines; the cgo bridge writers are atomics on the C
// side.
type vllmScraperSink VllmScraper

// pdKvUsageUnknown is the cgo contract's "not reported" value for
// llb_ai_update_ep_kv_usage (PD_KV_USAGE_UNKNOWN in sockproxy.h). The C bridge
// stores it as the zero-filled "unknown" encoding, so an EP whose /metrics
// carries no usage family scores neutral in decode selection, exactly like an
// EP the scraper has never reached.
const pdKvUsageUnknown = 0xFF

// pdKvUsagePct derives the decode KV-pressure argument of the bridge from a
// parsed sample. Presence, not value, tells "0 % reported" from "unknown": the
// lineparser leaves GPUCacheUsagePerc at 0 when no usage family was scraped,
// and only a family that was actually seen is a key of Raw. Present: the mean
// ratio as a whole percentage, truncated like WorkerMetrics.KVCacheUsagePerc
// and clamped to 0..100. Absent: pdKvUsageUnknown.
func pdKvUsagePct(smp aimetrics.WorkerSample) uint32 {
	_, kv := smp.Raw[aimetrics.FamilyKVCacheUsagePerc]
	_, gpu := smp.Raw[aimetrics.FamilyGPUCacheUsagePerc]
	_, tok := smp.Raw[aimetrics.FamilySGLangTokenUsage]
	if !kv && !gpu && !tok {
		return pdKvUsageUnknown
	}
	pct := smp.GPUCacheUsagePerc * 100
	if !(pct > 0) { // also NaN
		return 0
	}
	if pct >= 100 {
		return 100
	}
	return uint32(pct)
}

// kvUsageBridge is the seam between the sink and the cgo bridge: production
// code calls C.llb_ai_update_ep_kv_usage; the unit test swaps in a recorder so
// the arguments (service key, EP index, percentage or 0xFF) can be asserted
// without a proxy table on the C side.
var kvUsageBridge = func(serviceIP uint32, svcPortNet uint16, epIdx int, pct uint32) {
	C.llb_ai_update_ep_kv_usage(C.uint32_t(serviceIP), C.uint16_t(svcPortNet),
		C.int(epIdx), C.uint32_t(pct))
}

// OnSample implements aimetrics.Sink.
func (k *vllmScraperSink) OnSample(epIdx int, smp aimetrics.WorkerSample) {
	endpoint := k.endpoints[epIdx]

	// Extract IP portion for WorkerMetrics key.
	epIP := endpoint
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		epIP = host
	}

	metrics := WorkerMetrics{
		EndpointIP:       endpoint,
		QueuedRequests:   smp.NumRequestsWaiting,
		KVCacheUsagePerc: uint32(smp.GPUCacheUsagePerc * 100),
		NumGPUBlocks:     smp.NumGPUBlocks, // advertised capacity signal
		LastUpdate:       smp.LastUpdate,
	}

	// Update Go-side metrics.
	if k.updateFn != nil {
		k.updateFn(epIP, metrics)
	}

	// The proxy key holds the service port in network byte order (every
	// proxyKey.xport builder uses tk.Htons), while servicePort is kept in host
	// order. Passing it unconverted matched no proxy entry, so neither store
	// below ever landed.
	svcPortNet := tk.Htons(k.servicePort)

	// Update C-side queue depth for Tier 2 scoring.
	C.llb_ai_update_ep_queue_depth(C.uint32_t(k.serviceIP), C.uint16_t(svcPortNet),
		C.int(epIdx), C.uint32_t(smp.NumRequestsWaiting))

	// C2: update C-side advertised KV capacity (num_gpu_blocks) so the
	// PROXY_SEL_GPU_AWARE prefill scorer can capacity-weight live load. Mirrors
	// the queue-depth store; 0 (not advertised) is stored as-is and clamped to 1
	// at read time (V5 — never divide-by-zero in the cap math).
	C.llb_ai_update_ep_capacity(C.uint32_t(k.serviceIP), C.uint16_t(svcPortNet),
		C.int(epIdx), C.uint32_t(smp.NumGPUBlocks))

	// A3 (P/D decode selection): this EP's KV-cache pressure, read by
	// pd_select_decode_excluding when LLB_PD_DECODE_KV_WEIGHT is set. Called
	// after the queue-depth bridge on purpose: that call owns the
	// last_update_ts stamp, so this value is exactly as fresh as the queue
	// depth beside it and one staleness guard covers both. 0xFF tells the C
	// side the sample carried no usage family (stored as "unknown", which
	// scores neutral), as opposed to a reported 0 %, which scores 0.
	kvUsageBridge(k.serviceIP, svcPortNet, epIdx, pdKvUsagePct(smp))
}

// OnScrapeResult implements the optional aimetrics.ResultSink, exporting the
// outcome of every scrape attempt as loxilb_ai_worker_scrape_total{result}.
//
// OnSample above is reached ONLY by a scrape that parsed, so on its own it
// leaves the failure states invisible: when an endpoint stops answering
// /metrics the pushes just stop, the datapath's staleness guard quietly
// substitutes a fleet average for the value nobody is refreshing, and nothing
// is exported to say selection is now running on a fill-in. This is the hook
// that makes that state alertable.
//
// epIdx/endpoint are deliberately not turned into labels -- see the counter's
// declaration for the cardinality argument.
func (k *vllmScraperSink) OnScrapeResult(_ int, _ string, result string) {
	prom.RecordWorkerScrape(result)
}
