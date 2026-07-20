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
// 3-series lineparser (incl. the T-81-02-02 num_gpu_blocks label tolerance)
// moved verbatim to pkg/aimetrics so the CGO_ENABLED=0 global AI controller
// can reuse them. What stays here is exactly the loxilb-side Sink: the two
// cgo bridge calls (queue depth + advertised KV capacity) and the Go-side
// WorkerMetrics bookkeeping. Behavior-identical for loxilb: same series,
// same cgo sinks, same staleness stamping.
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
*/
import "C"

import (
	"context"
	"net"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aimetrics"
	tk "github.com/loxilb-io/loxilib"
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
//	servicePort: port for the LB service
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

// Run starts the scraper loop. It blocks until ctx is cancelled.
func (s *VllmScraper) Run(ctx context.Context) {
	s.poller.Run(ctx)
}

// Stop cancels the scraper goroutine.
func (s *VllmScraper) Stop() {
	s.poller.Stop()
}

// vllmScraperSink is the loxinet-side aimetrics.Sink: it performs exactly
// the two pre-extraction cgo bridge calls per sample, plus the Go-side
// WorkerMetrics bookkeeping. It is invoked from per-EP scrape goroutines;
// the cgo bridge writers are atomics on the C side.
type vllmScraperSink VllmScraper

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

	// Update C-side queue depth for Tier 2 scoring.
	C.llb_ai_update_ep_queue_depth(C.uint32_t(k.serviceIP), C.uint16_t(k.servicePort),
		C.int(epIdx), C.uint32_t(smp.NumRequestsWaiting))

	// C2: update C-side advertised KV capacity (num_gpu_blocks) so the
	// PROXY_SEL_GPU_AWARE prefill scorer can capacity-weight live load. Mirrors
	// the queue-depth store; 0 (not advertised) is stored as-is and clamped to 1
	// at read time (V5 — never divide-by-zero in the cap math).
	C.llb_ai_update_ep_capacity(C.uint32_t(k.serviceIP), C.uint16_t(k.servicePort),
		C.int(epIdx), C.uint32_t(smp.NumGPUBlocks))
}
