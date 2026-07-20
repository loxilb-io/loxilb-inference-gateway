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

// Package aimetrics is the shared vLLM /metrics collector core, extracted
// verbatim from pkg/loxinet/ai_vllm_scraper.go (CTRL-02 substrate).
//
// It is PURE Go: no cgo, no pkg/loxinet imports — a CGO_ENABLED=0 binary
// (the global AI controller) consumes exactly the same poll loop, in-flight
// dedup, LastUpdate staleness stamping, and label-parsing hardening that
// loxilb's data-plane scraper uses, instead of re-deriving them.
//
// Two-decoder split (locked, 96-PATTERNS):
//   - lineparser.go — the narrow 3-series parser (loxilb hot path,
//     behavior-identical to the pre-extraction scraper).
//   - expfmt.go — the full metric-family decoder on prometheus/common/expfmt
//     (controller-only; the loxilb shim must never switch to it).
package aimetrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Logger is the minimal leveled logging surface the poller needs. The
// loxilb shim adapts tk.LogIt to it (identical log lines/levels); the
// controller may plug its own. The default is a no-op — loxilib itself
// cannot be imported here because it does not compile on darwin or under
// CGO_ENABLED=0 consumers' cross-builds.
type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// maxScrapeBodyBytes bounds one scraped /metrics body (vLLM bodies are
// typically well under 1 MiB; 8 MiB tolerates very large fleets while keeping
// a hostile endpoint from streaming unbounded data).
const maxScrapeBodyBytes = 8 << 20

type nopLogger struct{}

func (nopLogger) Infof(string, ...interface{})  {}
func (nopLogger) Warnf(string, ...interface{})  {}
func (nopLogger) Debugf(string, ...interface{}) {}

// WorkerSample is one scrape result for one source (EP).
//
// NumRequestsRunning is declared for controller-side consumers; the narrow
// lineparser path does NOT populate it (the loxilb 3-series contract is
// unchanged) — controller consumers wanting it use DecodeFamilies (expfmt)
// or the Raw map when a future parser version supplies it.
type WorkerSample struct {
	NumRequestsWaiting uint32
	NumRequestsRunning uint32
	NumGPUBlocks       uint32
	GPUCacheUsagePerc  float64
	LastUpdate         time.Time
	Raw                map[string]float64
}

// Sink receives every successful scrape.
//
// Staleness contract (CTRL-02, folded EP-restart todo): the library ONLY
// stamps WorkerSample.LastUpdate — per-source staleness is the CONSUMER's
// job. A source whose LastUpdate has aged past the consumer's staleness
// window MUST be EXCLUDED from that consumer's normalization set, NEVER
// zero-filled: a zero-filled load/capacity for a merely-unreachable or
// just-restarted EP would poison relative scoring across the healthy
// sources (the EP-restart case — a restarting vLLM stops serving /metrics
// long before it stops being a real endpoint). OnSample is invoked from a
// per-EP scrape goroutine; implementations must be safe for concurrent
// calls with distinct epIdx values.
type Sink interface {
	OnSample(epIdx int, s WorkerSample)
}

// Poller polls vLLM /metrics endpoints on a fixed interval with per-EP
// in-flight dedup, and delivers parsed WorkerSamples to a Sink. It is the
// extracted Run/scrapeAll/scrapeOne skeleton of loxilb's VllmScraper.
type Poller struct {
	// endpoints indexes EP "ip:port" by EP index; empty entries are skipped
	// (allows sparse EP-index spaces from map-shaped callers).
	endpoints []string

	// interval between scrape cycles.
	interval time.Duration

	// client is the HTTP client with request timeout.
	client *http.Client

	// inFlight tracks which EP indices are currently being scraped.
	inFlight sync.Map

	// lifecycleMu guards cancel/stopped so a Stop racing (or preceding) Run
	// cannot lose the cancellation.
	lifecycleMu sync.Mutex

	// cancel stops the poller goroutine. Guarded by lifecycleMu.
	cancel context.CancelFunc

	// stopped records a Stop() that arrived before Run() installed cancel;
	// Run() then exits immediately. Guarded by lifecycleMu.
	stopped bool

	// sink receives every successful scrape.
	sink Sink

	// mergeLMCache, when true, ALSO parses lmcache:* families off the SAME
	// /metrics body (Pattern 1 piggyback, LMC-02) and merges them into
	// WorkerSample.Raw before delivery — no second scrape target. Default
	// false: the loxilb hot-path shim never enables it, so its narrow
	// 3-series scrape stays byte-identical (the body is streamed straight
	// into ParseVllmBody with no buffering, exactly as before).
	mergeLMCache bool

	// log is never nil (defaults to no-op).
	log Logger
}

// NewPoller creates a poller for the given vLLM endpoints. endpoints[i] is
// the "ip:port" of EP index i (empty string = skip that index). A
// non-positive interval defaults to 10s; the HTTP request timeout is 5s
// (both preserved from the original scraper).
func NewPoller(endpoints []string, interval time.Duration, sink Sink) *Poller {
	if interval <= 0 {
		interval = 10 * time.Second
	}

	return &Poller{
		endpoints: append([]string(nil), endpoints...),
		interval:  interval,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		sink: sink,
		log:  nopLogger{},
	}
}

// SetLogger installs a leveled logger (nil is ignored). Call before Run.
func (p *Poller) SetLogger(l Logger) {
	if l != nil {
		p.log = l
	}
}

// EnableLMCachePiggyback makes scrapeOne ALSO parse lmcache:* families off the
// SAME vLLM /metrics body (Pattern 1 piggyback, LMC-02) and merge them into the
// delivered WorkerSample.Raw — no second scrape target. Call before Run.
//
// This is OPT-IN and OFF by default: the loxilb data-plane shim never enables
// it, so its narrow-lineparser scrape path is untouched (byte-identical, no
// body buffering). Only the standalone controller enables it, where the small
// buffer+second-decode cost is acceptable for the KV-pressure/locality signals.
func (p *Poller) EnableLMCachePiggyback() { p.mergeLMCache = true }

// Run starts the poll loop. It blocks until ctx is cancelled. A Stop() that
// already happened (or happens concurrently) is honored: Run returns without
// scraping.
func (p *Poller) Run(ctx context.Context) {
	p.lifecycleMu.Lock()
	if p.stopped {
		p.lifecycleMu.Unlock()
		return
	}
	ctx, p.cancel = context.WithCancel(ctx)
	p.lifecycleMu.Unlock()

	n := 0
	for _, ep := range p.endpoints {
		if ep != "" {
			n++
		}
	}
	p.log.Infof("vLLM scraper: starting for %d endpoints (interval=%s)\n", n, p.interval)

	// Initial scrape immediately.
	p.scrapeAll(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.log.Infof("vLLM scraper: stopped\n")
			return
		case <-ticker.C:
			p.scrapeAll(ctx)
		}
	}
}

// Stop cancels the poller goroutine. Safe to call before, during, or after
// Run; a pre-Run Stop makes the later Run a no-op.
func (p *Poller) Stop() {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	p.stopped = true
	if p.cancel != nil {
		p.cancel()
	}
}

// scrapeAll iterates all endpoints and launches goroutines for those not in-flight.
func (p *Poller) scrapeAll(ctx context.Context) {
	for epIdx, addr := range p.endpoints {
		if addr == "" {
			continue // Sparse EP-index slot.
		}
		if _, loaded := p.inFlight.LoadOrStore(epIdx, true); loaded {
			continue // Previous scrape for this EP still running.
		}
		go func(idx int, endpoint string) {
			defer p.inFlight.Delete(idx)
			p.scrapeOne(ctx, idx, endpoint)
		}(epIdx, addr)
	}
}

// scrapeOne fetches /metrics from a single vLLM endpoint, parses the narrow
// 3-series set via the lineparser, stamps LastUpdate, and delivers the
// sample to the sink.
func (p *Poller) scrapeOne(ctx context.Context, epIdx int, endpoint string) {
	url := fmt.Sprintf("http://%s/metrics", endpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		p.log.Warnf("vLLM scraper: failed to create request for %s: %v\n", endpoint, err)
		return
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Debugf("vLLM scraper: %s unreachable: %v\n", endpoint, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.log.Warnf("vLLM scraper: %s returned HTTP %d\n", endpoint, resp.StatusCode)
		return
	}

	// Bound the scraped body: a misbehaving/hostile backend must not make the
	// scraper buffer or stream an unbounded response (metrics audit M-item).
	bodyReader := io.LimitReader(resp.Body, maxScrapeBodyBytes)

	if p.mergeLMCache {
		// Piggyback path (controller-only): buffer the body ONCE, decode both
		// the narrow vLLM 3-series and the lmcache:* families off it, and merge
		// the lmcache signals into WorkerSample.Raw. No second /metrics scrape.
		body, err := io.ReadAll(bodyReader)
		if err != nil {
			p.log.Debugf("vLLM scraper: %s body read failed: %v\n", endpoint, err)
			return
		}
		sample, found := ParseVllmBody(bytes.NewReader(body))
		if !found {
			p.log.Debugf("vLLM scraper: %s returned no recognized metrics\n", endpoint)
			return
		}
		if lm := ParseLMCacheBody(bytes.NewReader(body)); len(lm.Raw) > 0 {
			if sample.Raw == nil {
				sample.Raw = make(map[string]float64, len(lm.Raw))
			}
			for k, v := range lm.Raw {
				sample.Raw[k] = v
			}
		}
		sample.LastUpdate = time.Now()
		if p.sink != nil {
			p.sink.OnSample(epIdx, sample)
		}
		return
	}

	// Default path (loxilb hot path): stream straight into the narrow parser —
	// no buffering, no lmcache decode.
	sample, found := ParseVllmBody(bodyReader)
	if !found {
		p.log.Debugf("vLLM scraper: %s returned no recognized metrics\n", endpoint)
		return
	}

	sample.LastUpdate = time.Now()

	if p.sink != nil {
		p.sink.OnSample(epIdx, sample)
	}
}
