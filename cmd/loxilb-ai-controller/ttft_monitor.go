/*
 * Copyright (c) 2026 LoxiLB Authors
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

// ttft_monitor.go — the TTFT-03 live prediction-error monitor + α_ttft
// confidence decay ("online confidence decay" half).
//
// Each epoch the monitor compares the model's predicted log-TTFT against the
// server-side vllm:time_to_first_token histogram DELTA per EP (the window's
// mean observed TTFT). : this server-side signal is DIAGNOSTIC-grade —
// client-side aiperf remains the offline GATE truth; the monitor only needs
// regime-SHIFT detection, and histograms are what the controller can see
// live. α glides (bounded steps, never snaps) toward 0 on sustained breach
// and back toward 1 on recovery; the engine multiplies the TTFT term by α,
// so α=0 ⇒ the term is exactly neutral (TTFT-03).
//
// α update rule (per epoch, over the window's P50 |relative error| where
// relative error = |observed/exp(predicted) − 1|, the SAME metric shape the
// offline Gate 1 pre-registered):
//   - P50 ≤ threshold        ⇒ α steps toward 1 (recovery)
//   - P50 > 2 × threshold    ⇒ α steps toward 0 (regime shift)
//   - in between             ⇒ hold (hysteresis band)
//   - no observations        ⇒ hold — an idle fleet is absence of evidence,
//                              never a regime shift
// Steps are bounded (≤ ttftAlphaMaxStep per epoch) and α ∈ [0,1] always.

package main

import (
	"context"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// ttftObs is one EP's window observation: the model's predicted log-TTFT
// (from this epoch's feature vector) vs the observed mean TTFT (seconds)
// from the server histogram delta over the same window.
type ttftObs struct {
	PredLogTtft float64 // engine model prediction (log seconds)
	ObservedSec float64 // histogram-delta mean TTFT (seconds)
}

const (
	// ttftAlphaMaxStep bounds |Δα| per epoch — glide, never snap
	// undamped-jump conviction applies to confidence too).
	ttftAlphaMaxStep = 0.2
	// ttftDefaultP50Thr is the fallback P50 |relative error| threshold when
	// the coefficients file records no gate_thresholds.p50_rel_err (the A4
	// pre-registered default).
	ttftDefaultP50Thr = 0.30
	// ttftAlphaSnapEps snaps float-accumulation dust to the exact bounds so
	// "fully decayed" is EXACTLY 0 (the engine's neutral multiply) and full
	// confidence is exactly 1.
	ttftAlphaSnapEps = 1e-9
)

// ttftMonitor is the pure α_ttft state machine (fake-clock/table testable —
// no goroutines, no I/O; the scrape lives in ttftObservedSource).
type ttftMonitor struct {
	alpha   float64
	thr     float64
	lastP50 float64
	lastP90 float64
	hasErr  bool
}

// newTtftMonitor starts at FULL confidence (α=1.0: the model passed its
// offline gates to be armed at all — decay needs live evidence). p50Thr ≤ 0
// falls back to the pre-registered default 0.30.
func newTtftMonitor(p50Thr float64) *ttftMonitor {
	if p50Thr <= 0 {
		p50Thr = ttftDefaultP50Thr
	}
	return &ttftMonitor{alpha: 1.0, thr: p50Thr}
}

// Observe folds one window of observations into α and returns the new α.
// Degenerate observations (non-finite, negative observed) are dropped —
// hostile input is not evidence in either direction.
func (m *ttftMonitor) Observe(window []ttftObs) float64 {
	errs := make([]float64, 0, len(window))
	for _, o := range window {
		pred := math.Exp(o.PredLogTtft)
		if pred <= 0 || math.IsInf(pred, 0) || math.IsNaN(pred) ||
			o.ObservedSec < 0 || math.IsInf(o.ObservedSec, 0) || math.IsNaN(o.ObservedSec) {
			continue
		}
		errs = append(errs, math.Abs(o.ObservedSec/pred-1))
	}
	if len(errs) == 0 {
		return m.alpha // hold: absence of evidence ≠ regime shift
	}
	m.lastP50 = quantileAbs(errs, 0.5)
	m.lastP90 = quantileAbs(errs, 0.9)
	m.hasErr = true

	switch {
	case m.lastP50 <= m.thr: // healthy window ⇒ restore confidence gradually
		m.alpha += ttftAlphaMaxStep
	case m.lastP50 > 2*m.thr: // regime shift ⇒ decay toward neutral
		m.alpha -= ttftAlphaMaxStep
	}
	// Clamp + snap the bounds exact (α=0 must be EXACT neutrality).
	if m.alpha < ttftAlphaSnapEps {
		m.alpha = 0
	}
	if m.alpha > 1-ttftAlphaSnapEps {
		m.alpha = 1
	}
	return m.alpha
}

// Alpha returns the current confidence factor.
func (m *ttftMonitor) Alpha() float64 { return m.alpha }

// LastErr returns the last window's P50/P90 |relative error| (ok=false
// until a non-empty window has been observed; an empty window never
// clobbers prior evidence).
func (m *ttftMonitor) LastErr() (p50, p90 float64, ok bool) {
	return m.lastP50, m.lastP90, m.hasErr
}

// quantileAbs returns the q-quantile of vals by the nearest-rank method
// (the offline gate battery's convention). vals is not mutated.
func quantileAbs(vals []float64, q float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	idx := int(math.Ceil(q*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

// histPoint is one EP's cumulative TTFT histogram reading.
type histPoint struct {
	sum   float64
	count uint64
}

// ttftHistDelta turns cumulative per-EP histogram readings into windowed
// mean observations. First sighting of an EP PRIMES it (no observation);
// a zero count delta yields no observation (idle window ≠ evidence); a
// NEGATIVE delta (vLLM restart reset the counter) re-primes silently — a
// restart must never fabricate a bogus negative/huge mean.
type ttftHistDelta struct {
	prev map[string]histPoint
}

func newTtftHistDelta() *ttftHistDelta {
	return &ttftHistDelta{prev: make(map[string]histPoint)}
}

// Observe folds one cumulative reading for ep and returns the window mean
// TTFT when a valid delta exists.
func (d *ttftHistDelta) Observe(ep string, sum float64, count uint64) (mean float64, ok bool) {
	p, seen := d.prev[ep]
	d.prev[ep] = histPoint{sum: sum, count: count}
	if !seen {
		return 0, false // prime
	}
	if count < p.count || sum < p.sum {
		return 0, false // counter reset (EP restart) ⇒ silent re-prime
	}
	dc := count - p.count
	if dc == 0 {
		return 0, false // idle window ⇒ no evidence
	}
	return (sum - p.sum) / float64(dc), true
}

// ttftHistFamily is the vLLM TTFT histogram family (v0.17.0 name). Exact
// match (metrics audit H-21/F5): the old prefix match could claim a
// different family that merely shares the prefix (e.g. a future
// vllm:time_to_first_token_ms) and silently mix units.
const ttftHistFamily = "vllm:time_to_first_token_seconds"

// ttftHistFromFamilies extracts the TTFT histogram's cumulative sum/count
// off a decoded family map (the sanctioned DecodeFamilies path — never a
// hand-rolled histogram parse). Children are SUMMED (metrics audit H-21: a
// data-parallel vLLM server exports one child per engine — Metric()[0]
// under-counted DP>1 fleets). ok=false when the family is absent
// or carries no histogram — no observation, never a trusted zero.
func ttftHistFromFamilies(fams map[string]*dto.MetricFamily) (sum float64, count uint64, ok bool) {
	mf, found := fams[ttftHistFamily]
	if !found || mf.GetType() != dto.MetricType_HISTOGRAM {
		return 0, 0, false
	}
	for _, m := range mf.GetMetric() {
		h := m.GetHistogram()
		if h == nil {
			continue
		}
		sum += h.GetSampleSum()
		count += h.GetSampleCount()
		ok = true
	}
	return sum, count, ok
}

// ttftObservedSource scrapes the per-EP TTFT histograms (controller-only
// full-family decode — the documented DecodeFamilies use case) and feeds
// the delta tracker. Only constructed when a coefficients model is loaded:
// default-OFF ⇒ zero extra scrape traffic. Called synchronously from the
// epoch loop (no standing goroutines); the per-window scatter-gather is
// bounded by the 3s client timeout.
type ttftObservedSource struct {
	targets map[string]string // ip -> "ip:port"
	client  *http.Client
	delta   *ttftHistDelta
}

func newTtftObservedSource(targets map[string]string) *ttftObservedSource {
	return &ttftObservedSource{
		targets: targets,
		client:  &http.Client{Timeout: 3 * time.Second},
		delta:   newTtftHistDelta(),
	}
}

// WindowMeans scrapes every target once and returns ip -> window-mean TTFT
// (seconds) for EPs with a valid histogram delta this window. Unreachable
// or family-less EPs simply contribute no observation (the monitor holds).
func (s *ttftObservedSource) WindowMeans(ctx context.Context) map[string]float64 {
	type reading struct {
		ip    string
		sum   float64
		count uint64
		ok    bool
	}
	ch := make(chan reading, len(s.targets))
	var wg sync.WaitGroup
	for ip, addr := range s.targets {
		wg.Add(1)
		go func(ip, addr string) {
			defer wg.Done()
			sum, count, ok := s.scrapeOne(ctx, addr)
			ch <- reading{ip: ip, sum: sum, count: count, ok: ok}
		}(ip, addr)
	}
	wg.Wait()
	close(ch)

	out := make(map[string]float64, len(s.targets))
	for r := range ch { // delta fed serially: the tracker needs no lock
		if !r.ok {
			continue
		}
		if mean, ok := s.delta.Observe(r.ip, r.sum, r.count); ok {
			out[r.ip] = mean
		}
	}
	return out
}

// scrapeOne fetches one EP's /metrics body and extracts the TTFT histogram.
func (s *ttftObservedSource) scrapeOne(ctx context.Context, addr string) (float64, uint64, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/metrics", nil)
	if err != nil {
		return 0, 0, false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, false
	}
	fams, err := aimetrics.DecodeFamilies(resp.Body)
	if err != nil {
		return 0, 0, false
	}
	return ttftHistFromFamilies(fams)
}
