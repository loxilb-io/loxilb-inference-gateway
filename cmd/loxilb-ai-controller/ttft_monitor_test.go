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

// ttft_monitor_test.go — TTFT-03 monitor behavior tables (TDD):
//  1. windowed P50 |rel err| ≤ threshold ⇒ α steps toward 1 (bounded ≤0.2)
//  2. P50 > 2× threshold ⇒ α steps toward 0 (bounded ≤0.2)
//  3. in between ⇒ hold
//  4. no observations (idle fleet) ⇒ hold — absence of evidence ≠ regime shift
//  5. full decay→neutral(0)→recovery trajectory: bounded steps, α ∈ [0,1],
//     exact neutrality at 0, gradual restoration
// plus the histogram-delta tracker (prime / idle / counter-reset) and the
// family extraction off a realistic vLLM text-exposition body.

package main

import (
	"math"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// obsWithRelErr builds one observation with a known |relative error|:
// predLog=0 ⇒ predicted 1.0s, observed = 1+relErr.
func obsWithRelErr(relErr float64) ttftObs {
	return ttftObs{PredLogTtft: 0, ObservedSec: 1 + relErr}
}

// windowWithP50 builds a 3-obs window whose P50 |rel err| is exactly p50.
func windowWithP50(p50 float64) []ttftObs {
	return []ttftObs{
		obsWithRelErr(p50 - 0.01),
		obsWithRelErr(p50),
		obsWithRelErr(p50 + 0.01),
	}
}

const ttftTestThr = 0.30

func almostEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestTtftMonitorDecayOnBreach: P50 > 2× threshold decays α by EXACTLY the
// bounded step (0.2) — glide, never snap.
func TestTtftMonitorDecayOnBreach(t *testing.T) {
	m := newTtftMonitor(ttftTestThr)
	if !almostEq(m.Alpha(), 1.0) {
		t.Fatalf("initial alpha = %v; want 1.0 (full confidence when armed)", m.Alpha())
	}
	got := m.Observe(windowWithP50(0.65)) // 0.65 > 2×0.30
	if !almostEq(got, 0.8) {
		t.Errorf("alpha after breach = %v; want 0.8 (bounded -0.2 step)", got)
	}
}

// TestTtftMonitorHoldBetween: threshold < P50 ≤ 2× threshold holds α.
func TestTtftMonitorHoldBetween(t *testing.T) {
	m := newTtftMonitor(ttftTestThr)
	m.Observe(windowWithP50(0.65)) // decay to 0.8 first
	got := m.Observe(windowWithP50(0.45))
	if !almostEq(got, 0.8) {
		t.Errorf("alpha in the hold band = %v; want 0.8 (hold)", got)
	}
	// Exactly 2× threshold is still the hold band (decay needs STRICTLY >).
	// Exactly-representable fixture: thr=0.25 (2× = 0.5 exact) and observed
	// 1.5s vs predicted 1.0s ⇒ |rel err| EXACTLY 0.5 (the 0.30-based fixture
	// lands at 0.600000000000000089 > 2×thr and would test decay instead).
	mb := newTtftMonitor(0.25)
	mb.Observe(windowWithP50(0.75)) // > 2×0.25 ⇒ decay to 0.8
	twoX := []ttftObs{
		{PredLogTtft: 0, ObservedSec: 1.5},
		{PredLogTtft: 0, ObservedSec: 1.5},
		{PredLogTtft: 0, ObservedSec: 1.5},
	}
	if got := mb.Observe(twoX); !almostEq(got, 0.8) {
		t.Errorf("alpha at exactly 2x thr = %v; want 0.8 (hold)", got)
	}
}

// TestTtftMonitorRecoveryStep: P50 ≤ threshold steps α toward 1, bounded.
func TestTtftMonitorRecoveryStep(t *testing.T) {
	m := newTtftMonitor(ttftTestThr)
	m.Observe(windowWithP50(0.65)) // 0.8
	m.Observe(windowWithP50(0.65)) // 0.6
	got := m.Observe(windowWithP50(0.10))
	if !almostEq(got, 0.8) {
		t.Errorf("alpha after good window = %v; want 0.8 (bounded +0.2 step)", got)
	}
	// Capped at 1.0.
	m.Observe(windowWithP50(0.10))
	got = m.Observe(windowWithP50(0.05))
	if !almostEq(got, 1.0) {
		t.Errorf("alpha above cap = %v; want 1.0 (clamped)", got)
	}

	// At the boundary: P50 == threshold counts as good (≤ is inclusive).
	// Exactly-representable fixture: thr=0.25 and observed 1.25s vs predicted
	// 1.0s ⇒ |rel err| is EXACTLY 0.25 in binary float (1+0.30 fixtures land
	// at 0.30000000000000004 and would silently test the hold band instead).
	mb := newTtftMonitor(0.25)
	mb.Observe(windowWithP50(0.75)) // > 2×0.25 ⇒ decay to 0.8
	boundary := []ttftObs{
		{PredLogTtft: 0, ObservedSec: 1.25},
		{PredLogTtft: 0, ObservedSec: 1.25},
		{PredLogTtft: 0, ObservedSec: 1.25},
	}
	if got := mb.Observe(boundary); !almostEq(got, 1.0) {
		t.Errorf("alpha at P50==thr = %v; want 1.0 (≤ threshold steps up)", got)
	}
}

// TestTtftMonitorHoldOnNoData: an empty window (idle fleet) holds α at any
// point of the ladder — absence of evidence is not a regime shift.
func TestTtftMonitorHoldOnNoData(t *testing.T) {
	m := newTtftMonitor(ttftTestThr)
	if got := m.Observe(nil); !almostEq(got, 1.0) {
		t.Errorf("alpha after empty window at 1.0 = %v; want 1.0 (hold)", got)
	}
	m.Observe(windowWithP50(0.65)) // 0.8
	if got := m.Observe([]ttftObs{}); !almostEq(got, 0.8) {
		t.Errorf("alpha after empty window mid-ladder = %v; want 0.8 (hold)", got)
	}
}

// TestTtftMonitorTrajectory drives the full decay→neutral→recovery arc:
// every step bounded by 0.2, α always in [0,1], EXACT neutrality (0) under
// sustained breach, and gradual restoration to full confidence.
func TestTtftMonitorTrajectory(t *testing.T) {
	m := newTtftMonitor(ttftTestThr)
	prev := m.Alpha()

	wantDecay := []float64{0.8, 0.6, 0.4, 0.2, 0.0, 0.0}
	for i, want := range wantDecay {
		got := m.Observe(windowWithP50(0.9))
		if !almostEq(got, want) {
			t.Fatalf("decay step %d: alpha = %v; want %v", i, got, want)
		}
		if math.Abs(got-prev) > ttftAlphaMaxStep+1e-9 {
			t.Fatalf("decay step %d: |Δα| = %v > %v (must glide)", i, math.Abs(got-prev), ttftAlphaMaxStep)
		}
		if got < 0 || got > 1 {
			t.Fatalf("decay step %d: alpha %v outside [0,1]", i, got)
		}
		prev = got
	}
	if !almostEq(m.Alpha(), 0.0) {
		t.Fatalf("sustained breach did not reach EXACT neutrality: alpha = %v", m.Alpha())
	}

	wantRecover := []float64{0.2, 0.4, 0.6, 0.8, 1.0, 1.0}
	for i, want := range wantRecover {
		got := m.Observe(windowWithP50(0.1))
		if !almostEq(got, want) {
			t.Fatalf("recovery step %d: alpha = %v; want %v", i, got, want)
		}
		if math.Abs(got-prev) > ttftAlphaMaxStep+1e-9 {
			t.Fatalf("recovery step %d: |Δα| = %v > %v (must glide)", i, math.Abs(got-prev), ttftAlphaMaxStep)
		}
		prev = got
	}
}

// TestTtftMonitorPredErr locks observability export: LastErr
// reports the last non-empty window's P50/P90 |relative error| and stays
// unavailable (ok=false) until evidence exists.
func TestTtftMonitorPredErr(t *testing.T) {
	m := newTtftMonitor(ttftTestThr)
	if _, _, ok := m.LastErr(); ok {
		t.Errorf("LastErr ok=true before any window")
	}
	// |rel err| set {0.1, 0.2, 0.3, 0.4, 0.5}: P50 = 0.3, P90 = 0.5.
	window := []ttftObs{
		obsWithRelErr(0.1), obsWithRelErr(0.2), obsWithRelErr(0.3),
		obsWithRelErr(0.4), obsWithRelErr(0.5),
	}
	m.Observe(window)
	p50, p90, ok := m.LastErr()
	if !ok {
		t.Fatalf("LastErr ok=false after a non-empty window")
	}
	if !almostEq(p50, 0.3) || !almostEq(p90, 0.5) {
		t.Errorf("LastErr = (%v, %v); want (0.3, 0.5)", p50, p90)
	}
	// UNDER-prediction is an error too: observed 0.5s vs predicted 1.0s ⇒ 0.5.
	m2 := newTtftMonitor(ttftTestThr)
	m2.Observe([]ttftObs{{PredLogTtft: 0, ObservedSec: 0.5}})
	p50, _, _ = m2.LastErr()
	if !almostEq(p50, 0.5) {
		t.Errorf("under-prediction |rel err| = %v; want 0.5 (absolute)", p50)
	}
	// An empty window must NOT clobber the last evidence.
	m.Observe(nil)
	if p50b, _, okb := m.LastErr(); !okb || !almostEq(p50b, 0.3) {
		t.Errorf("empty window clobbered LastErr: (%v, %v)", p50b, okb)
	}
}

// TestTtftHistDelta locks the delta tracker: first sighting PRIMES (no
// observation), a positive delta yields the window mean, a zero count delta
// yields nothing (idle ≠ evidence), and a counter RESET (vLLM restart)
// re-primes silently instead of emitting a bogus negative mean.
func TestTtftHistDelta(t *testing.T) {
	d := newTtftHistDelta()

	if _, ok := d.Observe("10.0.0.5:8100", 10.0, 20); ok {
		t.Errorf("first sighting produced an observation; want prime-only")
	}
	mean, ok := d.Observe("10.0.0.5:8100", 16.0, 30)
	if !ok || !almostEq(mean, 0.6) {
		t.Errorf("delta = (%v, %v); want (0.6, true) — (16-10)/(30-20)", mean, ok)
	}
	if _, ok := d.Observe("10.0.0.5:8100", 16.0, 30); ok {
		t.Errorf("zero count delta produced an observation; want none (idle window)")
	}
	// Counter reset: cumulative values went DOWN ⇒ re-prime, no observation.
	if _, ok := d.Observe("10.0.0.5:8100", 1.0, 2); ok {
		t.Errorf("counter reset produced an observation; want silent re-prime")
	}
	mean, ok = d.Observe("10.0.0.5:8100", 3.0, 4)
	if !ok || !almostEq(mean, 1.0) {
		t.Errorf("post-reset delta = (%v, %v); want (1.0, true) — (3-1)/(4-2)", mean, ok)
	}
}

// TestQuantileAbs locks the nearest-rank percentile helper.
func TestQuantileAbs(t *testing.T) {
	vals := []float64{0.5, 0.1, 0.3, 0.2, 0.4} // unsorted on purpose
	if got := quantileAbs(vals, 0.5); !almostEq(got, 0.3) {
		t.Errorf("q50 = %v; want 0.3", got)
	}
	if got := quantileAbs(vals, 0.9); !almostEq(got, 0.5) {
		t.Errorf("q90 = %v; want 0.5", got)
	}
	if got := quantileAbs([]float64{0.7}, 0.5); !almostEq(got, 0.7) {
		t.Errorf("single-value q50 = %v; want 0.7", got)
	}
}

// TestTtftHistFromFamilies locks the family extraction off a realistic vLLM
// v0.17.0 text-exposition body (histogram sum/count via the sanctioned
// DecodeFamilies path — never hand-rolled).
func TestTtftHistFromFamilies(t *testing.T) {
	body := `# HELP vllm:num_requests_waiting Number of requests waiting.
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting{model_name="m"} 3.0
# HELP vllm:time_to_first_token_seconds Histogram of time to first token in seconds.
# TYPE vllm:time_to_first_token_seconds histogram
vllm:time_to_first_token_seconds_bucket{model_name="m",le="0.5"} 20
vllm:time_to_first_token_seconds_bucket{model_name="m",le="+Inf"} 25
vllm:time_to_first_token_seconds_sum{model_name="m"} 12.5
vllm:time_to_first_token_seconds_count{model_name="m"} 25
`
	fams, err := aimetrics.DecodeFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	sum, count, ok := ttftHistFromFamilies(fams)
	if !ok || !almostEq(sum, 12.5) || count != 25 {
		t.Errorf("ttftHistFromFamilies = (%v, %d, %v); want (12.5, 25, true)", sum, count, ok)
	}

	// Body without the TTFT family ⇒ ok=false (no observation, never zero).
	fams2, err := aimetrics.DecodeFamilies(strings.NewReader(
		"# TYPE vllm:num_requests_waiting gauge\nvllm:num_requests_waiting 1.0\n"))
	if err != nil {
		t.Fatalf("decode2: %v", err)
	}
	if _, _, ok := ttftHistFromFamilies(fams2); ok {
		t.Errorf("absent TTFT family reported ok=true; want false")
	}
}
