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

package engine

import (
	"reflect"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

var testNow = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

// TestEngineConfigLMCacheDefaults: a zero-valued EngineConfig withDefaults
// yields the default-OFF LMCache contract — LmcCostEnabled false (⇒ engine
// byte-identical to) and the two locked defaults.
func TestEngineConfigLMCacheDefaults(t *testing.T) {
	got := EngineConfig{}.withDefaults()
	if got.LmcCostEnabled {
		t.Fatal("LmcCostEnabled must default false (default-OFF ⇒ ≡)")
	}
	if got.LmcMaxPts != DefaultLmcMaxPts {
		t.Fatalf("LmcMaxPts default = %v, want %v", got.LmcMaxPts, DefaultLmcMaxPts)
	}
	if got.LmcStaleBudget != DefaultLmcStaleBudget {
		t.Fatalf("LmcStaleBudget default = %v, want %v", got.LmcStaleBudget, DefaultLmcStaleBudget)
	}
}

// TestEngineConfigLMCacheRoundTrip: an explicitly-set LMCache config round-trips
// unchanged through withDefaults (locked defaults never override a set value).
func TestEngineConfigLMCacheRoundTrip(t *testing.T) {
	in := EngineConfig{
		Now:            testNow,
		LmcCostEnabled: true,
		LmcMaxPts:      10,
		LmcStaleBudget: 30 * time.Second,
		LmcInvert:      true,
	}
	got := in.withDefaults()
	if !got.LmcCostEnabled {
		t.Fatal("LmcCostEnabled=true not preserved through withDefaults")
	}
	if got.LmcMaxPts != 10 {
		t.Fatalf("LmcMaxPts = %v, want 10 (set value preserved)", got.LmcMaxPts)
	}
	if got.LmcStaleBudget != 30*time.Second {
		t.Fatalf("LmcStaleBudget = %v, want 30s (set value preserved)", got.LmcStaleBudget)
	}
	if !got.LmcInvert {
		t.Fatal("LmcInvert=true not preserved through withDefaults")
	}
}

// fleetRegistry mirrors a reference GPU-testbed topology: 3x L4 prefill (prior 1.0),
// 1x L40S prefill (prior 2.0), 1x L40S decode.
func fleetRegistry() *Registry {
	return &Registry{
		Version:        1,
		Service:        ServiceDecl{Key: "10.0.0.12:9003:tcp", VIP: "10.0.0.12", Port: 9003},
		EpochPeriodSec: 10,
		Hosts: map[string]*Host{
			"10.0.0.7":  {GPUModel: "L4", HbmGb: 24, Role: RolePrefill, Port: 8100, EpIdx: 0, ExpectedNumGPUBlocks: 7408, ServingThroughputPrior: 1.0},
			"10.0.0.8":  {GPUModel: "L4", HbmGb: 24, Role: RolePrefill, Port: 8100, EpIdx: 1, ExpectedNumGPUBlocks: 7408, ServingThroughputPrior: 1.0},
			"10.0.0.9":  {GPUModel: "L4", HbmGb: 24, Role: RolePrefill, Port: 8100, EpIdx: 2, ExpectedNumGPUBlocks: 7408, ServingThroughputPrior: 1.0},
			"10.0.0.11": {GPUModel: "L40S", HbmGb: 48, Role: RolePrefill, Port: 8100, EpIdx: 3, ExpectedNumGPUBlocks: 32600, ServingThroughputPrior: 2.0},
			"10.0.0.10": {GPUModel: "L40S", HbmGb: 48, Role: RoleDecode, Port: 8200, EpIdx: 4, ExpectedNumGPUBlocks: 32600, ServingThroughputPrior: 2.0},
		},
	}
}

// trioRegistry is the homogeneous G1 parity arm: the L4 trio + decode.
func trioRegistry() *Registry {
	r := fleetRegistry()
	delete(r.Hosts, "10.0.0.11")
	return r
}

func freshSamples(r *Registry, at time.Time) map[string]Sourced {
	m := make(map[string]Sourced, len(r.Hosts))
	for ip := range r.Hosts {
		m[ip] = Sourced{IP: ip, Sample: aimetrics.WorkerSample{LastUpdate: at}}
	}
	return m
}

// TestComputeWeightsHomogeneousSteadyState: equal priors ⇒ all-100 raw; the
// dead-band holds 100 across epochs (zero churn at steady state).
func TestComputeWeightsHomogeneousSteadyState(t *testing.T) {
	reg := trioRegistry()
	cfg := EngineConfig{Now: testNow}
	samples := freshSamples(reg, testNow)

	var prev map[string]uint32
	for epoch := 0; epoch < 5; epoch++ {
		w, stats := ComputeWeights(reg, samples, prev, cfg)
		if stats.FleetStale {
			t.Fatal("fleet-stale on fresh samples")
		}
		for ip, got := range w {
			if got != 100 {
				t.Fatalf("epoch %d: %s = %d, want 100 (homogeneous)", epoch, ip, got)
			}
		}
		if len(w) != len(reg.Hosts) {
			t.Fatalf("epoch %d: %d weights, want %d", epoch, len(w), len(reg.Hosts))
		}
		prev = w
	}
}

// TestComputeWeightsDeadBandWiggle: with the default α=0.3/dead-band=5
// envelope, a ±4-point raw wiggle around the held weight never moves the
// output (churn guard).
func TestComputeWeightsDeadBandWiggle(t *testing.T) {
	cfg := EngineConfig{Now: testNow}.withDefaults()
	for _, raw := range []float64{96, 104, 98, 102, 100} {
		w, held, clamped := dampStep(raw, 100, cfg)
		if w != 100 || !held || clamped {
			t.Fatalf("raw %v from prev 100: got w=%d held=%v clamped=%v, want hold at 100",
				raw, w, held, clamped)
		}
	}
	// Sanity: a move past dead-band/α DOES escape the hold.
	if w, held, _ := dampStep(50, 100, cfg); held || w == 100 {
		t.Fatalf("raw 50 from prev 100 held (w=%d)", w)
	}
}

// TestComputeWeightsHeterogeneousConvergence: 2:1 priors converge to
// 100/50/50/50 within ceil(50/20)=3 epochs, each step respecting the ±20
// clamp. α=1.0 isolates the clamp arithmetic (the plan's step schedule
// 100→80→60→50); the default-α damped path is covered separately.
func TestComputeWeightsHeterogeneousConvergence(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{Now: testNow, EwmaAlpha: 1.0}
	samples := freshSamples(reg, testNow)

	wantL4 := []uint32{80, 60, 50} // per-epoch ±20-clamped walk from 100 to 50
	var prev map[string]uint32
	for epoch, want := range wantL4 {
		w, stats := ComputeWeights(reg, samples, prev, cfg)
		if stats.FleetStale {
			t.Fatal("fleet-stale on fresh samples")
		}
		for _, ip := range []string{"10.0.0.7", "10.0.0.8", "10.0.0.9"} {
			if w[ip] != want {
				t.Fatalf("epoch %d: %s = %d, want %d", epoch+1, ip, w[ip], want)
			}
			// Step bound: never more than 20 points per epoch.
			prevW := uint32(100)
			if prev != nil {
				prevW = prev[ip]
			}
			if diff := int(prevW) - int(w[ip]); diff > 20 || diff < -20 {
				t.Fatalf("epoch %d: %s stepped %d points (>20)", epoch+1, ip, diff)
			}
		}
		// The max-prior prefill EP holds raw weight 100 throughout.
		if w["10.0.0.11"] != 100 {
			t.Fatalf("epoch %d: L40S prefill = %d, want 100", epoch+1, w["10.0.0.11"])
		}
		// Single decode EP is always 100 (its own per-role normalization).
		if w["10.0.0.10"] != 100 {
			t.Fatalf("epoch %d: decode = %d, want 100", epoch+1, w["10.0.0.10"])
		}
		prev = w
	}
	// Epoch 4: converged — dead-band holds 50.
	w, _ := ComputeWeights(reg, samples, prev, cfg)
	if w["10.0.0.7"] != 50 {
		t.Fatalf("post-convergence epoch: L4 = %d, want 50 held", w["10.0.0.7"])
	}
}

// TestComputeWeightsDefaultAlphaConvergesMonotonically: under the default
// α=0.3 the L4 walk toward 50 is monotone non-increasing, never overshoots,
// and every step respects the ±20 clamp.
func TestComputeWeightsDefaultAlphaConvergesMonotonically(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{Now: testNow}
	samples := freshSamples(reg, testNow)

	var prev map[string]uint32
	last := uint32(100)
	for epoch := 0; epoch < 20; epoch++ {
		w, _ := ComputeWeights(reg, samples, prev, cfg)
		got := w["10.0.0.7"]
		if got > last {
			t.Fatalf("epoch %d: L4 rose %d→%d chasing a lower target", epoch+1, last, got)
		}
		if got < 50 {
			t.Fatalf("epoch %d: L4 overshot to %d (target 50)", epoch+1, got)
		}
		if step := int(last) - int(got); step > 20 {
			t.Fatalf("epoch %d: step %d > 20", epoch+1, step)
		}
		last = got
		prev = w
	}
	// EWMA-vs-prev + dead-band settles within DeadBand/α (5/0.3 ≈ 16.7
	// points) of the raw target.
	const settle = 50 + 17
	if last > settle {
		t.Fatalf("default-α walk settled at %d, want ≤ %d", last, settle)
	}
}

// TestComputeWeightsStaleSourceExcluded: a stale source is EXCLUDED from
// receiving a fresh computed weight and GLIDES damped toward neutral 100
// (never zero-filled); the fresh EPs' weights are unaffected by its
// exclusion.
//
// update: the pre-98 contract emitted a bare undamped out[ip]=100 on
// the stale edge — the exact jump VAL-03b convicted (one flapping EP swung
// siblings 50–100 pts). The stale edge now rides dampStep toward 100, so
// from a converged 50 under α=1.0 the first stale epoch clamps to 70.
func TestComputeWeightsStaleSourceExcluded(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{Now: testNow, EwmaAlpha: 1.0}
	converged := map[string]uint32{
		"10.0.0.7": 50, "10.0.0.8": 50, "10.0.0.9": 50,
		"10.0.0.11": 100, "10.0.0.10": 100,
	}

	// (a) LastUpdate aged past the 15s budget (soft-stale — still well
	// inside the 45s HardStaleBudget, so maxPrior is untouched).
	samples := freshSamples(reg, testNow)
	samples["10.0.0.8"] = Sourced{IP: "10.0.0.8",
		Sample: aimetrics.WorkerSample{LastUpdate: testNow.Add(-16 * time.Second)}}
	w, stats := ComputeWeights(reg, samples, converged, cfg)
	if stats.FleetStale {
		t.Fatal("fleet-stale with 4 fresh sources")
	}
	// damped glide 50 → 70 (±20 clamp toward neutral), NOT a bare 100.
	if w["10.0.0.8"] != 70 {
		t.Fatalf("stale EP = %d, want 70 (damped glide toward neutral, never zero)", w["10.0.0.8"])
	}
	if len(stats.StaleSources) != 1 || stats.StaleSources[0] != "10.0.0.8" {
		t.Fatalf("StaleSources = %v", stats.StaleSources)
	}
	if stats.FreshSources != 4 {
		t.Fatalf("FreshSources = %d, want 4", stats.FreshSources)
	}
	// Fresh EPs unaffected: L40S still max-prior 100, other L4s still 50.
	for ip, want := range map[string]uint32{
		"10.0.0.7": 50, "10.0.0.9": 50, "10.0.0.11": 100, "10.0.0.10": 100,
	} {
		if w[ip] != want {
			t.Fatalf("fresh %s = %d, want %d (normalization must be unaffected)", ip, w[ip], want)
		}
	}

	// (b) A missing sample (EP never scraped — the EP-restart case) is
	// hard-stale: excluded + the same damped glide toward neutral (:
	// 50 → 70 under the α=1.0 ±20 clamp, not a bare 100).
	samples = freshSamples(reg, testNow)
	delete(samples, "10.0.0.8")
	w, stats = ComputeWeights(reg, samples, converged, cfg)
	if w["10.0.0.8"] != 70 || len(stats.StaleSources) != 1 {
		t.Fatalf("missing sample: w=%d stale=%v", w["10.0.0.8"], stats.StaleSources)
	}

	// (c) Max-prior EP HARD-stale (sample absent ⇒ leaves maxPrior) ⇒
	// normalization recomputes over the remaining set (L4s become the
	// per-role max ⇒ raw 100). The hard-stale L40S itself was already at
	// neutral 100 ⇒ dead-band holds it there (glide is a no-op).
	samples = freshSamples(reg, testNow)
	delete(samples, "10.0.0.11")
	w, _ = ComputeWeights(reg, samples, converged, cfg)
	if w["10.0.0.11"] != 100 {
		t.Fatalf("stale L40S = %d, want neutral 100", w["10.0.0.11"])
	}
	// From prev 50 chasing raw 100 under the ±20 clamp: 50→70 this epoch.
	if w["10.0.0.7"] != 70 {
		t.Fatalf("L4 after max-prior exclusion = %d, want 70 (clamped toward 100)", w["10.0.0.7"])
	}
}

// TestComputeWeightsFleetStale: ALL sources stale ⇒ FleetStale, nil weights
// — the caller must emit NOTHING (CTRL-02 fleet-stale ⇒ stop).
func TestComputeWeightsFleetStale(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{Now: testNow}

	// Every LastUpdate aged out.
	stale := make(map[string]Sourced, len(reg.Hosts))
	for ip := range reg.Hosts {
		stale[ip] = Sourced{IP: ip,
			Sample: aimetrics.WorkerSample{LastUpdate: testNow.Add(-time.Minute)}}
	}
	w, stats := ComputeWeights(reg, stale, nil, cfg)
	if !stats.FleetStale {
		t.Fatal("FleetStale not set with every source stale")
	}
	if w != nil {
		t.Fatalf("weights emitted under fleet staleness: %v", w)
	}
	if len(stats.StaleSources) != len(reg.Hosts) {
		t.Fatalf("StaleSources = %v", stats.StaleSources)
	}

	// No samples at all ⇒ same stop.
	w, stats = ComputeWeights(reg, nil, nil, cfg)
	if !stats.FleetStale || w != nil {
		t.Fatalf("nil samples: FleetStale=%v w=%v", stats.FleetStale, w)
	}
}

// TestComputeWeightsOscillationDamping: a raw input alternating
// with amplitude 60 (40↔100) must come out with strictly smaller output
// alternation amplitude under the default envelope.
func TestComputeWeightsOscillationDamping(t *testing.T) {
	cfg := EngineConfig{Now: testNow}.withDefaults()
	raws := []float64{40, 100}
	prev := uint32(100)
	var outs []uint32
	for i := 0; i < 20; i++ {
		w, _, _ := dampStep(raws[i%2], prev, cfg)
		outs = append(outs, w)
		prev = w
	}
	// Measure the settled alternation amplitude over the last 10 outputs.
	lo, hi := outs[10], outs[10]
	for _, w := range outs[10:] {
		if w < lo {
			lo = w
		}
		if w > hi {
			hi = w
		}
	}
	inAmp := uint32(60)
	if outAmp := hi - lo; outAmp >= inAmp {
		t.Fatalf("output amplitude %d (range %d..%d) not damped below input %d — %v",
			outAmp, lo, hi, inAmp, outs)
	}
}

// TestComputeWeightsStepClampBoundary: exactness of the ±20 clamp
// (α=1 so the raw target hits the clamp directly, per the plan arithmetic).
func TestComputeWeightsStepClampBoundary(t *testing.T) {
	cfg := EngineConfig{Now: testNow, EwmaAlpha: 1.0}.withDefaults()

	// prev 100, target 40 ⇒ 80 next epoch (clamped).
	if w, _, clamped := dampStep(40, 100, cfg); w != 80 || !clamped {
		t.Fatalf("100→target40: w=%d clamped=%v, want 80,true", w, clamped)
	}
	// Upward symmetry: prev 40, target 100 ⇒ 60.
	if w, _, clamped := dampStep(100, 40, cfg); w != 60 || !clamped {
		t.Fatalf("40→target100: w=%d clamped=%v, want 60,true", w, clamped)
	}
	// Exactly-20 move passes unclamped.
	if w, _, clamped := dampStep(80, 100, cfg); w != 80 || clamped {
		t.Fatalf("100→target80: w=%d clamped=%v, want 80,false (boundary inclusive)", w, clamped)
	}
	// Output stays in the contract range [0,100].
	if w, _, _ := dampStep(0, 10, cfg); w > 100 {
		t.Fatalf("range violation: %d", w)
	}
}

// --- LMC-03: bounded, floored-at-1, default-OFF LMCache cost term ---

func strongLmcSignal(at time.Time) aimetrics.WorkerSample {
	return aimetrics.WorkerSample{LastUpdate: at, Raw: map[string]float64{
		aimetrics.RawKeyMatchedPrefixLength:    4096,
		aimetrics.FamilyLMCacheRetrieveHitRate: 0.95,
	}}
}

// TestLMCCostOFFByteIdentity (arm-B proof): with the sub-knob OFF, ComputeWeights
// over a fixture carrying STRONG fresh lmcache signals is byte-identical to the
// same fixture run through path (no carrier). This is the live
// default-OFF guard.
func TestLMCCostOFFByteIdentity(t *testing.T) {
	reg := fleetRegistry()
	cfgOff := EngineConfig{Now: testNow, EwmaAlpha: 1.0} // LmcCostEnabled defaults false
	samples := freshSamples(reg, testNow)

	lmc := map[string]aimetrics.WorkerSample{}
	for ip := range reg.Hosts {
		lmc[ip] = aimetrics.WorkerSample{LastUpdate: testNow, Raw: map[string]float64{
			aimetrics.RawKeyMatchedPrefixLength:     8192,
			aimetrics.FamilyLMCacheRemoteCacheUsage: 4 << 30,
			aimetrics.FamilyLMCacheRetrieveHitRate:  0.9,
		}}
	}

	var prev map[string]uint32
	for epoch := 0; epoch < 4; epoch++ {
		base, _ := ComputeWeights(reg, samples, prev, cfgOff)         // path
		withLmc, _ := ComputeWeights(reg, samples, prev, cfgOff, lmc) // carrier present, OFF
		if !reflect.DeepEqual(base, withLmc) {
			t.Fatalf("epoch %d: OFF not byte-identical\n base=%v\n lmc =%v", epoch, base, withLmc)
		}
		prev = base
	}
}

// TestLMCCostBounded: dw is always within [-LmcMaxPts, +LmcMaxPts] for every
// signal combination (including hostile magnitudes).
func TestLMCCostBounded(t *testing.T) {
	cfg := EngineConfig{Now: testNow, LmcCostEnabled: true, LmcMaxPts: 15}.withDefaults()
	cases := []map[string]float64{
		{aimetrics.FamilyLMCacheRemoteCacheUsage: 1e18},
		{aimetrics.RawKeyMatchedPrefixLength: 1e9},
		{aimetrics.FamilyLMCacheRetrieveHitRate: 1.0, aimetrics.RawKeyMatchedPrefixLength: 1e9},
		{aimetrics.FamilyLMCacheTimeToRetrieve: 0},
		{aimetrics.FamilyLMCacheRemoteCacheUsage: 1e18, aimetrics.RawKeyMatchedPrefixLength: 1e9},
		{aimetrics.FamilyLMCacheLocalCacheUsage: 2 << 30, aimetrics.FamilyLMCacheRetrieveHitRate: 0.5},
	}
	for i, raw := range cases {
		lmc := map[string]aimetrics.WorkerSample{"ep": {LastUpdate: testNow, Raw: raw}}
		dw := lmcCostTerm("ep", lmc, cfg)
		if dw < -cfg.LmcMaxPts-1e-9 || dw > cfg.LmcMaxPts+1e-9 {
			t.Fatalf("case %d: dw=%v out of [-%v,+%v]", i, dw, cfg.LmcMaxPts, cfg.LmcMaxPts)
		}
	}
}

// TestLMCCostFloorAtOne: maximal negative KV-pressure yields the most-negative
// dw (≈ -LmcMaxPts), yet the use-site clamp floors the post-term raw at 1 — an
// LMCache signal can never zero-out (DISABLE) or exclude an EP.
func TestLMCCostFloorAtOne(t *testing.T) {
	cfg := EngineConfig{Now: testNow, LmcCostEnabled: true}.withDefaults()
	lmc := map[string]aimetrics.WorkerSample{
		"ep": {LastUpdate: testNow, Raw: map[string]float64{
			aimetrics.FamilyLMCacheRemoteCacheUsage: 1e18, // pressure saturates → dw ≈ -B
		}},
	}
	dw := lmcCostTerm("ep", lmc, cfg)
	if dw > -cfg.LmcMaxPts+1.0 {
		t.Fatalf("maximal pressure dw=%v, want ≈ -%v", dw, cfg.LmcMaxPts)
	}
	// Even a raw at the very bottom of the scale can never drop below 1.
	for _, raw := range []float64{0, 0.5, 1, 15, 50, 100} {
		if got := clamp(raw+dw, 1, 100); got < 1 {
			t.Fatalf("floor breached: raw=%v dw=%v ⇒ %v (<1)", raw, dw, got)
		}
	}
}

// TestLMCCostStaleAbsentNeutral: a stale, never-stamped, absent, signal-less, or
// sub-knob-OFF lmcache source all decay the cost term to 0 (neutral) — never a
// zero-filled cost.
func TestLMCCostStaleAbsentNeutral(t *testing.T) {
	cfg := EngineConfig{Now: testNow, LmcCostEnabled: true}.withDefaults()

	// (a) aged past the 15s budget.
	lmc := map[string]aimetrics.WorkerSample{"ep": strongLmcSignal(testNow.Add(-16 * time.Second))}
	if dw := lmcCostTerm("ep", lmc, cfg); dw != 0 {
		t.Fatalf("stale lmcache ⇒ dw=%v, want 0", dw)
	}
	// (b) never-stamped (zero LastUpdate).
	lmc["ep"] = aimetrics.WorkerSample{Raw: strongLmcSignal(testNow).Raw}
	if dw := lmcCostTerm("ep", lmc, cfg); dw != 0 {
		t.Fatalf("never-stamped lmcache ⇒ dw=%v, want 0", dw)
	}
	// (c) absent EP.
	if dw := lmcCostTerm("ep", map[string]aimetrics.WorkerSample{}, cfg); dw != 0 {
		t.Fatalf("absent lmcache ⇒ dw=%v, want 0", dw)
	}
	// (d) nil carrier.
	if dw := lmcCostTerm("ep", nil, cfg); dw != 0 {
		t.Fatalf("nil carrier ⇒ dw=%v, want 0", dw)
	}
	// (e) present + fresh but carrying no lmcache signal.
	lmc["ep"] = aimetrics.WorkerSample{LastUpdate: testNow, Raw: map[string]float64{}}
	if dw := lmcCostTerm("ep", lmc, cfg); dw != 0 {
		t.Fatalf("no-signal lmcache ⇒ dw=%v, want 0", dw)
	}
	// (f) sub-knob OFF ignores even a strong fresh signal.
	off := EngineConfig{Now: testNow}.withDefaults() // LmcCostEnabled false
	lmc["ep"] = strongLmcSignal(testNow)
	if dw := lmcCostTerm("ep", lmc, off); dw != 0 {
		t.Fatalf("sub-knob OFF ⇒ dw=%v, want 0", dw)
	}
}

// TestLMCCostNegativeControlInvertible (VAL-02): the cost term measurably changes
// EP ordering, and LmcInvert flips that ordering (hooks the harness inversion).
func TestLMCCostNegativeControlInvertible(t *testing.T) {
	reg := trioRegistry() // homogeneous L4 trio (raw 100 each) + single decode
	samples := freshSamples(reg, testNow)

	// .7 strong LOCALITY (positive bias); .8 strong KV-PRESSURE (negative bias).
	lmc := map[string]aimetrics.WorkerSample{
		"10.0.0.7": {LastUpdate: testNow, Raw: map[string]float64{
			aimetrics.RawKeyMatchedPrefixLength:    8192,
			aimetrics.FamilyLMCacheRetrieveHitRate: 1.0,
		}},
		"10.0.0.8": {LastUpdate: testNow, Raw: map[string]float64{
			aimetrics.FamilyLMCacheRemoteCacheUsage: 1e18,
		}},
	}

	on := EngineConfig{Now: testNow, EwmaAlpha: 1.0, LmcCostEnabled: true}
	w, _ := ComputeWeights(reg, samples, nil, on, lmc)
	if !(w["10.0.0.7"] > w["10.0.0.8"]) {
		t.Fatalf("ON: locality EP .7 (%d) must outweigh pressure EP .8 (%d)", w["10.0.0.7"], w["10.0.0.8"])
	}

	inv := on
	inv.LmcInvert = true
	wi, _ := ComputeWeights(reg, samples, nil, inv, lmc)
	if !(wi["10.0.0.8"] > wi["10.0.0.7"]) {
		t.Fatalf("INVERTED: pressure EP .8 (%d) must outweigh locality EP .7 (%d)", wi["10.0.0.8"], wi["10.0.0.7"])
	}
	if (w["10.0.0.7"] > w["10.0.0.8"]) == (wi["10.0.0.7"] > wi["10.0.0.8"]) {
		t.Fatal("inversion did not change the ordering")
	}
}
