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

// staleness-flap regression suite (ROADMAP success criterion 5;
// the VAL-03b conviction from G1 campaign).
//
// Convicted mechanism (G1-INVESTIGATION-FINDING.md / 98-RESEARCH §RQ8): on a
// heterogeneous fleet, ONE EP flapping fresh/stale around StaleBudget swung
// every other EP's weight 50–100 pts because (a) maxPrior was computed over
// the FRESH set only — a flapping high-prior EP renormalized the whole role —
// and (b) the stale path emitted a bare undamped out[ip]=100.
//
// Five test families lock BOTH fixes:
//   TestFlapJitterInvisible          — scrape jitter invisible to siblings (fix 1)
//   TestFlapGenuineOutageDampedRenorm — real outage still renormalizes, damped (fix 1+2)
//   TestFlapRecoveryImmediate        — one fresh scrape restores membership (asymmetry)
//   TestFlapAllFreshByteIdentical    — the fix is invisible when nothing is stale
//   TestFlapLmcInteractionGuard      — flap fix changes nothing about the LMC term
//
// Fake-clock discipline throughout: EngineConfig{Now: ...} advanced epoch by
// epoch (period = the fleet's 10s epoch), toggling one EP's LastUpdate around
// StaleBudget/HardStaleBudget. ComputeWeights stays pure — no sleeps.

package engine

import (
	"reflect"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// flapPeriod is the decision-epoch period used by the flap simulations
// (mirrors the fleet registry's EpochPeriodSec: 10).
const flapPeriod = 10 * time.Second

func absDelta(a, b uint32) int {
	d := int(a) - int(b)
	if d < 0 {
		return -d
	}
	return d
}

// flapL4s are the homogeneous L4 prefill trio of fleetRegistry — the
// "siblings" whose weights the flapping L40S must not perturb.
var flapL4s = []string{"10.0.0.7", "10.0.0.8", "10.0.0.9"}

// convergeFresh runs n all-fresh epochs, advancing the fake clock each epoch,
// and returns the settled weights plus the advanced clock.
func convergeFresh(t *testing.T, reg *Registry, cfg EngineConfig, now time.Time,
	n int) (map[string]uint32, time.Time) {
	t.Helper()
	var prev map[string]uint32
	for e := 0; e < n; e++ {
		now = now.Add(flapPeriod)
		cfg.Now = now
		w, stats := ComputeWeights(reg, freshSamples(reg, now), prev, cfg)
		if stats.FleetStale {
			t.Fatalf("converge epoch %d: fleet-stale on fresh samples", e)
		}
		prev = w
	}
	return prev, now
}

// TestFlapJitterInvisible (fix site 1): the L40S (prior 2.0) alternates
// fresh/soft-stale each epoch around StaleBudget over ≥12 epochs. With its
// prior kept in the maxPrior normalization set while merely SOFT-stale,
// scrape jitter must be INVISIBLE: (a) every EP's per-epoch weight delta
// stays ≤ MaxStepPct, and (b) the three L4 siblings never leave a
// ±DeadBand-sized band around their settled value.
//
// Pre-fix this failed loudly: each stale epoch dropped maxPrior[prefill]
// 2.0→1.0, retargeting the trio 50→100 and walking them out of the band
// (the oscillation.r1.0.json 50–100 pt swings).
func TestFlapJitterInvisible(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{} // default envelope: α=0.3, DeadBand=5, MaxStepPct=20

	prev, now := convergeFresh(t, reg, cfg, testNow, 20)
	settled := prev["10.0.0.7"]
	for _, ip := range flapL4s {
		if prev[ip] != settled {
			t.Fatalf("asymmetric L4 settle: %s=%d vs %d", ip, prev[ip], settled)
		}
	}

	for e := 0; e < 14; e++ {
		now = now.Add(flapPeriod)
		cfg.Now = now
		samples := freshSamples(reg, now)
		if e%2 == 0 {
			// SOFT-STALE: aged just past StaleBudget (16s > 15s) but far
			// inside HardStaleBudget (45s) — the scrape-jitter regime.
			samples["10.0.0.11"] = Sourced{IP: "10.0.0.11",
				Sample: aimetrics.WorkerSample{LastUpdate: now.Add(-16 * time.Second)}}
		}
		w, stats := ComputeWeights(reg, samples, prev, cfg)
		if stats.FleetStale {
			t.Fatalf("flap epoch %d: fleet-stale with 4 fresh sources", e)
		}
		// (a) Damping envelope: no EP may step more than MaxStepPct/epoch.
		for ip := range reg.Hosts {
			if d := absDelta(w[ip], prev[ip]); d > DefaultMaxStepPct {
				t.Fatalf("flap epoch %d: %s stepped %d pts (> %d)", e, ip, d, DefaultMaxStepPct)
			}
		}
		// (b) Sibling invisibility: the L4 trio holds its settled band.
		for _, ip := range flapL4s {
			if d := absDelta(w[ip], settled); d > int(DefaultDeadBand) {
				t.Fatalf("flap epoch %d: sibling %s left the settled band: %d vs settled %d (> ±%v)",
					e, ip, w[ip], settled, DefaultDeadBand)
			}
		}
		prev = w
	}
}

// TestFlapGenuineOutageDampedRenorm (fix sites 1+2): a genuinely dead EP —
// aged past HardStaleBudget, not jitter — must STILL renormalize the fleet,
// but every step of the walk is damped (≤ MaxStepPct/epoch).
//
// EwmaAlpha is pinned to 1.0 so the walk arithmetic is the exact ±MaxStepPct
// clamp schedule (precedent: default α attenuates before the clamp
// binds, making literal step expectations α-dependent).
func TestFlapGenuineOutageDampedRenorm(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{EwmaAlpha: 1.0}

	// --- Scenario A: max-prior L40S outage ⇒ damped fleet renormalization.
	prev, now := convergeFresh(t, reg, cfg, testNow, 4)
	if prev["10.0.0.7"] != 50 || prev["10.0.0.11"] != 100 {
		t.Fatalf("unexpected converged state: %v", prev)
	}
	freeze := now // the L40S's last successful scrape
	// Epoch ages of the frozen sample: 10s(fresh) 20/30/40(soft) 50+(HARD).
	for e := 1; e <= 10; e++ {
		now = now.Add(flapPeriod)
		cfg.Now = now
		samples := freshSamples(reg, now)
		samples["10.0.0.11"] = Sourced{IP: "10.0.0.11",
			Sample: aimetrics.WorkerSample{LastUpdate: freeze}}
		w, _ := ComputeWeights(reg, samples, prev, cfg)
		for ip := range reg.Hosts {
			if d := absDelta(w[ip], prev[ip]); d > DefaultMaxStepPct {
				t.Fatalf("outage epoch %d: %s stepped %d pts (> %d) — renorm must be damped",
					e, ip, d, DefaultMaxStepPct)
			}
		}
		age := now.Sub(freeze)
		if age > DefaultStaleBudget && age <= DefaultHardStaleFactor*DefaultStaleBudget {
			// SOFT window: prior still in maxPrior ⇒ NO renormalization yet.
			for _, ip := range flapL4s {
				if w[ip] != 50 {
					t.Fatalf("soft-stale epoch %d (age %v): %s = %d, want 50 (no renorm before HardStaleBudget)",
						e, age, ip, w[ip])
				}
			}
		}
		// The dead L40S glides to neutral — it was already at 100, so it holds.
		if w["10.0.0.11"] != 100 {
			t.Fatalf("outage epoch %d: L40S = %d, want neutral 100", e, w["10.0.0.11"])
		}
		prev = w
	}
	// Renormalization DID occur: the trio walked (damped: 50→70→90→100) to 100.
	for _, ip := range flapL4s {
		if prev[ip] != 100 {
			t.Fatalf("post-outage: %s = %d, want 100 (hard-stale prior must leave maxPrior)", ip, prev[ip])
		}
	}

	// --- Scenario B: a non-neutral L4 dies ⇒ ITS weight glides damped to
	// neutral (fix site 2's teeth: pre-fix this jumped 50→100 in one epoch).
	prev, now = convergeFresh(t, reg, cfg, testNow, 4)
	freeze = now
	wantWalk := []uint32{50, 70, 90, 100, 100} // age 10(fresh) 20 30 40 50
	for e := 1; e <= 5; e++ {
		now = now.Add(flapPeriod)
		cfg.Now = now
		samples := freshSamples(reg, now)
		samples["10.0.0.7"] = Sourced{IP: "10.0.0.7",
			Sample: aimetrics.WorkerSample{LastUpdate: freeze}}
		w, _ := ComputeWeights(reg, samples, prev, cfg)
		if w["10.0.0.7"] != wantWalk[e-1] {
			t.Fatalf("dead-L4 epoch %d: .7 = %d, want %d (damped glide 50→70→90→100, never a bare jump)",
				e, w["10.0.0.7"], wantWalk[e-1])
		}
		if d := absDelta(w["10.0.0.7"], prev["10.0.0.7"]); d > DefaultMaxStepPct {
			t.Fatalf("dead-L4 epoch %d: stepped %d pts (> %d)", e, d, DefaultMaxStepPct)
		}
		// A dying non-max L4 renormalizes NOTHING: siblings hold 50.
		for _, ip := range []string{"10.0.0.8", "10.0.0.9"} {
			if w[ip] != 50 {
				t.Fatalf("dead-L4 epoch %d: sibling %s = %d, want 50", e, ip, w[ip])
			}
		}
		prev = w
	}
}

// TestFlapRecoveryImmediate: after a genuine outage has renormalized the
// fleet, ONE fresh L40S scrape restores its maxPrior membership immediately
// (asymmetry is inherent — no streak counter, RQ8's rejected alternative),
// and the weights return to the heterogeneous split through damped steps.
func TestFlapRecoveryImmediate(t *testing.T) {
	reg := fleetRegistry()
	cfg := EngineConfig{EwmaAlpha: 1.0} // exact clamp-walk arithmetic (precedent)

	// Drive to the post-outage state: L40S hard-stale, trio renormalized to 100.
	prev, now := convergeFresh(t, reg, cfg, testNow, 4)
	freeze := now
	for e := 1; e <= 10; e++ {
		now = now.Add(flapPeriod)
		cfg.Now = now
		samples := freshSamples(reg, now)
		samples["10.0.0.11"] = Sourced{IP: "10.0.0.11",
			Sample: aimetrics.WorkerSample{LastUpdate: freeze}}
		prev, _ = ComputeWeights(reg, samples, prev, cfg)
	}
	for _, ip := range flapL4s {
		if prev[ip] != 100 {
			t.Fatalf("outage precondition: %s = %d, want 100", ip, prev[ip])
		}
	}

	// ONE fresh scrape: membership restores THIS epoch — the trio's target
	// snaps back to 50 immediately and the walk down is clamp-damped.
	wantWalk := []uint32{80, 60, 50, 50}
	for e, want := range wantWalk {
		now = now.Add(flapPeriod)
		cfg.Now = now
		w, _ := ComputeWeights(reg, freshSamples(reg, now), prev, cfg)
		for _, ip := range flapL4s {
			if w[ip] != want {
				t.Fatalf("recovery epoch %d: %s = %d, want %d (immediate membership + damped walk)",
					e+1, ip, w[ip], want)
			}
		}
		if w["10.0.0.11"] != 100 || w["10.0.0.10"] != 100 {
			t.Fatalf("recovery epoch %d: L40S/decode = %d/%d, want 100/100",
				e+1, w["10.0.0.11"], w["10.0.0.10"])
		}
		prev = w
	}
}

// TestFlapAllFreshByteIdentical: with every EP fresh across 4 epochs the
// output is DeepEqual-identical to the pre- reference walk (the literal
// α=1.0 convergence schedule locked by TestComputeWeightsHeterogeneousConvergence
// long before this fix) — the fix must be INVISIBLE when nothing is stale.
// A second chain with an absurd explicit HardStaleBudget proves the new knob
// itself is inert on all-fresh input.
func TestFlapAllFreshByteIdentical(t *testing.T) {
	reg := fleetRegistry()
	cfgDefault := EngineConfig{EwmaAlpha: 1.0}
	cfgHuge := EngineConfig{EwmaAlpha: 1.0, HardStaleBudget: 999 * time.Hour}

	// Pre-fix reference output (97 behavior, byte-for-byte).
	ref := []map[string]uint32{
		{"10.0.0.7": 80, "10.0.0.8": 80, "10.0.0.9": 80, "10.0.0.11": 100, "10.0.0.10": 100},
		{"10.0.0.7": 60, "10.0.0.8": 60, "10.0.0.9": 60, "10.0.0.11": 100, "10.0.0.10": 100},
		{"10.0.0.7": 50, "10.0.0.8": 50, "10.0.0.9": 50, "10.0.0.11": 100, "10.0.0.10": 100},
		{"10.0.0.7": 50, "10.0.0.8": 50, "10.0.0.9": 50, "10.0.0.11": 100, "10.0.0.10": 100},
	}

	now := testNow
	var prevD, prevH map[string]uint32
	for epoch, want := range ref {
		now = now.Add(flapPeriod)
		cfgDefault.Now, cfgHuge.Now = now, now
		samples := freshSamples(reg, now)
		wd, _ := ComputeWeights(reg, samples, prevD, cfgDefault)
		wh, _ := ComputeWeights(reg, samples, prevH, cfgHuge)
		if !reflect.DeepEqual(wd, want) {
			t.Fatalf("epoch %d: all-fresh output diverged from the pre-fix reference\n got=%v\nwant=%v",
				epoch, wd, want)
		}
		if !reflect.DeepEqual(wd, wh) {
			t.Fatalf("epoch %d: HardStaleBudget knob perturbed all-fresh output\n default=%v\n huge=%v",
				epoch, wd, wh)
		}
		prevD, prevH = wd, wh
	}
}

// TestFlapLmcInteractionGuard: the flap fix changes NOTHING about the LMC
// cost term, flapping or not — (a) with the sub-knob OFF a carrier under
// flap stays byte-identical to the no-carrier run; (b) with the sub-knob ON
// the term still biases exactly the fresh EPs it targets (locality EP above
// pressure EP) while the flapping EP's weight is identical ON vs OFF (the
// stale path carries no LMC contribution).
func TestFlapLmcInteractionGuard(t *testing.T) {
	reg := fleetRegistry()
	// α=1.0: the ON-arm ordering assertion needs the converged raw split
	// (50±dw) rather than an α-attenuated blend (precedent).
	base := EngineConfig{EwmaAlpha: 1.0}
	on := base
	on.LmcCostEnabled = true

	now := testNow
	var prevOffBare, prevOffCarrier, prevOn map[string]uint32
	for e := 0; e < 8; e++ {
		now = now.Add(flapPeriod)
		base.Now, on.Now = now, now
		samples := freshSamples(reg, now)
		if e%2 == 1 {
			// The L40S flaps SOFT-stale on odd epochs — regime.
			samples["10.0.0.11"] = Sourced{IP: "10.0.0.11",
				Sample: aimetrics.WorkerSample{LastUpdate: now.Add(-16 * time.Second)}}
		}
		// Fresh LMC carrier: .7 strong locality (positive bias), .8 strong
		// KV-pressure (negative bias) — the TestLMCCostNegativeControlInvertible shape.
		lmc := map[string]aimetrics.WorkerSample{
			"10.0.0.7": {LastUpdate: now, Raw: map[string]float64{
				aimetrics.RawKeyMatchedPrefixLength:    8192,
				aimetrics.FamilyLMCacheRetrieveHitRate: 1.0,
			}},
			"10.0.0.8": {LastUpdate: now, Raw: map[string]float64{
				aimetrics.FamilyLMCacheRemoteCacheUsage: 1e18,
			}},
		}

		wOffBare, _ := ComputeWeights(reg, samples, prevOffBare, base)
		wOffCarrier, _ := ComputeWeights(reg, samples, prevOffCarrier, base, lmc)
		wOn, _ := ComputeWeights(reg, samples, prevOn, on, lmc)

		// (a) OFF byte-identity survives the flap regime.
		if !reflect.DeepEqual(wOffBare, wOffCarrier) {
			t.Fatalf("epoch %d: OFF + carrier not byte-identical under flap\n bare=%v\n lmc =%v",
				e, wOffBare, wOffCarrier)
		}
		// (b) The stale-path EP and the decode carry ZERO LMC contribution:
		// identical ON vs OFF every epoch, flapping or not.
		for _, ip := range []string{"10.0.0.11", "10.0.0.10"} {
			if wOn[ip] != wOffBare[ip] {
				t.Fatalf("epoch %d: %s differs ON(%d) vs OFF(%d) — LMC leaked outside its targets",
					e, ip, wOn[ip], wOffBare[ip])
			}
		}
		prevOffBare, prevOffCarrier, prevOn = wOffBare, wOffCarrier, wOn
	}
	// The LMC term still does its job with the flap fix in place: locality
	// EP .7 converges strictly above pressure EP .8; OFF keeps them equal.
	if !(prevOn["10.0.0.7"] > prevOn["10.0.0.8"]) {
		t.Fatalf("ON: locality .7 (%d) must outweigh pressure .8 (%d) despite the flap",
			prevOn["10.0.0.7"], prevOn["10.0.0.8"])
	}
	if prevOffBare["10.0.0.7"] != prevOffBare["10.0.0.8"] {
		t.Fatalf("OFF: L4 twins diverged without an LMC term: .7=%d .8=%d",
			prevOffBare["10.0.0.7"], prevOffBare["10.0.0.8"])
	}
}
