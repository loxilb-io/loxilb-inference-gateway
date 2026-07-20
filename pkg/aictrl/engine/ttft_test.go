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

// Expected-TTFT term regression suite (TTFT-02/03) — the LMC five-test
// template (engine_test.go :38) mirrored for the TTFT sub-knob, plus
// the coefficients-loader rejection table (the trust-boundary half,
// and the α-decay proof (TTFT-03).

package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ttftTestModel is the hand-checkable fixture model:
//
//	pred = 0.5 + 1.0·log_prompt_tokens + 2.0·waiting_over_capacity
//
// e.g. Predict{LogPromptTokens: 6, WaitingOverCapacity: 0.25}
//   - = 0.5 + 1.0×6 + 2.0×0.25 = 7.0 (every term exactly representable).
func ttftTestModel() *TtftModel {
	return &TtftModel{
		ModelVersion: 1,
		Features:     []string{TtftFeatIntercept, TtftFeatLogPromptTokens, TtftFeatWaitingOverCapacity},
		Coefficients: []float64{0.5, 1.0, 2.0},
		LogSpace:     true,
	}
}

// ttftFeatsFor builds a fresh carrier: every EP shares the reference prompt
// length (log 6.0 —: prompt length shifts predictions identically)
// and differs only in waiting_over_capacity.
func ttftFeatsFor(at time.Time, waiting map[string]float64) map[string]TtftEpochFeatures {
	m := make(map[string]TtftEpochFeatures, len(waiting))
	for ip, w := range waiting {
		m[ip] = TtftEpochFeatures{
			TtftFeatures: TtftFeatures{LogPromptTokens: 6.0, WaitingOverCapacity: w},
			LastUpdate:   at,
		}
	}
	return m
}

// TestEngineConfigTtftDefaults: a zero-valued EngineConfig withDefaults
// yields the default-OFF TTFT contract — TtftEnabled false, the two locked
// defaults, and CRITICALLY TtftAlpha stays 0 (0 is meaningful: fully decayed
// ⇒ neutral; the BINARY owns α — an un-wired α must fail-safe to neutral).
func TestEngineConfigTtftDefaults(t *testing.T) {
	got := EngineConfig{}.withDefaults()
	if got.TtftEnabled {
		t.Fatal("TtftEnabled must default false (default-OFF ⇒ byte-identical)")
	}
	if got.TtftMaxPts != DefaultTtftMaxPts {
		t.Fatalf("TtftMaxPts default = %v, want %v", got.TtftMaxPts, DefaultTtftMaxPts)
	}
	if got.TtftStaleBudget != DefaultTtftStaleBudget {
		t.Fatalf("TtftStaleBudget default = %v, want %v", got.TtftStaleBudget, DefaultTtftStaleBudget)
	}
	if got.TtftAlpha != 0 {
		t.Fatalf("TtftAlpha = %v, want 0 — withDefaults must NOT default α (TTFT-03: 0 = fully decayed is meaningful)", got.TtftAlpha)
	}
	if got.TtftModel != nil {
		t.Fatalf("TtftModel default = %v, want nil (structural OFF)", got.TtftModel)
	}
}

// TestTtftOFFByteIdentity (default-OFF proof, LMC byte-identity shape): with
// the sub-knob OFF, ComputeWeights over a carrier of STRONG divergent fresh
// TTFT features is byte-identical to the no-carrier path across 4 damped
// epochs. ALSO: TtftEnabled=true but TtftModel==nil (structural OFF) is
// byte-identical — "enabled but no coefficients" cannot perturb weights
// (metrics-only degrade). α is pinned to 1 in every arm so the ONLY
// thing keeping the term silent is the guard under test (revert-teeth:
// removing the enabled/model guards makes this test FAIL).
func TestTtftOFFByteIdentity(t *testing.T) {
	reg := fleetRegistry()
	samples := freshSamples(reg, testNow)
	feats := ttftFeatsFor(testNow, map[string]float64{
		"10.0.0.7": 0, "10.0.0.8": 5.0, "10.0.0.9": 0.5,
		"10.0.0.11": 2.0, "10.0.0.10": 1.0,
	})

	base := EngineConfig{Now: testNow, EwmaAlpha: 1.0} // no TTFT fields at all

	off := base
	off.TtftFeats = feats
	off.TtftModel = ttftTestModel()
	off.TtftAlpha = 1.0 // TtftEnabled stays false — the knob under test

	structOff := base
	structOff.TtftEnabled = true // enabled, but…
	structOff.TtftModel = nil    // …no coefficients ⇒ STRUCTURALLY OFF
	structOff.TtftFeats = feats
	structOff.TtftAlpha = 1.0

	var prev map[string]uint32
	for epoch := 0; epoch < 4; epoch++ {
		want, _ := ComputeWeights(reg, samples, prev, base)
		gotOff, _ := ComputeWeights(reg, samples, prev, off)
		if !reflect.DeepEqual(want, gotOff) {
			t.Fatalf("epoch %d: TtftEnabled=false not byte-identical\n base=%v\n ttft=%v", epoch, want, gotOff)
		}
		gotStruct, _ := ComputeWeights(reg, samples, prev, structOff)
		if !reflect.DeepEqual(want, gotStruct) {
			t.Fatalf("epoch %d: enabled+nil-model not byte-identical (structural OFF broken)\n base=%v\n ttft=%v", epoch, want, gotStruct)
		}
		prev = want
	}
}

// TestTtftBounded: hostile models and features driving |rel| → 1 (and past
// it, into Inf) never produce |dw| > TtftMaxPts, and the full pipeline keeps
// every weight in [1,100].
func TestTtftBounded(t *testing.T) {
	hostileModel := &TtftModel{
		ModelVersion: 1,
		Features:     []string{TtftFeatIntercept, TtftFeatWaitingOverCapacity},
		Coefficients: []float64{1e6, 1e6}, // at the loader's β sanity bound
		LogSpace:     true,
	}
	cfg := EngineConfig{
		Now: testNow, TtftEnabled: true, TtftModel: hostileModel, TtftAlpha: 1.0,
	}.withDefaults()

	cases := []map[string]float64{
		{"a": 0, "b": 1e12},   // b predicted astronomically slower
		{"a": 1e12, "b": 0},   // a predicted astronomically slower
		{"a": 0, "b": 1e303},  // overflow territory: pred → +Inf
		{"a": -1e12, "b": 0},  // hostile negative feature
		{"a": 0.1, "b": 0.11}, // near-tie
	}
	for i, waiting := range cases {
		feats := ttftFeatsFor(testNow, waiting)
		for ip := range waiting {
			dw := ttftCostTerm(ip, feats, cfg)
			if dw < -cfg.TtftMaxPts-1e-9 || dw > cfg.TtftMaxPts+1e-9 {
				t.Fatalf("case %d ep %s: dw=%v out of [-%v,+%v]", i, ip, dw, cfg.TtftMaxPts, cfg.TtftMaxPts)
			}
		}
	}

	// Full pipeline: hostile term magnitudes still leave every emitted
	// weight in the contract range, floored at 1.
	reg := trioRegistry()
	samples := freshSamples(reg, testNow)
	pipeCfg := cfg
	pipeCfg.EwmaAlpha = 1.0
	pipeCfg.TtftFeats = ttftFeatsFor(testNow, map[string]float64{
		"10.0.0.7": 0, "10.0.0.8": 1e12, "10.0.0.9": 0.5, "10.0.0.10": 0,
	})
	var prev map[string]uint32
	for epoch := 0; epoch < 5; epoch++ {
		w, _ := ComputeWeights(reg, samples, prev, pipeCfg)
		for ip, got := range w {
			if got < 1 || got > 100 {
				t.Fatalf("epoch %d: %s = %d outside [1,100]", epoch, ip, got)
			}
		}
		prev = w
	}
}

// TestTtftFloorAtOne: the worst-case negative term (an EP predicted maximally
// slower than the fleet mean) is ≈ -TtftMaxPts, yet the use-site clamp floors
// the post-term raw at 1 — a TTFT prediction can never zero-out (DISABLE) or
// exclude an EP (cost input, never eligibility).
func TestTtftFloorAtOne(t *testing.T) {
	cfg := EngineConfig{
		Now: testNow, TtftEnabled: true, TtftModel: ttftTestModel(), TtftAlpha: 1.0,
	}.withDefaults()

	// "slow" predicted 2×5.0=10 log-units above "fast" ⇒ rel saturates -1.
	feats := ttftFeatsFor(testNow, map[string]float64{"slow": 5.0, "fast": 0})
	dw := ttftCostTerm("slow", feats, cfg)
	if dw > -cfg.TtftMaxPts+1.0 {
		t.Fatalf("maximal slowness dw=%v, want ≈ -%v", dw, cfg.TtftMaxPts)
	}
	// Even a raw at the very bottom of the scale can never drop below 1.
	for _, raw := range []float64{0, 0.5, 1, 15, 50, 100} {
		if got := clamp(raw+dw, 1, 100); got < 1 {
			t.Fatalf("floor breached: raw=%v dw=%v ⇒ %v (<1)", raw, dw, got)
		}
	}
}

// TestTtftStaleNeutral: aged, never-stamped, absent, nil-carrier, sub-knob-OFF
// and nil-model feature sources ALL contribute exactly 0 (decay to neutral,
// never zero-fill) — and a stale sibling leaves the fleet-mean set.
func TestTtftStaleNeutral(t *testing.T) {
	cfg := EngineConfig{
		Now: testNow, TtftEnabled: true, TtftModel: ttftTestModel(), TtftAlpha: 1.0,
	}.withDefaults()
	strong := map[string]float64{"ep": 3.0, "other": 0}

	// (a) aged past the 15s budget.
	feats := ttftFeatsFor(testNow.Add(-16*time.Second), strong)
	if dw := ttftCostTerm("ep", feats, cfg); dw != 0 {
		t.Fatalf("stale features ⇒ dw=%v, want 0", dw)
	}
	// (b) never-stamped (zero LastUpdate).
	feats = ttftFeatsFor(time.Time{}, strong)
	if dw := ttftCostTerm("ep", feats, cfg); dw != 0 {
		t.Fatalf("never-stamped features ⇒ dw=%v, want 0", dw)
	}
	// (c) absent EP.
	feats = ttftFeatsFor(testNow, map[string]float64{"other": 0})
	if dw := ttftCostTerm("ep", feats, cfg); dw != 0 {
		t.Fatalf("absent EP ⇒ dw=%v, want 0", dw)
	}
	// (d) nil carrier.
	if dw := ttftCostTerm("ep", nil, cfg); dw != 0 {
		t.Fatalf("nil carrier ⇒ dw=%v, want 0", dw)
	}
	// (e) sub-knob OFF ignores even a strong fresh carrier.
	off := cfg
	off.TtftEnabled = false
	if dw := ttftCostTerm("ep", ttftFeatsFor(testNow, strong), off); dw != 0 {
		t.Fatalf("sub-knob OFF ⇒ dw=%v, want 0", dw)
	}
	// (f) nil model (structural OFF) likewise.
	noModel := cfg
	noModel.TtftModel = nil
	if dw := ttftCostTerm("ep", ttftFeatsFor(testNow, strong), noModel); dw != 0 {
		t.Fatalf("nil model ⇒ dw=%v, want 0", dw)
	}

	// (g) a STALE sibling with an extreme prediction must leave the
	// fleet-mean set: two fresh equal-feature EPs stay exactly neutral.
	mixed := ttftFeatsFor(testNow, map[string]float64{"a": 0.5, "b": 0.5})
	staleExtreme := ttftFeatsFor(testNow.Add(-16*time.Second), map[string]float64{"z": 1e6})
	mixed["z"] = staleExtreme["z"]
	if dw := ttftCostTerm("a", mixed, cfg); dw != 0 {
		t.Fatalf("stale extreme sibling perturbed the mean: dw=%v, want 0", dw)
	}
}

// TestTtftInvertFlips (VAL-02): TtftInvert produces the exactly mirrored
// per-EP delta on the same inputs, and flips the emitted EP ordering.
func TestTtftInvertFlips(t *testing.T) {
	cfg := EngineConfig{
		Now: testNow, TtftEnabled: true, TtftModel: ttftTestModel(), TtftAlpha: 1.0,
	}.withDefaults()
	feats := ttftFeatsFor(testNow, map[string]float64{"fast": 0, "mid": 0.5, "slow": 1.0})

	inv := cfg
	inv.TtftInvert = true
	for _, ip := range []string{"fast", "mid", "slow"} {
		dw := ttftCostTerm(ip, feats, cfg)
		dwi := ttftCostTerm(ip, feats, inv)
		if dwi != -dw {
			t.Fatalf("%s: inverted dw=%v, want mirrored %v", ip, dwi, -dw)
		}
	}

	// Pipeline ordering flip (the LMC invert-test shape): homogeneous trio,
	// .7 fast (waiting 0, positive bias) vs .8 slow (waiting 1.0, negative).
	reg := trioRegistry()
	samples := freshSamples(reg, testNow)
	on := EngineConfig{
		Now: testNow, EwmaAlpha: 1.0, TtftEnabled: true,
		TtftModel: ttftTestModel(), TtftAlpha: 1.0,
		TtftFeats: ttftFeatsFor(testNow, map[string]float64{
			"10.0.0.7": 0, "10.0.0.8": 1.0, "10.0.0.9": 0.5, "10.0.0.10": 0.5,
		}),
	}
	w, _ := ComputeWeights(reg, samples, nil, on)
	if !(w["10.0.0.7"] > w["10.0.0.8"]) {
		t.Fatalf("ON: fast EP .7 (%d) must outweigh slow EP .8 (%d)", w["10.0.0.7"], w["10.0.0.8"])
	}
	invOn := on
	invOn.TtftInvert = true
	wi, _ := ComputeWeights(reg, samples, nil, invOn)
	if !(wi["10.0.0.8"] > wi["10.0.0.7"]) {
		t.Fatalf("INVERTED: slow EP .8 (%d) must outweigh fast EP .7 (%d)", wi["10.0.0.8"], wi["10.0.0.7"])
	}
	if (w["10.0.0.7"] > w["10.0.0.8"]) == (wi["10.0.0.7"] > wi["10.0.0.8"]) {
		t.Fatal("inversion did not change the ordering")
	}
}

// TestTtftAlphaDecay (the TTFT-03 decay-to-neutral proof): α=1 gives the
// full effect; α=0.5 gives EXACTLY half the pre-clamp delta (dw scales
// linearly and halving is exact in IEEE754); α=0 makes ComputeWeights
// byte-identical to OFF — a fully-decayed confidence is indistinguishable
// from the knob never having been armed.
func TestTtftAlphaDecay(t *testing.T) {
	base := EngineConfig{
		Now: testNow, TtftEnabled: true, TtftModel: ttftTestModel(),
	}.withDefaults()
	// Non-saturating rel: waiting 0 vs 0.2 ⇒ preds 6.5 vs 6.9, |rel|=0.2.
	feats := ttftFeatsFor(testNow, map[string]float64{"fast": 0, "slow": 0.2})

	full := base
	full.TtftAlpha = 1.0
	half := base
	half.TtftAlpha = 0.5

	dwFull := ttftCostTerm("fast", feats, full)
	if dwFull == 0 {
		t.Fatal("fixture broken: α=1 dw must be nonzero")
	}
	if dwFull >= full.TtftMaxPts {
		t.Fatalf("fixture broken: α=1 dw=%v saturated — the half-delta assertion needs pre-clamp headroom", dwFull)
	}
	if dwHalf := ttftCostTerm("fast", feats, half); dwHalf != dwFull/2 {
		t.Fatalf("α=0.5 dw=%v, want exactly half of α=1 dw (%v/2=%v)", dwHalf, dwFull, dwFull/2)
	}

	// α out-of-range is clamped on use: α>1 behaves as 1.
	over := base
	over.TtftAlpha = 7.0
	if dwOver := ttftCostTerm("fast", feats, over); dwOver != dwFull {
		t.Fatalf("α=7 dw=%v, want clamped-to-1 value %v", dwOver, dwFull)
	}

	// α=0 ⇒ byte-identical to OFF across damped epochs (fleet fixture).
	reg := fleetRegistry()
	samples := freshSamples(reg, testNow)
	divergent := ttftFeatsFor(testNow, map[string]float64{
		"10.0.0.7": 0, "10.0.0.8": 5.0, "10.0.0.9": 0.5,
		"10.0.0.11": 2.0, "10.0.0.10": 1.0,
	})
	offCfg := EngineConfig{Now: testNow, EwmaAlpha: 1.0}
	zeroCfg := offCfg
	zeroCfg.TtftEnabled = true
	zeroCfg.TtftModel = ttftTestModel()
	zeroCfg.TtftFeats = divergent
	zeroCfg.TtftAlpha = 0 // fully decayed
	var prev map[string]uint32
	for epoch := 0; epoch < 4; epoch++ {
		want, _ := ComputeWeights(reg, samples, prev, offCfg)
		got, _ := ComputeWeights(reg, samples, prev, zeroCfg)
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("epoch %d: α=0 not byte-identical to OFF\n off=%v\n α0 =%v", epoch, want, got)
		}
		prev = want
	}
}

// --- coefficients-file trust boundary ---

const ttftValidYaml = `model_version: 1
fit_date: "2026-07-06"
training_data_provenance:
  - "R-calibration-sweep"
features: ["intercept", "log_prompt_tokens", "waiting_over_capacity"]
coefficients: [0.5, 1.0, 2.0]
log_space: true
gate_thresholds:
  p50_rel_err: 0.30
  p90_rel_err: 1.00
  pairwise_accuracy: 0.70
  kendall_flag: 0.30
  censor_seconds: 30
  censored_frac_max: 0.05
gate_verdicts:
  gate1_prediction_error: "PASS"
  gate2_ranking: "PASS"
`

func writeTtftYaml(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ttft-coefficients.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadTtftModelRejects: every malformed-file class from the Task-1
// contract is rejected with its SPECIFIC error, and the valid fixture
// round-trips with Predict returning the hand-computed dot product.
func TestLoadTtftModelRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "length mismatch",
			mutate: func(y string) string {
				return strings.Replace(y, "coefficients: [0.5, 1.0, 2.0]", "coefficients: [0.5, 1.0]", 1)
			},
			wantErr: "length mismatch",
		},
		{
			name: "unknown feature name",
			mutate: func(y string) string {
				return strings.Replace(y, `"waiting_over_capacity"`, `"queue_depth"`, 1)
			},
			wantErr: "unknown feature",
		},
		{
			name: "coefficient beyond sanity bound",
			mutate: func(y string) string {
				return strings.Replace(y, "coefficients: [0.5, 1.0, 2.0]", "coefficients: [0.5, 1.0, 2000001.0]", 1)
			},
			wantErr: "sanity bound",
		},
		{
			name: "NaN coefficient",
			mutate: func(y string) string {
				return strings.Replace(y, "coefficients: [0.5, 1.0, 2.0]", "coefficients: [0.5, .nan, 2.0]", 1)
			},
			wantErr: "sanity bound",
		},
		{
			name: "log_space false",
			mutate: func(y string) string {
				return strings.Replace(y, "log_space: true", "log_space: false", 1)
			},
			wantErr: "log_space false",
		},
		{
			name: "unknown YAML field",
			mutate: func(y string) string {
				return y + "surprise_extra_field: 1\n"
			},
			wantErr: "surprise_extra_field",
		},
		{
			name: "model_version zero",
			mutate: func(y string) string {
				return strings.Replace(y, "model_version: 1", "model_version: 0", 1)
			},
			wantErr: "model_version",
		},
		{
			name: "intercept not first",
			mutate: func(y string) string {
				return strings.Replace(y,
					`features: ["intercept", "log_prompt_tokens", "waiting_over_capacity"]`,
					`features: ["log_prompt_tokens", "intercept", "waiting_over_capacity"]`, 1)
			},
			wantErr: "intercept",
		},
		{
			name: "duplicate feature",
			mutate: func(y string) string {
				return strings.Replace(y, `"waiting_over_capacity"`, `"log_prompt_tokens"`, 1)
			},
			wantErr: "duplicate feature",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTtftYaml(t, tc.mutate(ttftValidYaml))
			m, err := LoadTtftModel(p)
			if err == nil {
				t.Fatalf("LoadTtftModel accepted a %s file: %+v", tc.name, m)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}

	// Valid fixture round-trips…
	m, err := LoadTtftModel(writeTtftYaml(t, ttftValidYaml))
	if err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	if m.ModelVersion != 1 || !m.LogSpace {
		t.Fatalf("round-trip lost core fields: %+v", m)
	}
	if m.GateThresholds.P50RelErr != 0.30 || m.GateThresholds.CensorSeconds != 30 {
		t.Fatalf("gate thresholds did not round-trip: %+v", m.GateThresholds)
	}
	if m.GateVerdicts["gate1_prediction_error"] != "PASS" {
		t.Fatalf("gate verdicts did not round-trip: %+v", m.GateVerdicts)
	}
	// …and Predict returns the hand-computed dot product:
	// 0.5 (intercept) + 1.0×6 (log prompt) + 2.0×0.25 (waiting) = 7.0.
	if got := m.Predict(TtftFeatures{LogPromptTokens: 6, WaitingOverCapacity: 0.25}); got != 7.0 {
		t.Fatalf("Predict = %v, want hand-computed 7.0", got)
	}
}
