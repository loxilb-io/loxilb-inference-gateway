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

// ttft_wiring_test.go — /2 wiring tests: TTFT knob defaults +
// env override, boot-time coefficients resolution (empty ⇒ never loaded;
// armed-without-model ⇒ error; armed-with-failed-gates ⇒ error), the
// feature-snapshot JSONL writer (empty-never-started + contract shape +
// rotation), the per-epoch feature builder (calibrated-vs-prior
// capacity denominator), and the fingerprint verifier's transition-only
// WARN + every-epoch-counter + never-eligibility semantics.

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	flags "github.com/jessevdk/go-flags"

	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// TestCtrlOptionsTtftDefaults locks the TTFT-02/03 default-OFF contract
// : with no env set, the term is OFF, the bounded max-points +
// staleness budget hold the locked 15/15 defaults, the coefficients file is
// empty (model never loaded), invert is off, the reference prompt length is
// 4096, and the feature-snapshot path is empty (writer never started).
func TestCtrlOptionsTtftDefaults(t *testing.T) {
	for _, k := range []string{
		"AICTRL_TTFT_WEIGHT", "AICTRL_TTFT_MAX_PTS", "AICTRL_TTFT_STALE_SEC",
		"AICTRL_TTFT_COEF_FILE", "AICTRL_TTFT_INVERT",
		"AICTRL_TTFT_REF_PROMPT_TOKENS", "AICTRL_FEATURE_SNAP_FILE",
	} {
		if old, ok := os.LookupEnv(k); ok {
			os.Unsetenv(k)
			t.Cleanup(func() { os.Setenv(k, old) })
		}
	}

	var o CtrlOptions
	p := flags.NewParser(&o, flags.Default)
	if _, err := p.ParseArgs(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if o.TtftEnabled {
		t.Errorf("TtftEnabled default = true; want false (default-OFF contract)")
	}
	if o.TtftMaxPts != 15 {
		t.Errorf("TtftMaxPts default = %v; want 15", o.TtftMaxPts)
	}
	if o.TtftStaleSec != 15 {
		t.Errorf("TtftStaleSec default = %d; want 15", o.TtftStaleSec)
	}
	if o.TtftCoefFile != "" {
		t.Errorf("TtftCoefFile default = %q; want \"\" (model never loaded)", o.TtftCoefFile)
	}
	if o.TtftInvert {
		t.Errorf("TtftInvert default = true; want false")
	}
	if o.TtftRefPromptTokens != 4096 {
		t.Errorf("TtftRefPromptTokens default = %d; want 4096", o.TtftRefPromptTokens)
	}
	if o.FeatureSnapFile != "" {
		t.Errorf("FeatureSnapFile default = %q; want \"\" (writer never started)", o.FeatureSnapFile)
	}
}

// TestCtrlOptionsTtftEnvOverride proves all 7 AICTRL_TTFT_*/AICTRL_FEATURE_
// SNAP_FILE env vars parse and override — the knobs the ±TTFT A/B toggles.
func TestCtrlOptionsTtftEnvOverride(t *testing.T) {
	t.Setenv("AICTRL_TTFT_WEIGHT", "true")
	t.Setenv("AICTRL_TTFT_MAX_PTS", "22")
	t.Setenv("AICTRL_TTFT_STALE_SEC", "9")
	t.Setenv("AICTRL_TTFT_COEF_FILE", "/etc/loxilb/ttft.yaml")
	t.Setenv("AICTRL_TTFT_INVERT", "true")
	t.Setenv("AICTRL_TTFT_REF_PROMPT_TOKENS", "1024")
	t.Setenv("AICTRL_FEATURE_SNAP_FILE", "/root/aictrl-feature-snap.jsonl")

	var o CtrlOptions
	p := flags.NewParser(&o, flags.Default)
	if _, err := p.ParseArgs(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !o.TtftEnabled || o.TtftMaxPts != 22 || o.TtftStaleSec != 9 ||
		o.TtftCoefFile != "/etc/loxilb/ttft.yaml" || !o.TtftInvert ||
		o.TtftRefPromptTokens != 1024 ||
		o.FeatureSnapFile != "/root/aictrl-feature-snap.jsonl" {
		t.Errorf("env override mismatch: %+v", o)
	}
}

// fixtureCoefYAML writes a strict-loader-valid coefficients file and returns
// its path. verdict controls the recorded gate verdicts.
func fixtureCoefYAML(t *testing.T, verdict string) string {
	t.Helper()
	yml := `model_version: 3
fit_date: "2026-07-06"
training_data_provenance: ["fixture"]
features: ["intercept", "waiting_over_capacity"]
coefficients: [0.5, 1.0]
log_space: true
gate_thresholds:
  p50_rel_err: 0.30
  p90_rel_err: 1.00
  pairwise_accuracy: 0.70
  kendall_flag: 0.30
  censor_seconds: 30
  censored_frac_max: 0.05
gate_verdicts:
  gate1: ` + verdict + `
  gate2: PASS
`
	p := filepath.Join(t.TempDir(), "ttft-coefficients.yaml")
	if err := os.WriteFile(p, []byte(yml), 0644); err != nil {
		t.Fatalf("fixture write: %v", err)
	}
	return p
}

// TestLoadTtftModelStartup locks the boot-time resolution ladder:
// empty-and-unarmed ⇒ (nil, nil) — model NEVER loaded (structural OFF);
// empty-and-armed ⇒ error (arming without coefficients is a misconfig);
// invalid file ⇒ error (fail loud, V5); valid file ⇒ model; armed with a
// non-PASS gate verdict ⇒ error (: failed gates are never armed);
// UNARMED with failed verdicts ⇒ fine (observability mode).
func TestLoadTtftModelStartup(t *testing.T) {
	// Empty coef file, unarmed: structurally OFF, no load attempted.
	m, err := loadTtftModelStartup("", false)
	if m != nil || err != nil {
		t.Errorf("empty+unarmed = (%v, %v); want (nil, nil)", m, err)
	}

	// Empty coef file, ARMED: fatal-shaped error.
	if _, err := loadTtftModelStartup("", true); err == nil {
		t.Errorf("empty+armed: want error (arming without coefficients), got nil")
	}

	// Present-but-invalid file: error propagates (fail loud at boot).
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("not: [valid, ttft"), 0644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := loadTtftModelStartup(bad, false); err == nil {
		t.Errorf("invalid file: want error, got nil")
	}

	// Valid file, all PASS verdicts: loads armed and unarmed.
	good := fixtureCoefYAML(t, "PASS")
	m, err = loadTtftModelStartup(good, true)
	if err != nil || m == nil || m.ModelVersion != 3 {
		t.Errorf("valid+armed = (%+v, %v); want model_version 3, nil error", m, err)
	}

	// Failed gate verdict: UNARMED loads (observability), ARMED refused.
	failed := fixtureCoefYAML(t, "FAIL")
	if m, err := loadTtftModelStartup(failed, false); err != nil || m == nil {
		t.Errorf("failed-gates+unarmed = (%v, %v); want model, nil (observability)", m, err)
	}
	if _, err := loadTtftModelStartup(failed, true); err == nil {
		t.Errorf("failed-gates+armed: want error (never armed), got nil")
	}
}

// TestFeatureSnapWriterEmptyNeverStarted locks the empty-never-started
// discipline: an empty path yields a nil writer (no open, no write) and a
// nil writer's Append is a safe no-op.
func TestFeatureSnapWriterEmptyNeverStarted(t *testing.T) {
	w, err := newFeatureSnapWriter("", 0)
	if w != nil || err != nil {
		t.Fatalf("newFeatureSnapWriter(\"\") = (%v, %v); want (nil, nil)", w, err)
	}
	if err := w.Append(featureSnapRow{}); err != nil { // nil-safe
		t.Errorf("nil writer Append = %v; want nil", err)
	}
}

// TestFeatureSnapWriterContract writes rows and re-reads them through the
// EXACT cmd/aictrl-ttft-fit SnapshotRecord shape ({ts, ep, features{...}}):
// the JSONL this controller emits must ingest field-for-field in the offline
// fit tool, with prompt length ABSENT from the row.
func TestFeatureSnapWriterContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.jsonl")
	w, err := newFeatureSnapWriter(path, 0)
	if err != nil || w == nil {
		t.Fatalf("writer: (%v, %v)", w, err)
	}
	defer w.Close()

	feats := engine.TtftFeatures{
		LogPromptTokens:     8.3, // must NOT appear in the row
		WaitingOverCapacity: 2.5,
		KvCacheUsagePerc:    0.7,
		FetchCost:           0.4,
		MatchedPrefixSat:    0.1,
	}
	row := featureSnapRow{
		TS: 1783300000, Epoch: 7, EP: "10.0.0.5:8100",
		Features: snapFeatureMap(feats), Alpha: 0.8, Armed: true,
	}
	if err := w.Append(row); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Re-read through the fit tool's contract shape (fit.go SnapshotRecord).
	type snapshotRecord struct {
		TS       float64            `json:"ts"`
		EP       string             `json:"ep"`
		Features map[string]float64 `json:"features"`
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("no JSONL line written")
	}
	var got snapshotRecord
	if err := json.Unmarshal(sc.Bytes(), &got); err != nil {
		t.Fatalf("contract unmarshal: %v", err)
	}
	if got.TS != 1783300000 || got.EP != "10.0.0.5:8100" {
		t.Errorf("ts/ep = %v/%q; want 1783300000/10.0.0.5:8100", got.TS, got.EP)
	}
	if got.Features[engine.TtftFeatWaitingOverCapacity] != 2.5 ||
		got.Features[engine.TtftFeatKvCacheUsagePerc] != 0.7 ||
		got.Features[engine.TtftFeatFetchCost] != 0.4 ||
		got.Features[engine.TtftFeatMatchedPrefixSat] != 0.1 {
		t.Errorf("epoch-signal features mismatch: %v", got.Features)
	}
	if _, present := got.Features[engine.TtftFeatLogPromptTokens]; present {
		t.Errorf("log_prompt_tokens leaked into the snapshot row (per-request covariate only)")
	}
	if _, present := got.Features[engine.TtftFeatIntercept]; present {
		t.Errorf("intercept leaked into the snapshot row")
	}
}

// TestFeatureSnapWriterRotation locks the size-capped rotation: once the cap
// is exceeded the live file is renamed to .1 and writing continues fresh.
func TestFeatureSnapWriterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.jsonl")
	w, err := newFeatureSnapWriter(path, 64) // tiny cap: rotate after ~1 row
	if err != nil || w == nil {
		t.Fatalf("writer: (%v, %v)", w, err)
	}
	defer w.Close()

	row := featureSnapRow{TS: 1, EP: "10.0.0.5:8100",
		Features: map[string]float64{engine.TtftFeatKvCacheUsagePerc: 0.5}}
	for i := 0; i < 3; i++ {
		row.Epoch = uint64(i)
		if err := w.Append(row); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("rotation: %s.1 missing after cap breach: %v", path, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("rotation: live file %s missing after rotation: %v", path, err)
	}
}

// fixtureRegistry builds a two-prefill registry: .5 carries a calibration
// block (ratio 2.0) over a 1.0 prior; .6 is prior-only.
func fixtureRegistry() *engine.Registry {
	return &engine.Registry{
		Version: 1,
		Service: engine.ServiceDecl{Key: "10.0.0.12:9003:tcp"},
		Hosts: map[string]*engine.Host{
			"10.0.0.5": {
				GPUModel: "L40S", Role: engine.RolePrefill, Port: 8100, EpIdx: 0,
				ExpectedNumGPUBlocks: 32600, ServingThroughputPrior: 1.0,
				Calibration: &engine.CalibrationDecl{
					ThroughputTokensPerSec: 4200, ThroughputRatio: 2.0,
					Fingerprint: "0123456789abcdef",
					FingerprintFields: map[string]string{
						engine.FpNumGpuBlocks: "32600",
					},
				},
			},
			"10.0.0.6": {
				GPUModel: "L4", Role: engine.RolePrefill, Port: 8100, EpIdx: 1,
				ExpectedNumGPUBlocks: 7408, ServingThroughputPrior: 1.0,
			},
		},
	}
}

// TestBuildTtftFeaturesCapacityFallback locks consumption site: the
// waiting_over_capacity denominator is the CALIBRATED ratio only when the
// fingerprint verified; unverified/mismatched ⇒ serving_throughput_prior.
func TestBuildTtftFeaturesCapacityFallback(t *testing.T) {
	reg := fixtureRegistry()
	now := time.Now()
	samples := map[string]engine.Sourced{
		"10.0.0.5": {IP: "10.0.0.5", Sample: aimetrics.WorkerSample{
			NumRequestsWaiting: 10, GPUCacheUsagePerc: 0.6, LastUpdate: now}},
	}

	// Verified: denominator = calibrated ratio 2.0 ⇒ 10/2.0 = 5.
	feats := buildTtftFeatures(reg, samples, nil, 8.0,
		map[string]bool{"10.0.0.5": true}, now, 15*time.Second)
	if got := feats["10.0.0.5"].WaitingOverCapacity; got != 5.0 {
		t.Errorf("verified WaitingOverCapacity = %v; want 5.0 (calibrated ratio 2.0)", got)
	}

	// Unverified (mismatched fingerprint): denominator = prior 1.0 ⇒ 10.
	feats = buildTtftFeatures(reg, samples, nil, 8.0, nil, now, 15*time.Second)
	if got := feats["10.0.0.5"].WaitingOverCapacity; got != 10.0 {
		t.Errorf("unverified WaitingOverCapacity = %v; want 10.0 (prior fallback)", got)
	}
	if got := feats["10.0.0.5"].KvCacheUsagePerc; got != 0.6 {
		t.Errorf("KvCacheUsagePerc = %v; want 0.6", got)
	}
	if got := feats["10.0.0.5"].LogPromptTokens; got != 8.0 {
		t.Errorf("LogPromptTokens = %v; want the reference 8.0", got)
	}

	// EP with no sample at all ⇒ NO entry (absent ⇒ engine-neutral decay).
	if _, present := feats["10.0.0.6"]; present {
		t.Errorf("sample-less EP got a feature entry; want absent (never zero-fill)")
	}
}

// TestBuildTtftFeaturesLmcSlots locks the LMCache-sourced slots: fresh lmc
// signal fills fetch_cost/matched_prefix_sat (saturating, hit-rate-adjusted);
// a STALE lmc signal decays both slots to 0 (neutral, never zero-fill trust).
func TestBuildTtftFeaturesLmcSlots(t *testing.T) {
	reg := fixtureRegistry()
	now := time.Now()
	samples := map[string]engine.Sourced{
		"10.0.0.5": {IP: "10.0.0.5", Sample: aimetrics.WorkerSample{LastUpdate: now}},
	}
	lmcFresh := map[string]aimetrics.WorkerSample{
		"10.0.0.5": {LastUpdate: now, Raw: map[string]float64{
			aimetrics.FamilyLMCacheTimeToRetrieve:  0.05, // == midpoint
			aimetrics.FamilyLMCacheRetrieveHitRate: 1.0,  // no adjustment
			aimetrics.RawKeyMatchedPrefixLength:    512,  // == midpoint
		}},
	}

	feats := buildTtftFeatures(reg, samples, lmcFresh, 8.0, nil, now, 15*time.Second)
	f := feats["10.0.0.5"]
	if f.FetchCost != 0.5 { // sat(0.05/1.0, 0.05) = 0.5
		t.Errorf("FetchCost = %v; want 0.5 (midpoint saturation)", f.FetchCost)
	}
	if f.MatchedPrefixSat != 0.5 { // sat(512, 512) = 0.5
		t.Errorf("MatchedPrefixSat = %v; want 0.5 (midpoint saturation)", f.MatchedPrefixSat)
	}

	// Hit-rate adjustment: hr=0.5 doubles the effective retrieve cost.
	lmcFresh["10.0.0.5"].Raw[aimetrics.FamilyLMCacheRetrieveHitRate] = 0.5
	f = buildTtftFeatures(reg, samples, lmcFresh, 8.0, nil, now, 15*time.Second)["10.0.0.5"]
	want := satFrac(0.1, ttftFetchCostSoftScaleSec)
	if f.FetchCost != want {
		t.Errorf("FetchCost hr=0.5 = %v; want %v (cost/hit-rate composite)", f.FetchCost, want)
	}

	// Stale lmc signal ⇒ both slots 0 (neutral).
	lmcStale := map[string]aimetrics.WorkerSample{
		"10.0.0.5": {LastUpdate: now.Add(-time.Minute), Raw: lmcFresh["10.0.0.5"].Raw},
	}
	f = buildTtftFeatures(reg, samples, lmcStale, 8.0, nil, now, 15*time.Second)["10.0.0.5"]
	if f.FetchCost != 0 || f.MatchedPrefixSat != 0 {
		t.Errorf("stale lmc slots = (%v, %v); want (0, 0) neutral decay", f.FetchCost, f.MatchedPrefixSat)
	}
}

// sampleWithBlocks builds a fresh Sourced sample advertising numGPUBlocks.
func sampleWithBlocks(ip string, blocks uint32, now time.Time) engine.Sourced {
	return engine.Sourced{IP: ip, Sample: aimetrics.WorkerSample{
		NumGPUBlocks: blocks, LastUpdate: now}}
}

// TestFpVerifierTransitionOnlyWarn locks /96 mismatch shape: the
// counter feed (Mismatches) fires EVERY mismatched epoch; the WARN feed
// (WarnDue) fires on TRANSITION only (new mismatch, or a mismatch whose
// discovered value changed); recovery flips Verified back and reports once.
func TestFpVerifierTransitionOnlyWarn(t *testing.T) {
	reg := fixtureRegistry() // .5 calibrated expecting num_gpu_blocks=32600
	now := time.Now()
	v := newFpVerifier()

	// Epoch 1: mismatched fixture (discovered 30000 ≠ declared 32600).
	res := v.VerifyEpoch(reg, map[string]engine.Sourced{
		"10.0.0.5": sampleWithBlocks("10.0.0.5", 30000, now)})
	if len(res.Mismatches) != 1 || res.Mismatches[0].Field != engine.FpNumGpuBlocks {
		t.Fatalf("epoch1 mismatches = %+v; want one num_gpu_blocks mismatch", res.Mismatches)
	}
	if _, due := res.WarnDue["10.0.0.5"]; !due {
		t.Errorf("epoch1: WARN not due on first mismatch (transition)")
	}
	if res.Verified["10.0.0.5"] {
		t.Errorf("epoch1: mismatched fingerprint marked verified")
	}

	// Epoch 2: SAME mismatch — counter feed again, WARN suppressed.
	res = v.VerifyEpoch(reg, map[string]engine.Sourced{
		"10.0.0.5": sampleWithBlocks("10.0.0.5", 30000, now)})
	if len(res.Mismatches) != 1 {
		t.Errorf("epoch2 mismatches = %d; want 1 (counter EVERY mismatched epoch)", len(res.Mismatches))
	}
	if _, due := res.WarnDue["10.0.0.5"]; due {
		t.Errorf("epoch2: WARN fired again for an unchanged mismatch (want transition-only)")
	}

	// Epoch 3: discovered value CHANGES — a new transition, WARN due again.
	res = v.VerifyEpoch(reg, map[string]engine.Sourced{
		"10.0.0.5": sampleWithBlocks("10.0.0.5", 29000, now)})
	if _, due := res.WarnDue["10.0.0.5"]; !due {
		t.Errorf("epoch3: WARN not due after the discovered value changed")
	}

	// Epoch 4: discovery matches the declaration — verified + recovery once.
	res = v.VerifyEpoch(reg, map[string]engine.Sourced{
		"10.0.0.5": sampleWithBlocks("10.0.0.5", 32600, now)})
	if !res.Verified["10.0.0.5"] || len(res.Mismatches) != 0 {
		t.Errorf("epoch4: match not verified (verified=%v mismatches=%d)",
			res.Verified["10.0.0.5"], len(res.Mismatches))
	}
	if len(res.Recovered) != 1 || res.Recovered[0] != "10.0.0.5" {
		t.Errorf("epoch4 recovered = %v; want [10.0.0.5]", res.Recovered)
	}
	// Epoch 5: still matching — no repeat recovery INFO.
	res = v.VerifyEpoch(reg, map[string]engine.Sourced{
		"10.0.0.5": sampleWithBlocks("10.0.0.5", 32600, now)})
	if len(res.Recovered) != 0 {
		t.Errorf("epoch5 recovered = %v; want none (report once)", res.Recovered)
	}
}

// TestFpVerifierNothingToVerify locks the unverified-by-default posture:
// no calibration block, no sample, or no discoverable capacity yet all mean
// UNVERIFIED (prior path) with zero mismatches and zero WARNs — nothing to
// verify is NOT a mismatch.
func TestFpVerifierNothingToVerify(t *testing.T) {
	reg := fixtureRegistry()
	now := time.Now()
	v := newFpVerifier()

	// .6 has no calibration; .5 scraped but no capacity label yet (blocks=0).
	res := v.VerifyEpoch(reg, map[string]engine.Sourced{
		"10.0.0.5": sampleWithBlocks("10.0.0.5", 0, now),
		"10.0.0.6": sampleWithBlocks("10.0.0.6", 7408, now),
	})
	if len(res.Mismatches) != 0 || len(res.WarnDue) != 0 {
		t.Errorf("nothing-to-verify produced mismatches/WARNs: %+v / %+v", res.Mismatches, res.WarnDue)
	}
	if res.Verified["10.0.0.5"] || res.Verified["10.0.0.6"] {
		t.Errorf("verified without evidence: %+v (want unverified ⇒ prior)", res.Verified)
	}
}

// TestFingerprintFallbackThroughComputeWeights proves fallback END
// TO END: with the TTFT term armed, a MISMATCHED fingerprint keeps the
// waiting_over_capacity denominator on ServingThroughputPrior, so the
// weights equal the pure-prior reference; a VERIFIED fingerprint switches to
// the calibrated ratio and the weights move. Eligibility is untouched on the
// mismatch path: every host keeps its weight-map entry with w ≥ 1.
func TestFingerprintFallbackThroughComputeWeights(t *testing.T) {
	reg := fixtureRegistry()
	now := time.Now()
	model, err := engine.LoadTtftModel(fixtureCoefYAML(t, "PASS"))
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	samples := map[string]engine.Sourced{
		"10.0.0.5": {IP: "10.0.0.5", Sample: aimetrics.WorkerSample{
			NumRequestsWaiting: 10, NumGPUBlocks: 30000, LastUpdate: now}}, // MISMATCH (≠32600)
		"10.0.0.6": {IP: "10.0.0.6", Sample: aimetrics.WorkerSample{
			NumRequestsWaiting: 10, NumGPUBlocks: 7408, LastUpdate: now}},
	}
	cfg := engine.EngineConfig{
		Now:       now,
		EwmaAlpha: 1.0, DeadBand: 1, // undamped-ish: expose the term movement
		TtftEnabled: true, TtftModel: model, TtftAlpha: 1.0,
	}
	weights := func(verified map[string]bool) map[string]uint32 {
		c := cfg
		c.TtftFeats = buildTtftFeatures(reg, samples, nil, 8.0, verified, now, 15*time.Second)
		w, _ := engine.ComputeWeights(reg, samples, nil, c)
		return w
	}

	// Mismatched (unverified): both EPs on the 1.0 prior ⇒ identical features
	// ⇒ TTFT term neutral ⇒ the pure-prior reference {100, 100}.
	mismatched := weights(nil)
	if mismatched["10.0.0.5"] != 100 || mismatched["10.0.0.6"] != 100 {
		t.Errorf("mismatched-fingerprint weights = %v; want the ServingThroughputPrior reference {100,100} (fallback)", mismatched)
	}
	// Eligibility untouched: every registry host present, never zeroed.
	for ip := range reg.Hosts {
		w, ok := mismatched[ip]
		if !ok || w < 1 {
			t.Errorf("mismatch path touched eligibility for %s (w=%d present=%v)", ip, w, ok)
		}
	}

	// Verified: .5's denominator becomes the calibrated ratio 2.0 ⇒ its
	// predicted E[TTFT] drops below the fleet mean ⇒ .5 bonused, .6 biased
	// down — the calibrated ratio is demonstrably IN the weight math now.
	verified := weights(map[string]bool{"10.0.0.5": true})
	if verified["10.0.0.6"] >= 100 || verified["10.0.0.5"] != 100 {
		t.Errorf("verified weights = %v; want .5=100 and .6<100 (calibrated ratio consumed)", verified)
	}
	if verified["10.0.0.6"] == mismatched["10.0.0.6"] {
		t.Errorf("verified and mismatched weights identical — the fingerprint flag is not gating CalibratedThroughputRatio")
	}
}
