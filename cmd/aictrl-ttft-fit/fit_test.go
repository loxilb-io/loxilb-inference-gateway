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

// fit_test.go — β recovery, ingest/attribution, censoring, and the
// engine round-trip fixtures.
//
// The round-trip test imports pkg/aictrl/engine — the ONLY sanctioned
// cross-import direction (tool→engine): the emitted YAML must strict-load
// and the runtime dot product must BE the fit's model.

package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
)

// trueBeta is the synthetic ground truth over the REAL vocabulary.
var trueBeta = map[string]float64{
	engine.TtftFeatIntercept:           1.2,
	engine.TtftFeatLogPromptTokens:     0.35,
	engine.TtftFeatWaitingOverCapacity: 0.8,
	engine.TtftFeatKvCacheUsagePerc:    1.5,
	engine.TtftFeatFetchCost:           0.25,
	engine.TtftFeatMatchedPrefixSat:    -0.6,
}

// synthRows generates n rows from trueBeta over varying features with
// N(0, noise) log-space error. Deterministic (fixed seed).
func synthRows(n int, noise float64, constantMatchedPrefix bool) []Row {
	r := rand.New(rand.NewSource(42))
	rows := make([]Row, 0, n)
	for i := 0; i < n; i++ {
		tokens := math.Exp(6.0 + 4.4*r.Float64()) // ~403..32,860 tokens
		matched := r.Float64()
		if constantMatchedPrefix {
			matched = 0 // the locality feature is all-zero until
		}
		feats := map[string]float64{
			engine.TtftFeatWaitingOverCapacity: 3 * r.Float64(),
			engine.TtftFeatKvCacheUsagePerc:    r.Float64(),
			engine.TtftFeatFetchCost:           2 * r.Float64(),
			engine.TtftFeatMatchedPrefixSat:    matched,
		}
		logT := trueBeta[engine.TtftFeatIntercept] +
			trueBeta[engine.TtftFeatLogPromptTokens]*math.Log(tokens) +
			trueBeta[engine.TtftFeatWaitingOverCapacity]*feats[engine.TtftFeatWaitingOverCapacity] +
			trueBeta[engine.TtftFeatKvCacheUsagePerc]*feats[engine.TtftFeatKvCacheUsagePerc] +
			trueBeta[engine.TtftFeatFetchCost]*feats[engine.TtftFeatFetchCost] +
			trueBeta[engine.TtftFeatMatchedPrefixSat]*feats[engine.TtftFeatMatchedPrefixSat]
		if noise > 0 {
			logT += noise * r.NormFloat64()
		}
		ts := float64(i)
		rows = append(rows, Row{
			Req: RequestRecord{
				TTFTSec:      math.Exp(logT),
				PromptTokens: tokens,
				EP:           "10.0.0.11:8100",
				TS:           ts,
				RateLabel:    "1.0",
				Source:       "synthetic",
			},
			Snap:    &SnapshotRecord{TS: ts - 0.5, EP: "10.0.0.11:8100", Features: feats},
			LogTTFT: logT,
		})
	}
	return rows
}

func coefByName(t *testing.T, fit *FitResult, name string) float64 {
	t.Helper()
	for i, f := range fit.Features {
		if f == name {
			return fit.Coefficients[i]
		}
	}
	t.Fatalf("feature %q not in fit features %v", name, fit.Features)
	return 0
}

// TestBetaRecoveryZeroNoise: on noiseless synthetic data the QR fit must
// recover each β EXACTLY (to float precision).
func TestBetaRecoveryZeroNoise(t *testing.T) {
	fit, err := fitOLS(synthRows(500, 0, false), io.Discard)
	if err != nil {
		t.Fatalf("fitOLS: %v", err)
	}
	if len(fit.Dropped) != 0 {
		t.Fatalf("unexpected dropped features: %v", fit.Dropped)
	}
	for name, want := range trueBeta {
		got := coefByName(t, fit, name)
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("β[%s] = %.12f, want %.12f (zero-noise recovery must be exact)", name, got, want)
		}
	}
	if fit.R2 < 1-1e-12 {
		t.Errorf("zero-noise R² = %v, want ≈1", fit.R2)
	}
}

// TestBetaRecoveryWithNoise: with small log-space noise every β is
// recovered within tolerance.
func TestBetaRecoveryWithNoise(t *testing.T) {
	fit, err := fitOLS(synthRows(500, 0.05, false), io.Discard)
	if err != nil {
		t.Fatalf("fitOLS: %v", err)
	}
	for name, want := range trueBeta {
		got := coefByName(t, fit, name)
		if math.Abs(got-want) > 0.05 {
			t.Errorf("β[%s] = %.4f, want %.4f ± 0.05", name, got, want)
		}
	}
}

// TestZeroVarianceDrop: a constant feature (the all-zero locality column
// until) must be DROPPED with a loud report line naming it — never
// allowed to make X silently rank-deficient.
func TestZeroVarianceDrop(t *testing.T) {
	var report bytes.Buffer
	fit, err := fitOLS(synthRows(200, 0, true), &report)
	if err != nil {
		t.Fatalf("fitOLS: %v", err)
	}
	if len(fit.Dropped) != 1 || fit.Dropped[0] != engine.TtftFeatMatchedPrefixSat {
		t.Fatalf("Dropped = %v, want [%s]", fit.Dropped, engine.TtftFeatMatchedPrefixSat)
	}
	for _, f := range fit.Features {
		if f == engine.TtftFeatMatchedPrefixSat {
			t.Fatalf("dropped feature still in fit features %v", fit.Features)
		}
	}
	if !strings.Contains(report.String(), `DROP zero-variance feature "matched_prefix_sat"`) {
		t.Fatalf("report missing the loud DROP line:\n%s", report.String())
	}
	// The surviving βs must still be recovered exactly.
	for _, name := range fit.Features {
		if math.Abs(coefByName(t, fit, name)-trueBeta[name]) > 1e-9 {
			t.Errorf("β[%s] drifted after the drop", name)
		}
	}
}

// TestRankDeficientHardError: a duplicated column (perfect collinearity
// that zero-variance dropping cannot catch) must be a HARD error naming
// collinear column candidates.
func TestRankDeficientHardError(t *testing.T) {
	rows := synthRows(100, 0, false)
	for i := range rows {
		// fetch_cost := exact copy of kv_cache_usage_perc ⇒ X rank-deficient.
		rows[i].Snap.Features[engine.TtftFeatFetchCost] =
			rows[i].Snap.Features[engine.TtftFeatKvCacheUsagePerc]
	}
	_, err := fitOLS(rows, io.Discard)
	if err == nil {
		t.Fatal("fitOLS accepted a rank-deficient design matrix")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rank-deficient") ||
		!strings.Contains(msg, engine.TtftFeatFetchCost) ||
		!strings.Contains(msg, engine.TtftFeatKvCacheUsagePerc) {
		t.Fatalf("error must name the collinear columns, got: %v", err)
	}
}

// TestPrefillAddrParsing: x-request-id contract — the FULL
// ___prefill_addr_<IP:PORT>___decode_addr_<IP:PORT>_<hexid> shape.
func TestPrefillAddrParsing(t *testing.T) {
	line := `{"x_request_id":"chatcmpl-9f2___prefill_addr_10.0.0.11:8100___decode_addr_10.0.0.10:8200_a1b2c3d4",` +
		`"metrics":{"time_to_first_token":{"value":110.5,"unit":"ms"},` +
		`"input_sequence_length":{"value":4096},` +
		`"timestamp_ns":1783300000123456789}}`
	rec, reason, ok := parseAiperfLine([]byte(line), "f.jsonl", "1.0")
	if !ok {
		t.Fatalf("parse failed: %s", reason)
	}
	if rec.EP != "10.0.0.11:8100" {
		t.Errorf("EP = %q, want prefill addr 10.0.0.11:8100 (never the decode addr)", rec.EP)
	}
	if math.Abs(rec.TTFTSec-0.1105) > 1e-12 {
		t.Errorf("TTFTSec = %v, want 0.1105 (ms→s)", rec.TTFTSec)
	}
	if rec.PromptTokens != 4096 {
		t.Errorf("PromptTokens = %v, want 4096", rec.PromptTokens)
	}
	if math.Abs(rec.TS-1783300000.123456789) > 1e-3 {
		t.Errorf("TS = %v, want ns-normalized 1783300000.123", rec.TS)
	}

	cases := []struct {
		name, line, reason string
	}{
		{"errored", `{"error":{"code":400,"message":"boom"},"metrics":{}}`, "errored"},
		{"no-addr", `{"metrics":{"time_to_first_token":{"value":100},"input_sequence_length":{"value":10},"timestamp":1783300000}}`, "no-prefill-addr"},
		{"no-ttft", `{"x_request_id":"___prefill_addr_10.0.0.11:8100___decode_addr_10.0.0.10:8200_ff","metrics":{"input_sequence_length":{"value":10}}}`, "no-ttft"},
	}
	for _, c := range cases {
		_, reason, ok := parseAiperfLine([]byte(c.line), "f", "1.0")
		if ok || reason != c.reason {
			t.Errorf("%s: got (ok=%v, reason=%q), want reason %q", c.name, ok, reason, c.reason)
		}
	}
}

// TestRateLabelFromPath: campaign-path rate attribution ("rep1" must not
// look like a rate).
func TestRateLabelFromPath(t *testing.T) {
	cases := map[string]string{
		"/rd/7arm/adaptive-r1.0/mooncake/rep2/genai_perf/profile_export.jsonl": "1.0",
		"/rd/goodput-https-r0.5/rep1/profile_export.jsonl":                     "0.5",
		"/rd/rate-2.0/profile_export.jsonl":                                    "2.0",
		"/rd/rep1/profile_export.jsonl":                                        "all",
		"/rd/warmup/profile_export.jsonl":                                      "all",
	}
	for path, want := range cases {
		if got := rateLabelFromPath(path); got != want {
			t.Errorf("rateLabelFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestJoinAndCensor: nearest-preceding snapshot join + the §RQ5 censor
// mark; a request with no preceding snapshot is excluded loudly.
func TestJoinAndCensor(t *testing.T) {
	snaps := map[string][]SnapshotRecord{
		"10.0.0.11:8100": {
			{TS: 100, EP: "10.0.0.11:8100", Features: map[string]float64{engine.TtftFeatWaitingOverCapacity: 1}},
			{TS: 200, EP: "10.0.0.11:8100", Features: map[string]float64{engine.TtftFeatWaitingOverCapacity: 2}},
		},
	}
	reqs := []RequestRecord{
		{TTFTSec: 0.5, PromptTokens: 100, EP: "10.0.0.11:8100", TS: 150},  // joins snap@100
		{TTFTSec: 40.0, PromptTokens: 100, EP: "10.0.0.11:8100", TS: 250}, // joins snap@200, CENSORED (>30s)
		{TTFTSec: 0.5, PromptTokens: 100, EP: "10.0.0.11:8100", TS: 50},   // NO preceding snapshot
		{TTFTSec: 0.5, PromptTokens: 100, EP: "10.0.0.99:8100", TS: 150},  // unknown EP
	}
	var report bytes.Buffer
	rows, st := joinRows(reqs, snaps, defaultCensorSeconds, &report)
	if st.Joined != 2 || st.NoSnapshot != 2 {
		t.Fatalf("join stats = %+v, want Joined=2 NoSnapshot=2", st)
	}
	if rows[0].Censored || rows[0].Snap.TS != 100 {
		t.Errorf("row0: censored=%v snapTS=%v, want uncensored joined to snap@100", rows[0].Censored, rows[0].Snap.TS)
	}
	if !rows[1].Censored || rows[1].Snap.TS != 200 {
		t.Errorf("row1: censored=%v snapTS=%v, want CENSORED joined to snap@200", rows[1].Censored, rows[1].Snap.TS)
	}
	if !strings.Contains(report.String(), "no-preceding-snapshot=2") {
		t.Errorf("report must count the excluded joins:\n%s", report.String())
	}
	// fitOLS must train on the uncensored subset only.
	train := synthRows(60, 0, false)
	train[7].Censored = true
	train[13].Censored = true
	fit, err := fitOLS(train, io.Discard)
	if err != nil {
		t.Fatalf("fitOLS: %v", err)
	}
	if len(fit.Rows) != 58 {
		t.Fatalf("fit trained on %d rows, want 58 (censored EXCLUDED from the fit)", len(fit.Rows))
	}
}

// TestIngestRequests: end-to-end file ingest with per-reason skip counts.
func TestIngestRequests(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"x_request_id":"___prefill_addr_10.0.0.11:8100___decode_addr_10.0.0.10:8200_ff","metrics":{"time_to_first_token":{"value":250},"input_sequence_length":{"value":1024},"timestamp":1783300000}}`,
		`{"error":{"code":400,"message":"boom"}}`,
		`{"metrics":{"time_to_first_token":{"value":250},"input_sequence_length":{"value":1024},"timestamp":1783300001}}`,
	}
	path := filepath.Join(dir, "arm-r1.0")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "profile_export.jsonl"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reqs, st, err := ingestRequests(filepath.Join(dir, "*", "profile_export.jsonl"), "", io.Discard)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if st.Parsed != 1 || st.Errored != 1 || st.NoEP != 1 {
		t.Fatalf("stats = %+v, want Parsed=1 Errored=1 NoEP=1", st)
	}
	if reqs[0].RateLabel != "1.0" {
		t.Errorf("rate label = %q, want path-attributed 1.0", reqs[0].RateLabel)
	}
}

// TestRoundTrip: fit a fixture → emit YAML → engine.LoadTtftModel →
// Predict on the training rows equals the tool's fitted values within
// 1e-9. The runtime dot product IS the fit's model (key link).
func TestRoundTrip(t *testing.T) {
	rows := synthRows(300, 0.05, false)
	fit, err := fitOLS(rows, io.Discard)
	if err != nil {
		t.Fatalf("fitOLS: %v", err)
	}
	thresholds := engine.TtftGateThresholds{
		P50RelErr:        defaultGate1P50RelErr,
		P90RelErr:        defaultGate1P90RelErr,
		PairwiseAccuracy: defaultGate2PairwiseAccuracy,
		KendallFlag:      defaultKendallFlagTau,
		CensorSeconds:    defaultCensorSeconds,
		CensoredFracMax:  defaultCensoredFracMax,
	}
	verdicts := map[string]string{
		"gate1": "PASS", "gate2": "PASS", "censored_fraction": "PASS", "overall": "PASS",
	}
	model := buildModel(fit, thresholds, verdicts,
		[]string{"synthetic-fixture", "ttft-unit:log-seconds"}, 1, "2026-07-06T00:00:00Z")
	path := filepath.Join(t.TempDir(), "ttft-coefficients.yaml")
	if err := emitModel(model, path); err != nil {
		t.Fatalf("emitModel: %v", err)
	}

	loaded, err := engine.LoadTtftModel(path)
	if err != nil {
		t.Fatalf("engine.LoadTtftModel rejected the tool's emission (round-trip broken): %v", err)
	}
	if fmt.Sprintf("%v", loaded.Features) != fmt.Sprintf("%v", fit.Features) {
		t.Fatalf("features drifted through the YAML: %v vs %v", loaded.Features, fit.Features)
	}
	if loaded.GateVerdicts["overall"] != "PASS" || !loaded.LogSpace {
		t.Fatalf("verdicts/log_space drifted: %+v log=%v", loaded.GateVerdicts, loaded.LogSpace)
	}
	for i, r := range fit.Rows {
		pred := loaded.Predict(engine.TtftFeatures{
			LogPromptTokens:     math.Log(r.Req.PromptTokens),
			WaitingOverCapacity: r.Snap.Features[engine.TtftFeatWaitingOverCapacity],
			KvCacheUsagePerc:    r.Snap.Features[engine.TtftFeatKvCacheUsagePerc],
			FetchCost:           r.Snap.Features[engine.TtftFeatFetchCost],
			MatchedPrefixSat:    r.Snap.Features[engine.TtftFeatMatchedPrefixSat],
		})
		if math.Abs(pred-r.Fitted) > 1e-9 {
			t.Fatalf("row %d: engine Predict %.15f != fitted %.15f (Δ=%g > 1e-9)",
				i, pred, r.Fitted, math.Abs(pred-r.Fitted))
		}
	}
}

// TestRoundTripAfterDrop: the emitted model must also round-trip when the
// zero-variance locality column was dropped (reality until
// enables /lookup).
func TestRoundTripAfterDrop(t *testing.T) {
	fit, err := fitOLS(synthRows(200, 0, true), io.Discard)
	if err != nil {
		t.Fatalf("fitOLS: %v", err)
	}
	model := buildModel(fit, engine.TtftGateThresholds{
		P50RelErr: defaultGate1P50RelErr, P90RelErr: defaultGate1P90RelErr,
		PairwiseAccuracy: defaultGate2PairwiseAccuracy, KendallFlag: defaultKendallFlagTau,
		CensorSeconds: defaultCensorSeconds, CensoredFracMax: defaultCensoredFracMax,
	}, map[string]string{"overall": "PASS"}, []string{"fixture"}, 1, "2026-07-06T00:00:00Z")
	path := filepath.Join(t.TempDir(), "coef.yaml")
	if err := emitModel(model, path); err != nil {
		t.Fatalf("emitModel: %v", err)
	}
	loaded, err := engine.LoadTtftModel(path)
	if err != nil {
		t.Fatalf("strict loader rejected the reduced-vocabulary emission: %v", err)
	}
	for _, f := range loaded.Features {
		if f == engine.TtftFeatMatchedPrefixSat {
			t.Fatal("dropped feature leaked into the emitted model")
		}
	}
}
