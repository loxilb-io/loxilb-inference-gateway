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

// gates_test.go — Gate 1/2 math, censored-fraction, minimum-power, and
// worst-gated-cell fixtures (§RQ3/§RQ4/§RQ5).

package main

import (
	"io"
	"math"
	"testing"

	"gonum.org/v1/gonum/stat"

	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
)

// testGateConfig returns the pre-registered defaults as a GateConfig
// (rate 2.0 INFO-only, reference prompt 8000 tokens).
func testGateConfig() GateConfig {
	return GateConfig{
		Gate1P50:           defaultGate1P50RelErr,
		Gate1P90:           defaultGate1P90RelErr,
		Gate2Accuracy:      defaultGate2PairwiseAccuracy,
		KendallFlag:        defaultKendallFlagTau,
		CensorSec:          defaultCensorSeconds,
		CensoredFracMax:    defaultCensoredFracMax,
		MinCellRequests:    defaultMinCellRequests,
		MinWindowPairs:     defaultMinWindowPairs,
		WindowSec:          defaultWindowSeconds,
		RefLogPromptTokens: math.Log(8000),
		InfoRates:          map[string]bool{defaultInfoRate: true},
		BucketEdges:        defaultBucketEdges(),
	}
}

// residualsOfRel converts relative-error magnitudes into log-space
// residuals: r = ln(1+rel) so |exp(r)-1| == rel exactly.
func residualsOfRel(rels []float64) []float64 {
	out := make([]float64, len(rels))
	for i, rel := range rels {
		out[i] = math.Log(1 + rel)
	}
	return out
}

// TestGate1Thresholds: constructed residual sets straddling the A4
// P50/P90 thresholds in BOTH directions plus the exact boundary.
func TestGate1Thresholds(t *testing.T) {
	rep := func(v float64, n int) []float64 {
		s := make([]float64, n)
		for i := range s {
			s[i] = v
		}
		return s
	}
	cases := []struct {
		name    string
		rels    []float64
		verdict string
	}{
		{"clean-pass", rep(0.10, 10), verdictPass},
		// P50 direction: 10 values [0.31×5, 0.32×5] ⇒ P50=0.31>0.30 FAIL, P90=0.32 fine.
		{"p50-fail", append(rep(0.31, 5), rep(0.32, 5)...), verdictFail},
		// P90 direction: [0.1×8, 1.5×2] ⇒ P50=0.1 fine, P90=1.5>1.00 FAIL.
		{"p90-fail", append(rep(0.10, 8), rep(1.5, 2)...), verdictFail},
		// Exact boundary is ≤: P50=0.30, P90=1.00 ⇒ PASS.
		{"boundary-pass", append(rep(0.30, 8), rep(1.00, 2)...), verdictPass},
		// Just past both: FAIL.
		{"both-fail", append(rep(0.35, 8), rep(1.2, 2)...), verdictFail},
	}
	for _, c := range cases {
		_, _, _, v := evalGate1Cell(residualsOfRel(c.rels), defaultGate1P50RelErr, defaultGate1P90RelErr)
		if v != c.verdict {
			p50, p90, _ := relErrQuantiles(residualsOfRel(c.rels))
			t.Errorf("%s: verdict %s, want %s (P50=%.3f P90=%.3f)", c.name, v, c.verdict, p50, p90)
		}
	}
	// Negative residuals count by magnitude too: exp(r)-1 < 0 ⇒ |·|.
	neg := []float64{math.Log(1 - 0.35), math.Log(1 - 0.35), math.Log(1 - 0.35)}
	if _, _, _, v := evalGate1Cell(neg, defaultGate1P50RelErr, defaultGate1P90RelErr); v != verdictFail {
		t.Error("under-prediction magnitudes must fail the P50 gate symmetrically")
	}
}

// TestScoreWindowPairs: known concordant/discordant/tie pair counts.
func TestScoreWindowPairs(t *testing.T) {
	pred := map[string]float64{"a": 1, "b": 2, "c": 3}
	meas := map[string]float64{"a": 10, "b": 20, "c": 15}
	// pairs: (a,b) con, (a,c) con, (b,c) pred b<c but meas b>c ⇒ discordant.
	con, scored, ties := scoreWindowPairs(pred, meas)
	if con != 2 || scored != 3 || ties != 0 {
		t.Fatalf("got con=%d scored=%d ties=%d, want 2/3/0", con, scored, ties)
	}
	// Tie handling: equal predicted ⇒ tie, never scored.
	predT := map[string]float64{"a": 1, "b": 1}
	measT := map[string]float64{"a": 10, "b": 20}
	con, scored, ties = scoreWindowPairs(predT, measT)
	if con != 0 || scored != 0 || ties != 1 {
		t.Fatalf("tie case: got con=%d scored=%d ties=%d, want 0/0/1", con, scored, ties)
	}
}

// TestKendallSanity: the research-verification τ shape — one adjacent swap
// in 5 ranks ⇒ τ = 1 − 2·1/C(5,2) = 0.8.
func TestKendallSanity(t *testing.T) {
	x := []float64{1, 2, 3, 4, 5}
	y := []float64{1, 2, 3, 5, 4}
	if tau := stat.Kendall(x, y, nil); math.Abs(tau-0.8) > 1e-12 {
		t.Fatalf("Kendall τ = %v, want 0.8", tau)
	}
}

// TestMaybeRebucket: the coded A7 rule — a bucket under 10% triggers
// quartile edges (loudly); a balanced distribution leaves the
// pre-registered edges untouched.
func TestMaybeRebucket(t *testing.T) {
	balanced := make([]float64, 0, 40)
	for i := 0; i < 10; i++ {
		balanced = append(balanced, 1000, 4000, 12000, 20000)
	}
	edges, adjusted := maybeRebucket(balanced, defaultBucketEdges(), io.Discard)
	if adjusted || edges[0] != 2048 {
		t.Fatalf("balanced distribution must keep the pre-registered edges, got %v adjusted=%v", edges, adjusted)
	}
	// Everything below 2k ⇒ three buckets empty (<10%) ⇒ quartiles.
	skew := make([]float64, 100)
	for i := range skew {
		skew[i] = float64(100 + i*10)
	}
	edges, adjusted = maybeRebucket(skew, defaultBucketEdges(), io.Discard)
	if !adjusted {
		t.Fatal("skewed distribution must trigger the A7 quartile rebucket")
	}
	if len(edges) != 3 || !(edges[0] < edges[1] && edges[1] < edges[2]) {
		t.Fatalf("quartile edges malformed: %v", edges)
	}
}

// ─── Gate 2 end-to-end fixture ─────────────────────────────────────────
//
// Two EPs A/B with constant epoch signals (A waiting=1 < B waiting=2) and
// a pure-waiting model ⇒ predicted order A<B in EVERY window. Measured
// medians per window decide concordance. 30 windows × 1 pair = 30 pairs
// (exactly the A8 floor); tokens cycle over all four pre-registered
// buckets ≥10% each so the A7 rule stays quiet; Fitted := LogTTFT keeps
// Gate 1 residuals at zero (isolates Gate 2).

const (
	fixEPA = "10.0.0.11:8100"
	fixEPB = "10.0.0.12:8100"
)

func gate2Fixture(concordantWindows, totalWindows int) (*FitResult, []Row, map[string][]SnapshotRecord) {
	tokensCycle := []float64{1000, 4000, 12000, 20000}
	snapA := SnapshotRecord{TS: 1, EP: fixEPA,
		Features: map[string]float64{engine.TtftFeatWaitingOverCapacity: 1}}
	snapB := SnapshotRecord{TS: 1, EP: fixEPB,
		Features: map[string]float64{engine.TtftFeatWaitingOverCapacity: 2}}
	snaps := map[string][]SnapshotRecord{
		fixEPA: {snapA},
		fixEPB: {snapB},
	}
	var rows []Row
	addReq := func(ep string, snap *SnapshotRecord, w int, tokens, ttft float64, k int) {
		ts := float64(w)*defaultWindowSeconds + 2 + float64(k)
		rows = append(rows, Row{
			Req: RequestRecord{
				TTFTSec: ttft, PromptTokens: tokens, EP: ep, TS: ts, RateLabel: "1.0",
			},
			Snap:    snap,
			LogTTFT: math.Log(ttft),
			Fitted:  math.Log(ttft), // residual 0 ⇒ Gate 1 PASS everywhere
		})
	}
	for w := 0; w < totalWindows; w++ {
		tokens := tokensCycle[w%len(tokensCycle)]
		ttftA, ttftB := 1.0, 2.0 // measured A<B == predicted A<B ⇒ concordant
		if w >= concordantWindows {
			ttftA, ttftB = 2.0, 1.0 // measured order flipped ⇒ discordant
		}
		for k := 0; k < 5; k++ { // ≥3 uncensored per EP per window
			addReq(fixEPA, &snapA, w, tokens, ttftA, k)
			addReq(fixEPB, &snapB, w, tokens, ttftB, k)
		}
	}
	fit := &FitResult{
		Features: []string{engine.TtftFeatIntercept, engine.TtftFeatLogPromptTokens,
			engine.TtftFeatWaitingOverCapacity},
		Coefficients: []float64{0, 0, 1}, // pred == waiting_over_capacity
		Rows:         rows,
	}
	return fit, rows, snaps
}

func verdictOf(t *testing.T, o *GateOutcome, key string) string {
	t.Helper()
	v, ok := o.Verdicts[key]
	if !ok {
		t.Fatalf("verdict %q missing: %v", key, o.Verdicts)
	}
	return v
}

// TestGate2AccuracyBoundary: 21/30 concordant = 0.70 (≥ gate) ⇒ PASS;
// 20/30 = 0.667 ⇒ FAIL — accuracy just above and just below the A5 line.
func TestGate2AccuracyBoundary(t *testing.T) {
	fit, rows, snaps := gate2Fixture(21, 30)
	o := evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "gate2"); v != verdictPass {
		t.Fatalf("21/30 concordant: gate2 = %s, want PASS (boundary is ≥0.70): %+v", v, o.Gate2)
	}
	if v := verdictOf(t, o, "overall"); v != verdictPass {
		t.Fatalf("overall = %s, want PASS (gate1 residuals 0, no censoring)", v)
	}
	var g *Gate2Result
	for i := range o.Gate2 {
		if o.Gate2[i].Rate == "1.0" {
			g = &o.Gate2[i]
		}
	}
	if g == nil || g.Pairs != 30 || math.Abs(g.Accuracy-0.70) > 1e-12 {
		t.Fatalf("gate2 row wrong: %+v (want 30 pairs at accuracy 0.70)", g)
	}

	fit, rows, snaps = gate2Fixture(20, 30)
	o = evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "gate2"); v != verdictFail {
		t.Fatalf("20/30 concordant: gate2 = %s, want FAIL", v)
	}
	if v := verdictOf(t, o, "overall"); v != verdictFail {
		t.Fatalf("one failing gated rate must FAIL overall (worst-gated-cell), got %s", v)
	}
}

// TestGate2MinimumPower: 29 pairs < the A8 floor of 30 ⇒ the rate is
// INSUFFICIENT-POWER — reported, never gated, never silently passed.
func TestGate2MinimumPower(t *testing.T) {
	fit, rows, snaps := gate2Fixture(10, 29) // would be 0.34 accuracy if gated
	o := evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "gate2"); v != verdictInsufficient {
		t.Fatalf("29 pairs: gate2 = %s, want INSUFFICIENT-POWER (A8)", v)
	}
	if v := verdictOf(t, o, "overall"); v == verdictPass {
		t.Fatal("nothing gated in gate2 must not yield a silent overall PASS")
	}
}

// badCellRows appends N rows in a separate (rate) cell with residual
// ln(1.5) ⇒ P50 rel err 0.5 > 0.30: a Gate 1 FAIL if the cell is gated.
func badCellRows(n int) []Row {
	snapC := &SnapshotRecord{TS: 1, EP: "10.0.0.13:8100",
		Features: map[string]float64{engine.TtftFeatWaitingOverCapacity: 1}}
	rows := make([]Row, 0, n)
	for i := 0; i < n; i++ {
		ttft := 1.5
		rows = append(rows, Row{
			Req: RequestRecord{
				TTFTSec: ttft, PromptTokens: 1000, EP: "10.0.0.13:8100",
				TS: float64(i), RateLabel: "0.7",
			},
			Snap:    snapC,
			LogTTFT: math.Log(ttft),
			Fitted:  math.Log(ttft) - math.Log(1.5), // residual ln(1.5)
		})
	}
	return rows
}

// TestWorstGatedCell: all cells pass except ONE gated cell ⇒ overall
// FAIL; the same failing cell UNDER-powered instead ⇒ overall PASS with
// the INSUFFICIENT-POWER tag visible (§RQ4 + A8 — the fixture).
func TestWorstGatedCell(t *testing.T) {
	// Variant 1: failing cell is GATED (60 ≥ 50) ⇒ overall FAIL.
	fit, rows, snaps := gate2Fixture(25, 30) // gate2 comfortably PASS (0.833)
	bad := badCellRows(60)
	fit.Rows = append(fit.Rows, bad...)
	rows = append(rows, bad...)
	o := evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "gate1"); v != verdictFail {
		t.Fatalf("gate1 = %s, want FAIL (one gated cell at P50=0.5)", v)
	}
	if v := verdictOf(t, o, "overall"); v != verdictFail {
		t.Fatalf("overall = %s, want FAIL — worst-gated-cell means ONE failing gated cell fails the model", v)
	}

	// Variant 2: same bad cell but 40 rows < 50 ⇒ INSUFFICIENT-POWER,
	// excluded from gating ⇒ overall PASS with the tag.
	fit, rows, snaps = gate2Fixture(25, 30)
	bad = badCellRows(40)
	fit.Rows = append(fit.Rows, bad...)
	rows = append(rows, bad...)
	o = evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "gate1"); v != verdictPass {
		t.Fatalf("gate1 = %s, want PASS (the bad cell is under-powered, not failing)", v)
	}
	if v := verdictOf(t, o, "overall"); v != verdictPass {
		t.Fatalf("overall = %s, want PASS", v)
	}
	tagged := false
	for _, c := range o.Cells {
		if c.Rate == "0.7" && c.Gate1 == verdictInsufficient {
			tagged = true
		}
	}
	if !tagged {
		t.Fatal("the under-powered cell must appear in the report with the INSUFFICIENT-POWER tag")
	}
}

// TestCensoredFractionGate: a gated cell at 6% censored FAILS for DATA
// QUALITY with the distinct verdict; exactly 5% passes (A9 boundary).
func TestCensoredFractionGate(t *testing.T) {
	build := func(unc, cens int) (*FitResult, []Row, map[string][]SnapshotRecord) {
		snap := &SnapshotRecord{TS: 1, EP: fixEPA,
			Features: map[string]float64{engine.TtftFeatWaitingOverCapacity: 1}}
		var all []Row
		for i := 0; i < unc; i++ {
			ttft := 1.0
			all = append(all, Row{
				Req:     RequestRecord{TTFTSec: ttft, PromptTokens: 5000, EP: fixEPA, TS: float64(i), RateLabel: "1.0"},
				Snap:    snap,
				LogTTFT: math.Log(ttft),
				Fitted:  math.Log(ttft),
			})
		}
		for i := 0; i < cens; i++ {
			all = append(all, Row{
				Req:      RequestRecord{TTFTSec: 40, PromptTokens: 5000, EP: fixEPA, TS: float64(unc + i), RateLabel: "1.0"},
				Snap:     snap,
				LogTTFT:  math.Log(40.0),
				Censored: true,
			})
		}
		var train []Row
		for _, r := range all {
			if !r.Censored {
				train = append(train, r)
			}
		}
		fit := &FitResult{
			Features:     []string{engine.TtftFeatIntercept, engine.TtftFeatWaitingOverCapacity},
			Coefficients: []float64{0, 0},
			Rows:         train,
		}
		return fit, all, map[string][]SnapshotRecord{fixEPA: {*snap}}
	}

	fit, rows, snaps := build(94, 6) // 6% > 5% ⇒ FAIL-DATA-QUALITY
	o := evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "censored_fraction"); v != verdictFailData {
		t.Fatalf("6%% censored: censored_fraction = %s, want %s", v, verdictFailData)
	}
	if v := verdictOf(t, o, "overall"); v != verdictFail {
		t.Fatalf("data-quality breach must FAIL overall, got %s", v)
	}
	found := false
	for _, c := range o.Cells {
		if c.CensorVerdict == verdictFailData && math.Abs(c.CensoredFrac-0.06) < 1e-12 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the 6%% cell must carry verdict: %+v", o.Cells)
	}

	fit, rows, snaps = build(95, 5) // exactly 5% ⇒ boundary PASS
	o = evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "censored_fraction"); v != verdictPass {
		t.Fatalf("5%% censored: censored_fraction = %s, want PASS (≤ boundary)", v)
	}
}

// TestInfoOnlyRate: a saturated rate (2.0, the G1 lesson) is INFO-only —
// even a terrible cell there cannot gate the verdict.
func TestInfoOnlyRate(t *testing.T) {
	fit, rows, snaps := gate2Fixture(25, 30)
	bad := badCellRows(60)
	for i := range bad {
		bad[i].Req.RateLabel = defaultInfoRate // move the bad cell to the saturated rate
	}
	fit.Rows = append(fit.Rows, bad...)
	rows = append(rows, bad...)
	o := evaluateGates(fit, rows, snaps, testGateConfig(), io.Discard)
	if v := verdictOf(t, o, "overall"); v != verdictPass {
		t.Fatalf("overall = %s, want PASS — saturated-rate cells are INFO-only (§RQ4)", v)
	}
	info := false
	for _, c := range o.Cells {
		if c.Rate == defaultInfoRate && c.Gate1 == verdictInfo {
			info = true
		}
	}
	if !info {
		t.Fatal("the saturated-rate cell must be tagged INFO-ONLY in the report")
	}
}

// TestVerdictOverGated: the fold itself.
func TestVerdictOverGated(t *testing.T) {
	cases := []struct {
		name string
		vs   []gatedVerdict
		want string
	}{
		{"all-gated-pass", []gatedVerdict{{true, verdictPass}, {true, verdictPass}}, verdictPass},
		{"one-gated-fail", []gatedVerdict{{true, verdictPass}, {true, verdictFail}}, verdictFail},
		{"faildata-propagates", []gatedVerdict{{true, verdictPass}, {true, verdictFailData}}, verdictFailData},
		{"ungated-fail-ignored", []gatedVerdict{{true, verdictPass}, {false, verdictFail}}, verdictPass},
		{"nothing-gated", []gatedVerdict{{false, verdictInsufficient}}, verdictInsufficient},
		{"empty", nil, verdictInsufficient},
	}
	for _, c := range cases {
		if got := verdictOverGated(c.vs); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// TestThresholdOverridesVisible: any deviation from the pre-registered
// defaults must surface and the defaults themselves must
// report clean.
func TestThresholdOverridesVisible(t *testing.T) {
	opts := defaultOptions()
	if ov := thresholdOverrides(opts); len(ov) != 0 {
		t.Fatalf("pristine defaults reported overrides: %v", ov)
	}
	opts.Gate1P50 = 0.25
	ov := thresholdOverrides(opts)
	if len(ov) != 1 || ov[0] != "gate1-p50=0.25 (pre-registered 0.3)" {
		t.Fatalf("override not visible or malformed: %v", ov)
	}
}
