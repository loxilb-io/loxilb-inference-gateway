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

// gates.go — the PRE-REGISTERED Gate 1/2 + censoring + regime-cell
// evaluation battery (RESEARCH §RQ3/§RQ4/§RQ5; TTFT-02).
//
// Every threshold below is a const carrying its pre-registration citation
// (Assumptions A4-A9). The DEFAULTS are the registration: flags may
// override them, but any override is printed into the gate report
// (— deviation from the registration is always visible).
//
// Gate application is WORST-GATED-CELL (§RQ4): the model must pass in
// every gated cell — pooled gating hides regime failure, and regime
// failure is exactly what the α confidence-decay must catch in production.
// Below-minimum-power cells are REPORTED with the tag, never silently
// passed (A8). Saturated-rate cells are INFO-only (the G1 lesson).

package main

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"gonum.org/v1/gonum/stat"

	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
)

// Pre-registered gate thresholds (RESEARCH Assumptions table).
const (
	// defaultGate1P50RelErr / defaultGate1P90RelErr — Gate 1 prediction-
	// error distribution (A4, §RQ3): P50 |relative error| ≤ 0.30 and
	// P90 ≤ 1.00 (within 2×) on exp(residual)-1 magnitudes over the
	// censored-EXCLUDED evaluation set, per gated regime cell.
	defaultGate1P50RelErr = 0.30
	defaultGate1P90RelErr = 1.00

	// defaultGate2PairwiseAccuracy — Gate 2 primary (A5, §RQ3): windowed
	// per-EP pairwise ranking accuracy ≥ 0.70 pooled over windows, per
	// gated rate (random = 0.50; the margin is the model's edge).
	defaultGate2PairwiseAccuracy = 0.70

	// defaultKendallFlagTau — Gate 2 secondary (A6, §RQ3): Kendall τ per
	// regime cell REPORT-ONLY; cells with τ < 0.3 are flagged, never gated.
	defaultKendallFlagTau = 0.3

	// defaultCensorSeconds — §RQ5 right-censor threshold (A9): TTFT > 30s
	// is mechanism-different (reaper-guillotine territory, PHASE-93 RCA) —
	// excluded from the fit AND from Gate 1/2 scoring.
	defaultCensorSeconds = 30.0

	// defaultCensoredFracMax — §RQ5 data-quality gate (A9): per gated
	// cell, censored fraction ≤ 5%; exceeding FAILS the cell for DATA
	// QUALITY (points at the fat-tail RCA), not model accuracy.
	defaultCensoredFracMax = 0.05

	// defaultMinCellRequests / defaultMinWindowPairs — minimum-power rule
	// (A8, §RQ4): a cell is GATED only with ≥50 uncensored requests
	// (Gate 1) and ≥30 scored window-pairs (Gate 2); below-minimum cells
	// are REPORTED "insufficient power", never silently passed.
	defaultMinCellRequests = 50
	defaultMinWindowPairs  = 30

	// defaultWindowSeconds — Gate 2 ranking window (§RQ3): 60s windows ×
	// prompt-length bucket.
	defaultWindowSeconds = 60.0

	// defaultInfoRate — saturated-rate cells are INFO-only (§RQ4, the G1
	// lesson: routing quality is unobservable at the goodput floor).
	// Rate 2.0 is saturated on today's fleet.
	defaultInfoRate = "2.0"

	// rebucketMinFraction — the A7 adjustment RULE (§RQ4): if any
	// pre-registered prompt-length bucket holds < 10% of the uncensored
	// requests, re-bucket to the trace quartiles and REPORT the change.
	rebucketMinFraction = 0.10

	// gate2MinRequestsPerEP — an EP is scored in a Gate 2 window only
	// with ≥3 uncensored requests (§RQ3: measured median needs support).
	gate2MinRequestsPerEP = 3
)

// observationalCaveat is printed into every gate report (§RQ3): Gate 2
// compares EPs observationally, not counterfactually.
const observationalCaveat = "CAVEAT (§RQ3): Gate 2 is an OBSERVATIONAL comparison — each request's TTFT is\n" +
	"observed only on the EP it actually hit; 60s-window × length-bucket matching is\n" +
	"the honest way to compare EPs without counterfactuals. This limitation is\n" +
	"inherent to offline evaluation; the ±TTFT A/B is the causal backstop.\n"

// defaultBucketEdges are the pre-registered prompt-length bucket UPPER
// edges (A7, §RQ4): <2k / 2k-8k / 8k-16k / >16k tokens, log-spaced over
// the le32000 trace.
func defaultBucketEdges() []float64 {
	return []float64{2048, 8192, 16384}
}

// Gate verdict strings. Anything other than verdictPass keeps the model
// UNARMED downstream (: validation-ttft-ab.sh exits unless ALL
// gate_verdicts read PASS — non-PASS strings fail safe).
const (
	verdictPass         = "PASS"
	verdictFail         = "FAIL"
	verdictFailData     = "FAIL-DATA-QUALITY"  // censored-fraction breach
	verdictInsufficient = "INSUFFICIENT-POWER" // A8 — reported, never gated
	verdictInfo         = "INFO-ONLY"          // saturated rate (§RQ4)
)

// GateConfig carries the (default = pre-registered) thresholds into the
// battery plus the reference prompt length for Gate 2 predictions.
type GateConfig struct {
	Gate1P50           float64
	Gate1P90           float64
	Gate2Accuracy      float64
	KendallFlag        float64
	CensorSec          float64
	CensoredFracMax    float64
	MinCellRequests    int
	MinWindowPairs     int
	WindowSec          float64
	RefLogPromptTokens float64
	InfoRates          map[string]bool
	BucketEdges        []float64
	Overrides          []string // threshold deviations from the registration
}

// GateOutcome is the battery's result: per-cell Gate 1 rows, per-rate
// Gate 2 rows, and the verdict map written into the coefficients YAML.
type GateOutcome struct {
	Cells       []CellResult
	Gate2       []Gate2Result
	BucketEdges []float64
	Rebucketed  bool
	Verdicts    map[string]string // gate1, gate2, censored_fraction, overall
}

// CellResult is one (prompt-length bucket × rate) regime cell (§RQ4).
type CellResult struct {
	Bucket        string
	Rate          string
	N             int // uncensored scored requests
	NCensored     int
	CensoredFrac  float64
	InfoOnly      bool // saturated rate — never gated
	Gated         bool // power met AND not info-only
	P50RelErr     float64
	P90RelErr     float64
	MdAPE         float64
	R2            float64
	KendallTau    float64
	TauFlagged    bool // τ < KendallFlag (report-only, A6)
	Gate1         string
	CensorVerdict string
}

// Gate2Result is the pooled windowed pairwise ranking outcome per rate.
type Gate2Result struct {
	Rate       string
	Windows    int
	Pairs      int // scored (non-tie) pairs
	Concordant int
	Ties       int
	Accuracy   float64
	InfoOnly   bool
	Gated      bool
	Verdict    string
}

// medianOf returns the median of an (unsorted) slice; 0 for empty input.
func medianOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return stat.Quantile(0.5, stat.Empirical, s, nil)
}

// bucketFor maps a prompt-token count onto its length-bucket label.
func bucketFor(tokens float64, edges []float64) string {
	for i, e := range edges {
		if tokens < e {
			if i == 0 {
				return fmt.Sprintf("<%g", e)
			}
			return fmt.Sprintf("%g-%g", edges[i-1], e)
		}
	}
	return fmt.Sprintf(">=%g", edges[len(edges)-1])
}

// maybeRebucket applies the coded A7 adjustment rule: if any
// pre-registered bucket holds < rebucketMinFraction of the uncensored
// requests, the edges are re-derived as the prompt-token quartiles and the
// change is REPORTED. Returns the effective edges and whether it adjusted.
func maybeRebucket(promptTokens []float64, edges []float64, report io.Writer) ([]float64, bool) {
	if len(promptTokens) == 0 {
		return edges, false
	}
	counts := make([]int, len(edges)+1)
	for _, t := range promptTokens {
		idx := len(edges)
		for i, e := range edges {
			if t < e {
				idx = i
				break
			}
		}
		counts[idx]++
	}
	n := float64(len(promptTokens))
	for i, c := range counts {
		if float64(c)/n < rebucketMinFraction {
			s := append([]float64(nil), promptTokens...)
			sort.Float64s(s)
			q := []float64{
				stat.Quantile(0.25, stat.Empirical, s, nil),
				stat.Quantile(0.50, stat.Empirical, s, nil),
				stat.Quantile(0.75, stat.Empirical, s, nil),
			}
			fmt.Fprintf(report,
				"REBUCKET (A7 rule): pre-registered bucket %d holds %.1f%% < %.0f%% of requests — edges adjusted to trace quartiles %v (was %v)\n",
				i, 100*float64(c)/n, 100*rebucketMinFraction, q, edges)
			return q, true
		}
	}
	return edges, false
}

// relErrQuantiles turns log-space residuals into multiplicative-error
// magnitudes |exp(residual)-1| and returns their P50/P90 (stat.Quantile,
// Empirical, §RQ3) plus MdAPE (== the P50 by definition, reported
// separately for the record).
func relErrQuantiles(residuals []float64) (p50, p90, mdape float64) {
	if len(residuals) == 0 {
		return math.NaN(), math.NaN(), math.NaN()
	}
	rel := make([]float64, len(residuals))
	for i, r := range residuals {
		rel[i] = math.Abs(math.Exp(r) - 1)
	}
	sort.Float64s(rel)
	p50 = stat.Quantile(0.5, stat.Empirical, rel, nil)
	p90 = stat.Quantile(0.9, stat.Empirical, rel, nil)
	return p50, p90, p50
}

// evalGate1Cell scores one gated cell's residual set against the A4
// thresholds.
func evalGate1Cell(residuals []float64, p50Thr, p90Thr float64) (p50, p90, mdape float64, verdict string) {
	p50, p90, mdape = relErrQuantiles(residuals)
	if p50 <= p50Thr && p90 <= p90Thr {
		return p50, p90, mdape, verdictPass
	}
	return p50, p90, mdape, verdictFail
}

// scoreWindowPairs scores every EP pair of one Gate 2 window: concordant
// if the predicted ordering matches the measured ordering. Ties (equal
// predicted or equal measured) are counted but never scored.
func scoreWindowPairs(pred, meas map[string]float64) (concordant, scored, ties int) {
	eps := make([]string, 0, len(meas))
	for ep := range meas {
		if _, ok := pred[ep]; ok {
			eps = append(eps, ep)
		}
	}
	sort.Strings(eps) // deterministic pair order
	for i := 0; i < len(eps); i++ {
		for j := i + 1; j < len(eps); j++ {
			a, b := eps[i], eps[j]
			if pred[a] == pred[b] || meas[a] == meas[b] {
				ties++
				continue
			}
			scored++
			if (pred[a] < pred[b]) == (meas[a] < meas[b]) {
				concordant++
			}
		}
	}
	return concordant, scored, ties
}

// cellKey identifies one regime cell.
type cellKey struct{ Bucket, Rate string }

// evaluateGates runs the full pre-registered battery over the fit result
// and writes the human-readable gate report.
func evaluateGates(fit *FitResult, rows []Row, snaps map[string][]SnapshotRecord,
	cfg GateConfig, report io.Writer) *GateOutcome {

	// A7 bucket adjustment over the uncensored training set.
	var promptTokens []float64
	for _, r := range fit.Rows {
		promptTokens = append(promptTokens, r.Req.PromptTokens)
	}
	edges, rebucketed := maybeRebucket(promptTokens, cfg.BucketEdges, report)

	// ── Regime cells (§RQ4): (length bucket × rate) ────────────────────
	uncByCell := map[cellKey][]Row{}
	censByCell := map[cellKey]int{}
	for _, r := range fit.Rows { // uncensored, Fitted filled
		k := cellKey{bucketFor(r.Req.PromptTokens, edges), r.Req.RateLabel}
		uncByCell[k] = append(uncByCell[k], r)
	}
	for _, r := range rows {
		if r.Censored {
			k := cellKey{bucketFor(r.Req.PromptTokens, edges), r.Req.RateLabel}
			censByCell[k]++
		}
	}
	keys := make([]cellKey, 0, len(uncByCell)+len(censByCell))
	seen := map[cellKey]bool{}
	for k := range uncByCell {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range censByCell {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Rate != keys[j].Rate {
			return keys[i].Rate < keys[j].Rate
		}
		return keys[i].Bucket < keys[j].Bucket
	})

	var cells []CellResult
	for _, k := range keys {
		unc := uncByCell[k]
		nc := censByCell[k]
		c := CellResult{
			Bucket:    k.Bucket,
			Rate:      k.Rate,
			N:         len(unc),
			NCensored: nc,
			InfoOnly:  cfg.InfoRates[k.Rate],
		}
		if c.N+nc > 0 {
			c.CensoredFrac = float64(nc) / float64(c.N+nc)
		}
		c.Gated = !c.InfoOnly && c.N >= cfg.MinCellRequests

		// Residual stats + per-cell R² + Kendall τ (reported for every
		// cell that has data; GATED only per the power rule).
		if c.N > 0 {
			residuals := make([]float64, c.N)
			fitted := make([]float64, c.N)
			measured := make([]float64, c.N)
			var ssRes, ssTot, mean float64
			for _, r := range unc {
				mean += r.LogTTFT
			}
			mean /= float64(c.N)
			for i, r := range unc {
				residuals[i] = r.LogTTFT - r.Fitted
				fitted[i] = r.Fitted
				measured[i] = r.LogTTFT
				ssRes += residuals[i] * residuals[i]
				d := r.LogTTFT - mean
				ssTot += d * d
			}
			if ssTot > 0 {
				c.R2 = 1 - ssRes/ssTot
			}
			var v string
			c.P50RelErr, c.P90RelErr, c.MdAPE, v = evalGate1Cell(residuals, cfg.Gate1P50, cfg.Gate1P90)
			if c.N >= 2 {
				c.KendallTau = stat.Kendall(fitted, measured, nil)
				c.TauFlagged = !math.IsNaN(c.KendallTau) && c.KendallTau < cfg.KendallFlag
			} else {
				c.KendallTau = math.NaN()
			}
			switch {
			case c.InfoOnly:
				c.Gate1 = verdictInfo
			case !c.Gated:
				c.Gate1 = verdictInsufficient
			default:
				c.Gate1 = v
			}
		} else {
			c.Gate1 = verdictInsufficient
			c.KendallTau = math.NaN()
		}

		// Censored-fraction data-quality gate (A9) — gated cells only.
		switch {
		case c.InfoOnly:
			c.CensorVerdict = verdictInfo
		case !c.Gated:
			c.CensorVerdict = verdictInsufficient
		case c.CensoredFrac > cfg.CensoredFracMax:
			c.CensorVerdict = verdictFailData
		default:
			c.CensorVerdict = verdictPass
		}
		cells = append(cells, c)
	}

	// ── Gate 2 (§RQ3): windowed pairwise EP ranking, pooled per rate ───
	// The interim model IS the emitted model's math: predictions go
	// through engine.Predict so the gate scores exactly what the runtime
	// will compute.
	model := &engine.TtftModel{
		ModelVersion: 1, Features: fit.Features, Coefficients: fit.Coefficients, LogSpace: true,
	}
	type winKey struct {
		Rate   string
		Bucket string
		Idx    int64
	}
	wins := map[winKey]map[string][]float64{} // window -> EP -> uncensored TTFTs
	for _, r := range fit.Rows {
		k := winKey{r.Req.RateLabel, bucketFor(r.Req.PromptTokens, edges), int64(r.Req.TS / cfg.WindowSec)}
		if wins[k] == nil {
			wins[k] = map[string][]float64{}
		}
		wins[k][r.Req.EP] = append(wins[k][r.Req.EP], r.Req.TTFTSec)
	}
	wkeys := make([]winKey, 0, len(wins))
	for k := range wins {
		wkeys = append(wkeys, k)
	}
	sort.Slice(wkeys, func(i, j int) bool {
		a, b := wkeys[i], wkeys[j]
		if a.Rate != b.Rate {
			return a.Rate < b.Rate
		}
		if a.Bucket != b.Bucket {
			return a.Bucket < b.Bucket
		}
		return a.Idx < b.Idx
	})
	type g2acc struct{ windows, pairs, concordant, ties int }
	g2 := map[string]*g2acc{}
	for _, wk := range wkeys {
		byEP := wins[wk]
		meas := map[string]float64{}
		pred := map[string]float64{}
		mid := (float64(wk.Idx) + 0.5) * cfg.WindowSec
		for ep, ttfts := range byEP {
			if len(ttfts) < gate2MinRequestsPerEP {
				continue
			}
			snap := nearestPreceding(snaps[ep], mid)
			if snap == nil {
				continue
			}
			meas[ep] = medianOf(ttfts)
			pred[ep] = model.Predict(snapshotFeatures(snap, cfg.RefLogPromptTokens))
		}
		if len(meas) < 2 {
			continue
		}
		con, scored, ties := scoreWindowPairs(pred, meas)
		acc := g2[wk.Rate]
		if acc == nil {
			acc = &g2acc{}
			g2[wk.Rate] = acc
		}
		acc.windows++
		acc.pairs += scored
		acc.concordant += con
		acc.ties += ties
	}
	rates := make([]string, 0, len(g2))
	for r := range g2 {
		rates = append(rates, r)
	}
	// Rates present in cells but with zero scorable windows still get a row.
	for _, c := range cells {
		if _, ok := g2[c.Rate]; !ok {
			g2[c.Rate] = &g2acc{}
			rates = append(rates, c.Rate)
		}
	}
	sort.Strings(rates)
	var gate2 []Gate2Result
	for _, rate := range rates {
		acc := g2[rate]
		g := Gate2Result{
			Rate: rate, Windows: acc.windows, Pairs: acc.pairs,
			Concordant: acc.concordant, Ties: acc.ties,
			InfoOnly: cfg.InfoRates[rate],
		}
		if g.Pairs > 0 {
			g.Accuracy = float64(g.Concordant) / float64(g.Pairs)
		}
		g.Gated = !g.InfoOnly && g.Pairs >= cfg.MinWindowPairs
		switch {
		case g.InfoOnly:
			g.Verdict = verdictInfo
		case !g.Gated:
			g.Verdict = verdictInsufficient
		case g.Accuracy >= cfg.Gate2Accuracy:
			g.Verdict = verdictPass
		default:
			g.Verdict = verdictFail
		}
		gate2 = append(gate2, g)
	}

	// ── Overall: worst-gated-cell (§RQ4) ───────────────────────────────
	verdicts := map[string]string{
		"gate1":             verdictOverGated(cellVerdicts(cells, func(c CellResult) (bool, string) { return c.Gated, c.Gate1 })),
		"gate2":             verdictOverGated(gate2Verdicts(gate2)),
		"censored_fraction": verdictOverGated(cellVerdicts(cells, func(c CellResult) (bool, string) { return c.Gated, c.CensorVerdict })),
	}
	switch {
	case verdicts["gate1"] == verdictFail || verdicts["gate2"] == verdictFail ||
		verdicts["censored_fraction"] == verdictFail || verdicts["censored_fraction"] == verdictFailData:
		verdicts["overall"] = verdictFail
	case verdicts["gate1"] == verdictPass && verdicts["gate2"] == verdictPass &&
		verdicts["censored_fraction"] == verdictPass:
		verdicts["overall"] = verdictPass
	default:
		verdicts["overall"] = verdictInsufficient
	}

	out := &GateOutcome{
		Cells:       cells,
		Gate2:       gate2,
		BucketEdges: edges,
		Rebucketed:  rebucketed,
		Verdicts:    verdicts,
	}
	writeGateReport(out, cfg, report)
	return out
}

// cellVerdicts projects the per-cell verdict of interest.
func cellVerdicts(cells []CellResult, f func(CellResult) (bool, string)) []gatedVerdict {
	out := make([]gatedVerdict, 0, len(cells))
	for _, c := range cells {
		gated, v := f(c)
		out = append(out, gatedVerdict{gated, v})
	}
	return out
}

func gate2Verdicts(g2 []Gate2Result) []gatedVerdict {
	out := make([]gatedVerdict, 0, len(g2))
	for _, g := range g2 {
		out = append(out, gatedVerdict{g.Gated, g.Verdict})
	}
	return out
}

type gatedVerdict struct {
	Gated   bool
	Verdict string
}

// verdictOverGated folds per-cell verdicts into one: FAIL if ANY gated
// cell fails (worst-gated-cell), PASS only if at least one cell was gated
// and every gated cell passed, INSUFFICIENT-POWER when nothing was gated
// (never silently passed, A8).
func verdictOverGated(vs []gatedVerdict) string {
	anyGated := false
	for _, v := range vs {
		if !v.Gated {
			continue
		}
		anyGated = true
		if v.Verdict != verdictPass {
			if v.Verdict == verdictFailData {
				return verdictFailData
			}
			return verdictFail
		}
	}
	if !anyGated {
		return verdictInsufficient
	}
	return verdictPass
}

// writeGateReport renders the human-readable gate report: registration +
// overrides, dropped features, per-cell table, Gate 2 table, verdicts,
// and the observational-comparison caveat.
func writeGateReport(o *GateOutcome, cfg GateConfig, w io.Writer) {
	fmt.Fprintf(w, "\n===== aictrl-ttft-fit GATE REPORT (pre-registered §RQ3/§RQ4/§RQ5) =====\n")
	fmt.Fprintf(w, "thresholds: gate1 P50<=%.2f P90<=%.2f (A4) | gate2 accuracy>=%.2f (A5) | tau-flag<%.2f (A6) | censor>%.0fs frac<=%.2f (A9) | power >=%d req / >=%d pairs (A8) | window %.0fs\n",
		cfg.Gate1P50, cfg.Gate1P90, cfg.Gate2Accuracy, cfg.KendallFlag,
		cfg.CensorSec, cfg.CensoredFracMax, cfg.MinCellRequests, cfg.MinWindowPairs, cfg.WindowSec)
	if len(cfg.Overrides) == 0 {
		fmt.Fprintf(w, "registration: PRE-REGISTERED DEFAULTS in effect (no overrides)\n")
	} else {
		fmt.Fprintf(w, "registration: !! THRESHOLD OVERRIDES ACTIVE : %s\n",
			strings.Join(cfg.Overrides, "; "))
	}
	fmt.Fprintf(w, "buckets: edges=%v rebucketed=%v\n", o.BucketEdges, o.Rebucketed)

	fmt.Fprintf(w, "\nGate 1 — prediction-error distribution per regime cell (exp(residual)-1 magnitudes):\n")
	fmt.Fprintf(w, "%-12s %-8s %6s %6s %8s %8s %8s %8s %8s %8s  %-22s %-24s\n",
		"bucket", "rate", "N", "Ncens", "censFrac", "P50rel", "P90rel", "MdAPE", "R2", "tau", "gate1", "censored-fraction")
	for _, c := range o.Cells {
		tau := "NaN"
		if !math.IsNaN(c.KendallTau) {
			tau = fmt.Sprintf("%.3f", c.KendallTau)
			if c.TauFlagged {
				tau += "!"
			}
		}
		fmt.Fprintf(w, "%-12s %-8s %6d %6d %8.3f %8.3f %8.3f %8.3f %8.3f %8s  %-22s %-24s\n",
			c.Bucket, c.Rate, c.N, c.NCensored, c.CensoredFrac,
			c.P50RelErr, c.P90RelErr, c.MdAPE, c.R2, tau, c.Gate1, c.CensorVerdict)
	}

	fmt.Fprintf(w, "\nGate 2 — windowed pairwise EP ranking pooled per rate:\n")
	fmt.Fprintf(w, "%-8s %8s %8s %10s %6s %9s  %-22s\n",
		"rate", "windows", "pairs", "concordant", "ties", "accuracy", "verdict")
	for _, g := range o.Gate2 {
		fmt.Fprintf(w, "%-8s %8d %8d %10d %6d %9.3f  %-22s\n",
			g.Rate, g.Windows, g.Pairs, g.Concordant, g.Ties, g.Accuracy, g.Verdict)
	}

	fmt.Fprintf(w, "\nVERDICTS: gate1=%s gate2=%s censored_fraction=%s overall=%s (worst-gated-cell)\n",
		o.Verdicts["gate1"], o.Verdicts["gate2"], o.Verdicts["censored_fraction"], o.Verdicts["overall"])
	fmt.Fprint(w, observationalCaveat)
}

// runGates builds the GateConfig from the CLI options and evaluates the
// pre-registered battery, writing the gate report as it goes.
func runGates(opts FitOptions, fit *FitResult, rows []Row,
	snaps map[string][]SnapshotRecord, report io.Writer) *GateOutcome {
	ref := refPromptTokens(opts, rows, report)
	infoRates := map[string]bool{}
	for _, r := range opts.InfoRates {
		infoRates[r] = true
	}
	cfg := GateConfig{
		Gate1P50:           opts.Gate1P50,
		Gate1P90:           opts.Gate1P90,
		Gate2Accuracy:      opts.Gate2Accuracy,
		KendallFlag:        opts.KendallFlag,
		CensorSec:          opts.CensorSec,
		CensoredFracMax:    opts.CensoredFracMax,
		MinCellRequests:    opts.MinCellRequests,
		MinWindowPairs:     opts.MinWindowPairs,
		WindowSec:          opts.WindowSec,
		RefLogPromptTokens: math.Log(ref),
		InfoRates:          infoRates,
		BucketEdges:        defaultBucketEdges(),
		Overrides:          thresholdOverrides(opts),
	}
	return evaluateGates(fit, rows, snaps, cfg, report)
}
