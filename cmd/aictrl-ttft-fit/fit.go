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

// fit.go — ingest + join + censor + QR-OLS fit core of the offline
// Expected-TTFT fit tool.
//
// Ground truth: aiperf per-request records (genai_perf/
// profile_export.jsonl — the bench/workloads/aiperf_to_bench_rate.py
// contract), EP-attributed by parsing x-request-id shape
// ___prefill_addr_<IP:PORT>___decode_addr_<IP:PORT>_<hexid> out of the raw
// record (separate attribution headers do NOT exist on the shipping image).
//
// Epoch feature snapshots: JSONL written by the controller
// AICTRL_FEATURE_SNAP_FILE) — SnapshotRecord below IS contract:
// one line per epoch per EP, {"ts": <unix-seconds>, "ep": "<IP:PORT>",
// "features": {"<TtftFeat* name>": <float>, ...}} carrying the EPOCH
// signals (waiting_over_capacity, kv_cache_usage_perc, fetch_cost,
// matched_prefix_sat). Prompt length is per-request (fit-time covariate,
// and never appears in a snapshot row.
//
// Fit (RESEARCH §RQ6, compile-verified pattern): log(TTFT seconds) ~ Xβ by
// gonum mat.QR — TTFT spans 3 orders of magnitude, so the error structure
// is multiplicative (§RQ3). The UNIT of TTFT (seconds here) only shifts the
// intercept; the engine's ttftCostTerm consumes log-space DIFFERENCES, so
// the choice is calibration-only and is recorded in the model provenance.
//
// gonum is confined to THIS tool: the runtime consumes only the
// emitted coefficients YAML via pkg/aictrl/engine.LoadTtftModel + a
// hand-written dot-product Predict.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gonum.org/v1/gonum/mat"

	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
)

// fitVocabulary is design-matrix column order — the engine's
// exported feature-name consts VERBATIM (contract): intercept first,
// then the per-request covariate, then the epoch signals.
var fitVocabulary = []string{
	engine.TtftFeatIntercept,
	engine.TtftFeatLogPromptTokens,
	engine.TtftFeatWaitingOverCapacity,
	engine.TtftFeatKvCacheUsagePerc,
	engine.TtftFeatFetchCost,
	engine.TtftFeatMatchedPrefixSat,
}

// prefillAddrRe extracts the routed prefill EP out of
// x-request-id contract: ___prefill_addr_<IP:PORT>___decode_addr_<IP:PORT>_<hexid>.
// Matched against the RAW jsonl line: wherever aiperf stashes the response
// header, the ___prefill_addr_ sentinel is unambiguous — this survives
// aiperf record-schema drift, which no field-name lookup would.
var prefillAddrRe = regexp.MustCompile(`___prefill_addr_([0-9]{1,3}(?:\.[0-9]{1,3}){3}:[0-9]{1,5})___`)

// rateLabelRe pulls a campaign rate out of a results-path component
// (arm dirs are shaped like "adaptive-r1.0", "goodput-https-r0.5",
// "rate-2.0"). "rep1"/"rep0-warmup" cannot match: after 'r' the pattern
// requires an optional "ate"/separator then a DIGIT.
var rateLabelRe = regexp.MustCompile(`(?i)(?:^|[-_./])r(?:ate)?[-_.=]?([0-9]+(?:\.[0-9]+)?)(?:[^0-9]|$)`)

// RequestRecord is one EP-attributed aiperf per-request ground-truth row.
type RequestRecord struct {
	TTFTSec      float64 // client-measured TTFT, seconds (aiperf reports ms)
	PromptTokens float64 // input_sequence_length
	EP           string  // prefill EP "IP:PORT" (x-request-id contract)
	TS           float64 // request timestamp, unix seconds
	RateLabel    string  // campaign rate label attributed from the results path
	Source       string  // provenance: the input file the record came from
}

// SnapshotRecord is one controller epoch feature-snapshot row —
// AICTRL_FEATURE_SNAP_FILE JSONL contract (see the file header).
type SnapshotRecord struct {
	TS       float64            `json:"ts"`       // unix seconds
	EP       string             `json:"ep"`       // "IP:PORT"
	Features map[string]float64 `json:"features"` // TtftFeat* epoch signals
}

// Row is one joined (request × nearest-preceding epoch snapshot) row.
type Row struct {
	Req      RequestRecord
	Snap     *SnapshotRecord
	LogTTFT  float64 // log(TTFT seconds) — the fit target
	Fitted   float64 // model fitted value (log space), filled by fitOLS
	Censored bool    // TTFT above the §RQ5 censor threshold
}

// IngestStats counts what the aiperf ingest kept and why it skipped rows.
type IngestStats struct {
	Files          int
	Total          int
	Parsed         int
	Errored        int // aiperf-marked error records
	NoTTFT         int
	NoPromptTokens int
	NoEP           int // no ___prefill_addr_ in the record (attribution miss)
	NoTS           int
}

// JoinStats counts the request→snapshot join outcome.
type JoinStats struct {
	Joined     int
	NoSnapshot int // no preceding snapshot for the request's EP — excluded, loud
}

// metricValue pulls a numeric out of an aiperf metrics entry, tolerating
// both the {"value": v, "unit": u} dict shape and a bare scalar.
func metricValue(m map[string]any, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	if d, ok := v.(map[string]any); ok {
		v = d["value"]
	}
	f, ok := v.(float64)
	return f, ok
}

// firstMetric returns the first present numeric among keys, checking the
// metrics dict first and the record top level second.
func firstMetric(rec, metrics map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if f, ok := metricValue(metrics, k); ok {
			return f, true
		}
		if f, ok := metricValue(rec, k); ok {
			return f, true
		}
	}
	return 0, false
}

// normalizeUnixSeconds maps an epoch timestamp of unknown resolution
// (s/ms/µs/ns — aiperf versions differ) onto unix seconds by magnitude:
// epoch-2026 is ~1.7e9 s, ~1.7e12 ms, ~1.7e15 µs, ~1.7e18 ns.
func normalizeUnixSeconds(v float64) float64 {
	switch {
	case v > 1e17:
		return v / 1e9
	case v > 1e14:
		return v / 1e6
	case v > 1e11:
		return v / 1e3
	default:
		return v
	}
}

// rateLabelFromPath attributes a campaign rate label to an input path by
// scanning its components deepest-first. Falls back to "all".
func rateLabelFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if m := rateLabelRe.FindStringSubmatch(parts[i]); m != nil {
			return m[1]
		}
	}
	return "all"
}

// parseAiperfLine parses one profile_export.jsonl line into a
// RequestRecord. Returns (rec, "", true) on success or (zero, reason,
// false) naming the skip bucket.
func parseAiperfLine(raw []byte, source, rateLabel string) (RequestRecord, string, bool) {
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		return RequestRecord{}, "unparseable", false
	}
	if e, ok := rec["error"]; ok && e != nil {
		if em, isMap := e.(map[string]any); !isMap || len(em) > 0 {
			return RequestRecord{}, "errored", false
		}
	}
	metrics, _ := rec["metrics"].(map[string]any)
	if metrics == nil {
		metrics = map[string]any{}
	}
	ttftMs, ok := firstMetric(rec, metrics, "time_to_first_token")
	if !ok || ttftMs <= 0 {
		return RequestRecord{}, "no-ttft", false
	}
	prompt, ok := firstMetric(rec, metrics, "input_sequence_length", "input_token_count", "prompt_tokens")
	if !ok || prompt <= 0 {
		return RequestRecord{}, "no-prompt-tokens", false
	}
	m := prefillAddrRe.FindSubmatch(raw)
	if m == nil {
		return RequestRecord{}, "no-prefill-addr", false
	}
	ts, ok := firstMetric(rec, metrics,
		"timestamp_ns", "start_time_ns", "request_timestamp", "timestamp", "start_time")
	if !ok || ts <= 0 {
		return RequestRecord{}, "no-timestamp", false
	}
	return RequestRecord{
		TTFTSec:      ttftMs / 1000.0,
		PromptTokens: prompt,
		EP:           string(m[1]),
		TS:           normalizeUnixSeconds(ts),
		RateLabel:    rateLabel,
		Source:       source,
	}, "", true
}

// ingestRequests globs and parses every matching aiperf per-request export.
func ingestRequests(glob, rateLabelOverride string, report io.Writer) ([]RequestRecord, IngestStats, error) {
	files, err := filepath.Glob(glob)
	if err != nil {
		return nil, IngestStats{}, fmt.Errorf("requests glob %q: %w", glob, err)
	}
	if len(files) == 0 {
		return nil, IngestStats{}, fmt.Errorf("requests glob %q matched no files", glob)
	}
	sort.Strings(files)
	var out []RequestRecord
	var st IngestStats
	st.Files = len(files)
	for _, f := range files {
		rate := rateLabelOverride
		if rate == "" {
			rate = rateLabelFromPath(f)
		}
		if err := func() error {
			fh, err := os.Open(f)
			if err != nil {
				return err
			}
			defer fh.Close()
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 0, 1<<20), 1<<24) // aiperf lines can be large
			for sc.Scan() {
				line := sc.Bytes()
				if len(strings.TrimSpace(string(line))) == 0 {
					continue
				}
				st.Total++
				rec, reason, ok := parseAiperfLine(line, f, rate)
				if !ok {
					switch reason {
					case "errored", "unparseable":
						st.Errored++
					case "no-ttft":
						st.NoTTFT++
					case "no-prompt-tokens":
						st.NoPromptTokens++
					case "no-prefill-addr":
						st.NoEP++
					case "no-timestamp":
						st.NoTS++
					}
					continue
				}
				st.Parsed++
				out = append(out, rec)
			}
			return sc.Err()
		}(); err != nil {
			return nil, st, fmt.Errorf("reading %s: %w", f, err)
		}
	}
	fmt.Fprintf(report,
		"INGEST files=%d records=%d parsed=%d errored=%d no-ttft=%d no-prompt=%d no-prefill-addr=%d no-ts=%d\n",
		st.Files, st.Total, st.Parsed, st.Errored, st.NoTTFT, st.NoPromptTokens, st.NoEP, st.NoTS)
	return out, st, nil
}

// loadSnapshots reads epoch feature-snapshot JSONL and returns
// per-EP snapshot series sorted ascending by timestamp.
func loadSnapshots(path string) (map[string][]SnapshotRecord, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("snapshots open: %w", err)
	}
	defer fh.Close()
	byEP := map[string][]SnapshotRecord{}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s SnapshotRecord
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			return nil, fmt.Errorf("snapshots %s:%d: %w", path, lineNo, err)
		}
		if s.EP == "" || s.TS <= 0 {
			return nil, fmt.Errorf("snapshots %s:%d: missing ep/ts", path, lineNo)
		}
		byEP[s.EP] = append(byEP[s.EP], s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("snapshots read: %w", err)
	}
	for ep := range byEP {
		s := byEP[ep]
		sort.Slice(s, func(i, j int) bool { return s[i].TS < s[j].TS })
	}
	return byEP, nil
}

// nearestPreceding returns the latest snapshot with TS <= ts for the EP.
func nearestPreceding(series []SnapshotRecord, ts float64) *SnapshotRecord {
	i := sort.Search(len(series), func(i int) bool { return series[i].TS > ts })
	if i == 0 {
		return nil
	}
	return &series[i-1]
}

// joinRows joins each request with the nearest-preceding epoch snapshot of
// its attributed EP and applies the §RQ5 censor mark (censorSec, A9).
// Requests with no preceding snapshot are EXCLUDED loudly (a feature vector
// cannot be invented for them).
func joinRows(reqs []RequestRecord, snaps map[string][]SnapshotRecord,
	censorSec float64, report io.Writer) ([]Row, JoinStats) {
	var rows []Row
	var st JoinStats
	for _, r := range reqs {
		snap := nearestPreceding(snaps[r.EP], r.TS)
		if snap == nil {
			st.NoSnapshot++
			continue
		}
		st.Joined++
		rows = append(rows, Row{
			Req:      r,
			Snap:     snap,
			LogTTFT:  math.Log(r.TTFTSec),
			Censored: r.TTFTSec > censorSec,
		})
	}
	fmt.Fprintf(report, "JOIN joined=%d no-preceding-snapshot=%d (excluded)\n",
		st.Joined, st.NoSnapshot)
	if st.NoSnapshot > 0 {
		fmt.Fprintf(report,
			"WARN %d requests had NO preceding epoch snapshot for their EP — check AICTRL_FEATURE_SNAP_FILE coverage \n",
			st.NoSnapshot)
	}
	return rows, st
}

// featureValue resolves one vocabulary feature for a joined row: the
// intercept is 1, log_prompt_tokens is the per-request covariate, every
// other name reads the joined snapshot's epoch signal (absent ⇒ 0 — the
// locality feature is all-zero until enables /lookup).
func featureValue(row Row, name string) float64 {
	switch name {
	case engine.TtftFeatIntercept:
		return 1
	case engine.TtftFeatLogPromptTokens:
		return math.Log(row.Req.PromptTokens)
	default:
		return row.Snap.Features[name]
	}
}

// snapshotFeatures builds the engine's apply-time feature vector from one
// epoch snapshot at a reference log prompt length (Gate 2 predictions).
func snapshotFeatures(s *SnapshotRecord, refLogPromptTokens float64) engine.TtftFeatures {
	return engine.TtftFeatures{
		LogPromptTokens:     refLogPromptTokens,
		WaitingOverCapacity: s.Features[engine.TtftFeatWaitingOverCapacity],
		KvCacheUsagePerc:    s.Features[engine.TtftFeatKvCacheUsagePerc],
		FetchCost:           s.Features[engine.TtftFeatFetchCost],
		MatchedPrefixSat:    s.Features[engine.TtftFeatMatchedPrefixSat],
	}
}

// FitResult is the QR-OLS outcome over the censored-EXCLUDED training set.
type FitResult struct {
	Features     []string  // kept columns, vocabulary order, intercept first
	Coefficients []float64 // aligned with Features
	Dropped      []string  // zero-variance columns dropped (loud report lines)
	Rows         []Row     // uncensored training rows with Fitted filled
	R2           float64   // overall log-space R²
}

// fitOLS fits log(TTFT) ~ Xβ by QR (RESEARCH §RQ6 verified pattern) over
// the uncensored rows. Zero-variance features are DROPPED with a loud
// report line (never allowed to make X silently rank-deficient — the
// locality column is all-zero until). A residual rank deficiency is
// a HARD error naming the collinear columns.
func fitOLS(rows []Row, report io.Writer) (*FitResult, error) {
	var train []Row
	for _, r := range rows {
		if !r.Censored {
			train = append(train, r)
		}
	}
	if len(train) == 0 {
		return nil, fmt.Errorf("no uncensored training rows")
	}

	// Zero-variance drop over the non-intercept vocabulary.
	kept := []string{engine.TtftFeatIntercept}
	var dropped []string
	for _, name := range fitVocabulary[1:] {
		v0 := featureValue(train[0], name)
		varies := false
		for _, r := range train[1:] {
			if featureValue(r, name) != v0 {
				varies = true
				break
			}
		}
		if varies {
			kept = append(kept, name)
		} else {
			dropped = append(dropped, name)
			fmt.Fprintf(report,
				"DROP zero-variance feature %q (constant %.6g over %d training rows) — excluded from the design matrix\n",
				name, v0, len(train))
		}
	}
	if len(kept) < 2 {
		return nil, fmt.Errorf("all non-intercept features are zero-variance — nothing to fit")
	}
	if len(train) < len(kept) {
		return nil, fmt.Errorf("underdetermined fit: %d rows < %d columns", len(train), len(kept))
	}

	beta, err := solveOLS(train, kept)
	if err != nil {
		// Diagnose: which column removals restore full rank?
		var collinear []string
		for i := 1; i < len(kept); i++ {
			sub := append(append([]string{}, kept[:i]...), kept[i+1:]...)
			if _, e := solveOLS(train, sub); e == nil {
				collinear = append(collinear, kept[i])
			}
		}
		return nil, fmt.Errorf("rank-deficient design matrix (%w); collinear column candidates: %v",
			err, collinear)
	}

	// Fitted values + R² (log space).
	var ssRes, ssTot, mean float64
	for _, r := range train {
		mean += r.LogTTFT
	}
	mean /= float64(len(train))
	for i := range train {
		var fitted float64
		for j, name := range kept {
			fitted += beta[j] * featureValue(train[i], name)
		}
		train[i].Fitted = fitted
		d := train[i].LogTTFT - fitted
		ssRes += d * d
		t := train[i].LogTTFT - mean
		ssTot += t * t
	}
	r2 := 0.0
	if ssTot > 0 {
		r2 = 1 - ssRes/ssTot
	}
	fmt.Fprintf(report, "FIT rows=%d features=%v R2=%.4f\n", len(train), kept, r2)
	return &FitResult{
		Features:     kept,
		Coefficients: beta,
		Dropped:      dropped,
		Rows:         train,
		R2:           r2,
	}, nil
}

// solveOLS runs the §RQ6 verified QR pattern over the given columns.
func solveOLS(train []Row, cols []string) ([]float64, error) {
	n, p := len(train), len(cols)
	X := mat.NewDense(n, p, nil)
	y := mat.NewVecDense(n, nil)
	for i, r := range train {
		for j, name := range cols {
			X.Set(i, j, featureValue(r, name))
		}
		y.SetVec(i, r.LogTTFT)
	}
	var qr mat.QR
	qr.Factorize(X)
	beta := mat.NewVecDense(p, nil)
	if err := qr.SolveVecTo(beta, false, y); err != nil {
		return nil, err
	}
	out := make([]float64, p)
	for j := 0; j < p; j++ {
		out[j] = beta.AtVec(j)
	}
	return out, nil
}

// buildModel assembles the versioned coefficients file (the engine's
// TtftModel schema VERBATIM — strict round-trip via LoadTtftModel).
func buildModel(fit *FitResult, thresholds engine.TtftGateThresholds,
	verdicts map[string]string, provenance []string, version int, fitDate string) *engine.TtftModel {
	return &engine.TtftModel{
		ModelVersion:           version,
		FitDate:                fitDate,
		TrainingDataProvenance: provenance,
		Features:               fit.Features,
		Coefficients:           fit.Coefficients,
		LogSpace:               true, // v1 contract: log(TTFT seconds) ~ Xβ
		GateThresholds:         thresholds,
		GateVerdicts:           verdicts,
	}
}

// emitModel writes the coefficients YAML. The output must survive the
// engine's strict loader (KnownFields, vocabulary allowlist, |β| bound) —
// asserted by the round-trip fixture.
func emitModel(m *engine.TtftModel, path string) error {
	b, err := marshalModel(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("coefficients write %s: %w", path, err)
	}
	return nil
}
