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

// Expected-TTFT coefficients model (TTFT-02/03) — the ENGINE half.
//
// The sophistication lives OFFLINE: cmd/aictrl-ttft-fit runs
// the QR-OLS fit + gate evaluation and emits a small versioned coefficients
// YAML. This file is the runtime consumer: a strict-parsed loader (the
// coefficients file is operator/fit-tool-produced input at a trust boundary
// — same posture as the capability registry) plus a hand-written
// dot-product Predict. NO numerics-library import in this package (RESEARCH
// the offline fit tool owns the numerics dependency): the
// controller runtime needs none — prediction is a trivial dot product over
// the shipped coefficients.
//
// CGO_ENABLED=0 discipline (package doc in registry.go): stdlib + yaml.v3
// only.

package engine

import (
	"fmt"
	"math"
	"os"

	yaml "gopkg.in/yaml.v3"
)

// Feature vocabulary (locked): core + fetch-cost + locality — exactly
// {intercept, log_prompt_tokens, waiting_over_capacity, kv_cache_usage_perc,
// fetch_cost, matched_prefix_sat}. Exported so the offline fit tool
// reuses the EXACT strings — a coefficients file naming a feature outside
// this vocabulary is REJECTED by LoadTtftModel (the engine cannot evaluate a
// feature it cannot source).
const (
	// TtftFeatIntercept is the model intercept β0 (must be Features[0]).
	TtftFeatIntercept = "intercept"
	// TtftFeatLogPromptTokens is log(prompt_tokens). At apply time the
	// caller fills it with the workload REFERENCE prompt length (e.g. trace
	// median) — per-request TTFT is a fit-time concept only.
	TtftFeatLogPromptTokens = "log_prompt_tokens"
	// TtftFeatWaitingOverCapacity is waiting_i / capacity_i (queue pressure
	// normalized by the EP's calibrated capacity).
	TtftFeatWaitingOverCapacity = "waiting_over_capacity"
	// TtftFeatKvCacheUsagePerc is vllm:kv_cache_usage_perc (KV pressure).
	TtftFeatKvCacheUsagePerc = "kv_cache_usage_perc"
	// TtftFeatFetchCost is lmcache remote-fetch-cost composite
	// (time_to_retrieve / retrieve_hit_rate).
	TtftFeatFetchCost = "fetch_cost"
	// TtftFeatMatchedPrefixSat is sat(matched_prefix_length) — the /lookup
	// locality signal, saturated into [0,1).
	TtftFeatMatchedPrefixSat = "matched_prefix_sat"
)

// ttftMaxAbsCoefficient is the β sanity bound (V5 input validation):
// LoadTtftModel rejects any |coefficient| above it — a pathological or
// tampered coefficients file must not be able to drive pathological weight
// math (the term clamp ±TtftMaxPts and the floor-at-1 are the
// structural backstops behind it).
const ttftMaxAbsCoefficient = 1e6

// ttftKnownFeatures is the loader's feature-name allowlist.
var ttftKnownFeatures = map[string]bool{
	TtftFeatIntercept:           true,
	TtftFeatLogPromptTokens:     true,
	TtftFeatWaitingOverCapacity: true,
	TtftFeatKvCacheUsagePerc:    true,
	TtftFeatFetchCost:           true,
	TtftFeatMatchedPrefixSat:    true,
}

// TtftGateThresholds records the PRE-REGISTERED gate numbers the fit tool
// evaluated against (RESEARCH §RQ3/4/5 — recorded for audit; the loader does
// not re-evaluate gates, it only carries the registration):
//   - Gate 1 (prediction-error distribution): P50 |rel err| ≤ P50RelErr,
//     P90 |rel err| ≤ P90RelErr on the censored-excluded set.
//   - Gate 2 (ranking accuracy): windowed per-EP pairwise accuracy ≥
//     PairwiseAccuracy; Kendall τ per cell flagged below KendallFlag.
//   - Censoring policy (§RQ5): right-censor at CensorSeconds; censored
//     fraction per gated cell ≤ CensoredFracMax (data-quality gate).
type TtftGateThresholds struct {
	P50RelErr        float64 `yaml:"p50_rel_err"`
	P90RelErr        float64 `yaml:"p90_rel_err"`
	PairwiseAccuracy float64 `yaml:"pairwise_accuracy"`
	KendallFlag      float64 `yaml:"kendall_flag"`
	CensorSeconds    float64 `yaml:"censor_seconds"`
	CensoredFracMax  float64 `yaml:"censored_frac_max"`
}

// TtftModel is one versioned Expected-TTFT coefficients file (emitted by
// cmd/aictrl-ttft-fit; strict-parsed here — trust boundary). Features
// and Coefficients are ORDER-ALIGNED (Coefficients[i] belongs to
// Features[i]; Features[0] must be "intercept"). LogSpace must be true in
// v1: predictions are log-TTFT (the fit is log(TTFT) ~ Xβ, §RQ3).
type TtftModel struct {
	ModelVersion           int                `yaml:"model_version"`
	FitDate                string             `yaml:"fit_date"`
	TrainingDataProvenance []string           `yaml:"training_data_provenance"`
	Features               []string           `yaml:"features"`
	Coefficients           []float64          `yaml:"coefficients"`
	LogSpace               bool               `yaml:"log_space"`
	GateThresholds         TtftGateThresholds `yaml:"gate_thresholds"`
	// GateVerdicts is populated by the fit tool (e.g. gate1: PASS). The
	// loader accepts any verdict content — : a failed gate means the
	// weight term is never ARMED (binary policy), not that the file is
	// unloadable as observability.
	GateVerdicts map[string]string `yaml:"gate_verdicts"`
}

// LoadTtftModel reads and strictly validates a versioned Expected-TTFT
// coefficients YAML. Unknown YAML fields, feature/coefficient length
// mismatch, unknown feature names, |β| beyond the sanity bound, and a
// non-log-space model are all errors — the coefficients file drives weight
// math and is operator/fit-tool-produced input at a trust boundary
// (V5).
func LoadTtftModel(path string) (*TtftModel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ttft model open: %w", err)
	}
	defer f.Close()

	var m TtftModel
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // strict: reject unknown fields (schema drift / tamper)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("ttft model decode %s: %w", path, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("ttft model validate %s: %w", path, err)
	}
	return &m, nil
}

func (m *TtftModel) validate() error {
	if m.ModelVersion < 1 {
		return fmt.Errorf("model_version %d not positive (want ≥ 1)", m.ModelVersion)
	}
	if len(m.Features) != len(m.Coefficients) {
		return fmt.Errorf("features/coefficients length mismatch: %d features vs %d coefficients",
			len(m.Features), len(m.Coefficients))
	}
	if len(m.Features) < 2 {
		return fmt.Errorf("model too small: %d features (want ≥ 2: intercept + at least one signal)",
			len(m.Features))
	}
	if m.Features[0] != TtftFeatIntercept {
		return fmt.Errorf("features[0] = %q, want %q (intercept-first ordering)",
			m.Features[0], TtftFeatIntercept)
	}
	if !m.LogSpace {
		return fmt.Errorf("log_space false: v1 models must predict log-TTFT")
	}
	seen := make(map[string]bool, len(m.Features))
	for i, name := range m.Features {
		if !ttftKnownFeatures[name] {
			return fmt.Errorf("unknown feature %q at index %d — not in vocabulary", name, i)
		}
		if seen[name] {
			return fmt.Errorf("duplicate feature %q at index %d", name, i)
		}
		seen[name] = true
	}
	for i, c := range m.Coefficients {
		// NaN/Inf compare false against every bound — check them explicitly
		// (a NaN β would silently poison every prediction downstream).
		if math.IsNaN(c) || math.IsInf(c, 0) || math.Abs(c) > ttftMaxAbsCoefficient {
			return fmt.Errorf("coefficient[%d] (%q) = %v outside the sanity bound |β| ≤ %g",
				i, m.Features[i], c, ttftMaxAbsCoefficient)
		}
	}
	return nil
}

// TtftFeatures is one EP's per-epoch feature vector — the values the model's
// vocabulary is evaluated against. All fields are float64 slots aligned with
// the TtftFeat* names; the prompt-length slot carries the workload REFERENCE
// prompt length (already log-transformed by the caller): per-request TTFT is
// a fit-time concept only — at apply time prompt length shifts
// every EP's prediction identically, so it calibrates magnitudes, not EP
// ordering.
type TtftFeatures struct {
	// LogPromptTokens = log(reference prompt_tokens).
	LogPromptTokens float64
	// WaitingOverCapacity = num_requests_waiting / calibrated capacity.
	WaitingOverCapacity float64
	// KvCacheUsagePerc = vllm:kv_cache_usage_perc ∈ [0,1].
	KvCacheUsagePerc float64
	// FetchCost = lmcache remote-fetch-cost composite.
	FetchCost float64
	// MatchedPrefixSat = sat(matched_prefix_length) ∈ [0,1).
	MatchedPrefixSat float64
}

// Predict returns the model's predicted log-TTFT for one EP's feature
// vector — a hand-written dot product over the ordered features (: the
// runtime math is trivial; no numerics library). Table-free and
// allocation-free: the switch resolves each feature name to its
// TtftFeatures slot inline.
func (m *TtftModel) Predict(f TtftFeatures) float64 {
	var sum float64
	for i, name := range m.Features {
		c := m.Coefficients[i]
		switch name {
		case TtftFeatIntercept:
			sum += c
		case TtftFeatLogPromptTokens:
			sum += c * f.LogPromptTokens
		case TtftFeatWaitingOverCapacity:
			sum += c * f.WaitingOverCapacity
		case TtftFeatKvCacheUsagePerc:
			sum += c * f.KvCacheUsagePerc
		case TtftFeatFetchCost:
			sum += c * f.FetchCost
		case TtftFeatMatchedPrefixSat:
			sum += c * f.MatchedPrefixSat
		}
	}
	return sum
}
