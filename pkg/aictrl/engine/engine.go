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

// Decision engine v1 (CTRL-04) — capacity-normalized weights ONLY.
//
// This is the ε/λ capacity-blindness fix (pkg/loxinet/ai_kv_unified.go keys
// its adaptive magnitude on raw Σactive_conns with no notion of absolute
// per-EP capacity): weights derive EXCLUSIVELY from the registry's
// serving-throughput priors, normalized per role over the FRESH source set.
// Deliberately dumb by design:
//
// - NO TTFT input (Expected-TTFT gating).
//   - NO scraped-load input: eligibility and live load stay LOCAL to loxilb
// (P1 — scraped-load 2.7x under-count root cause; the snapshot
//     proto structurally has no load fields). The ONLY WorkerSample field
//     this engine reads is LastUpdate (staleness).
//
// Staleness (CTRL-02 consumption semantics, two-threshold since):
//   - A source is FRESH when now − LastUpdate ≤ StaleBudget; SOFT-STALE in
//     (StaleBudget, HardStaleBudget]; HARD-STALE past HardStaleBudget or when
//     its sample is absent/never-stamped. Fresh-set membership for FleetStale
//     purposes stays age ≤ StaleBudget.
//   - SOFT-STALE and HARD-STALE sources stop receiving fresh computed weights
//     and GLIDE damped toward the neutral weight 100 — NEVER zero-filled (the
//     EP-restart folded todo: a restarting vLLM stops serving /metrics long
//     before it stops being a real endpoint; zero would poison relative
//     scoring) and never an undamped jump (the VAL-03b flap conviction).
//   - Only HARD-STALE priors leave the per-role maxPrior normalization set:
//     scrape jitter around StaleBudget can no longer renormalize the whole
//     fleet; a genuine outage (past HardStaleBudget) still does — through
//     damped steps.
//   - ALL sources stale ⇒ EngineStats.FleetStale — the caller emits NOTHING
//     (snapshot generation stops; appliers ride the staleness-deadline
//     ladder down to the proven autonomous baseline: "no snapshot" is safer
//     than "wrong snapshot").
//
// Damping (P2, table-proven in engine_test.go), in order:
//  1. EWMA      s_t = α·raw + (1−α)·prev        (default α 0.3)
//  2. dead-band |s_t − prev| ≤ DeadBand ⇒ HOLD  (default 5 weight points)
//  3. step clamp |out − prev| ≤ MaxStepPct      (default 20 points/epoch)
//
// Weights are integer-out (uint32 in [0,100]); float internals are fine
// here — this is the controller side, not the C hot path.

package engine

import (
	"math"
	"sort"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// Sourced wraps one scraped aimetrics.WorkerSample with its source IP
// (the registry host key).
type Sourced struct {
	IP     string
	Sample aimetrics.WorkerSample
}

// Damping-envelope defaults (locked by the phase plan; env-overridable
// wiring lands with the binary options).
const (
	// DefaultStaleBudget ≈ 3 scrape intervals (10s default scrape).
	DefaultStaleBudget = 15 * time.Second
	// DefaultEwmaAlpha is the EWMA smoothing factor α.
	DefaultEwmaAlpha = 0.3
	// DefaultDeadBand is the hold band in weight points.
	DefaultDeadBand = 5.0
	// DefaultMaxStepPct bounds |out−prev| per epoch (percent of the
	// 100-point scale ⇒ weight points).
	DefaultMaxStepPct = 20
	// DefaultHardStaleFactor derives HardStaleBudget from the effective
	// StaleBudget when unset (two-threshold staleness): a source must
	// age past DefaultHardStaleFactor × StaleBudget (≈45s at the 15s
	// default) before its prior leaves the maxPrior normalization set —
	// scrape jitter debounce without any per-IP mutable state.
	DefaultHardStaleFactor = 3
)

// LMCache cost-term defaults (LMC-03). The term is default-OFF: the mere
// presence of the EngineConfig LMCache fields with zero values leaves the
// engine byte-identical to (LmcCostEnabled defaults false; the
// enabling env wiring lands with the binary options).
const (
	// DefaultLmcMaxPts is the bound B (weight points) the LMCache cost term is
	// normalized into: dw ∈ [-DefaultLmcMaxPts, +DefaultLmcMaxPts].
	DefaultLmcMaxPts = 15.0
	// DefaultLmcStaleBudget is the per-source freshness budget for lmcache
	// signals — a signal aged past it decays the cost term to 0 (neutral),
	// exactly like the vLLM staleness partition (never zero-filled).
	DefaultLmcStaleBudget = 15 * time.Second
)

// Expected-TTFT cost-term defaults (TTFT-02/03). The term is default-OFF and
// mirrors the LMC carrier field-for-field: the mere presence of the
// EngineConfig Ttft* fields with zero values leaves the engine byte-identical
// to the pre-TTFT engine (TtftEnabled defaults false; the enabling env wiring
// lands with the binary options).
const (
	// DefaultTtftMaxPts is the bound B (weight points) the Expected-TTFT
	// term is normalized into: dw ∈ [-DefaultTtftMaxPts, +DefaultTtftMaxPts]
	// (same bound as the LMC term).
	DefaultTtftMaxPts = 15.0
	// DefaultTtftStaleBudget is the per-source freshness budget for the TTFT
	// feature carrier — features aged past it decay the term to 0 (neutral),
	// never zero-filled.
	DefaultTtftStaleBudget = 15 * time.Second
)

// EngineConfig parameterizes ComputeWeights. Zero-valued fields fall back
// to the locked defaults (a zero α/dead-band/step is not meaningful in v1).
type EngineConfig struct {
	// Now is the injected decision clock (fake-clock testable).
	// Zero ⇒ time.Now.
	Now time.Time
	// StaleBudget is the per-source staleness window (the SOFT threshold):
	// a source aged past it stops receiving fresh computed weights and
	// glides damped toward neutral.
	StaleBudget time.Duration
	// HardStaleBudget is HARD staleness threshold — the soft/hard
	// distinction: a source aged in (StaleBudget, HardStaleBudget] is
	// SOFT-STALE (excluded from fresh weights, but its prior REMAINS in the
	// per-role maxPrior normalization set, so a flapping scrape source
	// cannot renormalize the fleet); only past HardStaleBudget — a genuine
	// outage, not jitter — does the prior leave maxPrior and the fleet
	// renormalize (through damped steps). One fresh scrape instantly
	// restores full freshness (asymmetry is inherent; no streak counter).
	// Zero ⇒ DefaultHardStaleFactor × effective StaleBudget.
	HardStaleBudget time.Duration
	// EwmaAlpha is α in s_t = α·raw + (1−α)·prev.
	EwmaAlpha float64
	// DeadBand holds prev when |s_t − prev| is within it (weight points).
	DeadBand float64
	// MaxStepPct clamps |out − prev| per epoch (points on the 0-100 scale).
	MaxStepPct uint32

	// LmcCostEnabled is the master enable for the bounded LMCache cost term
	// (LMC-03). Default false ⇒ ComputeWeights is byte-identical to
	// (arm B of the LMC-04 A/B is the live proof).
	LmcCostEnabled bool
	// LmcMaxPts bounds the LMCache cost term to [-LmcMaxPts, +LmcMaxPts] weight
	// points (the "cost input, never eligibility" bound). Zero ⇒ DefaultLmcMaxPts.
	LmcMaxPts float64
	// LmcStaleBudget is the per-source freshness budget for lmcache signals; a
	// signal aged past it (or absent) decays the cost term to 0 (neutral).
	// Zero ⇒ DefaultLmcStaleBudget.
	LmcStaleBudget time.Duration
	// LmcInvert flips the LMCache cost-term sign — the engine-side VAL-02
	// negative control. Only active when LmcCostEnabled. Default false.
	LmcInvert bool

	// TtftEnabled is the master enable for the bounded Expected-TTFT cost
	// term (TTFT-02/03) — an INDEPENDENT sub-knob, sibling of LmcCostEnabled.
	// Default false ⇒ ComputeWeights is byte-identical to the pre-TTFT engine
	// (the arm-B/default-OFF contract).
	TtftEnabled bool
	// TtftMaxPts bounds the Expected-TTFT term to [-TtftMaxPts, +TtftMaxPts]
	// weight points (the "cost input, never eligibility" bound — the use-site
	// floors the post-term weight at 1). Zero ⇒ DefaultTtftMaxPts.
	TtftMaxPts float64
	// TtftStaleBudget is the per-source freshness budget for the TTFT feature
	// carrier; features aged past it (or absent/never-stamped) decay the term
	// to 0 (neutral). Zero ⇒ DefaultTtftStaleBudget.
	TtftStaleBudget time.Duration
	// TtftInvert flips the Expected-TTFT term sign — the engine-side VAL-02
	// negative control. Only active when TtftEnabled. Default false.
	TtftInvert bool
	// TtftModel is the loaded Expected-TTFT coefficients model
	// (LoadTtftModel). nil ⇒ the term is STRUCTURALLY OFF: the application
	// site is skipped entirely and the output stays byte-identical even with
	// TtftEnabled true — "enabled but no coefficients" cannot perturb weights
	// (metrics-only degrade).
	TtftModel *TtftModel
	// TtftAlpha is the externally-supplied confidence factor α_ttft ∈ [0,1]
	// (TTFT-03): the BINARY's live prediction-error monitor owns it and
	// decays it toward 0 on regime shift; the engine ONLY multiplies (clamped
	// into [0,1] on use). 0 is a MEANINGFUL value — fully decayed ⇒ the term
	// is exactly neutral — so withDefaults deliberately does NOT default it
	// to 1: an un-wired α reads 0 and the term stays neutral (fail-safe).
	TtftAlpha float64
	// TtftFeats is the optional per-epoch TTFT feature carrier, keyed by
	// registry host IP (the "variadic-or-optional carrier" following the LMC
	// precedent — the variadic slot is already taken by the LMC carrier, so
	// this one rides the per-epoch config like Now does). nil/absent ⇒ every
	// term is 0 and the output is byte-identical.
	TtftFeats map[string]TtftEpochFeatures
}

// TtftEpochFeatures stamps one EP's per-epoch TtftFeatures with the
// freshness clock the staleness ladder reads (mirrors the LMC carrier's
// WorkerSample.LastUpdate role).
type TtftEpochFeatures struct {
	TtftFeatures
	// LastUpdate is when the underlying signals were scraped. Zero
	// (never-stamped) or aged past TtftStaleBudget ⇒ the EP's term decays
	// to neutral and it leaves the fleet-mean set.
	LastUpdate time.Time
}

func (c EngineConfig) withDefaults() EngineConfig {
	if c.Now.IsZero() {
		c.Now = time.Now()
	}
	if c.StaleBudget <= 0 {
		c.StaleBudget = DefaultStaleBudget
	}
	// HardStaleBudget resolves AFTER StaleBudget so the factor applies to
	// the EFFECTIVE soft budget (≈45s at the 15s default).
	if c.HardStaleBudget <= 0 {
		c.HardStaleBudget = time.Duration(DefaultHardStaleFactor) * c.StaleBudget
	}
	if c.EwmaAlpha <= 0 {
		c.EwmaAlpha = DefaultEwmaAlpha
	}
	if c.DeadBand <= 0 {
		c.DeadBand = DefaultDeadBand
	}
	if c.MaxStepPct == 0 {
		c.MaxStepPct = DefaultMaxStepPct
	}
	// LMCache knobs: zero ⇒ locked default. LmcCostEnabled/LmcInvert keep their
	// zero value (false) — the default-OFF contract; the mere presence of these
	// fields must not perturb output.
	if c.LmcMaxPts <= 0 {
		c.LmcMaxPts = DefaultLmcMaxPts
	}
	if c.LmcStaleBudget <= 0 {
		c.LmcStaleBudget = DefaultLmcStaleBudget
	}
	// Expected-TTFT knobs: zero ⇒ locked default. TtftEnabled/TtftInvert keep
	// their zero value (false) — the default-OFF contract. TtftAlpha is
	// deliberately NOT defaulted: 0 is meaningful (fully decayed ⇒ neutral,
	// TTFT-03) — the BINARY owns α, the engine just multiplies.
	if c.TtftMaxPts <= 0 {
		c.TtftMaxPts = DefaultTtftMaxPts
	}
	if c.TtftStaleBudget <= 0 {
		c.TtftStaleBudget = DefaultTtftStaleBudget
	}
	return c
}

// EngineStats reports one decision epoch for observability (surfaced via
// CTRL-05 metrics — : decisions reconstructable without
// docker-log grep).
type EngineStats struct {
	// FleetStale is set when EVERY registry source is stale — the caller
	// must emit NO snapshot this epoch (CTRL-02: fleet-stale ⇒ stop).
	FleetStale bool
	// StaleSources lists the excluded (stale or sample-less) source IPs.
	StaleSources []string
	// FreshSources counts sources that entered normalization.
	FreshSources int
	// Held counts EPs the dead-band pinned to prev this epoch.
	Held int
	// Clamped counts EPs the ±MaxStepPct bound limited this epoch.
	Clamped int
}

// ComputeWeights derives the per-EP weight map (keyed by registry host IP,
// values in [0,100]) for one decision epoch. samples is keyed by source IP;
// prev is the previous epoch's OUTPUT weights (nil/missing entries default
// to the neutral 100 — first-epoch rule). When every source is stale the
// returned map is nil and stats.FleetStale is set.
// The optional variadic lmc carrier (LMC-03) supplies per-source LMCache
// signals keyed by registry host IP (KV-pressure + locality in
// aimetrics.WorkerSample.Raw, its own LastUpdate for staleness). It is absent
// in call sites; when absent — or when cfg.LmcCostEnabled is false
// — every cost adjustment is 0 and the output is byte-identical to.
// The Expected-TTFT carrier (TTFT-02/03) rides cfg.TtftFeats — absent
// carrier, TtftEnabled false, nil TtftModel, or α_ttft 0 all leave the
// output byte-identical. Deterministic term order: base → LMC → TTFT →
// dampStep.
func ComputeWeights(reg *Registry, samples map[string]Sourced,
	prev map[string]uint32, cfg EngineConfig,
	lmc ...map[string]aimetrics.WorkerSample) (map[string]uint32, EngineStats) {

	cfg = cfg.withDefaults()
	var stats EngineStats

	// Optional LMCache cost-term carrier (LMC-03). nil ⇒ every dw==0.
	var lmcSamples map[string]aimetrics.WorkerSample
	if len(lmc) > 0 {
		lmcSamples = lmc[0]
	}

	// (1) Three-way staleness partition, keyed on LastUpdate age
	// only — ComputeWeights stays pure. The ONLY sample field read anywhere
	// in this engine is LastUpdate (P1: live load stays local).
	//   FRESH      age ≤ StaleBudget                    (receives computed weight)
	//   SOFT-STALE StaleBudget < age ≤ HardStaleBudget  (damped glide to neutral;
	//                                                    prior STAYS in maxPrior)
	//   HARD-STALE age > HardStaleBudget, or the sample  (damped glide to neutral;
	//              is absent/never-stamped                prior LEAVES maxPrior)
	// The fresh SET for FleetStale purposes stays age ≤ StaleBudget.
	fresh := make(map[string]bool, len(reg.Hosts))
	hardStale := make(map[string]bool, len(reg.Hosts))
	for ip := range reg.Hosts {
		s, ok := samples[ip]
		if !ok || s.Sample.LastUpdate.IsZero() {
			// Absent / never-stamped ⇒ HARD-STALE (the EP-restart case: no
			// evidence the source ever existed this boot — never in maxPrior).
			hardStale[ip] = true
			stats.StaleSources = append(stats.StaleSources, ip)
			continue
		}
		age := cfg.Now.Sub(s.Sample.LastUpdate)
		switch {
		case age <= cfg.StaleBudget:
			fresh[ip] = true
			stats.FreshSources++
		case age <= cfg.HardStaleBudget:
			// SOFT-STALE: scrape jitter, not an outage — see (2).
			stats.StaleSources = append(stats.StaleSources, ip)
		default:
			hardStale[ip] = true
			stats.StaleSources = append(stats.StaleSources, ip)
		}
	}
	if stats.FreshSources == 0 {
		// Fleet-wide staleness: STOP — the caller emits nothing and the
		// appliers walk the staleness ladder to the autonomous baseline.
		stats.FleetStale = true
		return nil, stats
	}

	// (2) Per-role normalization over the FRESH ∪ SOFT-STALE set (fix
	// site 1): the max-prior member of each role anchors raw weight 100
	// (heterogeneous 2:1 priors ⇒ L40S 100 / L4 50; homogeneous trio ⇒ all
	// 100; a single fresh decode ⇒ 100). A SOFT-STALE prior stays in the set
	// so one EP flapping fresh/stale around StaleBudget cannot renormalize
	// every sibling; only a HARD-STALE prior (genuine outage) leaves it.
	// Every FRESH EP is in the set, so its role's maxPrior is always > 0.
	maxPrior := map[string]float64{}
	for ip, h := range reg.Hosts {
		if !hardStale[ip] && h.ServingThroughputPrior > maxPrior[h.Role] {
			maxPrior[h.Role] = h.ServingThroughputPrior
		}
	}

	// (3) Emit: stale (soft or hard) ⇒ damped glide toward neutral 100
	// (excluded from fresh weights, never zero-filled, never an undamped
	// jump — fix site 2); fresh ⇒ damped capacity-normalized weight.
	out := make(map[string]uint32, len(reg.Hosts))
	for ip, h := range reg.Hosts {
		prevW := uint32(100) // first-epoch rule
		if w, ok := prev[ip]; ok {
			prevW = w
		}
		if !fresh[ip] {
			w, held, clamped := dampStep(100, prevW, cfg)
			if held {
				stats.Held++
			}
			if clamped {
				stats.Clamped++
			}
			out[ip] = w
			continue
		}
		raw := 100 * h.ServingThroughputPrior / maxPrior[h.Role]
		// LMC-03: bounded, default-OFF LMCache cost term, floored at 1 so
		// it is a COST INPUT and NEVER eligibility — an LMCache signal can never
		// DISABLE or force an EP. OFF ⇒ this block is skipped ⇒ raw untouched ⇒
		// output byte-identical to. maxPrior/dampStep are unchanged
		// (owns the staleness-flap).
		if cfg.LmcCostEnabled {
			raw = clamp(raw+lmcCostTerm(ip, lmcSamples, cfg), 1, 100)
		}
		// TTFT-02/03: bounded, confidence-decaying, default-OFF
		// Expected-TTFT term at the SAME site shape as LMC — deterministic
		// application order: base → LMC → TTFT → dampStep. The model-nil
		// guard makes "enabled but no coefficients" STRUCTURALLY OFF (the
		// clamp is skipped entirely, not merely fed a zero term), so the
		// output stays byte-identical (metrics-only degrade). Cost
		// input never eligibility — the floor at 1 is the guarantee.
		if cfg.TtftEnabled && cfg.TtftModel != nil {
			raw = clamp(raw+ttftCostTerm(ip, cfg.TtftFeats, cfg), 1, 100)
		}
		w, held, clamped := dampStep(raw, prevW, cfg)
		if held {
			stats.Held++
		}
		if clamped {
			stats.Clamped++
		}
		out[ip] = w
	}
	return out, stats
}

// dampStep runs the locked damping pipeline for one EP: EWMA toward raw,
// dead-band hold, then the ±MaxStepPct step clamp — all relative to the
// previous OUTPUT weight (the pipeline's only state, so ComputeWeights
// stays pure).
func dampStep(raw float64, prevW uint32, cfg EngineConfig) (w uint32, held, clamped bool) {
	prevF := float64(prevW)

	// (a) EWMA smoothing.
	s := cfg.EwmaAlpha*raw + (1-cfg.EwmaAlpha)*prevF

	// (b) Dead-band: small moves HOLD the previous weight (churn guard).
	if math.Abs(s-prevF) <= cfg.DeadBand {
		return prevW, true, false
	}

	// (c) Step clamp: at most MaxStepPct points of movement per epoch.
	maxStep := float64(cfg.MaxStepPct)
	if s > prevF+maxStep {
		s = prevF + maxStep
		clamped = true
	} else if s < prevF-maxStep {
		s = prevF - maxStep
		clamped = true
	}

	// Integer-out, clamped to the contract range [0,100].
	r := math.Round(s)
	if r < 0 {
		r = 0
	}
	if r > 100 {
		r = 100
	}
	return uint32(r), false, clamped
}

// lmcSoftScale* are the saturating soft midpoints for the x/(x+scale)
// normalization (the signal magnitude at which a sub-signal reaches 0.5). They
// shape the cost term's dynamic range ONLY — they are NOT eligibility
// thresholds (the use-site floors the weight at 1). The saturating form needs
// no hard cap and maps [0,∞) monotonically into [0,1).
const (
	lmcUsageSoftScaleBytes   = float64(8 << 30) // 8 GiB KV-usage midpoint (pressure)
	lmcPrefixSoftScaleTokens = 512.0            // matched-prefix midpoint (locality)
	lmcRetrieveSoftScaleSec  = 0.05             // time_to_retrieve midpoint (fetch-cost)
)

// lmcCostTerm returns the bounded LMCache cost adjustment (weight points) for
// EP ip, in [-cfg.LmcMaxPts, +cfg.LmcMaxPts]. It combines KV-pressure (higher
// lmcache:*_cache_usage ⇒ negative bias, steer away from a saturated tier) with
// locality/fetch-cost (a matched /lookup prefix + high retrieve hit-rate + low
// time_to_retrieve ⇒ positive bias, this EP already holds the KV cheaply).
//
// It returns 0 (neutral — the α(t)/staleness decay analog) when:
//   - the sub-knob is OFF (cfg.LmcCostEnabled false),
//   - the carrier is nil or the EP has no lmcache sample (absent source),
//   - the sample carries no lmcache signal, or
//   - the sample is stale (LastUpdate zero or aged past cfg.LmcStaleBudget).
//
// A stale/absent source therefore DECAYS to neutral, never zero-fills. This is
// a COST INPUT, never eligibility: the caller floors the post-term weight at 1.
func lmcCostTerm(ip string, lmc map[string]aimetrics.WorkerSample, cfg EngineConfig) float64 {
	if !cfg.LmcCostEnabled || lmc == nil {
		return 0
	}
	s, ok := lmc[ip]
	if !ok {
		return 0 // absent lmcache source ⇒ neutral
	}
	// Per-source staleness (its own budget, independent of the vLLM scrape): a
	// stale or never-stamped signal decays to neutral — never zero-filled.
	if s.LastUpdate.IsZero() || cfg.Now.Sub(s.LastUpdate) > cfg.LmcStaleBudget {
		return 0
	}
	if len(s.Raw) == 0 {
		return 0 // sample present but no lmcache signal ⇒ neutral
	}

	// KV-pressure (negative bias): the EP's total lmcache KV footprint, saturating.
	usage := s.Raw[aimetrics.FamilyLMCacheLocalCacheUsage] + s.Raw[aimetrics.FamilyLMCacheRemoteCacheUsage]
	pressure := lmcSatFrac(usage, lmcUsageSoftScaleBytes) // [0,1)

	// Locality / fetch-cost (positive bias): the mean of the PRESENT sub-signals.
	var locSum float64
	var locN int
	if v, ok := s.Raw[aimetrics.RawKeyMatchedPrefixLength]; ok {
		locSum += lmcSatFrac(v, lmcPrefixSoftScaleTokens)
		locN++
	}
	if v, ok := s.Raw[aimetrics.FamilyLMCacheRetrieveHitRate]; ok {
		locSum += clamp(v, 0, 1)
		locN++
	}
	if v, ok := s.Raw[aimetrics.FamilyLMCacheTimeToRetrieve]; ok {
		// Low time_to_retrieve ⇒ cheap fetch ⇒ positive: cheapness = 1 − sat(t).
		// v is the WINDOWED mean retrieve latency (Δsum/Δcount per scrape
		// interval, H-18) — the controller's sample store windows the
		// cumulative histogram totals before publishing this key; the key is
		// absent (neutral) until a window exists.
		locSum += 1 - lmcSatFrac(v, lmcRetrieveSoftScaleSec)
		locN++
	}
	var locality float64
	if locN > 0 {
		locality = locSum / float64(locN)
	}

	net := locality - pressure // ∈ [-1, 1]
	dw := cfg.LmcMaxPts * net
	if cfg.LmcInvert {
		dw = -dw // engine-side VAL-02 negative control
	}
	return clamp(dw, -cfg.LmcMaxPts, cfg.LmcMaxPts)
}

// lmcSatFrac maps x∈[0,∞) into [0,1) via x/(x+scale) — a saturating fraction
// with no hard cap. A non-positive x or scale yields 0 (neutral).
func lmcSatFrac(x, scale float64) float64 {
	if x <= 0 || scale <= 0 {
		return 0
	}
	return x / (x + scale)
}

// ttftCostTerm returns the bounded Expected-TTFT cost adjustment (weight
// points) for EP ip, in [-cfg.TtftMaxPts, +cfg.TtftMaxPts] — the TTFT-02/03
// term, mirroring lmcCostTerm's neutral-decay ladder field-for-field.
//
// It returns 0 (neutral — never zero-fills) when:
//   - the sub-knob is OFF (cfg.TtftEnabled false) or the coefficients model
//     is absent (cfg.TtftModel nil — structural OFF),
//   - the carrier is nil/empty or the EP has no feature entry (absent source),
//   - the entry is stale (LastUpdate zero or aged past cfg.TtftStaleBudget), or
//   - the confidence factor α_ttft has decayed to 0 (TTFT-03: the BINARY's
//     live prediction-error monitor owns α; α=0 ⇒ exactly neutral).
//
// Magnitude: pred_i = model.Predict per EP (log-TTFT); rel = the fleet-mean
// delta (mean − pred_i) over EPs with a VALID (fresh, stamped) feature set
// this epoch, clamped into [-1,1] — predictions are log-space, so one log
// unit (e× faster/slower than the fleet geometric-mean TTFT) saturates the
// term, and LOWER-than-mean predicted E[TTFT] ⇒ POSITIVE (weight bonus).
// dw = TtftMaxPts × rel × clamp(α,0,1); TtftInvert flips the sign (VAL-02
// negative control); final clamp to ±TtftMaxPts. This is a COST INPUT, never
// eligibility: the caller floors the post-term weight at 1.
func ttftCostTerm(ip string, feats map[string]TtftEpochFeatures, cfg EngineConfig) float64 {
	if !cfg.TtftEnabled || cfg.TtftModel == nil || len(feats) == 0 {
		return 0
	}
	f, ok := feats[ip]
	if !ok {
		return 0 // absent feature source ⇒ neutral
	}
	// Per-source staleness (its own budget, independent of the vLLM scrape):
	// stale or never-stamped features decay to neutral — never zero-filled.
	if f.LastUpdate.IsZero() || cfg.Now.Sub(f.LastUpdate) > cfg.TtftStaleBudget {
		return 0
	}

	// Fleet mean over EPs with a valid prediction this epoch, summed in
	// sorted-key order so the float accumulation — and therefore the weight
	// output — is deterministic (decisions reconstructable).
	ips := make([]string, 0, len(feats))
	for fip := range feats {
		ips = append(ips, fip)
	}
	sort.Strings(ips)
	var sum float64
	var n int
	for _, fip := range ips {
		ef := feats[fip]
		if ef.LastUpdate.IsZero() || cfg.Now.Sub(ef.LastUpdate) > cfg.TtftStaleBudget {
			continue
		}
		sum += cfg.TtftModel.Predict(ef.TtftFeatures)
		n++
	}
	// ip itself passed the freshness check above, so n ≥ 1. A single valid
	// EP predicts exactly the fleet mean ⇒ rel 0 ⇒ neutral.
	mean := sum / float64(n)
	pred := cfg.TtftModel.Predict(f.TtftFeatures)

	rel := clamp(mean-pred, -1, 1) // lower predicted E[TTFT] ⇒ positive
	if math.IsNaN(rel) {
		return 0 // pathological feature input (Inf−Inf) ⇒ neutral, never poison
	}
	dw := cfg.TtftMaxPts * rel * clamp(cfg.TtftAlpha, 0, 1)
	if cfg.TtftInvert {
		dw = -dw // engine-side VAL-02 negative control
	}
	return clamp(dw, -cfg.TtftMaxPts, cfg.TtftMaxPts)
}

// clamp bounds v to [lo,hi].
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
