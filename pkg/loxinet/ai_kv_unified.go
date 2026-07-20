/*
 * Copyright (c) 2025 LoxiLB Authors
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

// ai_kv_unified.go — unified prefix-CHWBL + capacity-weighted
// bounded-load scoring core, kept PURE GO (no cgo) so it is unit-testable
// in isolation on any host and so llb_ai_kv_best_worker (cgo export in
// ai_kv_subscriber.go) merely gathers candidates and delegates here.
//
// Design (RESEARCH Pattern 2 / 81-PATTERNS.md Analog B — PORTED from the C
// bounded-load cap in loxilb-ebpf/common/sockproxy_lb.c:531-558, NOT
// re-derived):
//
//	total_load   = Σ load_i over the candidate EPs
//	total_cap    = Σ clamp(capacity_i, 1, MAX)
//	cap_i        = ceil((1+ε)·total_load·capacity_i / total_cap)
//	prefer argmax(overlap_i) among EPs with load_i < cap_i;
//	on overflow (the affinity winner is at/over cap_i) SPILL — CHWBL
//	semantics — to the next-best EP by overlap among the under-cap set,
//	breaking ties by least load.
//
// ε is expressed as the documented mean_load_factor percentage:
// mean_load_factor/100 == c == 1+ε (175 ⇒ ε=0.75), matching sockproxy_lb.c.
//
// CRITICAL:
//   - The blend shipped feature-flagged OFF for the W3 baseline measurement; as
// it is loxilb's DEFAULT (ON) so "loxilb" in the competitive
//     benchmark is loxilb-best. Set LOXILB_KV_UNIFIED_MODE=0 to restore the
//     legacy pure overlap-argmax selector (byte-identical to the W3 baseline)
//     when an unblended A/B leg is needed.
//   - The cap math GUARDS total_cap>0 and CLAMPS each capacity_i to [1,MAX]
//     before dividing — a buggy/malicious vLLM advertising NumGPUBlocks=0 or a
//     huge value can never divide-by-zero or overflow. All-zero capacities fall
//     back to a uniform cap (capacity_i treated as 1).

package loxinet

import (
	"os"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

// kvCapacityClampMax bounds each advertised NumGPUBlocks before it enters the
// cap division (V5 guard, 81-PATTERNS.md). 8M is ~13× the largest realistic
// vLLM num_gpu_blocks (~600k); anything beyond is clamped so the weighted sum
// cannot overflow the uint64 accumulator regardless of how many EPs report it.
const kvCapacityClampMax = 8_000_000

// kvUnifiedDefaultMeanLoadFactor is the default c = (1+ε)·100. 175 ⇒ ε=0.75,
// the documented sockproxy_lb.c value. The W4 sweep overrides this
// via LOXILB_KV_MEAN_LOAD_FACTOR.
const kvUnifiedDefaultMeanLoadFactor = 175

// kvUnifiedModeOnce / kvUnifiedMeanLoadFactorOnce resolve the env knobs ONCE
// (init-time discipline mirroring kvResolveMaxBlocks) — never per-call on the
// hot path.
var (
	kvUnifiedModeOnce       sync.Once
	kvUnifiedModeEnabled    bool
	kvMeanLoadFactorOnce    sync.Once
	kvMeanLoadFactorPercent uint32
)

// kvLbModeOnce / kvLbModeResolved resolve LOXILB_KV_LB_MODE ONCE (same
// init-time discipline as kvUnifiedModeOnce). (Option B): the new
// canonical selector toggle in {off, hard, soft}. Tests reset kvLbModeOnce +
// kvLbModeResolved to re-read the env (same pattern as kvUnifiedModeOnce).
var (
	kvLbModeOnce     sync.Once
	kvLbModeResolved string
)

// kvLoadPenaltyOnce / kvLoadPenaltyResolved resolve LOXILB_KV_LOAD_PENALTY ONCE
// — the soft-mode λ (queue-delay penalty per in-flight request, expressed in
// prefill-block units). See kvLoadPenalty.
var (
	kvLoadPenaltyOnce     sync.Once
	kvLoadPenaltyResolved uint32
)

// kvSpillReliefOnce / kvSpillReliefResolved resolve LOXILB_KV_SPILL_RELIEF ONCE
// into a TRI-STATE (§9 — was a plain bool through):
//
//	"on"   — explicit enable (1/true/on/yes): relief for EVERY service (the
//
// original opt-in semantics, unchanged).
//
//	"off"  — explicit disable (0/false/off/no): relief nowhere (kill switch).
//	"auto" — UNSET (or unrecognized): relief ON for SINGLE-ROLE services
//	         (kvExactMode==3) only, OFF for the P/D paths.
//
// The "auto" default flip for single-role is §9 evidence-banked
// decision: a hot single-cached prefix yields a SINGLETON positive-overlap
// candidate set whose self-referential cap (1+ε)·L ≥ L can never trigger a
// spill at ANY ε, so the fleet-wide relief pass is the ONLY unpin mechanism —
// and the post-fix competitive A/B recovered goodput 0.22→0.95 (rate 1.0) /
// 0.21→0.78 (rate 2.0) with it armed. The P/D default stays OFF per the
// substrate verdict (recompute-vs-queue tradeoff is load-dependent
// there). Tests reset kvSpillReliefOnce + kvSpillReliefResolved to re-read.
var (
	kvSpillReliefOnce     sync.Once
	kvSpillReliefResolved string
)

// kvLbDefaultLoadPenalty is the default λ for soft mode. Interpreted as
// "prefill-blocks cost per in-flight request": with the homogeneous L4 fleet's
// ~32-block average prompt, λ≈32 means one queued request costs
// about one full prefill — so soft trades roughly one full cache hit for one
// less in-flight request on an equal-capacity peer.
const kvLbDefaultLoadPenalty = 32

// kvSoftCostScale scales the per-block cost term into milli-blocks so the load
// penalty (lambda*load/cap_weight) is comparable to the overlap term without
// floating point. cost_i = uncached_blocks_i*SCALE + (lambda*load_i)/cap_weight_i.
const kvSoftCostScale = 1000

// kvNegligibleOverlap is the hard-mode "no meaningful cache hit" threshold. When
// the best under-cap candidate's overlap is <= this, the affinity pick is
// cache-irrelevant, so hard prefers the LEAST-LOADED under-cap EP instead of
// pinning to an arbitrary zero-overlap winner (negligible-cache refinement).
const kvNegligibleOverlap = 0

// ----------------------------------------------------------------------------
// load-adaptive ε/λ law.
//
// The §8 rate/ε-λ sweep proved NO static ε/λ is optimal across load:
// the shipped `hard ε=175` regresses below the off baseline at rate 2.0, and the
// per-rate optimum knob INCREASES with load (ε 175→300, λ 50000→100000 as the
// observed candidate-set Σ active_conns rises ~6→26). The durable fix is to scale
// ε/λ with the observed in-data-plane load L = Σ c.load over the candidate set.
//
// Calibrated clamped-linear law (§0.1, anchor = steadyMean Σ-inflight):
//
//	ε_eff(L) = clamp(175 + (125·(L−6))/20, 175, 300)   // slope (300−175)/(26−6) = 6.25/unit
//	λ_eff(L) = clamp(50000 + 2500·(L−6),   50000, 100000) // slope (100000−50000)/20 = 2500/unit
//
// At low load (L≲6, ≈ rate ≤1.0) → floors → byte-identical to today's hard/soft
// defaults (back-compat ✓). Kept PURE GO + integer fixed-point (no floats, no
// math import) mirroring the kvCapFor uint64 idiom; L is clamped to [anchor,sat]
// BEFORE the slope multiply so (L−6) ≤ 20 and the product can never overflow
//. Output is clamped to the documented [floor,cap] uint32 ranges, which
// sit strictly inside the env-validated static ranges ([100,1000]/[1,100000]) so
// the downstream selectors see no pathological knob.
// ----------------------------------------------------------------------------

// Adaptive ε law coefficients (§0.1, re-fit 2026-06-28 to TRUE totalLoad — see
// §0.2). ε is the mean_load_factor percentage (1+ε)·100; floor 175 ⇒ ε=0.75 (==
// kvUnifiedDefaultMeanLoadFactor), cap 300 ⇒ ε=2.0. The slope 12.5/unit is
// expressed as the integer fraction 125/10 to stay float-free (band re-keyed from
// 20 to 10 units when the floor anchor moved 6→16).
const (
	kvAdaptiveEpsFloorPct = 175 // ε floor (L≤anchor) — identical to the hard default
	kvAdaptiveEpsCapPct   = 300 // ε cap   (L≥sat)
	kvAdaptiveEpsSlopeNum = 125 // ε slope numerator   (300−175)
	kvAdaptiveEpsSlopeDen = 10  // ε slope denominator (sat−anchor); 125/10 == 12.5
)

// Adaptive λ law coefficients (§0.1, re-fit 2026-06-28 — see §0.2). λ is the
// soft-mode load penalty; floor 50000 (the §8 best-at-rate-1.0), cap 100000 (the
// §8 best-at-rate-2.0 == LOXILB_KV_LOAD_PENALTY upper bound). The slope
// (100000−50000)/10 = 5000 is an exact integer (band re-keyed 20→10 units when
// the floor anchor moved 6→16), so no fixed-point fraction is needed.
const (
	kvAdaptiveLambdaFloor = 50000  // λ floor (L≤anchor)
	kvAdaptiveLambdaCap   = 100000 // λ cap   (L≥sat)
	kvAdaptiveLambdaSlope = 5000   // λ slope per unit L ((100000−50000)/10)
)

// Adaptive load band (§0.1, re-fit 2026-06-28 to loxilb's TRUE [KV_INV] totalLoad
// — see §0.2). Below the anchor the knobs sit at their floors (system unsaturated,
// knob irrelevant); above the saturation load they sit at their caps. L is clamped
// into this band before the slope multiply so (L−anchor) is bounded by
// (sat−anchor)=10. The §0.1 anchors (6/26) came from the vLLM-side proxy, which
// under-counts loxilb's own active_conns at moderate load (proxy 6.1 vs true 16.5
// at rate 1.0; the two agree at saturation, true 25.5 ≈ 26). Anchor re-keyed 6→16
// so rate ≈1.0 correctly sits at the floor (the §8 rate-1.0 optimum, ε175/λ50000).
const (
	kvAdaptiveLoadAnchor = 16 // L at/below which ε/λ are at their floors (rate ≈1.0)
	kvAdaptiveLoadSat    = 26 // L at/above which ε/λ are at their caps   (rate ≈2.0)
)

// kvAdaptiveCapRefMilli is the reference Σcapacity (milli) of the fleet the
// 16/26 anchors were re-fit on (2026-06-28). The ref is a property of the
// LAW's calibration (the anchor fleet's Σ serving capacity in milli-units),
// NOT of the deployment — the deployment's Σcapacity arrives via
// LOXILB_KV_CAP_SUM_MILLI. When both are non-zero the law's magnitude
// key becomes L′ = L × (capRef / capActual), so anchors 16/26 are
// re-expressed per unit of fleet capacity and resized/heterogeneous fleets
// stop mis-firing (memo).
//
// PROVENANCE (plan calibration sweep, 2026-07-06): Σ calibrated
// prefill capacities of the anchor-fleet composition (3×L4 + 1×L40S — the
// same prefill candidate set the 2026-06-28 anchors were re-fit on), in
// milli-(prompt-tokens/s):
//
//	10.0.0.7  L4   2356.91 tok/s (RD p98-calibrate-10.0.0.7-20260706T061604Z)
//	10.0.0.8  L4   2326.51 tok/s (RD p98-calibrate-10.0.0.8-20260706T072513Z)
//	10.0.0.9  L4   2347.11 tok/s (RD p98-calibrate-10.0.0.9-20260706T083447Z)
//	10.0.0.11 L40S 8253.78 tok/s (RD p98-calibrate-10.0.0.11-20260706T094454Z)
//	Σ = 15284.31 tok/s → 15284310 milli. Today's deployment IS the anchor
//	fleet, so LOXILB_KV_CAP_SUM_MILLI=15284310 yields factor exactly 1.0;
//	the mechanism's value appears when the fleet resizes.
const kvAdaptiveCapRefMilli uint64 = 15284310

// kvCapRefMilli is the EFFECTIVE calibration reference, seeded from the const.
// It exists (as a var) solely so resized-fleet regression tests can
// inject a non-zero test ref while the shipped const is still the placeholder 0
// — the same test-override discipline as the kvLbModeOnce-family resets.
// Production code never writes it.
var kvCapRefMilli = kvAdaptiveCapRefMilli

// kvCapActualOnce / kvCapActualResolvedMilli resolve LOXILB_KV_CAP_SUM_MILLI
// ONCE (env-bootstrap: operator-set at container recreate, same
// init-time discipline as kvAdaptiveTLoadLogOnce). 0 == normalization disabled.
var (
	kvCapActualOnce          sync.Once
	kvCapActualResolvedMilli uint64
)

// kvCapActualMilli returns the deployment's Σcapacity in milli-units from
// LOXILB_KV_CAP_SUM_MILLI, read once. Parse-or-DISABLE (never parse-and-guess,
// : unset/empty/unparsable/zero ⇒ 0 (normalization off). Sanity
// clamp: if the resulting factor capRef/capActual would fall
// outside [1/8, 8] the knob is treated as fat-fingered — WARN [KV_CAPNORM] and
// disable (return 0) so a bad env can never skew the law 100×. Tests reset
// kvCapActualOnce + kvCapActualResolvedMilli to re-read the env.
func kvCapActualMilli() uint64 {
	kvCapActualOnce.Do(func() {
		kvCapActualResolvedMilli = 0
		v := os.Getenv("LOXILB_KV_CAP_SUM_MILLI")
		if v == "" {
			return // unset ⇒ disabled (default-OFF)
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			log.Warnf("[KV_CAPNORM] invalid LOXILB_KV_CAP_SUM_MILLI=%q (want a positive integer, milli-units), capacity normalization DISABLED (parse-or-disable)", v)
			return
		}
		// Sanity clamp: factor = capRef/capActual must sit in [1/8, 8].
		// Order matters — test n > ref*8 FIRST so a huge n never reaches the
		// n*8 multiply (uint64 overflow guard); once n ≤ ref*8 ≤ O(10⁸ milli)
		// the n*8 product is trivially safe.
		if ref := kvCapRefMilli; ref > 0 {
			if n > ref*8 || n*8 < ref {
				log.Warnf("[KV_CAPNORM] LOXILB_KV_CAP_SUM_MILLI=%d yields normalization factor ref(%d)/actual outside [1/8, 8] — capacity normalization DISABLED", n, ref)
				return
			}
		}
		kvCapActualResolvedMilli = n
		log.Infof("[KV_CAPNORM] capacity normalization armed: capActualMilli=%d capRefMilli=%d (LOXILB_KV_CAP_SUM_MILLI; effective only when the calibration ref is non-zero)", n, kvCapRefMilli)
	})
	return kvCapActualResolvedMilli
}

// kvCapNormEnabled reports whether capacity normalization is ACTIVE:
// both the calibration ref (const, plan fills it) and the deployment's
// LOXILB_KV_CAP_SUM_MILLI env must be non-zero. Exposed as a predicate so the
// regression tests can assert "the arithmetic path was SKIPPED"
// structurally, not by output equality alone.
func kvCapNormEnabled() bool {
	return kvCapRefMilli != 0 && kvCapActualMilli() != 0
}

// kvAdaptiveTLoadLogEnabled gates the per-selection [KV_INV] totalLoad= diagnostic
// emitted by llb_ai_kv_best_worker. It is Debug-level by default — SILENT in
// production, because logrus runs at Info and the KV-exact selection path must not
// log once per request. Set LOXILB_KV_TLOAD_LOG=1 to promote it to Info so the
// §0.1 calibration re-confirm can read loxilb's TRUE per-selection
// totalLoad (Σ active_conns) from `docker logs`. Read once (sync.Once).
var (
	kvAdaptiveTLoadLogOnce     sync.Once
	kvAdaptiveTLoadLogResolved bool
)

func kvAdaptiveTLoadLogEnabled() bool {
	kvAdaptiveTLoadLogOnce.Do(func() {
		kvAdaptiveTLoadLogResolved = os.Getenv("LOXILB_KV_TLOAD_LOG") == "1"
	})
	return kvAdaptiveTLoadLogResolved
}

// kvAdaptiveSumLoad sums the candidate-set in-data-plane load L = Σ c.load into a
// uint64 (overflow-safe regardless of EP count). This is loxilb's OWN
// per-EP active_conns aggregate — the congestion signal the §0.1 law is keyed on.
func kvAdaptiveSumLoad(cands []kvCandidate) uint64 {
	var l uint64
	for _, c := range cands {
		l += uint64(c.load)
	}
	return l
}

// kvAdaptiveNormalizedLoad is capacity-normalization wrapper feeding
// the adaptive ε/λ law accessors — the ONLY behavioral diff vs the shipped law
// (anchors/slopes/floors/caps untouched, so the locked law tables keep
// meaning). Disabled (ref==0 or env unset/invalid): returns the RAW
// Σ active_conns with ZERO arithmetic — the raw path is SKIPPED-into, not
// computed-to-identity (no L×1000/1000). Enabled: L′ = (L × capRef) / capActual
// in integer fixed-point uint64 — overflow impossible: L ≤ O(10³) conns,
// ref ≤ O(10⁷) milli, product ≪ 2⁶⁴. The [KV_CAPNORM] rawLoad/normLoad
// diagnostic extends the [KV_INV] totalLoad self-confirm discipline (Debug by
// default; LOXILB_KV_TLOAD_LOG=1 promotes to Info) without touching the
// ai_kv_subscriber.go call site.
func kvAdaptiveNormalizedLoad(cands []kvCandidate) uint64 {
	l := kvAdaptiveSumLoad(cands)
	if !kvCapNormEnabled() {
		return l // raw path — normalization arithmetic never runs
	}
	norm := (l * kvCapRefMilli) / kvCapActualMilli()
	if kvAdaptiveTLoadLogEnabled() {
		log.Infof("[KV_CAPNORM] rawLoad=%d normLoad=%d capRefMilli=%d capActualMilli=%d",
			l, norm, kvCapRefMilli, kvCapActualMilli())
	} else {
		log.Debugf("[KV_CAPNORM] rawLoad=%d normLoad=%d capRefMilli=%d capActualMilli=%d",
			l, norm, kvCapRefMilli, kvCapActualMilli())
	}
	return norm
}

// kvAdaptiveMeanLoadFactor maps the candidate-set Σ active_conns to the adaptive
// ε (mean_load_factor percentage) via the §0.1 clamped-linear law:
//
//	ε_eff(L) = clamp(175 + (125·(L−16))/10, 175, 300)
//
// L≤anchor (or empty cands / Σload==0) → 175 (floor, == the hard default, so
// adaptive at low load is byte-identical to hard). L≥sat → 300 (cap). Monotone
// non-decreasing in L. Integer fixed-point only (no floats). NO env reads — this
// is a per-call accessor; the env-resolved static knobs (kvMeanLoadFactor) stay
// separate. (§0.1 / PHASE-92-ADAPTIVE-KV-TUNING.md)
func kvAdaptiveMeanLoadFactor(cands []kvCandidate) uint32 {
	l := kvAdaptiveNormalizedLoad(cands)
	if l <= kvAdaptiveLoadAnchor {
		return kvAdaptiveEpsFloorPct
	}
	if l >= kvAdaptiveLoadSat {
		return kvAdaptiveEpsCapPct
	}
	// (L−anchor) ∈ [1,9] here, so the product is tiny — no overflow.
	delta := l - kvAdaptiveLoadAnchor
	eps := uint64(kvAdaptiveEpsFloorPct) + (uint64(kvAdaptiveEpsSlopeNum)*delta)/uint64(kvAdaptiveEpsSlopeDen)
	if eps > kvAdaptiveEpsCapPct { // defensive clamp (integer division can only undershoot)
		eps = kvAdaptiveEpsCapPct
	}
	return uint32(eps)
}

// kvAdaptiveLoadPenalty maps the candidate-set Σ active_conns to the adaptive λ
// (soft-mode load penalty) via the §0.1 clamped-linear law:
//
//	λ_eff(L) = clamp(50000 + 5000·(L−16), 50000, 100000)
//
// L≤anchor (or empty cands / Σload==0) → 50000 (floor, the §8 rate-1.0 optimum).
// L≥sat → 100000 (cap, the rate-2.0 optimum). Monotone non-decreasing in L.
// Integer-only (the slope 2500 is exact). NO env reads (per-call accessor; the
// static kvLoadPenalty stays separate). (§0.1 / PHASE-92-ADAPTIVE-KV-TUNING.md)
func kvAdaptiveLoadPenalty(cands []kvCandidate) uint32 {
	l := kvAdaptiveNormalizedLoad(cands)
	if l <= kvAdaptiveLoadAnchor {
		return kvAdaptiveLambdaFloor
	}
	if l >= kvAdaptiveLoadSat {
		return kvAdaptiveLambdaCap
	}
	delta := l - kvAdaptiveLoadAnchor // ∈ [1,9]
	lam := uint64(kvAdaptiveLambdaFloor) + uint64(kvAdaptiveLambdaSlope)*delta
	if lam > kvAdaptiveLambdaCap { // defensive clamp
		lam = kvAdaptiveLambdaCap
	}
	return uint32(lam)
}

// kvAdaptiveEwmaAlpha / kvAdaptiveEwmaScale define the integer EWMA weight
// (design §4): new = (α·raw + (k−α)·prev)/k. With α=1, k=4 the new sample carries
// 1/4 (≈0.25) weight, damping per-request noise on the totalLoad signal without
// any float arithmetic. A single spike therefore moves the smoothed value by
// strictly less than the full delta (hysteresis); repeated identical input
// converges toward rawL.
const (
	kvAdaptiveEwmaAlpha = 1 // weight numerator on the new sample
	kvAdaptiveEwmaScale = 4 // weight denominator (k); 1/4 ≈ 0.25 on the new sample
)

// kvAdaptiveEwmaMu guards kvAdaptiveEwmaState, the per-service smoothed-load
// store. The key is loxilb's OWN stable service key (NOT client-controlled), so
// the map is bounded by the live service set and its values are bounded by the
// clamp on L downstream.
var (
	kvAdaptiveEwmaMu    sync.Mutex
	kvAdaptiveEwmaState = make(map[string]uint64)
)

// kvAdaptiveEwmaLoad returns the integer-EWMA-smoothed load for a service key
// given the raw observed L (design §4). The FIRST observation for a key seeds the
// state with rawL (returns rawL exactly). Subsequent observations apply
// new = (α·raw + (k−α)·prev)/k so a single spike moves the smoothed value by less
// than the full delta and repeated identical input converges toward rawL. The
// caller passes a STABLE per-service key. Pure integer math; mutex-guarded
// . The raw accessors above operate on the RAW L; the wiring decides
// whether to feed raw or EWMA-smoothed L — both are exposed so each is provable
// independently in the unit tests.
func kvAdaptiveEwmaLoad(svcKey string, rawL uint64) uint64 {
	kvAdaptiveEwmaMu.Lock()
	defer kvAdaptiveEwmaMu.Unlock()
	prev, seen := kvAdaptiveEwmaState[svcKey]
	if !seen {
		kvAdaptiveEwmaState[svcKey] = rawL
		return rawL
	}
	// new = (α·raw + (k−α)·prev) / k — integer, k≥α so the (k−α) term is ≥0.
	smoothed := (uint64(kvAdaptiveEwmaAlpha)*rawL + uint64(kvAdaptiveEwmaScale-kvAdaptiveEwmaAlpha)*prev) / uint64(kvAdaptiveEwmaScale)
	kvAdaptiveEwmaState[svcKey] = smoothed
	return smoothed
}

// kvUnifiedModeOn reports whether unified blend is enabled. As
// the blend is loxilb's DOCUMENTED DEFAULT: it is ON unless
// LOXILB_KV_UNIFIED_MODE is set to an explicit disable value (0/false/off/no).
// Shipping the blend by default means "loxilb" in the competitive benchmark is
// loxilb-best — the capacity-bounded blend that fixes the KV-exact prefill
// hot-spot (AB-3way-SUMMARY.md: cuts TTFT p90 15.9s→10.0s, the only mode where
// KV-exact beats RR at the loose SLO). Set LOXILB_KV_UNIFIED_MODE=0 to restore
// the legacy pure overlap-argmax selector (the W3 baseline, byte-identical to
// the pre- behavior).
func kvUnifiedModeOn() bool {
	kvUnifiedModeOnce.Do(func() {
		switch os.Getenv("LOXILB_KV_UNIFIED_MODE") {
		case "0", "false", "off", "no", "FALSE", "Off", "No":
			kvUnifiedModeEnabled = false
			log.Infof("[KV_INV] unified prefix-CHWBL + capacity-bounded-load mode DISABLED via LOXILB_KV_UNIFIED_MODE (legacy overlap-argmax)")
		default:
			kvUnifiedModeEnabled = true
			log.Infof("[KV_INV] unified prefix-CHWBL + capacity-bounded-load mode ENABLED (shipped default since)")
		}
	})
	return kvUnifiedModeEnabled
}

// kvMeanLoadFactor returns c·100 == (1+ε)·100. Reads LOXILB_KV_MEAN_LOAD_FACTOR
// once; valid range [100, 1000] (ε ∈ [0, 9]). Out-of-range/garbage → default.
func kvMeanLoadFactor() uint32 {
	kvMeanLoadFactorOnce.Do(func() {
		kvMeanLoadFactorPercent = kvUnifiedDefaultMeanLoadFactor
		if v := os.Getenv("LOXILB_KV_MEAN_LOAD_FACTOR"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 100 && n <= 1000 {
				kvMeanLoadFactorPercent = uint32(n)
				log.Infof("[KV_INV] kvMeanLoadFactor=%d (from LOXILB_KV_MEAN_LOAD_FACTOR)", n)
			} else {
				log.Warnf("[KV_INV] invalid LOXILB_KV_MEAN_LOAD_FACTOR=%q (want 100..1000), using default %d",
					v, kvUnifiedDefaultMeanLoadFactor)
			}
		}
	})
	return kvMeanLoadFactorPercent
}

// kvLbMode resolves (Option B) selector mode in {off, hard, soft}.
//
//	off  — legacy pure overlap-argmax (kvArmPureArgmax), the blind A/B baseline.
//	hard — the capacity-bounded CHWBL cap (kvUnifiedSelect) + negligible-cache
//
// refinement. The default.
//
//	soft — the continuous penalty-score blend (kvSoftBlendSelect).
//
// Precedence (locked): if LOXILB_KV_LB_MODE is set to a VALID value it
// wins outright. If unset (or set to garbage → log.Warnf), fall back to the
// legacy LOXILB_KV_UNIFIED_MODE mapping for back-compat: an explicit disable
// value (0/false/off/no) → "off"; anything else, INCLUDING unset, → "hard" (the
// default-ON behavior preserved). Read ONCE (sync.Once); tests reset
// kvLbModeOnce + kvLbModeResolved to re-read the env.
func kvLbMode() string {
	kvLbModeOnce.Do(func() {
		switch v := os.Getenv("LOXILB_KV_LB_MODE"); v {
		case "off", "hard", "soft", "adaptive", "adaptive-soft":
			// adaptive (adaptive-hard, primary) scales ε on
			// the CHWBL cap; adaptive-soft scales λ on the soft penalty. The per-
			// call adaptive ε/λ come from kvAdaptiveMeanLoadFactor/LoadPenalty fed
			// by the caller (llb_ai_kv_best_worker); the mode itself just routes.
			kvLbModeResolved = v
			log.Infof("[KV_INV] LB mode = %q (LOXILB_KV_LB_MODE)", v)
		case "":
			// Unset → fall back to the legacy LOXILB_KV_UNIFIED_MODE mapping so
			// existing deployments keep default-ON (hard) behavior.
			kvLbModeResolved = kvLbModeFromLegacy()
			log.Infof("[KV_INV] LB mode = %q (legacy LOXILB_KV_UNIFIED_MODE mapping; LOXILB_KV_LB_MODE unset)",
				kvLbModeResolved)
		default:
			kvLbModeResolved = "hard"
			log.Warnf("[KV_INV] invalid LOXILB_KV_LB_MODE=%q (want off|hard|soft|adaptive|adaptive-soft), using default %q",
				v, kvLbModeResolved)
		}
	})
	return kvLbModeResolved
}

// kvLbModeFromLegacy maps the legacy LOXILB_KV_UNIFIED_MODE var to a mode string
// (used only when LOXILB_KV_LB_MODE is unset). An explicit disable value → "off";
// anything else, including unset, → "hard" (the default-ON behavior).
func kvLbModeFromLegacy() string {
	switch os.Getenv("LOXILB_KV_UNIFIED_MODE") {
	case "0", "false", "off", "no", "FALSE", "Off", "No":
		return "off"
	default:
		return "hard"
	}
}

// kvLoadPenalty returns the soft-mode λ from LOXILB_KV_LOAD_PENALTY. Read ONCE;
// valid range [1, 100000]; out-of-range/garbage → kvLbDefaultLoadPenalty. λ is
// "prefill-blocks cost per in-flight request" — one queued request ≈ one full
// prefill at the default. Tests reset
// kvLoadPenaltyOnce + kvLoadPenaltyResolved to re-read the env.
func kvLoadPenalty() uint32 {
	kvLoadPenaltyOnce.Do(func() {
		kvLoadPenaltyResolved = kvLbDefaultLoadPenalty
		if v := os.Getenv("LOXILB_KV_LOAD_PENALTY"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100000 {
				kvLoadPenaltyResolved = uint32(n)
				log.Infof("[KV_INV] kvLoadPenalty=%d (from LOXILB_KV_LOAD_PENALTY)", n)
			} else {
				log.Warnf("[KV_INV] invalid LOXILB_KV_LOAD_PENALTY=%q (want 1..100000), using default %d",
					v, kvLbDefaultLoadPenalty)
			}
		}
	})
	return kvLoadPenaltyResolved
}

// kvSpillReliefSetting resolves the LOXILB_KV_SPILL_RELIEF tri-state ONCE (see
// the kvSpillReliefResolved block comment for semantics + provenance). When a
// HOT single-cached prefix drives its ONE positive-overlap EP over cap, the
// affinity-only fallback has no eligible alternative and pins 100% to that
// saturated EP (the reference "C4 herding" flaw — live-observed: 288/288 on one
// EP at L≈90 with three idle EPs, 0 spills; and again in A/B:
// 1041/13/0 decisions across 3 SGLang EPs). With relief, kvSpillReliefTarget
// spills to the least-loaded UNDER-CAP EP across the FULL healthy fleet
// (including zero-overlap idle EPs), trading a cold-cache recompute to escape a
// deep queue. Read ONCE on the hot path.
func kvSpillReliefSetting() string {
	kvSpillReliefOnce.Do(func() {
		switch os.Getenv("LOXILB_KV_SPILL_RELIEF") {
		case "1", "true", "on", "yes", "TRUE", "On", "Yes":
			kvSpillReliefResolved = "on"
			log.Infof("[KV_INV] hot-prefix pressure-relief spill ENABLED for ALL services (LOXILB_KV_SPILL_RELIEF explicit-on)")
		case "0", "false", "off", "no", "FALSE", "Off", "No":
			kvSpillReliefResolved = "off"
			log.Infof("[KV_INV] hot-prefix pressure-relief spill DISABLED for ALL services (LOXILB_KV_SPILL_RELIEF explicit-off)")
		default:
			kvSpillReliefResolved = "auto"
			log.Infof("[KV_INV] hot-prefix pressure-relief spill AUTO — ON for single-role (kvExactMode=3) services, OFF for P/D (LOXILB_KV_SPILL_RELIEF unset §9 default)")
		}
	})
	return kvSpillReliefResolved
}

// kvSpillReliefFor reports whether the fleet-wide pressure-relief pass runs for
// THIS lookup. singleRole is the calling rule's kvExactMode==3 predicate,
// threaded across the CGO seam by llb_ai_kv_best_worker (twin-lockstep with
// sockproxy_ai_gw.h + sockproxy_kv_exact.c). Explicit env wins globally; the
// unset default is per-mode (single-role ON / P/D OFF — §9 vs
// verdicts respectively).
func kvSpillReliefFor(singleRole bool) bool {
	switch kvSpillReliefSetting() {
	case "on":
		return true
	case "off":
		return false
	default: // "auto"
		return singleRole
	}
}

// kvSpillReliefTarget applies hot-prefix pressure-relief AFTER the
// primary (affinity) selection, over the FULL healthy-prefill fleet — so the tuned
// primary cap/ε-λ math (computed over the positive-overlap candidate set) is left
// byte-identical. It exists because the caller filters the primary candidate set to
// positive-overlap EPs (`score > 0`): a hot single-cached prefix then has cands=1 and
// pins 100% to that EP even at saturation while idle EPs sit unused (verified live:
// 288/288 on one EP at L≈90, 0 spills).
//
// fleetCands = every healthy (prefill, not-excluded) EP with its live load+capacity
// (overlap is ignored here). selEp = the EP the affinity selector chose. Returns a
// relief target + true IFF selEp is over its FLEET-WIDE capacity cap AND a less-loaded
// under-cap EP exists; otherwise (selEp, false) — affinity preserved, no hotspot.
// The cap uses the SAME kvCapFor formula, but over the whole fleet (Σload/Σcap of all
// healthy EPs), which is what makes a single-cached-but-saturated EP register as over
// cap (its singleton self-cap never does). Least-loaded target, tie → lowest epIdx.
func kvSpillReliefTarget(fleetCands []kvCandidate, selEp int, meanLoadFactorPct uint32) (int, bool) {
	if len(fleetCands) < 2 {
		return selEp, false // nothing to relieve to
	}
	var totalLoad, totalCap uint64
	clamped := make([]uint64, len(fleetCands))
	selIdx := -1
	for i, c := range fleetCands {
		totalLoad += uint64(c.load)
		clamped[i] = kvClampCapacity(c.capacity)
		totalCap += clamped[i]
		if c.epIdx == selEp {
			selIdx = i
		}
	}
	if selIdx < 0 {
		return selEp, false // selected EP not in the fleet set — leave it
	}
	mlf := uint64(meanLoadFactorPct)
	// Is the affinity winner over its FLEET-WIDE cap? If not, keep affinity (no hotspot).
	if uint64(fleetCands[selIdx].load) < kvCapFor(totalLoad, clamped[selIdx], totalCap, mlf) {
		return selEp, false
	}
	// Saturated: spill to the least-loaded EP under its own fleet-wide cap.
	relief := -1
	for i, c := range fleetCands {
		if uint64(c.load) >= kvCapFor(totalLoad, clamped[i], totalCap, mlf) {
			continue // also over cap — not a relief target
		}
		if relief < 0 ||
			c.load < fleetCands[relief].load ||
			(c.load == fleetCands[relief].load && c.epIdx < fleetCands[relief].epIdx) {
			relief = i
		}
	}
	if relief >= 0 && fleetCands[relief].epIdx != selEp {
		return fleetCands[relief].epIdx, true
	}
	return selEp, false
}

// kvCandidate is one eligible prefill EP the selector ranks. overlap is the KV
// inventory MatchCount; capacity is the raw advertised NumGPUBlocks (pre-clamp);
// load is a non-negative composite of live KVCacheUsagePerc + QueuedRequests.
type kvCandidate struct {
	epIdx    int
	overlap  int
	capacity uint32
	load     uint32
}

// kvCtrlWeightAt reads controller weight for epIdx from the
// per-call C array (llb_ai_kv_best_worker epWeight, sourced from the
// pd_ctrl_ep[] atomics — NOT the scraper map; same provenance rule as the
// blind-blend fix). A nil slice (controller absent — the C caller passes
// NULL at pd_ctrl_mode==0) or an out-of-range index yields the neutral 100
// (bounds discipline). Values >100 clamp to 100: the snapshot may
// scale capacity down-or-neutral only, never widen eligibility (pure
// intersection). 0 flows through — an explicit ACTIVE|weight=0 degrades to
// the smallest positive share downstream (kvClampCapacity ≥1 floor).
func kvCtrlWeightAt(weights []uint32, epIdx int) uint32 {
	if weights == nil || epIdx < 0 || epIdx >= len(weights) {
		return 100
	}
	if w := weights[epIdx]; w < 100 {
		return w
	}
	return 100
}

// kvWeightedCapacity applies controller weight to a raw
// advertised capacity BEFORE kvClampCapacity in candidate assembly (key
// link): capacity' = capacity * weight / 100. All-uint64 intermediate (house
// style — no floats); weight ≤ 100 so the product never exceeds the input and
// the uint32 narrowing is lossless. weight==100 is an arithmetic no-op
// (G3-friendly); weight==0 yields 0, which kvClampCapacity floors to 1
// (smallest-positive-share, never zero — locked V5 semantics: true removal is
// a STATE, not a weight).
func kvWeightedCapacity(capacity uint32, weight uint32) uint32 {
	if weight >= 100 {
		return capacity
	}
	return uint32(uint64(capacity) * uint64(weight) / 100)
}

// kvClampCapacity bounds an advertised capacity into [1, kvCapacityClampMax].
// A 0 (absent/malicious NumGPUBlocks) becomes 1 so it still participates with
// the smallest positive weight and can never zero the weighted sum.
func kvClampCapacity(c uint32) uint64 {
	if c == 0 {
		return 1
	}
	if c > kvCapacityClampMax {
		return kvCapacityClampMax
	}
	return uint64(c)
}

// kvCapFor computes cap_i = ceil((1+ε)·total_load·capacity_i / total_cap) with
// the Σcapacity>0 guard already satisfied by the caller (total_cap is built
// from clamped capacities so it is always ≥ len(cands) ≥ 1). All arithmetic is
// uint64; the +(total_cap-1) numerator bias implements the ceiling. The result
// is floored at 1 so a live EP always has room for at least one request (mirrors
// sockproxy_lb.c's min_bound clamp — an EP is never capped to zero).
func kvCapFor(totalLoad uint64, capI uint64, totalCap uint64, meanLoadFactorPct uint64) uint64 {
	// numerator = meanLoadFactorPct * totalLoad * capI  (== 100·(1+ε)·load·cap)
	// denominator = 100 * totalCap
	num := meanLoadFactorPct * totalLoad * capI
	den := uint64(100) * totalCap
	if den == 0 {
		return 1 // defensive — caller guarantees totalCap>0; never divide-by-zero
	}
	cap := (num + den - 1) / den // ceiling division
	if cap < 1 {
		cap = 1
	}
	return cap
}

// kvUnifiedSelect implements unified scoring over the candidate set.
// It returns the chosen absolute epIdx and whether the choice SPILLED past the
// highest-overlap (affinity-preferred) EP because that EP was at/over its
// capacity-weighted cap.
//
// Selection:
//  1. Among EPs whose load_i < cap_i, pick the highest overlap (ties → least
//     load → lowest epIdx for determinism). This is the affinity-preserved-
//     below-cap winner.
//  2. If the global highest-overlap EP is NOT that winner (it was at/over cap),
//     the result is a SPILL (CHWBL bounded-load semantics).
//  3. If EVERY EP is at/over cap (saturated), fall back to the least-loaded EP
//     among all candidates (then highest overlap, then lowest epIdx) so the
//     selector still returns a hit rather than missing — and reports a spill.
//
// Returns bestEp=-1 only when cands is empty or no candidate has positive
// overlap (the caller then treats it as a Tier-1.5 miss, identical to argmax).
func kvUnifiedSelect(cands []kvCandidate, meanLoadFactorPct uint32) (bestEp int, spilled bool) {
	if len(cands) == 0 {
		return -1, false
	}

	// total_load and total_cap over the candidate set (cap from CLAMPED values
	// so total_cap > 0 is guaranteed — divide-by-zero guard).
	var totalLoad, totalCap uint64
	clamped := make([]uint64, len(cands))
	for i, c := range cands {
		totalLoad += uint64(c.load)
		clamped[i] = kvClampCapacity(c.capacity)
		totalCap += clamped[i]
	}
	mlf := uint64(meanLoadFactorPct)

	// Identify the global highest-overlap EP (the affinity-preferred winner the
	// pure-argmax path would pick) for the spill determination. Deterministic
	// tie-break: higher overlap, then lower epIdx.
	argmaxIdx := -1
	for i, c := range cands {
		if c.overlap <= 0 {
			continue
		}
		if argmaxIdx < 0 ||
			c.overlap > cands[argmaxIdx].overlap ||
			(c.overlap == cands[argmaxIdx].overlap && c.epIdx < cands[argmaxIdx].epIdx) {
			argmaxIdx = i
		}
	}
	if argmaxIdx < 0 {
		return -1, false // no positive-overlap candidate — Tier-1.5 miss
	}

	// Pick the best UNDER-CAP candidate by overlap (ties → least load → lowest
	// epIdx). Cap is computed per-EP from the clamped capacity weight.
	underCapBest := -1
	for i, c := range cands {
		if c.overlap <= 0 {
			continue
		}
		capI := kvCapFor(totalLoad, clamped[i], totalCap, mlf)
		if uint64(c.load) >= capI {
			continue // at/over cap — not eligible to win without spilling
		}
		if underCapBest < 0 {
			underCapBest = i
			continue
		}
		b := cands[underCapBest]
		switch {
		case c.overlap > b.overlap:
			underCapBest = i
		case c.overlap == b.overlap && c.load < b.load:
			underCapBest = i
		case c.overlap == b.overlap && c.load == b.load && c.epIdx < b.epIdx:
			underCapBest = i
		}
	}

	if underCapBest >= 0 {
		// Negligible-cache refinement: if the best under-cap winner's
		// overlap is <= kvNegligibleOverlap ("no meaningful cache hit"), the
		// affinity pick is cache-irrelevant — pinning to it just concentrates
		// load on an arbitrary EP. Instead prefer the LEAST-LOADED under-cap EP
		// (tie → lowest epIdx). Guarded by the threshold so the existing
		// positive-overlap winners (overlap 6-10 in TestKvUnified*) are untouched.
		if cands[underCapBest].overlap <= kvNegligibleOverlap {
			leastLoaded := -1
			for i, c := range cands {
				if c.overlap <= 0 {
					continue
				}
				capI := kvCapFor(totalLoad, clamped[i], totalCap, mlf)
				if uint64(c.load) >= capI {
					continue // not under cap — ineligible
				}
				if leastLoaded < 0 ||
					c.load < cands[leastLoaded].load ||
					(c.load == cands[leastLoaded].load && c.epIdx < cands[leastLoaded].epIdx) {
					leastLoaded = i
				}
			}
			if leastLoaded >= 0 {
				return cands[leastLoaded].epIdx, leastLoaded != argmaxIdx
			}
		}
		// A below-cap winner exists. It is a spill iff it is NOT the global
		// argmax (i.e. the affinity winner was over cap and we moved off it).
		spilled = underCapBest != argmaxIdx
		return cands[underCapBest].epIdx, spilled
	}

	// Saturated: every positive-overlap EP is at/over cap. Fall back to the
	// least-loaded among all positive-overlap candidates (then highest overlap,
	// then lowest epIdx). This is always a spill (we left the affinity winner).
	//
	// NOTE: a hot SINGLE-cached prefix has exactly ONE positive-overlap EP, so
	// `cands` here is a singleton and this fallback returns it unchanged (with a
	// singleton cand its self-referential cap == (1+ε)·load ≥ load, so it never even
	// reaches here). Relieving that hotspot needs the IDLE zero-overlap EPs, which
	// the caller filters out of `cands` (ai_kv_subscriber.go: `score > 0`). That
	// relief is therefore applied POST-selection over the full fleet — see
	// kvSpillReliefTarget — not here, so the tuned cap/ε-λ math stays untouched.
	fallback := -1
	for i, c := range cands {
		if c.overlap <= 0 {
			continue
		}
		if fallback < 0 {
			fallback = i
			continue
		}
		b := cands[fallback]
		switch {
		case c.load < b.load:
			fallback = i
		case c.load == b.load && c.overlap > b.overlap:
			fallback = i
		case c.load == b.load && c.overlap == b.overlap && c.epIdx < b.epIdx:
			fallback = i
		}
	}
	// fallback is >=0 here because argmaxIdx>=0 guaranteed ≥1 positive-overlap EP.
	return cands[fallback].epIdx, fallback != argmaxIdx
}

// ----------------------------------------------------------------------------
// C2: the explicit arm seam.
//
// The head-to-head A/B selects between two arms on ONE build:
//   arm C1 — the SHIPPED pure overlap-argmax (no load guard). This is what the
//            W3 homogeneous baseline measured and what runs when the unified
//            blend is OFF. It has no concept of capacity or load.
//   arm C2 — the capacity-weighted bounded-load blend (kvUnifiedSelect): keep
//            the affinity (overlap) winner while it is under its capacity-
//            weighted cap, spill CHWBL-style when it is over.
//
// kvSelectArm is the single seam llb_ai_kv_best_worker delegates to so the arm
// is chosen by ONE boolean (c2On) rather than scattered flag checks — making
// C1 provably byte-identical when C2 is OFF (guarantee, unit-proven by
// TestKvArmC1ByteIdentical).
// ----------------------------------------------------------------------------

// kvArmPureArgmax returns the arm-C1 winner: the highest-overlap EP among the
// candidates, ties broken by lowest epIdx (deterministic). Returns -1 when no
// candidate has positive overlap (Tier-1.5 miss). This is the EXACT ordering
// the shipped overlap-argmax loop in llb_ai_kv_best_worker produces — it is the
// reference C1 selector for byte-identical guarantee.
func kvArmPureArgmax(cands []kvCandidate) (bestEp int) {
	bestEp = -1
	bestIdx := -1
	for i, c := range cands {
		if c.overlap <= 0 {
			continue
		}
		if bestIdx < 0 ||
			c.overlap > cands[bestIdx].overlap ||
			(c.overlap == cands[bestIdx].overlap && c.epIdx < cands[bestIdx].epIdx) {
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		return -1
	}
	return cands[bestIdx].epIdx
}

// kvSelectArm chooses the prefill EP for the active arm. (Option B)
// generalizes the old c2On bool into the three-way mode string (kvLbMode):
//
//	mode == "off"  → arm C1: pure overlap-argmax (kvArmPureArgmax). Never spills
//	                  (spilled is always false) — no load guard. This path is
//	                  byte-identical to the shipped W3-baseline selector.
//	mode == "hard" → the capacity-weighted CHWBL bounded-load blend
//	                  (kvUnifiedSelect, with the negligible-cache refinement) and
//	                  the ε knob = meanLoadFactorPct/100. This is the old "arm C2".
//	mode == "soft" → the continuous penalty-score blend (kvSoftBlendSelect) with
//	                  the λ knob = lambda (LOXILB_KV_LOAD_PENALTY).
//
// Any unrecognized mode falls through to "hard" (the default) so a
// mis-resolved toggle degrades to the safe load-aware selector rather than the
// blind argmax.
//
// Returns (epIdx, spilled); epIdx == -1 on a Tier-1.5 miss (no positive-overlap
// candidate), identical for all modes.
func kvSelectArm(cands []kvCandidate, mode string, meanLoadFactorPct uint32, lambda uint32) (bestEp int, spilled bool) {
	switch mode {
	case "off":
		// Arm C1: the shipped pure overlap-argmax. No load/capacity guard, so it
		// never spills — byte-identical to the W3 baseline selector.
		return kvArmPureArgmax(cands), false
	case "soft":
		// Soft: continuous penalty-score (argmin uncached+λ·load/cap_weight).
		return kvSoftBlendSelect(cands, lambda)
	case "adaptive":
		// adaptive-hard — the CHWBL bounded-load cap with the ε
		// supplied per-call by the caller from kvAdaptiveMeanLoadFactor(cands)
		// (the §0.1 load-scaled ε). Routing is identical to "hard"; only the ε
		// ARGUMENT differs, so the SLA-friendly hard cap semantics are preserved.
		return kvUnifiedSelect(cands, meanLoadFactorPct)
	case "adaptive-soft":
		// adaptive-soft — the soft penalty blend with the λ
		// supplied per-call from kvAdaptiveLoadPenalty(cands) (the §0.1 load-
		// scaled λ). Routing is identical to "soft"; only the λ ARGUMENT differs.
		return kvSoftBlendSelect(cands, lambda)
	default:
		// "hard" (and any unexpected value): the capacity-weighted bounded-load
		// blend (V5 guards + negligible-cache refinement live inside).
		return kvUnifiedSelect(cands, meanLoadFactorPct)
	}
}

// kvSoftBlendSelect implements the SOFT mode: a continuous expected-cost
// selector with no hard cutoff. It picks argmin over the candidates of
//
//	cost_i = uncached_blocks_i*SCALE + (lambda*load_i) / cap_weight_i
//
// where:
//   - uncached_blocks_i = promptBlocks - overlap_i is the prefill-compute proxy
//     in block units. promptBlocks is the MAX overlap across the candidate set,
//     used as an in-set proxy for the total prompt-block count (the kvCandidate
//     struct does not carry prompt_blocks). This keeps the function fully
//     self-contained / unit-testable and makes uncached_blocks_i a non-negative
//     "how many MORE blocks than the best-matching EP must this EP recompute"
//     term — which is exactly what differentiates the candidates. The
//     best-overlap EP has uncached=0; lower-overlap EPs pay the gap.
//   - SCALE (kvSoftCostScale) puts the per-block term in milli-blocks so the
//     integer load penalty is comparable without floating point.
//   - cap_weight_i = kvClampCapacity(capacity_i) >= 1 — the V5 divide-by-zero
//     guard reused, so a 0/huge num_gpu_blocks can never divide-by-zero or
//     overflow. A larger-capacity EP is penalized LESS per unit load.
//   - lambda (LOXILB_KV_LOAD_PENALTY) is the queue-delay penalty per in-flight
//     request, in prefill-block units.
//
// At zero load the load term vanishes for every EP, so argmin(cost) ==
// argmin(uncached_blocks) == argmax(overlap): soft reduces to overlap-argmax.
//
// Tie-break (deterministic): lower cost, then higher overlap, then lower load,
// then lowest epIdx.
//
// Returns (epIdx, spilled). spilled == true iff the winner is NOT the
// pure-overlap argmax (so the Plan-03 spill counter is meaningful for soft too).
// Returns bestEp=-1 when cands is empty or no candidate has positive overlap
// (a Tier-1.5 miss, identical to the other arms).
func kvSoftBlendSelect(cands []kvCandidate, lambda uint32) (bestEp int, spilled bool) {
	if len(cands) == 0 {
		return -1, false
	}

	// promptBlocks proxy = max overlap among positive-overlap candidates; also
	// the pure-overlap argmax (for the spill determination). Deterministic
	// tie-break: higher overlap, then lower epIdx.
	argmaxIdx := -1
	promptBlocks := 0
	for i, c := range cands {
		if c.overlap <= 0 {
			continue
		}
		if c.overlap > promptBlocks {
			promptBlocks = c.overlap
		}
		if argmaxIdx < 0 ||
			c.overlap > cands[argmaxIdx].overlap ||
			(c.overlap == cands[argmaxIdx].overlap && c.epIdx < cands[argmaxIdx].epIdx) {
			argmaxIdx = i
		}
	}
	if argmaxIdx < 0 {
		return -1, false // no positive-overlap candidate — Tier-1.5 miss
	}

	lam := uint64(lambda)
	scale := uint64(kvSoftCostScale)

	bestIdx := -1
	var bestCost uint64
	for i, c := range cands {
		if c.overlap <= 0 {
			continue
		}
		uncached := uint64(promptBlocks - c.overlap) // >= 0 by construction
		capW := kvClampCapacity(c.capacity)          // >= 1, never zero
		cost := uncached*scale + (lam*uint64(c.load))/capW
		if bestIdx < 0 {
			bestIdx = i
			bestCost = cost
			continue
		}
		b := cands[bestIdx]
		switch {
		case cost < bestCost:
			bestIdx, bestCost = i, cost
		case cost == bestCost && c.overlap > b.overlap:
			bestIdx, bestCost = i, cost
		case cost == bestCost && c.overlap == b.overlap && c.load < b.load:
			bestIdx, bestCost = i, cost
		case cost == bestCost && c.overlap == b.overlap && c.load == b.load && c.epIdx < b.epIdx:
			bestIdx, bestCost = i, cost
		}
	}
	// bestIdx >= 0 here because argmaxIdx >= 0 guaranteed >= 1 positive-overlap EP.
	return cands[bestIdx].epIdx, bestIdx != argmaxIdx
}
