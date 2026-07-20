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

/*
 * loxilb-ai-controller — the standalone global AI controller binary
 * (CTRL-01/CTRL-05 W5b).
 *
 * PURE GO, CGO_ENABLED=0: no pkg/loxinet, no cgo anywhere in the
 * dependency graph. Wiring:
 *
 *   registry (pkg/aictrl/engine.LoadRegistry)
 *     -> aimetrics.Poller over the registry EPs (vLLM /metrics scrapes)
 *     -> ComputeWeights (capacity-normalized engine, locked damping)
 *     -> [optional VAL-02 negative-control inversion, harness only]
 *     -> Generator.Maybe (SotW emission, churn guard, re-anchor)
 *     -> snapshotServer.Broadcast (gRPC WatchSnapshots fan-out)
 *
 * Graceful stop (SIGTERM/SIGINT): stop EMITTING first, then stop the
 * server — appliers ride the staleness ladder down to the autonomous
 * baseline (P5), never see a torn write.
 */
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/loxilb-io/loxilb/pkg/aictrl"
	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

var opts CtrlOptions

// metricLmcCostActive is self-confirm gauge for the LMCache cost-term
// arm (CTRL-05, mirrors metricNegativeControl): 1 when AICTRL_LMC_COST is set,
// else 0. The LMC-04 A/B harness asserts this gauge is 1 in the cost-ON arm and
// 0 in the OFF (byte-identical-to) arm, so no run can silently mislabel
// which arm actually FIRED. The series name is the literal aictrl_lmc_cost_active.
var metricLmcCostActive = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "aictrl_lmc_cost_active",
	Help: "1 when the LMCache cost term is enabled (AICTRL_LMC_COST), else 0 (default-OFF => byte-identical to)",
})

// sampleStore is the in-memory aimetrics.Sink: keeps the latest
// engine.Sourced per registry IP and runs discovery validation on
// every fresh NumGPUBlocks (mismatch => WARN-on-change + counter-always;
// the DISCOVERED value wins inside the registry overlay).
type sampleStore struct {
	reg     *engine.Registry
	idxToIP []string

	mu       sync.Mutex
	samples  map[string]engine.Sourced
	warnedAt map[string]uint32 // last discovered value already WARNed for

	// lmcSamples holds the per-IP LMCache signal (LMC-02): the lmcache:*
	// families piggybacked off the vLLM /metrics body plus the /lookup
	// matched_prefix_length, merged into one WorkerSample.Raw carrying its own
	// LastUpdate for the engine's independent LMCache staleness budget. Kept
	// separate from `samples` so weight math never sees it (the
	// cost term reads it only via the ComputeWeights lmc carrier, and only
	// when AICTRL_LMC_COST is set — default-OFF => byte-identical).
	lmcSamples map[string]aimetrics.WorkerSample

	// lmcWindows windows the cumulative time_to_retrieve (sum,count) pair
	// per IP into a per-scrape mean retrieve latency (metrics audit H-18).
	// Guarded by mu.
	lmcWindows *aimetrics.HistWindow
}

func newSampleStore(reg *engine.Registry, idxToIP []string) *sampleStore {
	return &sampleStore{
		reg:        reg,
		idxToIP:    idxToIP,
		samples:    make(map[string]engine.Sourced, len(reg.Hosts)),
		warnedAt:   make(map[string]uint32, len(reg.Hosts)),
		lmcSamples: make(map[string]aimetrics.WorkerSample, len(reg.Hosts)),
		lmcWindows: aimetrics.NewHistWindow(),
	}
}

// OnSample implements aimetrics.Sink (called from per-EP scrape goroutines).
func (st *sampleStore) OnSample(epIdx int, s aimetrics.WorkerSample) {
	if epIdx < 0 || epIdx >= len(st.idxToIP) || st.idxToIP[epIdx] == "" {
		return
	}
	ip := st.idxToIP[epIdx]

	// discovery validation on each fresh capacity observation.
	if s.NumGPUBlocks > 0 {
		m := st.reg.ValidateDiscovery(ip, s.NumGPUBlocks)
		if m.Mismatched {
			metricRegistryMismatch.WithLabelValues(ip).Inc()
			st.mu.Lock()
			warnDue := st.warnedAt[ip] != m.Discovered
			if warnDue {
				st.warnedAt[ip] = m.Discovered
			}
			st.mu.Unlock()
			if warnDue { // transition-logged (the [PD_CTRL] precedent)
				log.Warnf("[AICTRL] registry mismatch source=%s expected_num_gpu_blocks=%d discovered=%d — discovered wins",
					ip, m.Expected, m.Discovered)
			}
		}
	}

	// Split the piggybacked lmcache:* families (LMC-02) out of the vLLM sample
	// into the separate lmc store, keyed by IP with this scrape's LastUpdate —
	// weight math (which reads `samples`) never sees them.
	lmcRaw := selectLMCacheRaw(s.Raw)

	st.mu.Lock()
	st.samples[ip] = engine.Sourced{IP: ip, Sample: s}
	if len(lmcRaw) > 0 {
		st.mergeLMCacheLocked(ip, lmcRaw, s.LastUpdate)
	}
	st.mu.Unlock()
}

// selectLMCacheRaw returns the lmcache:* subset of a scraped Raw map (nil when
// none present). The vLLM 3-series keys are left behind for the weight math.
func selectLMCacheRaw(raw map[string]float64) map[string]float64 {
	var out map[string]float64
	for k, v := range raw {
		if len(k) >= len(aimetrics.LMCacheFamilyPrefix) &&
			k[:len(aimetrics.LMCacheFamilyPrefix)] == aimetrics.LMCacheFamilyPrefix {
			if out == nil {
				out = make(map[string]float64, len(raw))
			}
			out[k] = v
		}
	}
	return out
}

// mergeLMCacheLocked REPLACES the LMCache signal set for ip with this
// scrape's keys (metrics audit H-20: overlaying let keys absent from a fresh
// scrape ride the new timestamp indefinitely — with the /lookup source
// deleted, the /metrics piggyback is the only producer, so a fresh scrape is
// authoritative). Caller holds st.mu; raw is a per-call map (safe to mutate).
//
// H-18: lmcache:time_to_retrieve arrives as the CUMULATIVE histogram
// (sum,count) pair; it is windowed here into the mean retrieve latency for
// this scrape interval, published under the plain family key the consumers
// (engine lmcCostTerm, buildTtftFeatures FetchCost) already read. No window
// yet or no retrieves this interval ⇒ the key is dropped (absent ⇒ neutral,
// never a stale or cumulative value).
func (st *sampleStore) mergeLMCacheLocked(ip string, raw map[string]float64, lastUpdate time.Time) {
	sumKey := aimetrics.FamilyLMCacheTimeToRetrieve + aimetrics.RawSuffixHistSum
	cntKey := aimetrics.FamilyLMCacheTimeToRetrieve + aimetrics.RawSuffixHistCount
	sum, hasSum := raw[sumKey]
	cnt, hasCnt := raw[cntKey]
	delete(raw, sumKey)
	delete(raw, cntKey)
	delete(raw, aimetrics.FamilyLMCacheTimeToRetrieve) // cumulative — never publish raw
	if hasSum && hasCnt {
		if mean, ok := st.lmcWindows.Mean(ip, sum, cnt); ok {
			raw[aimetrics.FamilyLMCacheTimeToRetrieve] = mean
		}
	}
	st.lmcSamples[ip] = aimetrics.WorkerSample{Raw: raw, LastUpdate: lastUpdate}
}

// snapshot returns a copy of the current sample set for one engine tick.
func (st *sampleStore) snapshot() map[string]engine.Sourced {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make(map[string]engine.Sourced, len(st.samples))
	for k, v := range st.samples {
		out[k] = v
	}
	return out
}

// lmcSnapshot returns a deep copy of the current LMCache signal set for one
// engine tick — the ComputeWeights lmc carrier. Empty (no LMCache signal seen)
// is fine: the cost term treats an absent IP as neutral.
func (st *sampleStore) lmcSnapshot() map[string]aimetrics.WorkerSample {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make(map[string]aimetrics.WorkerSample, len(st.lmcSamples))
	for ip, s := range st.lmcSamples {
		cp := s
		cp.Raw = make(map[string]float64, len(s.Raw))
		for k, v := range s.Raw {
			cp.Raw[k] = v
		}
		out[ip] = cp
	}
	return out
}

// invertWeights applies the VAL-02 negative control AFTER the damping
// pipeline: over the FRESH prefill EPs, w'_i = min_w + max_w - w_i (weight
// ORDER inversion — the best-capacity EP gets the worst weight). Stale EPs
// and the decode role are untouched.
func invertWeights(reg *engine.Registry, weights map[string]uint32,
	staleSources []string) map[string]uint32 {

	stale := make(map[string]bool, len(staleSources))
	for _, ip := range staleSources {
		stale[ip] = true
	}

	var minW, maxW uint32
	first := true
	for ip, w := range weights {
		h, ok := reg.Hosts[ip]
		if !ok || h.Role != engine.RolePrefill || stale[ip] {
			continue
		}
		if first {
			minW, maxW, first = w, w, false
			continue
		}
		if w < minW {
			minW = w
		}
		if w > maxW {
			maxW = w
		}
	}
	out := make(map[string]uint32, len(weights))
	for ip, w := range weights {
		out[ip] = w
	}
	if first {
		return out // no fresh prefill EPs — nothing to invert
	}
	for ip, w := range weights {
		h, ok := reg.Hosts[ip]
		if !ok || h.Role != engine.RolePrefill || stale[ip] {
			continue
		}
		out[ip] = minW + maxW - w
	}
	return out
}

// refreshStalenessMetrics updates the per-source CTRL-05 gauges each tick.
func refreshStalenessMetrics(reg *engine.Registry, samples map[string]engine.Sourced,
	stats engine.EngineStats, now, start time.Time) {

	stale := make(map[string]bool, len(stats.StaleSources))
	for _, ip := range stats.StaleSources {
		stale[ip] = true
	}
	for ip := range reg.Hosts {
		age := now.Sub(start) // never scraped: age since process start
		if s, ok := samples[ip]; ok && !s.Sample.LastUpdate.IsZero() {
			age = now.Sub(s.Sample.LastUpdate)
		}
		metricSourceStaleness.WithLabelValues(ip).Set(age.Seconds())
		v := 0.0
		if stale[ip] {
			v = 1.0
		}
		metricSourceStale.WithLabelValues(ip).Set(v)
	}
	if stats.FleetStale {
		metricFleetStale.Set(1)
	} else {
		metricFleetStale.Set(0)
	}
}

// ── TTFT-02/03 feature sourcing + coefficients startup ────────

// TTFT feature soft-scale midpoints — deliberately the SAME values the engine's
// lmcCostTerm uses (engine.go lmcRetrieveSoftScaleSec / lmcPrefixSoftScaleTokens):
// the snapshot JSONL is the fit tool's training input AND the same builder feeds
// the runtime TtftFeats carrier, so fit-time and apply-time feature semantics
// can never drift as long as one function computes both.
const (
	// ttftFetchCostSoftScaleSec is the fetch-cost saturation midpoint (sec).
	ttftFetchCostSoftScaleSec = 0.05
	// ttftPrefixSoftScaleTokens is the matched-prefix saturation midpoint.
	ttftPrefixSoftScaleTokens = 512.0
)

// satFrac maps x∈[0,∞) into [0,1) via x/(x+scale) — the engine's lmcSatFrac
// analog (saturating fraction, no hard cap). Non-positive x or scale ⇒ 0.
func satFrac(x, scale float64) float64 {
	if x <= 0 || scale <= 0 {
		return 0
	}
	return x / (x + scale)
}

// loadTtftModelStartup resolves the boot-time Expected-TTFT model state
// (pure function — options/server test style):
//   - coefFile == "" and NOT armed  ⇒ (nil, nil): model never loaded, the
//     term is STRUCTURALLY off (the LmcLookupURL empty-never-started shape).
//   - coefFile == "" and ARMED      ⇒ error: arming without coefficients is
//     an operator misconfig — fail loud at boot, never a silent no-op (V5).
//   - coefFile != "" ⇒ engine.LoadTtftModel; any load/validate error
//     propagates (a present-but-invalid file is an operator mistake — the
//     caller Fatals). When ARMING, every recorded gate verdict must read
//
// PASS: pins "failed gates ⇒ the weight term is never ARMED" as
//
//	BINARY policy, so an armed-with-failed-gates boot is refused here
//	(observability mode — model loaded UNARMED — accepts any verdicts).
func loadTtftModelStartup(coefFile string, armed bool) (*engine.TtftModel, error) {
	if coefFile == "" {
		if armed {
			return nil, fmt.Errorf("AICTRL_TTFT_WEIGHT set but AICTRL_TTFT_COEF_FILE empty — arming without coefficients is a misconfig (term would be structurally OFF); ship fit output and point AICTRL_TTFT_COEF_FILE at it")
		}
		return nil, nil // default-OFF: model never loaded
	}
	m, err := engine.LoadTtftModel(coefFile)
	if err != nil {
		return nil, err
	}
	if armed {
		for gate, verdict := range m.GateVerdicts {
			if verdict != "PASS" {
				return nil, fmt.Errorf("AICTRL_TTFT_WEIGHT set but coefficients file %s records gate verdict %s=%q — : a model that failed its gates is NEVER armed (run unarmed observability mode instead)", coefFile, gate, verdict)
			}
		}
	}
	return m, nil
}

// buildTtftFeatures assembles the per-epoch per-EP TTFT feature carrier from
// the sampleStore signals. Carrier discipline mirrors LMC:
// the map is threaded into EngineConfig.TtftFeats UNCONDITIONALLY every
// epoch — the TtftEnabled knob gates consumption, not collection.
//
// Slots (the vocabulary, engine.TtftFeat* consts):
//   - waiting_over_capacity = num_requests_waiting / calibrated throughput
//
// ratio via reg.CalibratedThroughputRatio(ip, verified[ip]) —
//
//	  consumption site: an unverified/mismatched fingerprint falls back to
//	  serving_throughput_prior (never an eligibility change).
//	- kv_cache_usage_perc  = the scraped vllm KV-usage gauge.
//	- fetch_cost           = sat(time_to_retrieve / retrieve_hit_rate) — the
//
// lmcache remote-fetch-cost composite (absent/stale ⇒ 0 neutral).
//   - matched_prefix_sat   = sat(matched_prefix_length) — the /lookup
//     locality signal when that source is armed (absent/stale ⇒ 0 neutral).
//   - log_prompt_tokens    = logRefPromptTokens (workload REFERENCE length,
//
// a fit covariate that shifts every EP identically).
//
// LastUpdate = the vLLM sample's scrape stamp (the primary epoch clock); EPs
// with no sample at all get no entry (absent ⇒ the engine's neutral decay).
func buildTtftFeatures(reg *engine.Registry, samples map[string]engine.Sourced,
	lmc map[string]aimetrics.WorkerSample, logRefPromptTokens float64,
	verified map[string]bool, now time.Time, lmcFreshBudget time.Duration) map[string]engine.TtftEpochFeatures {

	out := make(map[string]engine.TtftEpochFeatures, len(reg.Hosts))
	for ip := range reg.Hosts {
		s, ok := samples[ip]
		if !ok {
			continue // never scraped ⇒ absent entry ⇒ engine-neutral
		}
		ratio, ok := reg.CalibratedThroughputRatio(ip, verified[ip])
		if !ok || ratio <= 0 {
			continue // structurally impossible post-LoadRegistry; defensive
		}
		f := engine.TtftFeatures{
			LogPromptTokens:     logRefPromptTokens,
			WaitingOverCapacity: float64(s.Sample.NumRequestsWaiting) / ratio,
			KvCacheUsagePerc:    s.Sample.GPUCacheUsagePerc,
		}
		// LMCache-sourced slots: independent staleness (the lmc carrier's own
		// LastUpdate) — stale or absent decays the SLOT to 0 (neutral), never
		// a trusted zero-fill of the whole vector.
		if ls, ok := lmc[ip]; ok && aimetrics.Fresh(now, ls, lmcFreshBudget) {
			if t, ok := ls.Raw[aimetrics.FamilyLMCacheTimeToRetrieve]; ok {
				// t is the WINDOWED mean retrieve latency (H-18) — seconds per
				// retrieve over the last scrape interval. Dividing by the hit
				// rate scales it to an expected cost per lookup (a miss forces
				// the expensive path), keeping the covariate dimensionally a
				// latency rather than the old cumulative-sum/ratio artifact.
				base := t
				if hr, ok := ls.Raw[aimetrics.FamilyLMCacheRetrieveHitRate]; ok && hr > 0 {
					base = t / hr
				}
				f.FetchCost = satFrac(base, ttftFetchCostSoftScaleSec)
			}
			if v, ok := ls.Raw[aimetrics.RawKeyMatchedPrefixLength]; ok {
				f.MatchedPrefixSat = satFrac(v, ttftPrefixSoftScaleTokens)
			}
		}
		out[ip] = engine.TtftEpochFeatures{
			TtftFeatures: f,
			LastUpdate:   s.Sample.LastUpdate,
		}
	}
	return out
}

// ── fingerprint field-wise verify ────────────────────────

// discoveredFingerprint builds the LIVE-DISCOVERABLE fingerprint subset for
// one scraped sample. Of the RQ2 live-verifiable fields (num_gpu_blocks,
// block_size, model_id, max_model_len) this binary can actually source ONLY
// num_gpu_blocks today: the narrow lineparser extracts just that label off
// vllm:cache_config_info (block_size is on the same _info line but is not
// parsed), and /v1/models is deliberately NOT a poll target of this binary
// (scope: verify only fields actually available — the startup INFO
// line documents the subset). nil when the sample carries no capacity yet.
func discoveredFingerprint(s aimetrics.WorkerSample) map[string]string {
	if s.NumGPUBlocks == 0 {
		return nil
	}
	return map[string]string{
		engine.FpNumGpuBlocks: fmt.Sprint(s.NumGPUBlocks),
	}
}

// fpEpochResult is one epoch's fingerprint-verification outcome.
type fpEpochResult struct {
	// Verified marks IPs whose calibration fingerprint verified against the
	// live-discovered subset this epoch (⇒ CalibratedThroughputRatio may
	// return the calibrated ratio). Anything else — no calibration block,
	// nothing discoverable yet, or a mismatch — stays on the prior.
	Verified map[string]bool
	// Mismatches carries EVERY FieldMismatch this epoch — the counter feed
	// (aictrl_fingerprint_mismatch_total increments every mismatched epoch).
	Mismatches []engine.FieldMismatch
	// WarnDue maps IPs whose mismatch signature CHANGED this epoch to the
	// human-readable signature — the transition-only WARN feed
	// [PD_CTRL] precedent: log on transition, count every epoch).
	WarnDue map[string]string
	// Recovered lists IPs that transitioned mismatched → clean this epoch.
	Recovered []string
}

// fpVerifier runs the per-epoch fingerprint verification over every
// calibrated registry host, tracking per-IP mismatch signatures so WARNs
// fire on TRANSITION only. Report-only by construction: it returns records;
// the caller logs/counts, and the ONLY downstream reaction is the
// CalibratedThroughputRatio prior fallback — eligibility is NEVER touched
// (no exclusion, no state writes, no weight-map key changes).
type fpVerifier struct {
	lastSig map[string]string // ip -> last WARNed mismatch signature ("" = clean)
}

func newFpVerifier() *fpVerifier {
	return &fpVerifier{lastSig: make(map[string]string)}
}

// VerifyEpoch verifies every calibrated host against its live-discovered
// fingerprint subset for one epoch's sample set.
func (v *fpVerifier) VerifyEpoch(reg *engine.Registry, samples map[string]engine.Sourced) fpEpochResult {
	res := fpEpochResult{
		Verified: make(map[string]bool, len(reg.Hosts)),
		WarnDue:  make(map[string]string),
	}
	for ip, h := range reg.Hosts {
		if h.Calibration == nil {
			continue // nothing declared ⇒ prior path, nothing to verify
		}
		s, ok := samples[ip]
		if !ok {
			continue // never scraped ⇒ unverified ⇒ prior
		}
		discovered := discoveredFingerprint(s.Sample)
		if len(discovered) == 0 {
			continue // no live-discoverable signal yet ⇒ unverified ⇒ prior
		}
		mismatches := engine.VerifyFingerprint(ip, h.Calibration, discovered)
		if len(mismatches) == 0 {
			res.Verified[ip] = true
			if v.lastSig[ip] != "" {
				res.Recovered = append(res.Recovered, ip)
				v.lastSig[ip] = ""
			}
			continue
		}
		res.Mismatches = append(res.Mismatches, mismatches...)
		sig := ""
		for _, m := range mismatches { // VerifyFingerprint output is field-sorted
			if sig != "" {
				sig += "; "
			}
			sig += fmt.Sprintf("%s expected=%q discovered=%q", m.Field, m.Expected, m.Discovered)
		}
		if v.lastSig[ip] != sig { // transition-only WARN
			res.WarnDue[ip] = sig
			v.lastSig[ip] = sig
		}
	}
	return res
}

// snapFeatureMap projects one EP's feature vector into the snapshot-row
// features map — EPOCH signals only (the cmd/aictrl-ttft-fit SnapshotRecord
// contract): prompt length is a per-request fit-time covariate
// and NEVER appears in a snapshot row; the intercept is implicit.
func snapFeatureMap(f engine.TtftFeatures) map[string]float64 {
	return map[string]float64{
		engine.TtftFeatWaitingOverCapacity: f.WaitingOverCapacity,
		engine.TtftFeatKvCacheUsagePerc:    f.KvCacheUsagePerc,
		engine.TtftFeatFetchCost:           f.FetchCost,
		engine.TtftFeatMatchedPrefixSat:    f.MatchedPrefixSat,
	}
}

// featureSnapRow is one feature-snapshot JSONL line. The ts/ep/features
// triple IS the cmd/aictrl-ttft-fit SnapshotRecord ingest contract
// (fit.go:4 — field-for-field); epoch/alpha/armed are supplementary
// audit fields the fit tool's json.Unmarshal ignores.
type featureSnapRow struct {
	TS       float64            `json:"ts"`    // unix seconds
	Epoch    uint64             `json:"epoch"` // controller epoch tick (audit)
	EP       string             `json:"ep"`    // "IP:PORT"
	Features map[string]float64 `json:"features"`
	Alpha    float64            `json:"alpha"` // α_ttft used this epoch
	Armed    bool               `json:"armed"` // TTFT term armed this epoch
}

// featureSnapMaxBytes is the size-capped rotation threshold (100MB → .1).
const featureSnapMaxBytes = int64(100 << 20)

// featureSnapWriter appends feature-snapshot JSONL rows with simple
// size-capped rotation (: the artifact must not grow unbounded on
// .13). newFeatureSnapWriter("") returns nil — the empty-never-started
// discipline: no open, no write, zero I/O when the knob is unset.
type featureSnapWriter struct {
	path     string
	maxBytes int64
	f        *os.File
	size     int64
}

// newFeatureSnapWriter opens (append-mode) the snapshot file. Empty path ⇒
// nil (never started). An unopenable path is returned as an error — a
// configured-but-unwritable artifact is an operator misconfig (fail loud at
// boot, V5).
func newFeatureSnapWriter(path string, maxBytes int64) (*featureSnapWriter, error) {
	if path == "" {
		return nil, nil // default-OFF: writer never started
	}
	if maxBytes <= 0 {
		maxBytes = featureSnapMaxBytes
	}
	w := &featureSnapWriter{path: path, maxBytes: maxBytes}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *featureSnapWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("feature snapshot open %s: %w", w.path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("feature snapshot stat %s: %w", w.path, err)
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Append writes one JSONL row, rotating (path → path+".1", replacing any
// previous .1) when the size cap is exceeded. Runtime write errors are
// returned for the caller to WARN on — an observability artifact must never
// crash the controller mid-run.
func (w *featureSnapWriter) Append(row featureSnapRow) error {
	if w == nil || w.f == nil {
		return nil
	}
	if w.size >= w.maxBytes {
		w.f.Close()
		if err := os.Rename(w.path, w.path+".1"); err != nil {
			return fmt.Errorf("feature snapshot rotate %s: %w", w.path, err)
		}
		if err := w.open(); err != nil {
			return err
		}
	}
	b, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("feature snapshot marshal: %w", err)
	}
	b = append(b, '\n')
	n, err := w.f.Write(b)
	w.size += int64(n)
	if err != nil {
		return fmt.Errorf("feature snapshot write %s: %w", w.path, err)
	}
	return nil
}

// Close flushes and closes the writer (nil-safe).
func (w *featureSnapWriter) Close() {
	if w != nil && w.f != nil {
		w.f.Close()
	}
}

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	setupLogging(opts.LogLevel)
	log.Info("loxilb-ai-controller starting")

	// ── Registry (CTRL-03) ────────────────────────────────────────────────
	reg, err := engine.LoadRegistry(opts.Registry)
	if err != nil {
		log.WithError(err).Fatal("registry load failed")
	}
	maxIdx := 0
	for _, h := range reg.Hosts {
		if int(h.EpIdx) > maxIdx {
			maxIdx = int(h.EpIdx)
		}
	}
	endpoints := make([]string, maxIdx+1)
	idxToIP := make([]string, maxIdx+1)
	for ip, h := range reg.Hosts {
		endpoints[h.EpIdx] = fmt.Sprintf("%s:%d", ip, h.Port)
		idxToIP[h.EpIdx] = ip
	}
	log.WithFields(log.Fields{
		"registry": opts.Registry,
		"service":  reg.Service.Key,
		"hosts":    len(reg.Hosts),
	}).Info("capability registry loaded")

	// ── Negative-control arm state: export 0/1 up front ────────
	if opts.NegativeControlInvert {
		metricNegativeControl.Set(1)
		log.Warn("[AICTRL] NEGATIVE CONTROL ACTIVE — VAL-02 harness arm: fresh-prefill weight order INVERTED")
	} else {
		metricNegativeControl.Set(0)
	}

	// ── LMCache cost-term arm state (self-confirm): export 0/1 up front.
	//    LMC-02 collection is independent of this knob (piggyback lands live);
	//    this gauge tracks only whether the LMC-03 cost term modulates weights.
	if opts.LmcCostEnabled {
		metricLmcCostActive.Set(1)
		log.Warnf("[AICTRL] LMCACHE COST TERM ACTIVE (LMC-03) — max_pts=%v stale_sec=%d — weights are NO LONGER byte-identical",
			opts.LmcMaxPts, opts.LmcStaleSec)
	} else {
		metricLmcCostActive.Set(0)
	}

	// ── Expected-TTFT term state (TTFT-02/03): model load + arm gauge.
	//    Empty AICTRL_TTFT_COEF_FILE ⇒ model never loaded (structurally OFF);
	//    armed without a model, invalid file, or armed with failed gate
	// verdicts ⇒ FATAL at boot (V5 — never a silent no-op).
	ttftModel, err := loadTtftModelStartup(opts.TtftCoefFile, opts.TtftEnabled)
	if err != nil {
		log.WithError(err).Fatal("ttft coefficients startup failed")
	}
	ttftModelVersion := "none"
	if ttftModel != nil {
		ttftModelVersion = fmt.Sprint(ttftModel.ModelVersion)
		metricTtftModelVersion.Set(float64(ttftModel.ModelVersion))
		log.WithFields(log.Fields{
			"coef_file":     opts.TtftCoefFile,
			"model_version": ttftModel.ModelVersion,
			"fit_date":      ttftModel.FitDate,
			"features":      ttftModel.Features,
		}).Info("Expected-TTFT coefficients model loaded")
	} else {
		metricTtftModelVersion.Set(0)
	}
	ttftArmed := opts.TtftEnabled && ttftModel != nil
	if ttftArmed {
		metricTtftActive.WithLabelValues(ttftModelVersion).Set(1)
		log.Warnf("[AICTRL] TTFT WEIGHT TERM ACTIVE (TTFT-03) — model_version=%s max_pts=%v stale_sec=%d invert=%v — weights are NO LONGER byte-identical",
			ttftModelVersion, opts.TtftMaxPts, opts.TtftStaleSec, opts.TtftInvert)
	} else {
		metricTtftActive.WithLabelValues(ttftModelVersion).Set(0)
		if ttftModel != nil {
			// observability posture: predicted-vs-measured evidence is
			// exported (alpha/pred-err gauges + feature snapshots) while the
			// weight term stays structurally un-armed.
			log.Infof("[AICTRL] TTFT model loaded UNARMED (observability mode) — model_version=%s; weights stay byte-identical", ttftModelVersion)
		}
	}
	logRefPromptTokens := math.Log(float64(opts.TtftRefPromptTokens))

	// fingerprint verification scope : announce the
	// live-verifiable subset up front so no reader over-trusts the verify —
	// only fields this binary actually sources are compared.
	calibrated := 0
	for _, h := range reg.Hosts {
		if h.Calibration != nil {
			calibrated++
		}
	}
	log.Infof("[AICTRL] fingerprint live-verify subset = [%s] (block_size/model_id/max_model_len are NOT scraped by this binary — harness-verified at calibration time); calibrated hosts=%d/%d; : mismatch => WARN + aictrl_fingerprint_mismatch_total + prior fallback, NEVER an eligibility change",
		engine.FpNumGpuBlocks, calibrated, len(reg.Hosts))

	// ── TTFT-03 live prediction-error monitor : only constructed
	//    when a coefficients model is loaded (default-OFF ⇒ zero extra scrape
	// traffic). Runs in BOTH armed and observability postures — the
	//    unarmed mode's whole point is exporting predicted-vs-measured
	//    evidence (aictrl_ttft_alpha / aictrl_ttft_pred_err_ratio_*).
	var ttftMon *ttftMonitor
	var ttftObsSrc *ttftObservedSource
	if ttftModel != nil {
		ttftMon = newTtftMonitor(ttftModel.GateThresholds.P50RelErr)
		targets := make(map[string]string, len(reg.Hosts))
		for ip, h := range reg.Hosts {
			targets[ip] = fmt.Sprintf("%s:%d", ip, h.Port)
		}
		ttftObsSrc = newTtftObservedSource(targets)
		metricTtftAlpha.Set(ttftMon.Alpha())
		log.Infof("[AICTRL] TTFT live prediction-error monitor started — server-histogram delta (diagnostic; aiperf stays the offline gate truth); p50_thr=%v, |dAlpha|<=%v/epoch",
			ttftModel.GateThresholds.P50RelErr, ttftAlphaMaxStep)
	}

	// ── Feature-snapshot JSONL writer (RESEARCH OQ-3): empty path ⇒
	//    NEVER started (nil writer — no open, no write).
	snapW, err := newFeatureSnapWriter(opts.FeatureSnapFile, featureSnapMaxBytes)
	if err != nil {
		log.WithError(err).Fatal("feature snapshot writer startup failed")
	}
	if snapW != nil {
		defer snapW.Close()
		log.WithField("path", opts.FeatureSnapFile).Info("per-epoch feature-snapshot JSONL writer started")
	}

	// ── aimetrics collection loop (CTRL-02 substrate) ─────────────────────
	store := newSampleStore(reg, idxToIP)
	poller := aimetrics.NewPoller(endpoints,
		time.Duration(opts.ScrapeIntervalSec)*time.Second, store)
	// LMC-02: pull lmcache:* families off the SAME vLLM /metrics body (Pattern 1
	// piggyback — no second scrape target). Collection is unconditional; the
	// cost term that consumes it stays default-OFF above.
	poller.EnableLMCachePiggyback()
	pollCtx, pollCancel := context.WithCancel(context.Background())
	go poller.Run(pollCtx)

	// The LMCache /lookup locality poller was removed in the metrics audit
	// (H-19/D3): the controller has no request-scoped token stream, so its
	// empty-token probe could only ever measure matched_prefix_length == 0
	// yet delivered it as a trusted fresh sample. Locality signal now comes
	// solely from the /metrics piggyback above.

	// ── gRPC snapshot bus ─────────────────────────────────────────────────
	srv := newSnapshotServer(0, 0, metricsHooks(log.Infof))
	lis, err := net.Listen("tcp", opts.GrpcAddr)
	if err != nil {
		log.WithError(err).WithField("addr", opts.GrpcAddr).Fatal("gRPC listen failed")
	}
	grpcSrv := grpc.NewServer()
	aictrl.RegisterAiCtrlServer(grpcSrv, srv)
	go func() {
		log.WithField("addr", opts.GrpcAddr).Info("gRPC snapshot bus serving")
		if err := grpcSrv.Serve(lis); err != nil {
			log.WithError(err).Error("gRPC server stopped")
		}
	}()

	// ── CTRL-05 /metrics ──────────────────────────────────────────────────
	metricsSrv := serveMetrics(opts.MetricsAddr, func(err error) {
		log.WithError(err).Fatal("metrics server failed")
	})
	log.WithField("addr", opts.MetricsAddr).Info("metrics server serving")

	// ── Decision + emission loop (epoch cadence) ─────────────────────
	engCfg := engine.EngineConfig{
		StaleBudget: time.Duration(opts.StaleBudgetSec) * time.Second,
		EwmaAlpha:   opts.EwmaAlpha,
		DeadBand:    opts.DeadBand,
		MaxStepPct:  opts.MaxStepPct,

		// LMC-03 cost-term knobs. LmcCostEnabled=false (default) makes the whole
		// term inert inside ComputeWeights ⇒ byte-identical to; the
		// LMCache samples are still threaded in every epoch (harmless when OFF).
		LmcCostEnabled: opts.LmcCostEnabled,
		LmcMaxPts:      opts.LmcMaxPts,
		LmcStaleBudget: time.Duration(opts.LmcStaleSec) * time.Second,

		// TTFT-02/03 knobs. TtftEnabled=false (default) or a nil
		// TtftModel keeps the term STRUCTURALLY off ⇒ weights byte-identical;
		// the feature carrier is still threaded every epoch (knob gates
		// consumption — the LMC precedent). TtftAlpha is set per epoch below.
		TtftEnabled:     opts.TtftEnabled,
		TtftMaxPts:      opts.TtftMaxPts,
		TtftStaleBudget: time.Duration(opts.TtftStaleSec) * time.Second,
		TtftInvert:      opts.TtftInvert,
		TtftModel:       ttftModel,
	}
	epochPeriod := time.Duration(opts.EpochPeriodSec) * time.Second
	reanchor, clamped := effectiveReanchor(opts.ReanchorSec, epochPeriod)
	if clamped {
		log.Warnf("[AICTRL] --reanchor-sec=%ds exceeds one epoch (%s); the re-anchor is the applier liveness heartbeat and must stay well inside the 3×epoch=%s staleness deadline — clamping to %s to prevent applier mode oscillation",
			opts.ReanchorSec, epochPeriod, 3*epochPeriod, reanchor)
	}
	gen := engine.NewGenerator(reg, engine.GeneratorConfig{
		EpochPeriod:   epochPeriod,
		ReanchorEvery: reanchor,
	})
	log.WithFields(log.Fields{
		"boot_id":      gen.BootID(),
		"epoch_period": epochPeriod,
	}).Info("snapshot generator ready")

	loopCtx, loopCancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		start := time.Now()
		var prev map[string]uint32
		var epochTick uint64
		fpv := newFpVerifier()
		ticker := time.NewTicker(epochPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case now := <-ticker.C:
				epochTick++
				samples := store.snapshot()
				lmc := store.lmcSnapshot()
				cfg := engCfg
				cfg.Now = now
				// fingerprint verify, alongside the discovery validation:
				// WARN on transition only, counter EVERY mismatched epoch, and
				// the ONLY downstream reaction is the CalibratedThroughputRatio
				// prior fallback below — eligibility is never touched.
				fpRes := fpv.VerifyEpoch(reg, samples)
				for _, m := range fpRes.Mismatches {
					metricFingerprintMismatch.WithLabelValues(m.IP).Inc()
				}
				for ip, sig := range fpRes.WarnDue {
					log.Warnf("[AICTRL] fingerprint mismatch source=%s [%s] — calibrated ratio DISTRUSTED, falling back to serving_throughput_prior (eligibility unchanged)",
						ip, sig)
				}
				for _, ip := range fpRes.Recovered {
					log.Infof("[AICTRL] fingerprint verified again source=%s — calibrated throughput ratio back in use", ip)
				}
				// TTFT-02/03: build + thread the per-epoch feature carrier
				// UNCONDITIONALLY (knob gates consumption — the LMC precedent).
				// The fingerprint-verified flag gates the calibrated-vs-prior
				// capacity denominator per EP.
				ttftFeats := buildTtftFeatures(reg, samples, lmc, logRefPromptTokens,
					fpRes.Verified, now, cfg.TtftStaleBudget)
				cfg.TtftFeats = ttftFeats
				// α_ttft (TTFT-03): the live prediction-error monitor owns it.
				// Predictions come from THIS epoch's fresh feature vectors;
				// observations from the per-EP TTFT histogram delta over the
				// same window. No monitor (no model loaded) ⇒ α stays 1.0 and
				// the engine ignores it (term structurally OFF).
				ttftAlpha := 1.0
				if ttftMon != nil {
					preds := make(map[string]float64, len(ttftFeats))
					for ip, ef := range ttftFeats {
						if !ef.LastUpdate.IsZero() && now.Sub(ef.LastUpdate) <= cfg.TtftStaleBudget {
							preds[ip] = ttftModel.Predict(ef.TtftFeatures)
						}
					}
					window := make([]ttftObs, 0, len(preds))
					for ip, mean := range ttftObsSrc.WindowMeans(loopCtx) {
						if p, ok := preds[ip]; ok {
							window = append(window, ttftObs{PredLogTtft: p, ObservedSec: mean})
						}
					}
					ttftAlpha = ttftMon.Observe(window)
					metricTtftAlpha.Set(ttftAlpha)
					if p50, p90, ok := ttftMon.LastErr(); ok {
						setTtftPredErr(p50, p90)
					}
				}
				cfg.TtftAlpha = ttftAlpha
				// Feature-snapshot JSONL (OQ-3): one row per EP per epoch,
				// written whenever the writer is configured — including
				// fleet-stale epochs (the offline gate eval must see exactly
				// what the controller saw).
				if snapW != nil {
					for ip, ef := range ttftFeats {
						row := featureSnapRow{
							TS:       float64(now.Unix()),
							Epoch:    epochTick,
							EP:       fmt.Sprintf("%s:%d", ip, reg.Hosts[ip].Port),
							Features: snapFeatureMap(ef.TtftFeatures),
							Alpha:    ttftAlpha,
							Armed:    ttftArmed,
						}
						if err := snapW.Append(row); err != nil {
							log.WithError(err).Warn("feature snapshot append failed")
						}
					}
				}
				// Thread the LMCache signals in as the optional lmc carrier: the
				// cost term reads them ONLY when cfg.LmcCostEnabled (default-OFF),
				// so with the knob unset this is byte-identical to.
				weights, stats := engine.ComputeWeights(reg, samples, prev, cfg, lmc)
				refreshStalenessMetrics(reg, samples, stats, now, start)
				if stats.FleetStale {
					// CTRL-02: emit NOTHING — appliers walk the ladder.
					log.Warnf("[AICTRL] fleet stale (%d sources) — no snapshot emitted",
						len(stats.StaleSources))
					continue
				}
				prev = weights // damping state = TRUE pipeline output

				emitW := weights
				if opts.NegativeControlInvert {
					emitW = invertWeights(reg, weights, stats.StaleSources)
				}
				for ip, w := range emitW {
					metricEpWeight.WithLabelValues(reg.Service.Key,
						fmt.Sprint(reg.Hosts[ip].EpIdx)).Set(float64(w))
				}

				snap := gen.Maybe(now, emitW, nil, stats.FleetStale)
				if snap == nil {
					continue // churn-guarded / unchanged, re-anchor not due
				}
				metricSnapshotsEmitted.Inc()
				metricCurrentEpoch.Set(float64(snap.GetEpoch()))
				if opts.NegativeControlInvert {
					// loud on EVERY emission so a leftover flag can
					// never masquerade as the real controller arm.
					log.Warnf("[AICTRL] NEGATIVE CONTROL ACTIVE — emitting INVERTED weights epoch=%d", snap.GetEpoch())
				}
				srv.Broadcast(snap)
				log.WithFields(log.Fields{
					"epoch":   snap.GetEpoch(),
					"fresh":   stats.FreshSources,
					"stale":   len(stats.StaleSources),
					"held":    stats.Held,
					"clamped": stats.Clamped,
				}).Info("snapshot emitted")
			}
		}
	}()

	// ── Signals: stop EMITTING first, then the server (appliers ride the
	//    staleness ladder), then the poller ─────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.WithField("signal", sig.String()).Info("shutdown: stopping emission first")

	loopCancel()
	<-loopDone
	grpcSrv.Stop() // streams die => appliers begin the decay ladder
	pollCancel()
	poller.Stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(shutdownCtx)

	log.Info("loxilb-ai-controller stopped")
}

// setupLogging configures logrus to match the loxilb-kv-agent style.
func setupLogging(level string) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	lvl, err := log.ParseLevel(level)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
}
