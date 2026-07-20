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

// lmcache.go — the LMCache signal collector (LMC-02). One controller-only signal
// surface feeds engine a future cost term: lmcache:* Prometheus families,
// piggybacked on the vLLM /metrics body and selected off the FULL-family
// expfmt path (expfmt.go DecodeFamilies) — the narrow hot-path lineparser.go
// 3-series contract is NEVER touched. (The POST /lookup KV-index source was
// removed in the metrics audit, H-19/D3 — its empty-token probe could only
// measure 0.)
//
// The collector keeps a hardened discipline: defensive parse (absent / empty
// / non-numeric / negative / NaN / Inf ⇒ neutral, never panic — the
// parseNumGPUBlocksLabel / analog) and per-source LastUpdate staleness
// (a stale or empty source is decayed to neutral by the consumer, NEVER
// zero-filled).
//
// Signals ride in the existing WorkerSample.Raw map + LastUpdate. No
// scraped-load-shaped fields are introduced (P1 — the engine reads only
// LastUpdate on the load path; KV-pressure/locality are memory/locality signals
// the data plane does not track, the sole reason they may later enter a bounded,
// default-OFF weight term).
package aimetrics

import (
	"io"
	"math"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// LMCacheFamilyPrefix selects the piggybacked LMCache metric families off the
// decoded vLLM /metrics family map.
const LMCacheFamilyPrefix = "lmcache:"

// LMCache metric-family names (mirrors the lineparser constant block). These are
// the KV-pressure + remote-fetch-cost signal families the collector surfaces;
// the prefix selector below is authoritative, these name the canonical series a
// consumer keys on.
const (
	// FamilyLMCacheRetrieveHitRate is the retrieve-path hit-rate gauge.
	FamilyLMCacheRetrieveHitRate = "lmcache:retrieve_hit_rate"
	// FamilyLMCacheLocalCacheUsage is the local (CPU-tier) KV usage gauge (bytes).
	FamilyLMCacheLocalCacheUsage = "lmcache:local_cache_usage"
	// FamilyLMCacheRemoteCacheUsage is the remote-tier KV usage gauge (bytes) —
	// the cross-instance KV-pressure signal.
	FamilyLMCacheRemoteCacheUsage = "lmcache:remote_cache_usage"
	// FamilyLMCacheTimeToRetrieve is the retrieve-latency histogram — the
	// remote-fetch-cost signal (its SampleSum is surfaced as the scalar).
	FamilyLMCacheTimeToRetrieve = "lmcache:time_to_retrieve"
)

// ParseLMCacheBody decodes a full Prometheus text-exposition body and returns a
// WorkerSample whose Raw map carries every lmcache:* series keyed by full family
// name. LastUpdate is left zero — stamping is the source/poller's job.
//
// It is defensive by construction: a body expfmt cannot decode yields an empty
// (neutral) Raw with no panic; a decoded family with no usable scalar (absent /
// non-numeric / negative / NaN / Inf) is skipped, never zero-filled. A body with
// zero lmcache:* series yields an empty Raw so the caller can distinguish
// "fired but absent".
func ParseLMCacheBody(r io.Reader) WorkerSample {
	s := WorkerSample{Raw: make(map[string]float64)}

	families, err := DecodeFamilies(r)
	if err != nil {
		return s // malformed body — neutral, no panic
	}

	for name, val := range SelectLMCacheFamilies(families) {
		s.Raw[name] = val
	}
	return s
}

// Raw-key suffixes for histogram/summary families: the cumulative SampleSum
// and SampleCount are exposed side by side so a consumer can WINDOW them
// (Δsum/Δcount = the mean over the window) instead of misreading the
// monotonic total as an instantaneous value (metrics audit H-18).
const (
	// RawSuffixHistSum keys a histogram family's cumulative SampleSum.
	RawSuffixHistSum = ":sum"
	// RawSuffixHistCount keys a histogram family's cumulative SampleCount.
	RawSuffixHistCount = ":count"
)

// SelectLMCacheFamilies picks the lmcache:*-prefixed families out of a decoded
// family map (the expfmt full-family path) and returns their scalar values keyed
// by full family name. A family with no usable scalar value is omitted.
//
// Aggregation across family children (metrics audit H-21 — Metric()[0] alone
// under-counts DP fleets): counters, histograms/summaries and byte-usage
// gauges SUM; the hit-rate ratio gauge takes the MEAN of its children.
//
// Histogram/summary families additionally emit "<family>:sum" and
// "<family>:count" keys carrying the CUMULATIVE totals; the plain family key
// keeps the cumulative SampleSum for backward compatibility, but consumers
// wanting a latency must window the (sum,count) pair — the cumulative sum is
// NOT an instantaneous latency (H-18).
func SelectLMCacheFamilies(families map[string]*dto.MetricFamily) map[string]float64 {
	out := make(map[string]float64)
	for name, mf := range families {
		if !strings.HasPrefix(name, LMCacheFamilyPrefix) {
			continue
		}
		v, count, isHist, ok := familyScalar(mf)
		if !ok || !usableLMCacheValue(v) {
			continue // defensive: absent/non-numeric/negative/NaN/Inf ⇒ neutral
		}
		if name == FamilyLMCacheRetrieveHitRate {
			// Ratio gauge: mean across children, not sum.
			if n := len(mf.GetMetric()); n > 1 {
				v /= float64(n)
			}
		}
		out[name] = v
		if isHist && usableLMCacheValue(count) {
			out[name+RawSuffixHistSum] = v
			out[name+RawSuffixHistCount] = count
		}
	}
	return out
}

// familyScalar extracts an aggregated scalar from a metric family, summing
// across ALL children (metrics audit H-21), dispatching on the family type.
// Gauges/counters/untyped yield their summed value; histograms and summaries
// yield their summed SampleSum plus the summed SampleCount (isHist=true).
// A family with no usable value block yields ok=false — the caller treats
// that as neutral/absent.
func familyScalar(mf *dto.MetricFamily) (value, count float64, isHist, ok bool) {
	if mf == nil || len(mf.GetMetric()) == 0 {
		return 0, 0, false, false
	}
	for _, m := range mf.GetMetric() {
		switch mf.GetType() {
		case dto.MetricType_GAUGE:
			if m.Gauge == nil {
				continue
			}
			value += m.GetGauge().GetValue()
			ok = true
		case dto.MetricType_COUNTER:
			if m.Counter == nil {
				continue
			}
			value += m.GetCounter().GetValue()
			ok = true
		case dto.MetricType_UNTYPED:
			if m.Untyped == nil {
				continue
			}
			value += m.GetUntyped().GetValue()
			ok = true
		case dto.MetricType_HISTOGRAM:
			if m.Histogram == nil {
				continue
			}
			value += m.GetHistogram().GetSampleSum()
			count += float64(m.GetHistogram().GetSampleCount())
			isHist = true
			ok = true
		case dto.MetricType_SUMMARY:
			if m.Summary == nil {
				continue
			}
			value += m.GetSummary().GetSampleSum()
			count += float64(m.GetSummary().GetSampleCount())
			isHist = true
			ok = true
		default:
			return 0, 0, false, false
		}
	}
	return value, count, isHist, ok
}

// usableLMCacheValue is defensive-value discipline for LMCache
// signals: reject NaN, ±Inf, and negatives (all nonsensical for a hit-rate /
// byte-usage / latency series). The clamp to a usable magnitude happens at the
// engine cost-term use-site, not here — this layer records only what LMCache
// advertised, minus the plainly hostile values.
func usableLMCacheValue(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// RawKeyMatchedPrefixLength is the WorkerSample.Raw key under which an LMCache
// locality signal (matched prefix length, in tokens) would be delivered.
// The controller-side POST /lookup source that used to produce it was removed
// in the metrics audit (H-19/D3): with no request-scoped token stream the
// probe could only ever measure 0 yet delivered it as a trusted fresh sample.
// The key constant stays because the cost-term consumers still read it and a
// future request-path source can produce it again.
const RawKeyMatchedPrefixLength = "lmcache:matched_prefix_length"

// HistWindow tracks per-source cumulative (sum,count) histogram totals and
// yields the windowed mean between consecutive observations — the H-18 fix:
// a cumulative SampleSum consumed as an instantaneous latency saturates any
// cost term permanently; only Δsum/Δcount over a scrape window is a latency.
// Not goroutine-safe; callers serialize (the controller uses it under its
// sample-store mutex).
type HistWindow struct {
	prev map[string][2]float64
}

// NewHistWindow returns an empty window tracker.
func NewHistWindow() *HistWindow {
	return &HistWindow{prev: make(map[string][2]float64)}
}

// Mean feeds the current cumulative (sum,count) for source key and returns
// the mean over the window since the previous observation. ok=false when
// there is no previous observation yet (first scrape), no new samples landed
// in the window (Δcount==0), or the backend restarted and reset its counters
// (negative delta — the window re-primes on the new baseline).
func (w *HistWindow) Mean(key string, sum, count float64) (float64, bool) {
	p, has := w.prev[key]
	w.prev[key] = [2]float64{sum, count}
	if !has {
		return 0, false
	}
	dSum, dCount := sum-p[0], count-p[1]
	if dCount <= 0 || dSum < 0 {
		return 0, false
	}
	return dSum / dCount, true
}

// Forget drops a source's window state (EP decommission).
func (w *HistWindow) Forget(key string) {
	delete(w.prev, key)
}

// Fresh reports whether sample's LastUpdate is within budget of now. A zero
// LastUpdate (a source that never delivered) is always stale. Consumers use this
// to decay a stale LMCache signal to NEUTRAL — never to zero-fill it (CTRL-02):
// a just-restarted or briefly-unreachable EP is still a real endpoint.
func Fresh(now time.Time, sample WorkerSample, budget time.Duration) bool {
	if sample.LastUpdate.IsZero() {
		return false
	}
	return now.Sub(sample.LastUpdate) <= budget
}
