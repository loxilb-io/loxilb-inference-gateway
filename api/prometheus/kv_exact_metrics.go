/*
 * Copyright (c) 2026 NetLOX Inc
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

package prometheus

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// Tier-1.5 routing cost and match depth
// ============================================================================
// pd_kv_exact_select (loxilb-ebpf/common/sockproxy_kv_exact.c) times its
// stages on every lookup — tokenize (CGO → HF tokenizer), hash (CBOR + chained
// block hash), cgo (llb_ai_kv_best_worker, which includes the inventory scan)
// — and records how many blocks the prompt hashed to and how many of them
// the chosen endpoint's inventory held. The C side accumulated all of this
// since the stage timers landed (record_kv_stage / record_kv_blocks) but
// exported none of it; the only view was a debug log line. These families
// put it on the scrape so an operator can answer, from the gateway alone,
// whether a slow TTFT is the gateway's decision path or the engine, and how
// much of each prompt the exact tier actually found cached.
//
//   loxilb_kv_exact_stage_seconds{stage,outcome}   per-stage cost, hit vs miss
//   loxilb_kv_exact_prompt_blocks                  blocks the prompt hashed to
//   loxilb_kv_exact_overlap_blocks                 blocks found on the chosen EP
//
// overlap_blocks_sum / prompt_blocks_sum is the fleet-wide cached share of
// what was asked (the number the bounded-load blend acts on); the quotient of
// the two histograms' buckets gives its distribution.
//
// The C side keeps cumulative le buckets like the TTFB histogram, so the same
// sanitize/merge treatment applies (torn reads within one snapshot, never
// going backwards across snapshots), and the collector emits const metrics on
// scrape. The label values below are the C enums' order in
// sockproxy_kv_exact.h; the snapshot dimensions are fixed there and mirrored
// in the cgo preamble.
//
// KV_STAGE_SCAN (slot 3) is reserved in that header: pd_kv_exact_select
// measures tokenize, hash and cgo only (the inventory scan is folded into
// the cgo crossing), so the 4th slot can never move. The snapshot keeps it
// (the C layout), the export leaves it out — a series that cannot move is
// not published (bed 2026-10-10, O-PRIO-1).
// ============================================================================

const (
	kvStages         = 4  // enum kv_stage (the C layout, incl. the reserved SCAN slot)
	kvExportedStages = 3  // tokenize, hash, cgo — the stages pd_kv_exact_select measures
	kvOutcomes       = 2  // miss, hit
	kvBlockKinds     = 2  // prompt, overlap
	kvBounds         = 12 // finite bucket bounds of every histogram here
)

var (
	kvStageLabels   = [kvStages]string{"tokenize", "hash", "cgo", "scan"}
	kvOutcomeLabels = [kvOutcomes]string{"miss", "hit"}
)

// kvStageBounds are the stage bucket upper bounds in SECONDS; they must match
// latency_bucket_bounds_us (microseconds) in sockproxy_metrics.c — the stage
// histograms reuse the TTFB bounds. kvBlocksBounds are in BLOCKS and must
// match kv_blocks_bucket_bounds there.
var (
	kvStageBounds  = [kvBounds]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}
	kvBlocksBounds = [kvBounds]float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048}
)

// kvHist is one cumulative histogram as the C side keeps it; sum is already
// in the exported unit (seconds or blocks).
type kvHist struct {
	buckets [kvBounds]uint64
	count   uint64
	sum     float64
}

// kvExactSnapshot is the Tier-1.5 state taken from one C snapshot.
type kvExactSnapshot struct {
	stage  [kvStages][kvOutcomes]kvHist
	blocks [kvBlockKinds]kvHist
}

// sanitizeKvHist clamps a torn read within one snapshot, as
// sanitizeTtfbSnapshot does: the cumulative sequence is made non-decreasing
// and the count at least the highest bucket.
func sanitizeKvHist(raw kvHist) kvHist {
	s := raw
	for i := 1; i < len(s.buckets); i++ {
		if s.buckets[i] < s.buckets[i-1] {
			s.buckets[i] = s.buckets[i-1]
		}
	}
	if s.count < s.buckets[len(s.buckets)-1] {
		s.count = s.buckets[len(s.buckets)-1]
	}
	return s
}

// mergeKvHist keeps the exposed histogram from going backwards, as
// mergeTtfbSnapshot does, including its reading of a count below half the
// previous one as a genuine reset.
func mergeKvHist(prev, next kvHist) kvHist {
	if next.count < prev.count/2 {
		return next
	}
	merged := next
	for i := range merged.buckets {
		if prev.buckets[i] > merged.buckets[i] {
			merged.buckets[i] = prev.buckets[i]
		}
	}
	if prev.count > merged.count {
		merged.count = prev.count
	}
	if prev.sum > merged.sum {
		merged.sum = prev.sum
	}
	return merged
}

// mergeKvExact sanitizes next and merges it into prev.
func mergeKvExact(prev, next kvExactSnapshot) kvExactSnapshot {
	m := next
	for st := range m.stage {
		for o := range m.stage[st] {
			m.stage[st][o] = mergeKvHist(prev.stage[st][o], sanitizeKvHist(next.stage[st][o]))
		}
	}
	for k := range m.blocks {
		m.blocks[k] = mergeKvHist(prev.blocks[k], sanitizeKvHist(next.blocks[k]))
	}
	return m
}

var (
	kvExactStoreMutex sync.Mutex
	kvExactStore      kvExactSnapshot
)

// updateKvExactStore merges a raw snapshot into the store. Called once per
// collection cycle by RunSockproxyMetrics.
func updateKvExactStore(raw kvExactSnapshot) {
	kvExactStoreMutex.Lock()
	kvExactStore = mergeKvExact(kvExactStore, raw)
	kvExactStoreMutex.Unlock()
}

var kvExactStageDesc = prometheus.NewDesc(
	"loxilb_kv_exact_stage_seconds",
	"Tier-1.5 KV-exact routing cost per stage of pd_kv_exact_select, by outcome (hit: the exact tier chose the endpoint; miss: it fell through).",
	[]string{"stage", "outcome"}, nil,
)

var kvExactPromptBlocksDesc = prometheus.NewDesc(
	"loxilb_kv_exact_prompt_blocks",
	"Blocks the prompt hashed to per Tier-1.5 lookup that reached the scorer (the chain is capped at KV_MAX_TOKENS).",
	nil, nil,
)

var kvExactOverlapBlocksDesc = prometheus.NewDesc(
	"loxilb_kv_exact_overlap_blocks",
	"Blocks of the chosen endpoint's KV inventory that overlapped the prompt per Tier-1.5 lookup (0 when no endpoint held any).",
	nil, nil,
)

func kvBucketMap(bounds [kvBounds]float64, h kvHist) map[float64]uint64 {
	out := make(map[float64]uint64, kvBounds)
	for i, ub := range bounds {
		out[ub] = h.buckets[i]
	}
	return out
}

// kvExactCollector emits the Tier-1.5 families from kvExactStore on every
// scrape. Every series is present from the start, at zero.
type kvExactCollector struct{}

// Describe implements prometheus.Collector.
func (kvExactCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- kvExactStageDesc
	ch <- kvExactPromptBlocksDesc
	ch <- kvExactOverlapBlocksDesc
}

// Collect implements prometheus.Collector.
func (kvExactCollector) Collect(ch chan<- prometheus.Metric) {
	kvExactStoreMutex.Lock()
	s := kvExactStore
	kvExactStoreMutex.Unlock()

	for st := 0; st < kvExportedStages; st++ {
		for o := 0; o < kvOutcomes; o++ {
			h := s.stage[st][o]
			ch <- prometheus.MustNewConstHistogram(kvExactStageDesc, h.count, h.sum,
				kvBucketMap(kvStageBounds, h), kvStageLabels[st], kvOutcomeLabels[o])
		}
	}
	h := s.blocks[0]
	ch <- prometheus.MustNewConstHistogram(kvExactPromptBlocksDesc, h.count, h.sum,
		kvBucketMap(kvBlocksBounds, h))
	h = s.blocks[1]
	ch <- prometheus.MustNewConstHistogram(kvExactOverlapBlocksDesc, h.count, h.sum,
		kvBucketMap(kvBlocksBounds, h))
}

func init() {
	datapathRegisterer{}.MustRegister(kvExactCollector{})
}
