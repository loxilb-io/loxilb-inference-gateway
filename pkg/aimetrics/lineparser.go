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

// lineparser.go — the NARROW line parser for backend /metrics bodies, the
// loxilb hot-path decoder; the loxinet shim must stay on it (never expfmt).
//
// Recognized series (loxilb contract):
//   - vllm:num_requests_waiting            (queue depth)
//   - vllm:kv_cache_usage_perc             (KV-cache pressure; see below)
//   - vllm:cache_config_info               (num_gpu_blocks capacity LABEL)
//   - sglang:num_queue_reqs                (SGLang queue depth, D6)
//   - sglang:token_usage                   (SGLang KV-pressure ratio, D6)
//
// KV-cache family-name fix (live finding, directed at): vLLM
// v0.17.0 (v1 engine — the pinned fleet) exports `vllm:kv_cache_usage_perc`;
// the v0-era engine called it `vllm:gpu_cache_usage_perc`. The pre-extraction
// scraper parsed only the OLD name and silently read 0 on the fleet. The
// parser now recognizes BOTH names (still one logical series).
//
// Multi-series aggregation (metrics audit H-21): a data-parallel vLLM server
// (`engine="N"` label) exports one child per engine for each family. The
// parser aggregates across children instead of keeping the first line seen:
// counts (queue depth, capacity blocks) SUM, ratios (cache usage) take the
// MEAN. Hardening (metrics audit M-items): family names match exactly (not
// by prefix), the VALUE token is located independently of an optional
// trailing exposition timestamp, NaN/±Inf are rejected, ratios clamp to
// [0,1], and the line scanner is bounded but larger than bufio's 64 KiB
// default.
package aimetrics

import (
	"bufio"
	"io"
	"math"
	"strconv"
	"strings"
)

// Metric family names recognized by the narrow parser.
const (
	// FamilyNumRequestsWaiting is the vLLM queue-depth gauge.
	FamilyNumRequestsWaiting = "vllm:num_requests_waiting"
	// FamilyKVCacheUsagePerc is the v1-engine (vLLM >= 0.17.0 fleets) KV
	// cache usage gauge name.
	FamilyKVCacheUsagePerc = "vllm:kv_cache_usage_perc"
	// FamilyGPUCacheUsagePerc is the legacy v0-engine name for the same
	// logical series (kept for backward compatibility).
	FamilyGPUCacheUsagePerc = "vllm:gpu_cache_usage_perc"
	// FamilyCacheConfigInfo is the `_info` gauge whose num_gpu_blocks LABEL
	// advertises static KV-block capacity.
	FamilyCacheConfigInfo = "vllm:cache_config_info"
	// FamilySGLangNumQueueReqs is the SGLang queue-depth gauge (D6) — the
	// SGLang analog of vllm:num_requests_waiting.
	FamilySGLangNumQueueReqs = "sglang:num_queue_reqs"
	// FamilySGLangTokenUsage is the SGLang KV-pressure ratio gauge (D6) — the
	// SGLang analog of vllm:kv_cache_usage_perc (fraction of KV token budget
	// in use, [0,1]).
	FamilySGLangTokenUsage = "sglang:token_usage"
)

// maxMetricLineBytes bounds a single exposition line; lines longer than this
// abort the scan (scanner.Err() != nil) and the parser returns whatever was
// already aggregated. bufio's 64 KiB default silently aborted mid-body on
// long _info lines; 1 MiB tolerates any sane exposition line.
const maxMetricLineBytes = 1 << 20

// ParseVllmBody scans a Prometheus text-exposition body line by line and
// extracts the narrow series set, without pulling in the full expfmt
// library (hot-path decoder). It returns found=false when NEITHER the
// queue-depth nor the cache-usage series was recognized (the original
// scraper's "no recognized metrics" condition — capacity alone does not
// count, preserved verbatim). SGLang bodies satisfy the same condition via
// their analog families.
//
// The returned sample has a zero LastUpdate — stamping is the poller's job.
func ParseVllmBody(r io.Reader) (WorkerSample, bool) {
	var waitingSum float64
	var usageSum float64
	var usageN int
	var blocksSum uint64
	var foundWaiting, foundCache bool
	raw := make(map[string]float64)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxMetricLineBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue // Skip comments.
		}

		switch {
		case familyLineMatches(line, FamilyNumRequestsWaiting):
			if v, ok := sampleValue(line); ok && v >= 0 {
				waitingSum += v // H-21: sum across DP-engine children
				foundWaiting = true
				raw[FamilyNumRequestsWaiting] = waitingSum
			}
		case familyLineMatches(line, FamilySGLangNumQueueReqs):
			// D6: SGLang queue depth joins the same logical signal.
			if v, ok := sampleValue(line); ok && v >= 0 {
				waitingSum += v
				foundWaiting = true
				raw[FamilySGLangNumQueueReqs] = v
			}
		case familyLineMatches(line, FamilyKVCacheUsagePerc):
			// v0.17.0 / v1-engine name (fix).
			if v, ok := sampleValue(line); ok && usableRatio(v) {
				usageSum += clampRatio(v) // H-21: mean across children (below)
				usageN++
				foundCache = true
				raw[FamilyKVCacheUsagePerc] = clampRatio(v)
			}
		case familyLineMatches(line, FamilyGPUCacheUsagePerc):
			// Legacy v0-engine name — same logical series.
			if v, ok := sampleValue(line); ok && usableRatio(v) {
				usageSum += clampRatio(v)
				usageN++
				foundCache = true
				raw[FamilyGPUCacheUsagePerc] = clampRatio(v)
			}
		case familyLineMatches(line, FamilySGLangTokenUsage):
			// D6: SGLang KV-pressure ratio joins the same logical signal.
			if v, ok := sampleValue(line); ok && usableRatio(v) {
				usageSum += clampRatio(v)
				usageN++
				foundCache = true
				raw[FamilySGLangTokenUsage] = clampRatio(v)
			}
		case familyLineMatches(line, FamilyCacheConfigInfo):
			// NumGPUBlocks is advertised as a LABEL on this `_info`
			// gauge whose VALUE column is always 1.0 — sampleValue
			// would read 1.0, so a dedicated label extractor is required.
			// A buggy/absent/0 label yields 0 (tolerated; clamped at the cap
			// use-site). H-21: DP-engine children each advertise their own
			// blocks — capacity sums.
			blocksSum += uint64(parseNumGPUBlocksLabel(line))
			raw[FamilyCacheConfigInfo] = float64(blocksSum)
		}
	}
	// A scan error (oversized line, transport error surfaced through the
	// reader) aborts the sweep; whatever was aggregated up to that point is
	// still per-line valid, so it is returned rather than discarded.
	_ = scanner.Err()

	if !foundWaiting && !foundCache {
		return WorkerSample{}, false
	}

	if waitingSum > math.MaxUint32 {
		waitingSum = math.MaxUint32
	}
	var usage float64
	if usageN > 0 {
		usage = usageSum / float64(usageN)
	}
	if blocksSum > math.MaxUint32 {
		blocksSum = math.MaxUint32
	}

	return WorkerSample{
		NumRequestsWaiting: uint32(waitingSum),
		GPUCacheUsagePerc:  usage,
		NumGPUBlocks:       uint32(blocksSum), // advertised capacity signal
		Raw:                raw,
	}, true
}

// familyLineMatches reports whether line is a sample of exactly the given
// metric family: the family name followed by a label block or the value
// separator. A bare HasPrefix would also claim differently-named families
// that merely share the prefix (e.g. `vllm:num_requests_waiting_total`).
func familyLineMatches(line, family string) bool {
	if !strings.HasPrefix(line, family) {
		return false
	}
	if len(line) == len(family) {
		return false // name with no value column — not a sample line
	}
	switch line[len(family)] {
	case '{', ' ', '\t':
		return true
	}
	return false
}

// sampleValue extracts the VALUE column from an exposition sample line,
// tolerating a label block and an OPTIONAL trailing timestamp:
//
//	name{labels} value [timestamp_ms]
//	name value [timestamp_ms]
//
// The pre-hardening parser took the LAST whitespace token, silently reading
// the timestamp as the value when one was present. NaN/±Inf parse but are
// rejected by the callers' usableRatio / v >= 0 guards (NaN fails both).
func sampleValue(line string) (float64, bool) {
	rest := line
	if i := strings.LastIndexByte(line, '}'); i >= 0 {
		rest = line[i+1:]
	} else if i := strings.IndexAny(line, " \t"); i >= 0 {
		rest = line[i:]
	} else {
		return 0, false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0, false // no value column
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// usableRatio accepts a finite value usable as a cache-usage ratio. Values
// above 1 are tolerated here (some backends briefly report >1 under
// reclamation) and clamped by clampRatio; negatives/NaN/Inf are rejected
// (sampleValue already drops NaN/Inf — the check is kept for direct callers).
func usableRatio(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// clampRatio clamps a cache-usage ratio into [0,1]. The data plane converts
// the ratio to a uint32 percentage; an unbounded >1 value would otherwise
// flow into undefined float→uint conversion territory.
func clampRatio(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// parseNumGPUBlocksLabel extracts the static KV-block capacity advertised by
// vLLM as the `num_gpu_blocks` LABEL on the `vllm:cache_config_info` `_info`
// gauge:
//
//	vllm:cache_config_info{num_gpu_blocks="2048",block_size="16"} 1.0
//
// This is NOT sampleValue: that reads the trailing VALUE column which
// for an `_info` gauge is always 1.0. The capacity lives in the label set.
//
// Per the threat model the extractor tolerates an absent,
// empty, non-numeric, or negative label with no panic, returning 0 in every
// such case. The clamp to a usable capacity (>=1) happens at the cap
// use-site (the unified blend in ai_kv_subscriber.go), not here — this layer
// faithfully records what vLLM advertised, including a malicious "0".
func parseNumGPUBlocksLabel(line string) uint32 {
	const key = `num_gpu_blocks="`
	start := strings.Index(line, key)
	if start < 0 {
		return 0 // label absent — tolerated
	}
	start += len(key)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return 0 // malformed (no closing quote) — tolerated
	}
	raw := line[start : start+end]
	if raw == "" {
		return 0 // empty label — tolerated
	}
	// ParseUint rejects negatives and non-numerics — both yield 0 (no wrap,
	// no panic). Base 10, 32-bit to match WorkerSample.NumGPUBlocks.
	val, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}
