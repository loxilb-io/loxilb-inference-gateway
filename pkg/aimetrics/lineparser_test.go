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

// lineparser_test.go — table-driven guard for NumGPUBlocks
// capacity-label extractor (tolerance suite, moved from
// pkg/loxinet/ai_vllm_scraper_test.go with the code) + fixture-driven
// ParseVllmBody coverage including kv_cache_usage_perc
// family-name fix and its legacy-name compatibility path.

package aimetrics

import (
	"os"
	"strings"
	"testing"
)

// TestNumGPUBlocksLabelTolerance: vLLM advertises the static KV-block
// capacity as a LABEL on an `_info` gauge whose VALUE column is always 1.0.
// parsePrometheusGauge reads parts[len-1] (the value == 1.0) and is
// therefore WRONG for this metric. Per the threat model the
// label extractor must tolerate an absent / malformed / "0" label with no
// panic — the clamp to a usable capacity happens at the cap use-site.
func TestNumGPUBlocksLabelTolerance(t *testing.T) {
	tests := []struct {
		name string
		line string
		want uint32
	}{
		{
			name: "well-formed capacity gauge",
			line: `vllm:cache_config_info{num_gpu_blocks="2048",block_size="16"} 1.0`,
			want: 2048,
		},
		{
			name: "label first in the set",
			line: `vllm:cache_config_info{num_gpu_blocks="512"} 1.0`,
			want: 512,
		},
		{
			name: "label among many, different order",
			line: `vllm:cache_config_info{model="llama",block_size="16",num_gpu_blocks="4096"} 1.0`,
			want: 4096,
		},
		{
			name: "absent num_gpu_blocks label tolerated -> 0",
			line: `vllm:cache_config_info{block_size="16",model="llama"} 1.0`,
			want: 0,
		},
		{
			name: "malicious zero capacity recorded as 0 (clamp is downstream)",
			line: `vllm:cache_config_info{num_gpu_blocks="0"} 1.0`,
			want: 0,
		},
		{
			name: "malformed non-numeric label tolerated -> 0",
			line: `vllm:cache_config_info{num_gpu_blocks="abc"} 1.0`,
			want: 0,
		},
		{
			name: "empty label value tolerated -> 0",
			line: `vllm:cache_config_info{num_gpu_blocks=""} 1.0`,
			want: 0,
		},
		{
			name: "no braces at all tolerated -> 0",
			line: `vllm:cache_config_info 1.0`,
			want: 0,
		},
		{
			name: "negative value tolerated -> 0 (uint32, no wrap)",
			line: `vllm:cache_config_info{num_gpu_blocks="-5"} 1.0`,
			want: 0,
		},
		{
			name: "missing closing quote tolerated -> 0",
			line: `vllm:cache_config_info{num_gpu_blocks="2048 1.0`,
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNumGPUBlocksLabel(tc.line)
			if got != tc.want {
				t.Errorf("parseNumGPUBlocksLabel(%q) = %d, want %d", tc.line, got, tc.want)
			}
		})
	}
}

// TestValueColumnParsersUnaffected is a regression guard: the value-column
// parse (sampleValue) must keep working for plain, labeled, and
// timestamped sample lines, and the label extractor must NOT be applied to
// those lines.
func TestValueColumnParsersUnaffected(t *testing.T) {
	if v, ok := sampleValue(`vllm:num_requests_waiting 7`); !ok || v != 7 {
		t.Errorf("sampleValue(num_requests_waiting) = %v/%v, want 7/true", v, ok)
	}
	if v, ok := sampleValue(`vllm:kv_cache_usage_perc 0.42`); !ok || v != 0.42 {
		t.Errorf("sampleValue(kv_cache_usage_perc) = %v/%v, want 0.42/true", v, ok)
	}
	if v, ok := sampleValue(`vllm:gpu_cache_usage_perc 0.42`); !ok || v != 0.42 {
		t.Errorf("sampleValue(gpu_cache_usage_perc) = %v/%v, want 0.42/true", v, ok)
	}
	// Labeled series with an optional exposition TIMESTAMP: the value column
	// (not the trailing timestamp) must win (metrics audit M-item).
	if v, ok := sampleValue(`vllm:num_requests_waiting{engine="0"} 7 1721286000000`); !ok || v != 7 {
		t.Errorf("sampleValue(timestamped) = %v/%v, want 7/true", v, ok)
	}
	if v, ok := sampleValue(`vllm:num_requests_waiting 7 1721286000000`); !ok || v != 7 {
		t.Errorf("sampleValue(timestamped, no labels) = %v/%v, want 7/true", v, ok)
	}
	// NaN/Inf rejected.
	if _, ok := sampleValue(`vllm:kv_cache_usage_perc NaN`); ok {
		t.Error("sampleValue(NaN) ok=true, want false")
	}
	if _, ok := sampleValue(`vllm:kv_cache_usage_perc +Inf`); ok {
		t.Error("sampleValue(+Inf) ok=true, want false")
	}
	// The label extractor must return 0 for the value-column metrics (no
	// num_gpu_blocks label present) — proves the branches do not cross-contaminate.
	if v := parseNumGPUBlocksLabel(`vllm:num_requests_waiting 7`); v != 0 {
		t.Errorf("parseNumGPUBlocksLabel(num_requests_waiting) = %d, want 0", v)
	}
}

// TestFamilyLineMatchesExact: family matching must be exact (a family that
// merely shares the prefix must not be claimed) — metrics audit L2.
func TestFamilyLineMatchesExact(t *testing.T) {
	if familyLineMatches(`vllm:num_requests_waiting_total 3`, FamilyNumRequestsWaiting) {
		t.Error("prefix-sharing family claimed as num_requests_waiting")
	}
	if !familyLineMatches(`vllm:num_requests_waiting 3`, FamilyNumRequestsWaiting) {
		t.Error("plain sample line not matched")
	}
	if !familyLineMatches(`vllm:num_requests_waiting{engine="0"} 3`, FamilyNumRequestsWaiting) {
		t.Error("labeled sample line not matched")
	}
	if familyLineMatches(`vllm:num_requests_waiting`, FamilyNumRequestsWaiting) {
		t.Error("name-only line (no value column) matched")
	}
}

// TestParseVllmBodyMultiSeriesAggregation (H-21): a data-parallel vLLM server
// exports one child per engine; queue depth and capacity must SUM across
// children, cache usage takes the MEAN — first-line-wins under-counted DP>1
// fleets.
func TestParseVllmBodyMultiSeriesAggregation(t *testing.T) {
	body := `vllm:num_requests_waiting{engine="0"} 5
vllm:num_requests_waiting{engine="1"} 3
vllm:kv_cache_usage_perc{engine="0"} 0.2
vllm:kv_cache_usage_perc{engine="1"} 0.6
vllm:cache_config_info{engine="0",num_gpu_blocks="1024"} 1.0
vllm:cache_config_info{engine="1",num_gpu_blocks="1024"} 1.0
`
	s, found := ParseVllmBody(strings.NewReader(body))
	if !found {
		t.Fatal("ParseVllmBody(DP body) found=false, want true")
	}
	if s.NumRequestsWaiting != 8 {
		t.Errorf("NumRequestsWaiting = %d, want 8 (5+3 summed across engines)", s.NumRequestsWaiting)
	}
	if s.GPUCacheUsagePerc != 0.4 {
		t.Errorf("GPUCacheUsagePerc = %v, want 0.4 (mean of 0.2 and 0.6)", s.GPUCacheUsagePerc)
	}
	if s.NumGPUBlocks != 2048 {
		t.Errorf("NumGPUBlocks = %d, want 2048 (1024+1024 summed)", s.NumGPUBlocks)
	}
}

// TestParseVllmBodyRatioClamp: cache-usage ratios above 1 clamp to 1 (the
// data plane converts to uint32 percentage — undefined float→uint territory
// otherwise); negatives are rejected as before.
func TestParseVllmBodyRatioClamp(t *testing.T) {
	body := `vllm:num_requests_waiting 1
vllm:kv_cache_usage_perc 1.7
`
	s, found := ParseVllmBody(strings.NewReader(body))
	if !found {
		t.Fatal("found=false, want true")
	}
	if s.GPUCacheUsagePerc != 1.0 {
		t.Errorf("GPUCacheUsagePerc = %v, want 1.0 (clamped)", s.GPUCacheUsagePerc)
	}
}

// TestParseSGLangBody (D6): SGLang EPs join load-aware routing via
// sglang:num_queue_reqs and sglang:token_usage.
func TestParseSGLangBody(t *testing.T) {
	body := `sglang:num_queue_reqs{model_name="llama"} 4.0
sglang:token_usage{model_name="llama"} 0.35
`
	s, found := ParseVllmBody(strings.NewReader(body))
	if !found {
		t.Fatal("ParseVllmBody(sglang body) found=false, want true")
	}
	if s.NumRequestsWaiting != 4 {
		t.Errorf("NumRequestsWaiting = %d, want 4 (sglang:num_queue_reqs)", s.NumRequestsWaiting)
	}
	if s.GPUCacheUsagePerc != 0.35 {
		t.Errorf("GPUCacheUsagePerc = %v, want 0.35 (sglang:token_usage)", s.GPUCacheUsagePerc)
	}
	if s.Raw[FamilySGLangNumQueueReqs] != 4 {
		t.Errorf("Raw[%s] = %v, want 4", FamilySGLangNumQueueReqs, s.Raw[FamilySGLangNumQueueReqs])
	}
}

// TestParseVllmBodyHealthyFixture drives the narrow parser against the
// realistic v0.17.0 fixture (kv_cache_usage_perc name, labeled series,
// histogram noise present).
func TestParseVllmBodyHealthyFixture(t *testing.T) {
	f, err := os.Open("testdata/vllm_metrics_healthy.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	s, found := ParseVllmBody(f)
	if !found {
		t.Fatal("ParseVllmBody(healthy) found=false, want true")
	}
	if s.NumRequestsWaiting != 3 {
		t.Errorf("NumRequestsWaiting = %d, want 3", s.NumRequestsWaiting)
	}
	if s.GPUCacheUsagePerc != 0.42 {
		t.Errorf("GPUCacheUsagePerc = %v, want 0.42", s.GPUCacheUsagePerc)
	}
	if s.NumGPUBlocks != 7408 {
		t.Errorf("NumGPUBlocks = %d, want 7408", s.NumGPUBlocks)
	}
	if !s.LastUpdate.IsZero() {
		t.Errorf("LastUpdate must be zero from the parser (stamping is the poller's job), got %v", s.LastUpdate)
	}
	if s.Raw[FamilyKVCacheUsagePerc] != 0.42 {
		t.Errorf("Raw[%s] = %v, want 0.42", FamilyKVCacheUsagePerc, s.Raw[FamilyKVCacheUsagePerc])
	}
}

// TestParseVllmBodyNoLabelFixture: cache_config_info WITHOUT num_gpu_blocks
// (tolerance path) — 0, no error, other series intact.
func TestParseVllmBodyNoLabelFixture(t *testing.T) {
	f, err := os.Open("testdata/vllm_metrics_nolabel.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	s, found := ParseVllmBody(f)
	if !found {
		t.Fatal("ParseVllmBody(nolabel) found=false, want true")
	}
	if s.NumGPUBlocks != 0 {
		t.Errorf("NumGPUBlocks = %d, want 0 (absent label tolerated)", s.NumGPUBlocks)
	}
	if s.NumRequestsWaiting != 2 {
		t.Errorf("NumRequestsWaiting = %d, want 2", s.NumRequestsWaiting)
	}
	if s.GPUCacheUsagePerc != 0.13 {
		t.Errorf("GPUCacheUsagePerc = %v, want 0.13", s.GPUCacheUsagePerc)
	}
}

// TestParseVllmBodyLegacyGpuCacheName: the v0-era gpu_cache_usage_perc name
// still populates the same logical series (backward compatibility of the
// family-name fix).
func TestParseVllmBodyLegacyGpuCacheName(t *testing.T) {
	body := `vllm:num_requests_waiting 5
vllm:gpu_cache_usage_perc 0.55
vllm:cache_config_info{num_gpu_blocks="1024"} 1.0
`
	s, found := ParseVllmBody(strings.NewReader(body))
	if !found {
		t.Fatal("ParseVllmBody(legacy) found=false, want true")
	}
	if s.GPUCacheUsagePerc != 0.55 {
		t.Errorf("GPUCacheUsagePerc = %v, want 0.55 (legacy family name)", s.GPUCacheUsagePerc)
	}
	if s.NumRequestsWaiting != 5 || s.NumGPUBlocks != 1024 {
		t.Errorf("waiting/blocks = %d/%d, want 5/1024", s.NumRequestsWaiting, s.NumGPUBlocks)
	}
}

// TestParseVllmBodyNoRecognizedMetrics preserves the original scraper's
// early-return condition: NEITHER waiting nor cache-usage found ⇒ found=false
// (capacity alone does not count).
func TestParseVllmBodyNoRecognizedMetrics(t *testing.T) {
	if _, found := ParseVllmBody(strings.NewReader("go_goroutines 42\n")); found {
		t.Error("ParseVllmBody(unrelated body) found=true, want false")
	}
	if _, found := ParseVllmBody(strings.NewReader("")); found {
		t.Error("ParseVllmBody(empty body) found=true, want false")
	}
	// Capacity-only body: preserved original semantics — NOT "found".
	capOnly := `vllm:cache_config_info{num_gpu_blocks="2048"} 1.0` + "\n"
	if _, found := ParseVllmBody(strings.NewReader(capOnly)); found {
		t.Error("ParseVllmBody(capacity-only body) found=true, want false (original condition preserved)")
	}
}
