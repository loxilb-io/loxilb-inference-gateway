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

// lmcache_test.go — LMC-02 collector tests: lmcache:* family selection off the
// expfmt full-family path (defensive, hot-path-lineparser-untouched) plus the
// per-source staleness helper.

package aimetrics

import (
	"strings"
	"testing"
	"time"
)

// A golden fleet-style /metrics body carrying BOTH the loxilb 3-series (vllm:*)
// and the piggybacked lmcache:* families (gauges + one histogram).
const lmcacheGoldenBody = `# HELP vllm:num_requests_waiting Number of requests waiting.
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting{model="q"} 3
# TYPE vllm:kv_cache_usage_perc gauge
vllm:kv_cache_usage_perc 0.42
# TYPE vllm:cache_config_info gauge
vllm:cache_config_info{num_gpu_blocks="7408",block_size="16"} 1.0
# TYPE lmcache:retrieve_hit_rate gauge
lmcache:retrieve_hit_rate 0.75
# TYPE lmcache:local_cache_usage gauge
lmcache:local_cache_usage 1.048576e+06
# TYPE lmcache:remote_cache_usage gauge
lmcache:remote_cache_usage 2.097152e+06
# TYPE lmcache:time_to_retrieve histogram
lmcache:time_to_retrieve_bucket{le="0.1"} 5
lmcache:time_to_retrieve_bucket{le="+Inf"} 10
lmcache:time_to_retrieve_sum 1.5
lmcache:time_to_retrieve_count 10
`

// TestLMCacheGoldenFamiliesParse: every lmcache:* series lands in Raw keyed by
// its full family name; the histogram contributes its SampleSum scalar.
func TestLMCacheGoldenFamiliesParse(t *testing.T) {
	s := ParseLMCacheBody(strings.NewReader(lmcacheGoldenBody))

	want := map[string]float64{
		FamilyLMCacheRetrieveHitRate:  0.75,
		FamilyLMCacheLocalCacheUsage:  1048576,
		FamilyLMCacheRemoteCacheUsage: 2097152,
		FamilyLMCacheTimeToRetrieve:   1.5,
	}
	for k, v := range want {
		got, ok := s.Raw[k]
		if !ok {
			t.Errorf("missing lmcache series %q in Raw", k)
			continue
		}
		if got != v {
			t.Errorf("Raw[%q] = %v, want %v", k, got, v)
		}
	}
	// No vllm:* series must leak into the lmcache subset.
	for k := range s.Raw {
		if !strings.HasPrefix(k, LMCacheFamilyPrefix) {
			t.Errorf("non-lmcache key %q leaked into lmcache Raw subset", k)
		}
	}
}

// TestLMCacheMalformedLineIsNeutral: a negative (semantically malformed)
// lmcache value is dropped (neutral/absent) WITHOUT a panic, while the other
// lmcache series still parse.
func TestLMCacheMalformedLineIsNeutral(t *testing.T) {
	body := `# TYPE lmcache:retrieve_hit_rate gauge
lmcache:retrieve_hit_rate 0.5
# TYPE lmcache:remote_cache_usage gauge
lmcache:remote_cache_usage -1
`
	s := ParseLMCacheBody(strings.NewReader(body))

	if _, ok := s.Raw[FamilyLMCacheRemoteCacheUsage]; ok {
		t.Errorf("negative lmcache value must be neutral/absent, got %v", s.Raw[FamilyLMCacheRemoteCacheUsage])
	}
	if got, ok := s.Raw[FamilyLMCacheRetrieveHitRate]; !ok || got != 0.5 {
		t.Errorf("other lmcache series must still parse: got %v ok=%v, want 0.5", got, ok)
	}
}

// TestLMCacheWholeBodyMalformedNeutral: a truly malformed exposition body
// (non-numeric value) yields an empty lmcache subset and never panics.
func TestLMCacheWholeBodyMalformedNeutral(t *testing.T) {
	body := "# TYPE lmcache:retrieve_hit_rate gauge\nlmcache:retrieve_hit_rate notanumber\n"
	s := ParseLMCacheBody(strings.NewReader(body)) // must not panic
	if len(s.Raw) != 0 {
		t.Errorf("malformed body must yield empty lmcache Raw, got %v", s.Raw)
	}
}

// TestLMCacheZeroSeriesAbsent: a body with ZERO lmcache:* series (the
// PROMETHEUS_MULTIPROC_DIR-unset simulation) yields an empty lmcache subset so
// the caller can detect "fired but absent" (input).
func TestLMCacheZeroSeriesAbsent(t *testing.T) {
	body := `# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting 1
# TYPE vllm:kv_cache_usage_perc gauge
vllm:kv_cache_usage_perc 0.1
`
	s := ParseLMCacheBody(strings.NewReader(body))
	if len(s.Raw) != 0 {
		t.Errorf("no lmcache:* series expected, got %v", s.Raw)
	}
}

// TestLMCacheContractGuardLineparserUnchanged: feeding the SAME golden body to
// the loxilb hot-path lineparser yields exactly its 3-series output — LMCache
// parsing lives only in the new file; the narrow parser ignores lmcache:*.
func TestLMCacheContractGuardLineparserUnchanged(t *testing.T) {
	s, found := ParseVllmBody(strings.NewReader(lmcacheGoldenBody))
	if !found {
		t.Fatal("lineparser did not recognize the vllm 3-series in the golden body")
	}
	if s.NumRequestsWaiting != 3 || s.GPUCacheUsagePerc != 0.42 || s.NumGPUBlocks != 7408 {
		t.Errorf("lineparser 3-series drifted: %+v, want waiting=3 kv=0.42 blocks=7408", s)
	}
	for k := range s.Raw {
		if strings.HasPrefix(k, LMCacheFamilyPrefix) {
			t.Errorf("lineparser leaked an lmcache key %q — hot-path contract violated", k)
		}
	}
}

// TestLMCacheFreshStaleness: the staleness helper reports a sample aged past the
// budget as stale so the consumer can decay to neutral (never zero-fill). A zero
// LastUpdate (never delivered) is always stale.
func TestLMCacheFreshStaleness(t *testing.T) {
	now := time.Now()
	budget := 15 * time.Second

	fresh := WorkerSample{LastUpdate: now.Add(-5 * time.Second)}
	if !Fresh(now, fresh, budget) {
		t.Errorf("sample aged 5s within a 15s budget must be fresh")
	}
	stale := WorkerSample{LastUpdate: now.Add(-30 * time.Second)}
	if Fresh(now, stale, budget) {
		t.Errorf("sample aged 30s past a 15s budget must be stale")
	}
	var never WorkerSample // zero LastUpdate
	if Fresh(now, never, budget) {
		t.Errorf("never-delivered (zero LastUpdate) sample must be stale")
	}
}
