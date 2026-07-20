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

// expfmt_test.go — controller-side full-family decoder coverage + the
// DECODER-AGREEMENT gate: the narrow lineparser and the hardened expfmt
// decoder must agree on the shared series against the same fixture, or the
// two-decoder split silently forks semantics.

package aimetrics

import (
	"os"
	"strings"
	"testing"
)

// TestDecodeFamiliesHealthy: all families from
// EXPECT_VLLM_FAMILIES list decode, including the TTFT histogram the
// lineparser deliberately ignores.
func TestDecodeFamiliesHealthy(t *testing.T) {
	f, err := os.Open("testdata/vllm_metrics_healthy.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	fams, err := DecodeFamilies(f)
	if err != nil {
		t.Fatalf("DecodeFamilies: %v", err)
	}

	for _, want := range []string{
		"vllm:num_requests_waiting",
		"vllm:num_requests_running",
		"vllm:kv_cache_usage_perc",
		"vllm:cache_config_info",
		"vllm:prompt_tokens_total",
		"vllm:generation_tokens_total",
		"vllm:time_to_first_token_seconds",
	} {
		if _, ok := fams[want]; !ok {
			t.Errorf("family %q missing from decoded set", want)
		}
	}

	// The histogram must decode as a real histogram with buckets — the
	// whole point of the expfmt path over the lineparser.
	ttft := fams["vllm:time_to_first_token_seconds"]
	if ttft == nil || len(ttft.GetMetric()) == 0 {
		t.Fatal("TTFT family empty")
	}
	h := ttft.GetMetric()[0].GetHistogram()
	if h == nil {
		t.Fatal("TTFT metric is not a histogram")
	}
	if h.GetSampleCount() != 812 {
		t.Errorf("TTFT sample count = %d, want 812", h.GetSampleCount())
	}
	if len(h.GetBucket()) == 0 {
		t.Error("TTFT histogram has no buckets")
	}
}

// TestDecodeFamiliesMalformed: a malformed body errors instead of returning
// partial silent data (— hardened parser, no hand-rolling).
func TestDecodeFamiliesMalformed(t *testing.T) {
	f := `vllm:num_requests_waiting{unclosed="x 3.0` + "\n"
	if _, err := DecodeFamilies(strings.NewReader(f)); err == nil {
		t.Error("DecodeFamilies(malformed) err=nil, want error")
	}
}

// TestDecoderAgreement is the two-decoder split gate: lineparser value ==
// expfmt value for every shared series on the healthy fixture.
func TestDecoderAgreement(t *testing.T) {
	// lineparser side.
	lf, err := os.Open("testdata/vllm_metrics_healthy.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer lf.Close()
	sample, found := ParseVllmBody(lf)
	if !found {
		t.Fatal("lineparser found=false on healthy fixture")
	}

	// expfmt side.
	ef, err := os.Open("testdata/vllm_metrics_healthy.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer ef.Close()
	fams, err := DecodeFamilies(ef)
	if err != nil {
		t.Fatalf("DecodeFamilies: %v", err)
	}

	// vllm:num_requests_waiting — the headline agreement assertion.
	waiting := fams["vllm:num_requests_waiting"].GetMetric()[0].GetGauge().GetValue()
	if uint32(waiting) != sample.NumRequestsWaiting {
		t.Errorf("decoder disagreement: expfmt waiting=%v, lineparser=%d", waiting, sample.NumRequestsWaiting)
	}

	// vllm:kv_cache_usage_perc.
	kv := fams["vllm:kv_cache_usage_perc"].GetMetric()[0].GetGauge().GetValue()
	if kv != sample.GPUCacheUsagePerc {
		t.Errorf("decoder disagreement: expfmt kv=%v, lineparser=%v", kv, sample.GPUCacheUsagePerc)
	}

	// vllm:cache_config_info num_gpu_blocks label.
	var labelBlocks string
	for _, lp := range fams["vllm:cache_config_info"].GetMetric()[0].GetLabel() {
		if lp.GetName() == "num_gpu_blocks" {
			labelBlocks = lp.GetValue()
		}
	}
	if labelBlocks != "7408" || sample.NumGPUBlocks != 7408 {
		t.Errorf("decoder disagreement: expfmt num_gpu_blocks=%q, lineparser=%d, want 7408 both",
			labelBlocks, sample.NumGPUBlocks)
	}
}
