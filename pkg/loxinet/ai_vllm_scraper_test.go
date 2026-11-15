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

package loxinet

import (
	"testing"

	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/loxilb-io/loxilb/pkg/aimetrics"
)

// The decode KV-pressure argument the sink hands to the C bridge: presence of
// a usage family in Raw decides between a percentage and the 0xFF sentinel,
// and a reported 0 % must stay 0 (scored as empty), never become "unknown".
func TestPdKvUsagePct(t *testing.T) {
	cases := []struct {
		name string
		smp  aimetrics.WorkerSample
		want uint32
	}{
		{"absent: no usage family (queue depth only)",
			aimetrics.WorkerSample{NumRequestsWaiting: 3,
				Raw: map[string]float64{aimetrics.FamilyNumRequestsWaiting: 3}},
			pdKvUsageUnknown},
		{"absent: nil Raw",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 0.5}, pdKvUsageUnknown},
		{"present: vllm:kv_cache_usage_perc 0.42",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 0.42,
				Raw: map[string]float64{aimetrics.FamilyKVCacheUsagePerc: 0.42}},
			42},
		{"present: legacy vllm:gpu_cache_usage_perc 0.875",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 0.875,
				Raw: map[string]float64{aimetrics.FamilyGPUCacheUsagePerc: 0.875}},
			87},
		{"present: sglang:token_usage 0.5",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 0.5,
				Raw: map[string]float64{aimetrics.FamilySGLangTokenUsage: 0.5}},
			50},
		{"present: reported 0 % is 0, not unknown",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 0,
				Raw: map[string]float64{aimetrics.FamilyKVCacheUsagePerc: 0}},
			0},
		{"present: 1.0 is 100",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 1.0,
				Raw: map[string]float64{aimetrics.FamilyKVCacheUsagePerc: 1.0}},
			100},
		{"present: above 1.0 clamps to 100 (never reads as 0xFF)",
			aimetrics.WorkerSample{GPUCacheUsagePerc: 2.55,
				Raw: map[string]float64{aimetrics.FamilyKVCacheUsagePerc: 1.0}},
			100},
		{"present: negative clamps to 0",
			aimetrics.WorkerSample{GPUCacheUsagePerc: -0.1,
				Raw: map[string]float64{aimetrics.FamilyKVCacheUsagePerc: 0}},
			0},
	}
	for _, c := range cases {
		if got := pdKvUsagePct(c.smp); got != c.want {
			t.Errorf("%s: pdKvUsagePct = %d, want %d", c.name, got, c.want)
		}
	}
}

type kvBridgeCall struct {
	serviceIP  uint32
	svcPortNet uint16
	epIdx      int
	pct        uint32
}

// OnSample must call the KV-usage bridge once per sample with the same
// service key (VIP, port in network order) and EP index as the queue-depth
// and capacity calls, and must keep the Go-side WorkerMetrics bookkeeping.
// The queue-depth and capacity bridges run for real here; without a proxy
// table on the C side they return before touching anything.
func TestVllmScraperSinkOnSampleKvUsageBridge(t *testing.T) {
	var calls []kvBridgeCall
	saved := kvUsageBridge
	kvUsageBridge = func(serviceIP uint32, svcPortNet uint16, epIdx int, pct uint32) {
		calls = append(calls, kvBridgeCall{serviceIP, svcPortNet, epIdx, pct})
	}
	defer func() { kvUsageBridge = saved }()

	const vip = uint32(0x0a00000c) // any value; passed through unchanged
	const port = uint16(8080)
	var gotKey string
	var gotMetrics WorkerMetrics
	s := NewVllmScraper(map[int]string{0: "10.0.0.1:8000", 2: "10.0.0.3:8000"},
		vip, port, 0, func(key string, m WorkerMetrics) {
			gotKey, gotMetrics = key, m
		})
	sink := (*vllmScraperSink)(s)

	cases := []struct {
		name    string
		epIdx   int
		smp     aimetrics.WorkerSample
		wantPct uint32
	}{
		{"present", 2, aimetrics.WorkerSample{NumRequestsWaiting: 5, GPUCacheUsagePerc: 0.42,
			Raw: map[string]float64{aimetrics.FamilyNumRequestsWaiting: 5,
				aimetrics.FamilyKVCacheUsagePerc: 0.42}}, 42},
		{"absent", 0, aimetrics.WorkerSample{NumRequestsWaiting: 1,
			Raw: map[string]float64{aimetrics.FamilyNumRequestsWaiting: 1}}, pdKvUsageUnknown},
		{"zero reported", 2, aimetrics.WorkerSample{GPUCacheUsagePerc: 0,
			Raw: map[string]float64{aimetrics.FamilySGLangTokenUsage: 0}}, 0},
	}
	for _, c := range cases {
		calls = nil
		sink.OnSample(c.epIdx, c.smp)
		if len(calls) != 1 {
			t.Fatalf("%s: kv bridge called %d times, want 1", c.name, len(calls))
		}
		want := kvBridgeCall{vip, tk.Htons(port), c.epIdx, c.wantPct}
		if calls[0] != want {
			t.Errorf("%s: kv bridge args %+v, want %+v", c.name, calls[0], want)
		}
		if c.epIdx == 2 && gotKey != "10.0.0.3" {
			t.Errorf("%s: updateFn key %q, want host part of the endpoint", c.name, gotKey)
		}
		wantGo := uint32(c.smp.GPUCacheUsagePerc * 100)
		if gotMetrics.KVCacheUsagePerc != wantGo || gotMetrics.QueuedRequests != c.smp.NumRequestsWaiting {
			t.Errorf("%s: WorkerMetrics %+v, want KVCacheUsagePerc %d queued %d",
				c.name, gotMetrics, wantGo, c.smp.NumRequestsWaiting)
		}
	}
}
