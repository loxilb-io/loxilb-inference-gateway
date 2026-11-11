/*
 * Copyright (c) 2023 NetLOX Inc
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
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	prom "github.com/prometheus/client_golang/prometheus"
)

// Existing snapshot/registration unit tests model an initialized datapath.
// Runtime tests below explicitly select unavailable, peer-only, or ready state.
func TestMain(m *testing.M) {
	datapathAvailable.Store(true)
	os.Exit(m.Run())
}

// Any embedded datapath method panics: speaker metrics must never call it.
type peerMetricsHook struct{ cmn.NetHookInterface }

func metricFamilies(t *testing.T) map[string]bool {
	t.Helper()
	families, err := prom.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, family := range families {
		names[family.GetName()] = true
	}
	return names
}

func saveMetricsRuntime(t *testing.T) {
	t.Helper()
	if err := PrometheusTurnOff(); err != nil {
		t.Fatal(err)
	}
	oldHooks, oldAvailable, oldPeriod := hooks, datapathAvailable.Load(), PrometheusDefaultPeriod
	t.Cleanup(func() {
		if err := PrometheusTurnOff(); err != nil {
			t.Error(err)
		}
		PrometheusRegister(oldHooks, oldAvailable)
		PrometheusDefaultPeriod = oldPeriod
	})
}

func TestPeerOnlyMetricsLifecycle(t *testing.T) {
	saveMetricsRuntime(t)
	PrometheusDefaultPeriod = time.Millisecond
	PrometheusRegister(&peerMetricsHook{}, false)
	for cycle := 0; cycle < 3; cycle++ {
		if err := Init(); err != nil {
			t.Fatal(err)
		}
		generation := prometheusDone
		if err := Init(); err != nil || prometheusDone != generation {
			t.Fatalf("duplicate Init: %v", err)
		}
		for scrape := 0; scrape < 4; scrape++ {
			time.Sleep(2 * time.Millisecond)
			names := metricFamilies(t)
			for _, name := range []string{"loxilb_proxy_active_connections", MetricActiveConntrackCount, MetricHealthyEndpointsCount, "loxilb_ai_admission_anomalies_total"} {
				if names[name] {
					t.Errorf("unavailable datapath series emitted: %s", name)
				}
			}
			for _, name := range []string{"go_goroutines", "process_cpu_seconds_total", MetricSystemMemoryUtilization, "loxilb_datapath_metrics_available", "loxilb_proxy_listen_drops_total"} {
				if !names[name] {
					t.Errorf("independent series missing: %s", name)
				}
			}
		}
		health := GetMetricsHealth()
		if health["load_balancer_core"] != "UNAVAILABLE" {
			t.Fatalf("peer reported an available datapath: %v", health)
		}
		// Sub-jiffy CPU samples can fail independently of datapath support.
		// Check the forbidden collectors specifically; a system-read error
		// must not be misclassified as an attempted datapath operation.
		breakerMu.Lock()
		for _, component := range []string{"conntrack_collection", "endpoint_collection", "firewall_collection", "lbrule_collection", "active_conntrack", "sockproxy_metrics", "security_rate_stats", "ip_filter_stats", "l4_error_stats"} {
			if b := breakers[component]; b != nil && b.errors.Load() != 0 {
				t.Errorf("peer attempted %s: %d errors", component, b.errors.Load())
			}
		}
		breakerMu.Unlock()
		if err := PrometheusTurnOff(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-generation:
		default:
			t.Fatal("Stop returned before workers exited")
		}
		if err := CheckInit(); err == nil {
			t.Fatal("stopped generation still running")
		}
	}
}

func TestMetricsFailClosedBeforeRegistration(t *testing.T) {
	saveMetricsRuntime(t)
	PrometheusRegister(nil, false)
	if err := Init(); err == nil {
		t.Fatal("Init accepted missing hooks")
	}
	done := make(chan struct{})
	go func() { RunSockproxyMetrics(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("uninitialized native worker ran")
	}
	if metricFamilies(t)["loxilb_proxy_active_connections"] {
		t.Fatal("uninitialized proxy reported healthy zero")
	}
}

func TestDatapathExpositionRecoversWithCapability(t *testing.T) {
	saveMetricsRuntime(t)
	for _, available := range []bool{false, true, false} {
		PrometheusRegister(&peerMetricsHook{}, available)
		families, err := prom.DefaultGatherer.Gather()
		if err != nil {
			t.Fatal(err)
		}
		seenNative, seenCapability := false, false
		for _, family := range families {
			switch family.GetName() {
			case "loxilb_proxy_active_connections":
				seenNative = true
			case "loxilb_datapath_metrics_available":
				seenCapability = true
				want := float64(0)
				if available {
					want = 1
				}
				if got := family.GetMetric()[0].GetGauge().GetValue(); got != want {
					t.Errorf("capability gauge = %v, want %v", got, want)
				}
			}
		}
		if !seenCapability || seenNative != available {
			t.Fatalf("available=%v: native=%v capability=%v", available, seenNative, seenCapability)
		}
	}
}

func TestMetricsStopTimeoutPreventsOverlappingRestart(t *testing.T) {
	saveMetricsRuntime(t)
	PrometheusRegister(&peerMetricsHook{}, false)
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	prometheusCtx, prometheusCancel = ctx, cancel
	prometheusDone = startMetricWorkers(ctx, func(context.Context) { <-release })
	deadline, end := context.WithTimeout(context.Background(), time.Millisecond)
	defer end()
	if err := Stop(deadline); !errors.Is(err, ErrMetricsStopping) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop must report stopping and deadline: %v", err)
	}
	if err := CheckInit(); !errors.Is(err, ErrMetricsStopping) {
		t.Fatalf("cancelled generation reported running/off: %v", err)
	}
	if err := Init(); !errors.Is(err, ErrMetricsStopping) {
		t.Fatalf("Init must refuse stopping generation: %v", err)
	}
	close(release)
	if err := PrometheusTurnOff(); err != nil {
		t.Fatal(err)
	}
	if err := Init(); err != nil {
		t.Fatalf("failed to recover after draining: %v", err)
	}
}

func TestMetricsConcurrentLifecycle(t *testing.T) {
	saveMetricsRuntime(t)
	PrometheusRegister(&peerMetricsHook{}, false)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if err := Init(); err != nil && !errors.Is(err, ErrMetricsStopping) {
					t.Error(err)
				}
				_ = CheckInit()
				_ = GetMetricsHealth()
				if _, err := prom.DefaultGatherer.Gather(); err != nil {
					t.Error(err)
				}
				if err := PrometheusTurnOff(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

// A worker can query lifecycle diagnostics while it drains. Waiting with
// initMutex held would deadlock this worker until Stop's own deadline.
func TestMetricsStopAllowsReentrantHealthQueries(t *testing.T) {
	saveMetricsRuntime(t)
	PrometheusRegister(&peerMetricsHook{}, false)
	ctx, cancel := context.WithCancel(context.Background())
	observations := make(chan error, 1)
	initMutex.Lock()
	prometheusCtx, prometheusCancel = ctx, cancel
	prometheusGeneration++
	prometheusDone = startMetricWorkers(ctx, func(ctx context.Context) {
		<-ctx.Done()
		stateErr := CheckInit()
		_ = GetMetricsHealth()
		_ = IsHooksAvailable()
		if !errors.Is(stateErr, ErrMetricsStopping) {
			observations <- fmt.Errorf("draining worker saw %v", stateErr)
		} else {
			observations <- nil
		}
	})
	initMutex.Unlock()
	deadline, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if err := Stop(deadline); err != nil {
		t.Fatalf("reentrant worker could not drain: %v", err)
	}
	if err := <-observations; err != nil {
		t.Fatal(err)
	}
	if err := CheckInit(); err == nil || errors.Is(err, ErrMetricsStopping) {
		t.Fatalf("joined generation is not off: %v", err)
	}
}

// Canonical Tier 1.5 children are pre-created and gatherable when the owner
// declares a datapath available; unavailable mode must hide the same families.
func TestKvTier15MissCountersRegistered(t *testing.T) {
	saveMetricsRuntime(t)
	const missMetricName = "loxilb_pd_kv_tier15_miss_reason_total"
	const fallthroughMetricName = "loxilb_pd_kv_tier15_fallthrough_total"

	PrometheusRegister(&peerMetricsHook{}, false)
	names := metricFamilies(t)
	for _, name := range []string{missMetricName, fallthroughMetricName} {
		if names[name] {
			t.Errorf("unavailable native family emitted: %s", name)
		}
	}
	PrometheusRegister(&peerMetricsHook{}, true)

	mfs, err := prom.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("DefaultGatherer.Gather() returned error: %v", err)
	}

	seen := map[string]bool{}
	reasonSeen := map[string]bool{}
	for _, mf := range mfs {
		name := mf.GetName()
		if name == missMetricName || name == fallthroughMetricName {
			seen[name] = true
		}
		if name == missMetricName {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "reason" {
						reasonSeen[lp.GetValue()] = true
					}
				}
			}
		}
	}

	// Every canonical reason child must exist immediately after package init
	// (pre-created so dashboards see the full series set before any
	// increment). The last four are the contract-gate / typed-bridge
	// classes — lockstep with pd_kv_t15_miss_* in sockproxy.h.
	for _, reason := range []string{
		"mode_off", "warmup", "text_empty", "model_empty", "tokenize",
		"hashes", "no_worker", "excluded", "shallow",
		"not_ready", "api_mode", "unsupported_feature", "runtime_fault",
	} {
		if !reasonSeen[reason] {
			t.Errorf("miss-reason child %q not pre-created", reason)
		}
	}

	if !seen[missMetricName] {
		// Surface all registered metric names with the loxilb_pd_kv prefix
		// to make diagnosis easier if registration ever regresses.
		var kvMetricNames []string
		for _, mf := range mfs {
			if strings.HasPrefix(mf.GetName(), "loxilb_pd_kv") {
				kvMetricNames = append(kvMetricNames, mf.GetName())
			}
		}
		t.Errorf("metric %q not registered; loxilb_pd_kv_* metrics seen: %v",
			missMetricName, kvMetricNames)
	}
	if !seen[fallthroughMetricName] {
		t.Errorf("metric %q not registered", fallthroughMetricName)
	}
}
