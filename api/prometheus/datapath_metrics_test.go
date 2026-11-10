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
	PrometheusRegister(&peerMetricsHook{}, false)
	if metricFamilies(t)["loxilb_proxy_active_connections"] {
		t.Fatal("unavailable series emitted")
	}
	PrometheusRegister(&peerMetricsHook{}, true)
	if !metricFamilies(t)["loxilb_proxy_active_connections"] {
		t.Fatal("ready datapath series absent")
	}
	PrometheusRegister(&peerMetricsHook{}, false)
	if metricFamilies(t)["loxilb_proxy_active_connections"] {
		t.Fatal("stale datapath series emitted")
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
