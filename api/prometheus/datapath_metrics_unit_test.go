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
	"sync/atomic"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
)

func TestDatapathCollectorDoesNotSampleUnavailableSource(t *testing.T) {
	old := datapathAvailable.Load()
	defer datapathAvailable.Store(old)
	var calls atomic.Int64
	source := prom.NewGaugeFunc(prom.GaugeOpts{Name: "test_native_source", Help: "test"}, func() float64 { calls.Add(1); return 7 })
	registry := prom.NewPedanticRegistry()
	registry.MustRegister(datapathCollector{source})
	for _, available := range []bool{false, true, false, true} {
		datapathAvailable.Store(available)
		before := calls.Load()
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		if available {
			if len(families) != 1 || calls.Load() != before+1 || families[0].Metric[0].Gauge.GetValue() != 7 {
				t.Fatal("ready source not sampled")
			}
		} else if len(families) != 0 || calls.Load() != before {
			t.Fatal("unavailable source sampled or exported")
		}
	}
}

func TestDatapathCollectorPreservesDescriptorIdentity(t *testing.T) {
	registry := prom.NewRegistry()
	source := prom.NewGauge(prom.GaugeOpts{Name: "test_duplicate_datapath", Help: "test"})
	wrapped := datapathCollector{source}
	registry.MustRegister(wrapped)
	if err := registry.Register(source); err == nil {
		t.Fatal("wrapper hid duplicate descriptor")
	}
	if !registry.Unregister(wrapped) {
		t.Fatal("wrapper could not be unregistered")
	}
	if err := registry.Register(source); err != nil {
		t.Fatal(err)
	}
}

func TestMetricWorkersJoinCancelledGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stopped atomic.Int64
	worker := func(ctx context.Context) { <-ctx.Done(); stopped.Add(1) }
	done := startMetricWorkers(ctx, worker, worker, worker)
	select {
	case <-done:
		t.Fatal("workers prematurely complete")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers failed to join")
	}
	if stopped.Load() != 3 {
		t.Fatal("done closed before all workers exited")
	}
}

func TestMetricPeriodStopsImmediatelyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { waitMetricPeriod(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector sleep ignored cancellation")
	}
}
