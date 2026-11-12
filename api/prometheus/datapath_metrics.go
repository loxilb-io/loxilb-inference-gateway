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
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ErrMetricsStopping distinguishes a cancelled, unjoined generation from an
// off subsystem. Disable must be retried after it drains before enabling again.
var ErrMetricsStopping = errors.New("metrics collectors are still stopping; retry disable before enabling")

// The datapath owner registers its capability before the API listener starts.
// The default is unavailable, including before registration and partial startup.
// Registering a metric alone never authorizes CGO.
var datapathAvailable atomic.Bool
var datapathMetrics = promauto.With(datapathRegisterer{})

var datapathMetricsAvailable = promauto.NewGaugeFunc(prometheus.GaugeOpts{
	Name: "loxilb_datapath_metrics_available",
	Help: "Whether this process initialized the native datapath required by datapath metrics. Zero means those series are unavailable, not measured zero.",
}, func() float64 {
	if datapathAvailable.Load() {
		return 1
	}
	return 0
})

type datapathCollector struct{ prometheus.Collector }

func (c datapathCollector) Collect(ch chan<- prometheus.Metric) {
	if datapathAvailable.Load() {
		c.Collector.Collect(ch)
	}
}

// Gate exposition at registration, without maintaining a fragile list of metric
// names or changing how callers update counters. Describe remains unconditional
// so descriptor identity and duplicate-registration checks are preserved.
type datapathRegisterer struct{}

func (datapathRegisterer) Register(c prometheus.Collector) error {
	return prometheus.DefaultRegisterer.Register(datapathCollector{c})
}
func (r datapathRegisterer) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}
func (datapathRegisterer) Unregister(c prometheus.Collector) bool {
	return prometheus.DefaultRegisterer.Unregister(datapathCollector{c})
}

// One generation owns all its workers. Stop must join this generation before
// Init can reset shared baselines or a later generation can start.
func startMetricWorkers(ctx context.Context, workers ...func(context.Context)) <-chan struct{} {
	var wg sync.WaitGroup
	for _, worker := range workers {
		wg.Add(1)
		go func(run func(context.Context)) { defer wg.Done(); run(ctx) }(worker)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	return done
}

func waitMetricPeriod(ctx context.Context, period time.Duration) {
	timer := time.NewTimer(period)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
