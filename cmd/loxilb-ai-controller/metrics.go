/*
 * Copyright (c) 2026 LoxiLB Authors
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

// CTRL-05 self-metrics : every emitted epoch, per-source
// staleness, and decision input/output is Prometheus-reconstructable — no
// docker-log grep needed. Series names are LOCKED by the plan.
package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// aictrl_snapshots_emitted_total — one increment per generator emission.
	metricSnapshotsEmitted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aictrl_snapshots_emitted_total",
		Help: "Total SotW snapshots emitted (epoch increments)",
	})

	// aictrl_current_epoch — the last emitted epoch (monotonic per boot_id).
	metricCurrentEpoch = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_current_epoch",
		Help: "Last emitted snapshot epoch (monotonic within one boot_id)",
	})

	// aictrl_source_staleness_seconds{source} — refreshed each engine tick.
	metricSourceStaleness = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aictrl_source_staleness_seconds",
		Help: "Seconds since the last successful scrape per source (engine-tick refreshed)",
	}, []string{"source"})

	// aictrl_source_stale{source} — 0/1 staleness verdict per source.
	metricSourceStale = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aictrl_source_stale",
		Help: "1 when the source is excluded as stale (aged or absent sample), else 0",
	}, []string{"source"})

	// aictrl_fleet_stale — 0/1: ALL sources stale => emission stops (CTRL-02).
	metricFleetStale = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_fleet_stale",
		Help: "1 when every source is stale and snapshot emission is stopped",
	})

	// aictrl_ep_weight{service,ep_idx} — the engine OUTPUT (post negative-
	// control when that harness arm is active): decision reconstructable.
	metricEpWeight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aictrl_ep_weight",
		Help: "Per-EP weight the controller decided this epoch (would-emit value)",
	}, []string{"service", "ep_idx"})

	// aictrl_registry_mismatch_total{source} — discovery-vs-expectation
	// WARN counter (discovered wins; expectation is never rewritten).
	metricRegistryMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aictrl_registry_mismatch_total",
		Help: "Discovery validations disagreeing with the registry expectation",
	}, []string{"source"})

	// aictrl_watchers_connected — live WatchSnapshots stream count.
	metricWatchersConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_watchers_connected",
		Help: "Currently connected WatchSnapshots watchers (gateways)",
	})

	// aictrl_acks_applied_total{gateway} / aictrl_acks_rejected_total{gateway}.
	metricAcksApplied = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aictrl_acks_applied_total",
		Help: "ACK_STATUS_APPLIED acks received per gateway",
	}, []string{"gateway"})
	metricAcksRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aictrl_acks_rejected_total",
		Help: "ACK_STATUS_REJECTED acks received per gateway (telemetry only — never re-pushed)",
	}, []string{"gateway"})

	// aictrl_negative_control_active — 0/1 harness self-confirm.
	// The G1 script asserts this gauge is 0 in every non-NC arm.
	metricNegativeControl = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_negative_control_active",
		Help: "1 when the VAL-02 negative-control weight inversion is active",
	})

	// aictrl_watcher_dropped_snapshots_total{gateway} — drop-oldest events
	// (superseded SotW dropped for a slow watcher; supplementary series).
	metricWatcherDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aictrl_watcher_dropped_snapshots_total",
		Help: "Superseded snapshots dropped from a slow watcher's buffer (SotW re-converges)",
	}, []string{"gateway"})

	// aictrl_ttft_active{model_version} — TTFT-03 arm self-confirm gauge
	// (mirrors metricLmcCostActive/metricNegativeControl): 1 ONLY when
	// AICTRL_TTFT_WEIGHT is set AND a coefficients model is loaded; 0 in the
	// default-OFF and observability (model loaded UNARMED) postures. The
	// ±TTFT A/B harness asserts this gauge per arm so no run can silently
	// mislabel which arm actually FIRED.
	metricTtftActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aictrl_ttft_active",
		Help: "1 when the Expected-TTFT weight term is armed (AICTRL_TTFT_WEIGHT + coefficients loaded), else 0 (default-OFF => byte-identical weights)",
	}, []string{"model_version"})

	// aictrl_ttft_model_version — the loaded coefficients model_version as a
	// plain numeric gauge (0 = no model loaded). The harness reads this
	// exact series (TTFT_MV_GAUGE) to cross-check the shipped file's version
	// against what the controller actually loaded.
	metricTtftModelVersion = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_ttft_model_version",
		Help: "Loaded Expected-TTFT coefficients model_version (0 when no model is loaded)",
	})

	// aictrl_ttft_alpha — the live α_ttft confidence factor (TTFT-03): the
	// prediction-error monitor decays it toward 0 on regime shift and back
	// toward 1 on recovery; the engine multiplies the TTFT term by it, so
	// α=0 ⇒ the term is exactly neutral.
	metricTtftAlpha = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_ttft_alpha",
		Help: "Live Expected-TTFT confidence factor alpha_ttft in [0,1] (TTFT-03: decays to 0/neutral on regime shift)",
	})

	// aictrl_ttft_pred_err_ratio_p50 / _p90 — windowed |relative error| of the
	// model's predicted vs server-observed TTFT (observability export;
	// the server-side histogram delta is DIAGNOSTIC-grade — client-side
	// aiperf remains the offline GATE truth). Unitless ratio.
	//
	// NOT promauto: registered lazily on the first real error window via
	// setTtftPredErr — an eagerly-registered gauge exports 0 ("perfect
	// prediction") before any window exists and whenever the term is
	// default-OFF, which reads as evidence instead of absence.
	//
	// Known biases (documented, accepted): the prediction and observation
	// windows are one epoch apart under load ramps (window skew), and the
	// prediction uses a fixed reference prompt length rather than the live
	// per-request mix (constant covariate bias) — treat these series as
	// trend diagnostics, not accuracy ground truth.
	metricTtftPredErrP50 = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_ttft_pred_err_ratio_p50",
		Help: "Windowed P50 |relative error| ratio of predicted vs observed TTFT (server-histogram diagnostic; absent until the first observation window)",
	})
	metricTtftPredErrP90 = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aictrl_ttft_pred_err_ratio_p90",
		Help: "Windowed P90 |relative error| ratio of predicted vs observed TTFT (server-histogram diagnostic; absent until the first observation window)",
	})
	ttftPredErrRegisterOnce sync.Once

	// aictrl_fingerprint_mismatch_total{source} — calibration-fingerprint
	// field mismatches (metricRegistryMismatch template): incremented EVERY
	// mismatched epoch per FieldMismatch; the WARN log is transition-only.
	// The ONLY consumer reaction is the prior fallback — never eligibility.
	metricFingerprintMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aictrl_fingerprint_mismatch_total",
		Help: "Calibration-fingerprint field mismatches vs the live-discovered subset (prior fallback, never an eligibility change)",
	}, []string{"source"})
)

// setTtftPredErr publishes a prediction-error window, registering the two
// gauges on first use so the series are ABSENT (not a fake perfect 0) until
// a real window exists.
func setTtftPredErr(p50, p90 float64) {
	ttftPredErrRegisterOnce.Do(func() {
		prometheus.MustRegister(metricTtftPredErrP50, metricTtftPredErrP90)
	})
	metricTtftPredErrP50.Set(p50)
	metricTtftPredErrP90.Set(p90)
}

// metricsHooks wires the snapshot server's observability callbacks into the
// promauto series above.
func metricsHooks(logf func(string, ...interface{})) serverHooks {
	return serverHooks{
		ackApplied:  func(gw string) { metricAcksApplied.WithLabelValues(gw).Inc() },
		ackRejected: func(gw string) { metricAcksRejected.WithLabelValues(gw).Inc() },
		watchers:    func(n int) { metricWatchersConnected.Set(float64(n)) },
		dropped:     func(gw string) { metricWatcherDropped.WithLabelValues(gw).Inc() },
		logf:        logf,
	}
}

// serveMetrics starts the /metrics HTTP endpoint (CTRL-05) and returns the
// server for graceful shutdown.
func serveMetrics(addr string, onErr func(error)) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			onErr(err)
		}
	}()
	return srv
}
