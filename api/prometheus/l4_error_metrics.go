/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSD-2-Clause
 *
 * L4 connection-error metrics — always-on, event-driven, trace-INDEPENDENT.
 *
 * WHY THIS FILE EXISTS (metric/trace separation):
 * The precise per-connection error signal (RST / abort / protocol error) is
 * produced by the eBPF CT state machine. Historically the only Go-side consumer
 * of that signal was the L4 *trace* pipeline (span assembler), which is
 * compile-gated (build tag l4trace), runtime-gated (trace enabled), and SAMPLED.
 * Metrics must NOT depend on any of that — they have to be exact and present in
 * every build. So the data plane now bumps a dedicated, unsampled ct_err_stats
 * map on every error transition (see llb_kern_ct.c), and this module reads it via
 * the always-on hook interface and exposes it as a Prometheus counter. No build
 * tag, no sampling, no dependency on the trace subsystem.
 *
 * This supersedes the conntrack-sweep error accounting (loxilb_errors_total) as
 * the source of truth for L4 error alerting: the sweep only samples connection
 * *state* every PrometheusDefaultPeriod and therefore misses short-lived error
 * flows entirely, whereas these counters catch every transition.
 */

package prometheus

import (
	"context"
	"fmt"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// l4ErrorEventsTotal counts L4 connection errors exactly once per occurrence,
// labeled by protocol and reason. Always registered (reads 0 when there are no
// errors or the data plane predates the ct_err_stats map), so dashboards and the
// LoxilbL4ErrorBurst alert never see "No data".
//
// Label cardinality is bounded and tiny: proto ∈ {tcp,sctp}, reason ∈
// {rst,error,abort}.
var l4ErrorEventsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "loxilb_l4_error_events_total",
		Help: "L4 connection error events by protocol and reason (event-driven, unsampled; RST/abort/protocol-error). Source of truth for LoxilbL4ErrorBurst.",
	},
	[]string{"proto", "reason"},
)

// prevCtErrStats holds the previous cumulative snapshot for delta computation
// (the eBPF map counters are cumulative; the Prometheus counter takes deltas).
var prevCtErrStats cmn.CtErrorStats

// ctErrSeeded guards the first collection cycle: on startup we adopt the current
// cumulative values as the baseline WITHOUT emitting them, so a loxilb restart
// (or a late Prometheus start) does not replay historical errors as one large
// burst and false-trip LoxilbL4ErrorBurst.
var ctErrSeeded bool

// ctErrDelta returns cur-prev, treating a decrease (map cleared / DP restart) as
// a fresh count of `cur` rather than a negative delta.
func ctErrDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// RunL4ErrorStats periodically reads the always-on ct_err_stats counters and
// advances loxilb_l4_error_events_total by the per-cycle delta. Mirrors
// RunSecurityRateStats; runs under safeGoroutineOperation (panic-isolated loop).
func RunL4ErrorStats(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		stats, err := hooks.NetCtErrorStatsGet()
		if err != nil {
			return fmt.Errorf("ct error stats get failed: %v", err)
		}

		if !ctErrSeeded {
			// First cycle: baseline only, do not emit historical accumulation.
			prevCtErrStats = stats
			ctErrSeeded = true
			time.Sleep(PrometheusDefaultPeriod)
			return nil
		}

		l4ErrorEventsTotal.WithLabelValues("tcp", "rst_client").Add(float64(ctErrDelta(stats.TCPRstClient, prevCtErrStats.TCPRstClient)))
		l4ErrorEventsTotal.WithLabelValues("tcp", "rst_server").Add(float64(ctErrDelta(stats.TCPRstServer, prevCtErrStats.TCPRstServer)))
		l4ErrorEventsTotal.WithLabelValues("tcp", "error").Add(float64(ctErrDelta(stats.TCPErr, prevCtErrStats.TCPErr)))
		l4ErrorEventsTotal.WithLabelValues("sctp", "abort").Add(float64(ctErrDelta(stats.SCTPAbort, prevCtErrStats.SCTPAbort)))
		l4ErrorEventsTotal.WithLabelValues("sctp", "error").Add(float64(ctErrDelta(stats.SCTPErr, prevCtErrStats.SCTPErr)))

		prevCtErrStats = stats

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "l4_error_stats", ctx)
}
