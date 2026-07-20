/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * sockproxy HA state-sync Prometheus metrics.
 * SPEC.md req: A5, A6 + CONTEXT (7 metrics total).
 *
 *
 * Naming convention: loxilb_<area>_<thing>_<unit>. All registered via
 * promauto.New* (auto-registration, no MustRegister needed).
 */

package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

// sockproxySyncOverflowTotal counts dropped events on ring/queue overflow.
// Labels (the values actually emitted by pkg/loxinet/sockproxy_sync.go):
//
//   - "outbound_batch" — per-peer outbound queue overflowed (slow peer).
//   - per-event kinds "session.create|session.update|session.delete|
//     conv.create|conv.update|conv.delete|session.unknown" — the inbound
//     event channel overflowed and an event of that kind was dropped
//     (drop-oldest semantics).
var sockproxySyncOverflowTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "loxilb_sockproxy_sync_overflow_total",
		Help: "Events dropped due to ring/queue overflow (kind=outbound_batch or the dropped event kind, e.g. session.update, conv.create).",
	},
	[]string{"kind"},
)

// sockproxySyncHealthRejectTotal counts synced session entries rejected by
// receiver-side health gate (SPEC A5). Label: reason — currently ONLY
// "local_unhealthy" is emitted: the C applier returns a single health-reject
// code that covers both a locally-unhealthy ep_idx and an out-of-bounds
// ep_idx (the WARN log carries the distinction; the metric cannot until the
// C side returns separate codes).
var sockproxySyncHealthRejectTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "loxilb_sockproxy_sync_health_reject_total",
		Help: "Synced session entries dropped by receiver health gate (reason=local_unhealthy; includes out-of-bounds ep_idx).",
	},
	[]string{"reason"},
)

// sockproxySyncApplyErrorsTotal counts receiver-side apply failures (the C
// applier returned a negative outcome — service unknown, malformed entry).
// Previously invisible in every sync metric (metrics audit): a peer could
// stream entries that all failed to apply while the conflict/health counters
// stayed flat.
var sockproxySyncApplyErrorsTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "loxilb_sockproxy_sync_apply_errors_total",
		Help: "Synced session entries whose receiver-side apply failed outright (negative C applier outcome).",
	},
)

// sockproxySyncConflictTotal counts Active-Active first-writer-wins
// conflict-resolution outcomes (SPEC A6). Labels: outcome ∈ {"local_kept",
// "remote_won", "tie_local_kept"}.
var sockproxySyncConflictTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "loxilb_sockproxy_sync_conflict_total",
		Help: "Active-Active conflict resolution outcomes (outcome=local_kept|remote_won|tie_local_kept).",
	},
	[]string{"outcome"},
)

// sockproxySyncPushLatencySeconds is the per-RPC push latency observed by
// the sender (after gRPC Send returns). Labels: peer, rpc. Buckets cover
// 0.1ms–13.1s (ExponentialBuckets(0.0001, 2, 18)): the RPC timeout is 10s,
// so the histogram must resolve the slow tail — the previous ~205ms top
// bucket lumped every degraded push into +Inf.
var sockproxySyncPushLatencySeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "loxilb_sockproxy_sync_push_latency_seconds",
		Help:    "Per-RPC sockproxy sync push latency at sender (post-gRPC.Send).",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 18),
	},
	[]string{"peer", "rpc"},
)

// sockproxySyncInflightRpc is the number of in-flight unary RPCs per peer.
// Used to detect coordinator backpressure (should be ≤ 1 per peer per
// RPC-family — single in-flight invariant per CONTEXT D "Claude's Discretion").
var sockproxySyncInflightRpc = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "loxilb_sockproxy_sync_inflight_rpc",
		Help: "Currently in-flight sockproxy sync RPCs per peer.",
	},
	[]string{"peer"},
)

// sockproxySyncDropTotal counts per-peer outbound batches that were
// dropped after exhausting the retry budget. Labels:
//
//		reason ∈ {"peer_unreachable", "shutdown"}.
//
//	  - "peer_unreachable" — the per-peer consumer issued 3 retries of
//	    sendOnce against the peer's XSync client and every attempt failed
//	    (non-Unimplemented; codes.Unimplemented uses the existing capability
//	    degrade path and does NOT count as a drop).
//	  - "shutdown" — the consumer received the shutdown signal while a batch
//	    was still in flight or queued; reserved for future use.
var sockproxySyncDropTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "loxilb_sockproxy_sync_drop_total",
		Help: "Per-peer sockproxy sync batches dropped after retries (reason=peer_unreachable|shutdown).",
	},
	[]string{"reason"},
)

// ---------- Exported convenience helpers (used by pkg/loxinet/sockproxy_sync.go) ----------

// SockproxySyncOverflowInc increments the overflow counter for the given kind.
func SockproxySyncOverflowInc(kind string) {
	sockproxySyncOverflowTotal.WithLabelValues(kind).Inc()
}

// SockproxySyncHealthRejectInc increments the health-reject counter.
func SockproxySyncHealthRejectInc(reason string) {
	sockproxySyncHealthRejectTotal.WithLabelValues(reason).Inc()
}

// SockproxySyncConflictInc increments the conflict-resolution counter.
func SockproxySyncConflictInc(outcome string) {
	sockproxySyncConflictTotal.WithLabelValues(outcome).Inc()
}

// SockproxySyncPushLatencyObserve records a push-latency observation.
func SockproxySyncPushLatencyObserve(peer, rpc string, seconds float64) {
	sockproxySyncPushLatencySeconds.WithLabelValues(peer, rpc).Observe(seconds)
}

// SockproxySyncInflightRpcInc / Dec track the in-flight gauge.
func SockproxySyncInflightRpcInc(peer string) {
	sockproxySyncInflightRpc.WithLabelValues(peer).Inc()
}
func SockproxySyncInflightRpcDec(peer string) {
	sockproxySyncInflightRpc.WithLabelValues(peer).Dec()
}

// SockproxySyncDropInc increments the per-reason drop counter
// / CR-02 retry-exhaustion path).
func SockproxySyncDropInc(reason string) {
	sockproxySyncDropTotal.WithLabelValues(reason).Inc()
}

// SockproxySyncApplyErrorInc counts one receiver-side apply failure.
func SockproxySyncApplyErrorInc() {
	sockproxySyncApplyErrorsTotal.Inc()
}

// SockproxySyncDropValue returns the current value of the drop counter
// for the given reason label. Test-only getter — avoids forcing the
// prometheus/testutil package into the loxinet module's import graph.
func SockproxySyncDropValue(reason string) float64 {
	c := sockproxySyncDropTotal.WithLabelValues(reason)
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		return 0
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}
