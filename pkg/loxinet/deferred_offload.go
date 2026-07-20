/*
 * Copyright (c) 2022 NetLOX Inc
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

// B23-02 : deferred-retry queue for paired-offload flows
// that hit a transient atomic-rollback (e.g., g_egress_steer capacity_full).
//
// Producer: pairedLBFlowOffload rollback paths (forward-fail and reply-fail)
// in dpu_doca_bf2.go call markDeferred(fwd, rev, lbMark) after the C-side has
// atomically rolled back any half-installed CT entry.
//
// Consumer: sweepDeferred runs every aging tick AS A SEPARATE GOROUTINE
// (S4 —) so it never blocks the DOCA worker thread. Each
// deferred flow gets up to deferredMaxAttempts retries; thereafter the
// entry is dropped silently (the eBPF slow-path keeps the flow alive).
//
// Capacity gate: when activeEntries on g_egress_steer is at or above
// 0.9 * capacity, the entire sweep skips so we don't amplify load on a
// pipe that is already at the brink of capacity_full.

package loxinet

import (
	"sync/atomic"
)

// deferredEntry tracks one pending paired-offload flow waiting for a retry.
// fwd / rev are the conntrack 5-tuples; lbMark is the LB rule mark used at
// install time. attempts is incremented atomically by the sweep goroutine.
type deferredEntry struct {
	fwd, rev *DpCtInfo
	lbMark   int
	attempts atomic.Int32
}

const (
	// deferredMaxAttempts caps per-flow retry attempts so a permanently
	// poisoned 5-tuple (e.g., resolver returning the wrong port forever)
	// cannot consume the deferred-retry budget indefinitely.
	deferredMaxAttempts int32 = 3

	// deferredCapacityRatio is the headroom watermark: when active steer
	// entries reach this fraction of capacity, sweepDeferred skips the
	// entire sweep to avoid retry storms (D-B23-02).
	deferredCapacityRatio float64 = 0.9
)

// markDeferred queues a flow that failed atomic-rollback for next-tick
// re-offload. Called from pairedLBFlowOffload rollback paths.
//
// Idempotent: a flow already in the queue is NOT re-queued (LoadOrStore guard
// prevents the attempt-counter from being reset by repeated rollback hits).
func (d *DpDocaBf2) markDeferred(fwd, rev *DpCtInfo, lbMark int) {
	if d == nil || fwd == nil {
		return
	}
	key := fwd.Key()
	if _, loaded := d.deferredOffload.LoadOrStore(key, &deferredEntry{
		fwd: fwd, rev: rev, lbMark: lbMark,
	}); !loaded {
		docaOffloadDeferredRetryTotal.WithLabelValues("queued").Inc()
	}
}

// sweepDeferred re-attempts each deferred flow ONCE per call.
//
// MUST be invoked AS A SEPARATE GOROUTINE from agingPollCycle (S4 worker-thread
// re-entrancy avoidance —). The re-attempt routes through
// d.pairedLBFlowOffload, which itself routes through submit — calling that
// from inside agingPollCycle (the worker pthread) would self-deadlock.
//
// Capacity gate (D-B23-02): when activeEntries >= capacity * 0.9 the entire
// sweep skips so we don't amplify load on a pipe that is already saturated.
//
// Per-flow attempt cap (D-B23-02): once attempts > deferredMaxAttempts the
// entry is removed from the queue silently and a "gave_up" telemetry sample
// is recorded. The eBPF slow-path keeps the flow alive in the meantime.
func (d *DpDocaBf2) sweepDeferred(activeEntries int, capacity int) {
	if d == nil {
		return
	}
	if capacity <= 0 {
		return
	}
	// Capacity gate: skip if g_egress_steer is at or above the headroom limit.
	if float64(activeEntries) >= float64(capacity)*deferredCapacityRatio {
		return
	}

	// Pick the re-attempt function. Production path is d.pairedLBFlowOffload;
	// tests inject d.pairedOffloadFn to assert sweep semantics without CGO.
	attempt := d.pairedLBFlowOffload
	if d.pairedOffloadFn != nil {
		attempt = d.pairedOffloadFn
	}

	d.deferredOffload.Range(func(k, v any) bool {
		de, ok := v.(*deferredEntry)
		if !ok || de == nil {
			d.deferredOffload.Delete(k)
			return true
		}
		attempts := de.attempts.Add(1)
		if attempts > deferredMaxAttempts {
			d.deferredOffload.Delete(k)
			docaOffloadDeferredRetryTotal.WithLabelValues("gave_up").Inc()
			return true
		}
		if err := attempt(de.fwd, de.rev, de.lbMark); err == nil {
			d.deferredOffload.Delete(k)
			docaOffloadDeferredRetryTotal.WithLabelValues("ok").Inc()
		} else {
			docaOffloadDeferredRetryTotal.WithLabelValues("failed").Inc()
		}
		return true
	})
}
