//go:build !doca

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

package loxinet

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// makeDeferredCT builds a DpCtInfo whose Key is unique per `tag` so each
// test entry is keyed distinctly in the sync.Map.
func makeDeferredCT(tag uint8) *DpCtInfo {
	return &DpCtInfo{
		DIP:   net.IPv4(10, 0, 0, tag),
		SIP:   net.IPv4(10, 0, 1, tag),
		Dport: 80,
		Sport: 1024,
		Proto: "tcp",
	}
}

// TestMarkDeferred_StoresFlow asserts that markDeferred stores the flow
// keyed by fwd.Key and increments the queued counter exactly once
// per unique flow.
func TestMarkDeferred_StoresFlow(t *testing.T) {
	d := &DpDocaBf2{}
	fwd := makeDeferredCT(1)
	rev := makeDeferredCT(2)

	queuedBefore := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("queued"))
	d.markDeferred(fwd, rev, 7)
	queuedAfter := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("queued"))

	if queuedAfter-queuedBefore != 1 {
		t.Fatalf("queued counter delta = %v; want 1", queuedAfter-queuedBefore)
	}

	v, ok := d.deferredOffload.Load(fwd.Key())
	if !ok {
		t.Fatalf("deferredOffload missing key %q after markDeferred", fwd.Key())
	}
	de, _ := v.(*deferredEntry)
	if de == nil || de.fwd != fwd || de.rev != rev || de.lbMark != 7 {
		t.Fatalf("stored deferredEntry mismatch: %+v", de)
	}

	// Idempotent: a second markDeferred for the same key MUST NOT bump queued.
	d.markDeferred(fwd, rev, 7)
	queuedFinal := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("queued"))
	if queuedFinal != queuedAfter {
		t.Fatalf("idempotency broken: queued went from %v to %v on duplicate mark", queuedAfter, queuedFinal)
	}
}

// TestSweepDeferred_CapacityGate asserts that when activeEntries >=
// capacity * deferredCapacityRatio, sweepDeferred returns IMMEDIATELY
// without invoking the re-attempt function (the capacity gate fires first).
func TestSweepDeferred_CapacityGate(t *testing.T) {
	d := &DpDocaBf2{}

	var attempts atomic.Int32
	d.pairedOffloadFn = func(_, _ *DpCtInfo, _ int) error {
		attempts.Add(1)
		return nil
	}

	// Queue one flow.
	d.markDeferred(makeDeferredCT(3), makeDeferredCT(4), 0)

	// Capacity is 1024; ratio is 0.9 → the gate condition is
	// activeEntries >= 1024*0.9 = 921.6, so 922 is the first integer at or
	// above the watermark (int truncation of 921.6 lands just BELOW the
	// float threshold and would never trip the gate).
	capacity := 1024
	gateTrip := 922

	d.sweepDeferred(gateTrip, capacity)
	if attempts.Load() != 0 {
		t.Fatalf("capacity gate failed: attempts = %d (expected 0 — gate should have skipped sweep)", attempts.Load())
	}

	// Below the gate, the sweep DOES iterate.
	d.sweepDeferred(0, capacity)
	if attempts.Load() != 1 {
		t.Fatalf("post-gate sweep failed: attempts = %d (expected 1)", attempts.Load())
	}
}

// TestSweepDeferred_GivesUpAfter3 asserts that after deferredMaxAttempts
// failed re-attempts the entry is removed from the queue and a "gave_up"
// telemetry sample is emitted.
func TestSweepDeferred_GivesUpAfter3(t *testing.T) {
	d := &DpDocaBf2{}
	fwd := makeDeferredCT(5)
	rev := makeDeferredCT(6)

	failErr := errors.New("synthetic capacity_full")
	d.pairedOffloadFn = func(_, _ *DpCtInfo, _ int) error { return failErr }
	d.markDeferred(fwd, rev, 0)

	gaveUpBefore := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("gave_up"))
	failedBefore := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("failed"))

	// 4 sweeps under the gate: attempts=1 (failed), 2 (failed), 3 (failed),
	// 4 (gave_up — exceeds cap of 3, entry deleted).
	for i := 0; i < 4; i++ {
		d.sweepDeferred(0, 1024)
	}

	failedAfter := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("failed"))
	gaveUpAfter := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("gave_up"))

	if failedAfter-failedBefore != 3 {
		t.Fatalf("failed counter delta = %v; want 3", failedAfter-failedBefore)
	}
	if gaveUpAfter-gaveUpBefore != 1 {
		t.Fatalf("gave_up counter delta = %v; want 1", gaveUpAfter-gaveUpBefore)
	}
	if _, ok := d.deferredOffload.Load(fwd.Key()); ok {
		t.Fatalf("deferredOffload still has key after gave_up; expected delete")
	}
}

// TestSweepDeferred_DeletesOnSuccess asserts that on a successful re-offload
// the entry is removed from the queue and an "ok" sample is emitted.
func TestSweepDeferred_DeletesOnSuccess(t *testing.T) {
	d := &DpDocaBf2{}
	fwd := makeDeferredCT(7)
	rev := makeDeferredCT(8)
	d.pairedOffloadFn = func(_, _ *DpCtInfo, _ int) error { return nil }
	d.markDeferred(fwd, rev, 0)

	okBefore := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("ok"))
	d.sweepDeferred(0, 1024)
	okAfter := testutil.ToFloat64(docaOffloadDeferredRetryTotal.WithLabelValues("ok"))

	if okAfter-okBefore != 1 {
		t.Fatalf("ok counter delta = %v; want 1", okAfter-okBefore)
	}
	if _, ok := d.deferredOffload.Load(fwd.Key()); ok {
		t.Fatalf("deferredOffload still has key after success; expected delete")
	}
}
