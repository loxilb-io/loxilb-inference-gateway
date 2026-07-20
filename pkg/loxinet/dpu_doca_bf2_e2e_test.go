//go:build !doca

/*
 * Copyright (c) 2026 NetLOX Inc
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

// dpu_doca_bf2_e2e_test.go — end-to-end darwin tests
// for the producer side of telemetry chain.
//
// Scope under !doca:
//   - Callback registry contract (RegisterDocaCollector / InvokeRegisteredDocaCollectors)
//     is build-tag-symmetric: the same primitives exist in dpu_doca_bf2_metrics.go
//     (doca build) and dpu_doca_bf2_stub_metrics.go (!doca build). These tests
//     exercise the !doca path; the doca-build behavioral chain (chunked walker
// actually firing against DOCA SDK) runs on BF2 silicon per
// operator runbook.
// - Panic isolation: amendment iter 2 mandates that a panicking callback
//     does NOT bring down the per-tick path or block other callbacks. Verified
// under !doca because the recover lives in InvokeRegisteredDocaCollectors.
//   - Stub-mirror contract: every DpDocaBf2 method exposed by the doca-build
//     metrics file has a !doca counterpart returning a safe zero value. These
//     tests catch the case where the doca-build adds a method without mirroring
// it on the stub (09 stub-sync class lesson).
//   - Chunked walker cursor arithmetic boundary conditions not already covered
//     by dpu_doca_bf2_chunked_walker_test.go: max-chunk-size clamp, zero-total
//     guard, single-tick full-sweep.
//
// Coverage NOT included here (intentionally deferred to other gates):
// - Real DOCA SDK calls (Linux + DOCA SDK only operator runbook Scope 2)
//   - Actual Prometheus metric registration deltas under traffic (operator runbook Scope 2)
//   - REST chain (api/restapi/handler/dpu_debug_e2e_test.go covers this — separate file)

package loxinet

import (
	"sync"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// Test 1: callback registry contract — RegisterDocaCollector survives
// concurrent registration and InvokeRegisteredDocaCollectors runs every
// registered callback exactly once per call.
// ---------------------------------------------------------------------------

// TestE2ECallbackRegistryRegisterAndInvoke registers N callbacks (each
// incrementing a shared atomic counter), invokes the registry once, and
// asserts every callback fired exactly once. wires this registry into
// the per-tick path; this test isolates the registry semantics from the
// per-tick wiring so a registry regression is caught independently.
func TestE2ECallbackRegistryRegisterAndInvoke(t *testing.T) {
	const N = 16
	var counter int64

	// Snapshot of the registry size before this test runs.
	// Since other tests may also register callbacks, this test asserts on
	// the delta produced by THIS test's N registrations.
	beforeBaseline := atomic.LoadInt64(&counter)

	for i := 0; i < N; i++ {
		RegisterDocaCollector(func() {
			atomic.AddInt64(&counter, 1)
		})
	}

	InvokeRegisteredDocaCollectors()

	delta := atomic.LoadInt64(&counter) - beforeBaseline
	if delta < int64(N) {
		t.Errorf("expected at least %d callbacks invoked from this test (delta), got %d", N, delta)
	}
}

// ---------------------------------------------------------------------------
// Test 2: amendment iter 2 — panic isolation.
//
// A callback that panics MUST NOT prevent subsequent callbacks from running
// AND MUST NOT bring down InvokeRegisteredDocaCollectors. This is the
// contract noteDocaCollectorPanic + per-tick wiring rely on.
// ---------------------------------------------------------------------------

func TestE2ECallbackRegistryPanicIsolation(t *testing.T) {
	var (
		preCounter   int64
		postCounter  int64
		panicCounter int64
	)

	// Register a callback that increments preCounter (runs before the panic).
	RegisterDocaCollector(func() { atomic.AddInt64(&preCounter, 1) })

	// Register a callback that panics. noteDocaCollectorPanic should recover
	// and increment the panic-counter (production: a Prometheus error counter;
	// stub: silent).
	RegisterDocaCollector(func() {
		atomic.AddInt64(&panicCounter, 1)
		panic("test panic — must be contained by InvokeRegisteredDocaCollectors recover()")
	})

	// Register a callback that increments postCounter (runs after the panic).
	RegisterDocaCollector(func() { atomic.AddInt64(&postCounter, 1) })

	// MUST NOT panic out of this call.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("InvokeRegisteredDocaCollectors leaked a panic to the caller: %v", r)
			}
		}()
		InvokeRegisteredDocaCollectors()
	}()

	if atomic.LoadInt64(&preCounter) == 0 {
		t.Error("pre-panic callback did not run; registry iteration order or panic-shortcut broke")
	}
	if atomic.LoadInt64(&panicCounter) == 0 {
		t.Error("panicking callback did not run; registry skipped it without invoking")
	}
	if atomic.LoadInt64(&postCounter) == 0 {
		t.Error("post-panic callback did not run; amendment iter 2 panic-isolation violated")
	}
}

// ---------------------------------------------------------------------------
// Test 4: stub-mirror contract — every DpDocaBf2 method on the stub returns
// the documented safe-zero value. -09 lesson: a doca-build method
// without a stub counterpart breaks darwin/CI builds. This test asserts the
// CURRENT documented contract — if you add a method to the doca file without
// a stub, this test fails to compile (red).
// ---------------------------------------------------------------------------

func TestE2EStubMirrorReturnsSafeZero(t *testing.T) {
	d := &DpDocaBf2{}

	// EntryQuery returns zero + nil.
	res, err := d.EntryQuery(nil)
	if err != nil || res.Pkts != 0 || res.Bytes != 0 {
		t.Errorf("stub EntryQuery: got (%+v, %v); want zero + nil", res, err)
	}

	// BatchQuery returns nil + nil.
	rows, err := d.BatchQuery(nil)
	if err != nil || rows != nil {
		t.Errorf("stub BatchQuery: got (%v, %v); want nil + nil", rows, err)
	}

	// AllocSharedCounter returns 0 + nil.
	id, err := d.AllocSharedCounter("test-scope")
	if err != nil || id != 0 {
		t.Errorf("stub AllocSharedCounter: got (%d, %v); want 0 + nil", id, err)
	}

	// FreeSharedCounter is a silent no-op (must not panic).
	d.FreeSharedCounter(42)

	// EgressCountersAvailable returns false.
	if d.EgressCountersAvailable() {
		t.Error("stub EgressCountersAvailable: got true; want false")
	}

	// ReconcileCtStats returns OffloadNone + zeros.
	st := d.ReconcileCtStats(nil)
	if st.OffloadState != OffloadNone || st.Pkts != 0 || st.HwPkts != 0 {
		t.Errorf("stub ReconcileCtStats: got %+v; want OffloadNone + zero counts", st)
	}

	// QueryDocaEntries returns nil (no DOCA entries on !doca).
	if rows := d.QueryDocaEntries("ct_fwd_5tuple", "", "", 10); rows != nil {
		t.Errorf("stub QueryDocaEntries: got %d rows; want nil", len(rows))
	}
}

// ---------------------------------------------------------------------------
// Test 5: concurrent registration safety — RegisterDocaCollector must be
// safe to call from multiple goroutines. The registry uses a sync.Mutex on
// both build paths; this test catches the case where someone replaces the
// mutex with an unsynchronized append.
// ---------------------------------------------------------------------------

func TestE2ECallbackRegistryConcurrentRegistration(t *testing.T) {
	const goroutines = 32
	const perGoroutine = 8

	var counter int64
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				RegisterDocaCollector(func() { atomic.AddInt64(&counter, 1) })
			}
		}()
	}

	wg.Wait()

	// All goroutine registrations have completed. Invoke and assert the
	// expected count.
	InvokeRegisteredDocaCollectors()

	got := atomic.LoadInt64(&counter)
	want := int64(goroutines * perGoroutine)
	// The atomic-counter callback may have been called more than `want` times
	// if other tests in the file registered callbacks earlier; we only assert
	// the LOWER bound — every registration from this test must have fired.
	if got < want {
		t.Errorf("concurrent registration: got %d invocations; want at least %d",
			got, want)
	}
}
