/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Sub-phase B: Rate-limiter HA tests. SPEC.md req: B1, B2.
 *
 * Tests cover the four-method Export/Import/Delta/Gossip surface added in
 * ratelimit_sync.go. All tests are race-clean (`go test -race ./pkg/ratelimit/...`).
 *
 *   TestRateLimiterRoundTrip            — SPEC B1: Export→Import preserves
 *                                         per-key config + per-tenant atomic
 *                                         window state byte-for-byte.
 *   TestRateLimiterApplyGossipDelta     — gossip max-merge idempotent under
 *                                         reordered messages (RESEARCH §4).
 *   TestRateLimiterExportConcurrent     — SPEC B2: ExportState races
 *                                         CheckKey/CheckTenant/AllowTokens
 *                                         under the race detector.
 * TestRateLimiterImportL8Reservation — : documents and
 *                                         observes the orphaned-reservation
 *                                         trade-off.
 *   TestRateLimiterCleanupCompat        — Cleanup goroutine continues to run
 *                                         untouched alongside the new sync API.
 *   TestRateLimiterExportDeltaProgress  — ExportDelta only emits entries
 *                                         whose Consumed has increased
 *                                         since the prev snapshot.
 *   TestRateLimiterEpochAdvance         — newer epoch on receive resets
 *                                         consumed; older is ignored.
 */

package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- B1: round-trip equivalence ----------

// TestRateLimiterRoundTrip exercises SPEC B1: ExportState → ImportState
// preserves per-key (rps, burst, lastAccess) config and per-tenant
// (windowEpoch, consumed, exceeded) atomic-window state.
//
// rate.Limiter internal state (tokens, last refill) is NOT preserved per
// / I-4 (opaque upstream API). The test asserts only the
// fields that ARE round-trippable.
func TestRateLimiterRoundTrip(t *testing.T) {
	t.Parallel()

	src := newTestStore()

	// Populate 100 per-key buckets with varied (rps, burst).
	const nKeys = 100
	for i := 0; i < nKeys; i++ {
		rps := 10 + (i % 50)
		burst := rps + (i % 5)
		// CheckKey internally calls s.update path, populating entries map.
		src.CheckKey("rt-key-"+itoa(i), rps, burst)
	}

	// Populate 50 tenant quotas with varied consumed counts.
	const nTenants = 50
	for i := 0; i < nTenants; i++ {
		tenantID := "rt-tenant-" + itoa(i)
		// AllowTokens populates quotaMap and atomically bumps consumed.
		src.AllowTokens(tenantID, 10+i, 100000) // large budget so no exceed
	}
	// Mark one tenant as exceeded to verify the bool round-trips.
	src.AllowTokens("rt-tenant-exceeded", 1000000, 1000000)
	src.AllowTokens("rt-tenant-exceeded", 1, 1000000) // push over → exceeded=1

	// Export.
	snap := src.ExportState()

	// Sanity: snapshot has the expected counts (per-key + per-tenant).
	wantTotal := nKeys + nTenants + 1 // +1 for the exceeded tenant
	if len(snap) != wantTotal {
		t.Fatalf("expected %d entries in snapshot, got %d", wantTotal, len(snap))
	}

	// Import into a fresh store.
	dst := newTestStore()
	dst.ImportState(snap)

	// Verify per-key config preservation. Re-acquire under lock so the
	// race detector is happy with the comparison.
	src.mu.Lock()
	srcEntries := make(map[string]*limiterEntry, len(src.entries))
	for k, v := range src.entries {
		srcEntries[k] = v
	}
	src.mu.Unlock()

	dst.mu.Lock()
	defer dst.mu.Unlock()
	if len(dst.entries) != nKeys {
		t.Fatalf("expected %d per-key entries on dst, got %d", nKeys, len(dst.entries))
	}
	for k, srcEntry := range srcEntries {
		dstEntry, ok := dst.entries[k]
		if !ok {
			t.Errorf("key %q present in src but missing in dst", k)
			continue
		}
		if dstEntry.rps != srcEntry.rps {
			t.Errorf("key %q rps mismatch: src=%d dst=%d", k, srcEntry.rps, dstEntry.rps)
		}
		if dstEntry.burst != srcEntry.burst {
			t.Errorf("key %q burst mismatch: src=%d dst=%d", k, srcEntry.burst, dstEntry.burst)
		}
		// lastAccess round-trips via UnixNano — equality is exact.
		if dstEntry.lastAccess.UnixNano() != srcEntry.lastAccess.UnixNano() {
			t.Errorf("key %q lastAccess mismatch: src=%d dst=%d",
				k, srcEntry.lastAccess.UnixNano(), dstEntry.lastAccess.UnixNano())
		}
	}

	// Verify per-tenant atomic state preservation.
	for i := 0; i < nTenants; i++ {
		tenantID := "rt-tenant-" + itoa(i)
		srcV, ok := src.quotaMap.Load(tenantID)
		if !ok {
			t.Errorf("tenant %q missing from src.quotaMap", tenantID)
			continue
		}
		dstV, ok := dst.quotaMap.Load(tenantID)
		if !ok {
			t.Errorf("tenant %q missing from dst.quotaMap (Import lost it)", tenantID)
			continue
		}
		srcWE := srcV.(*tokenWindowEntry)
		dstWE := dstV.(*tokenWindowEntry)
		if atomic.LoadInt64(&srcWE.consumed) != atomic.LoadInt64(&dstWE.consumed) {
			t.Errorf("tenant %q consumed mismatch: src=%d dst=%d",
				tenantID,
				atomic.LoadInt64(&srcWE.consumed),
				atomic.LoadInt64(&dstWE.consumed))
		}
		if atomic.LoadInt64(&srcWE.windowEpoch) != atomic.LoadInt64(&dstWE.windowEpoch) {
			t.Errorf("tenant %q windowEpoch mismatch: src=%d dst=%d",
				tenantID,
				atomic.LoadInt64(&srcWE.windowEpoch),
				atomic.LoadInt64(&dstWE.windowEpoch))
		}
	}

	// Verify the exceeded flag round-trips.
	dstExceededV, ok := dst.quotaMap.Load("rt-tenant-exceeded")
	if !ok {
		t.Fatalf("rt-tenant-exceeded missing from dst.quotaMap")
	}
	if atomic.LoadInt32(&dstExceededV.(*tokenWindowEntry).exceeded) != 1 {
		t.Errorf("expected exceeded=1 to round-trip, got %d",
			atomic.LoadInt32(&dstExceededV.(*tokenWindowEntry).exceeded))
	}
}

// ---------- Gossip-delta semantics ----------

// TestRateLimiterApplyGossipDelta verifies the max merge rule and
// idempotency under reordered delta messages (RESEARCH §4 "max" rule +
// I-3 invariant).
func TestRateLimiterApplyGossipDelta(t *testing.T) {
	t.Parallel()

	s := newTestStore()

	// Seed local state: tenant_a consumed = 100, epoch = E.
	const tenantA = "tenant_a"
	s.AllowTokens(tenantA, 100, 1000000)

	v, _ := s.quotaMap.Load(tenantA)
	localEpoch := atomic.LoadInt64(&v.(*tokenWindowEntry).windowEpoch)

	// Receive higher value: should advance to 250.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: 250},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).consumed); got != 250 {
		t.Errorf("after first delta: expected consumed=250, got %d", got)
	}

	// Receive reordered (older) value: max-merge keeps 250.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: 175},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).consumed); got != 250 {
		t.Errorf("after reordered (older) delta: expected consumed STAYS at 250, got %d", got)
	}

	// Receive identical value: no-op.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: 250},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).consumed); got != 250 {
		t.Errorf("after identical delta: expected consumed=250, got %d", got)
	}

	// Receive higher value again: advances to 500.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: 500},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).consumed); got != 500 {
		t.Errorf("after second forward delta: expected consumed=500, got %d", got)
	}
}

// TestRateLimiterEpochAdvance verifies that a newer epoch in an incoming
// gossip message resets the consumed counter, while an older epoch is
// ignored.
func TestRateLimiterEpochAdvance(t *testing.T) {
	t.Parallel()

	s := newTestStore()
	const tenantB = "tenant_b"
	s.AllowTokens(tenantB, 100, 1000000)
	v, _ := s.quotaMap.Load(tenantB)
	localEpoch := atomic.LoadInt64(&v.(*tokenWindowEntry).windowEpoch)

	// Newer epoch: consumed resets to incoming value.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantB, IsTenant: true, WindowEpoch: localEpoch + 1, Consumed: 25},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).consumed); got != 25 {
		t.Errorf("after newer-epoch delta: expected consumed=25 (reset), got %d", got)
	}
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).windowEpoch); got != localEpoch+1 {
		t.Errorf("after newer-epoch delta: expected epoch=%d, got %d", localEpoch+1, got)
	}

	// Older epoch: completely ignored.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantB, IsTenant: true, WindowEpoch: localEpoch - 10, Consumed: 9999},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).consumed); got != 25 {
		t.Errorf("after older-epoch delta: expected consumed STAYS at 25, got %d", got)
	}
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).windowEpoch); got != localEpoch+1 {
		t.Errorf("after older-epoch delta: expected epoch STAYS at %d, got %d", localEpoch+1, got)
	}
}

// ---------- B2: race-clean ExportState under concurrent hot-path traffic ----------

// TestRateLimiterExportConcurrent runs ExportState in a goroutine while
// 100 worker goroutines pound on CheckKey / CheckTenant / AllowTokens
// for 1 second. The Go race detector must report 0 races.
//
// Acceptance: `go test -race -run TestRateLimiterExportConcurrent` exits 0.
func TestRateLimiterExportConcurrent(t *testing.T) {
	t.Parallel()

	s := newTestStore()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Producer goroutines: 100 workers hitting the hot path.
	const nProducers = 100
	for i := 0; i < nProducers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			keyID := "race-key-" + itoa(workerID%10)       // shared keys
			tenantID := "race-tenant-" + itoa(workerID%10) // shared tenants
			for {
				select {
				case <-stop:
					return
				default:
					s.CheckKey(keyID, 1000, 1000)
					s.CheckTenant(tenantID, 1000)
					s.AllowTokens(tenantID, 1, 1000000)
				}
			}
		}(i)
	}

	// Exporter goroutine: continuously snapshots.
	var exportCount atomic.Int32
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.ExportState()
				exportCount.Add(1)
			}
		}
	}()

	// Run for 1 second.
	time.Sleep(1 * time.Second)
	close(stop)
	wg.Wait()

	if exportCount.Load() < 1 {
		t.Fatalf("expected at least one ExportState call to complete, got %d", exportCount.Load())
	}
	t.Logf("ExportState completed %d times under 100-worker hot-path load", exportCount.Load())
}

// ---------- documentation: orphaned-reservation trade-off ----------

// TestRateLimiterImportL8Reservation documents the L-8 trade-off: after
// ImportState replaces the per-key entries map, any outstanding
// rate.Limiter.Reserve reservations from the prior limiter instance
// are silently orphaned. The replacement limiter starts with a full
// bucket (worst case: ~1 RPS extra burst, which the test observes).
//
// This is the accepted trade-off documented in RESEARCH §4
// L-8 and in the ImportState comment block. The test exists to
// surface the behaviour to future maintainers — NOT to demand a fix.
// A reservation-preserving import is NOT possible without upstream
// API changes to golang.org/x/time/rate.
func TestRateLimiterImportL8Reservation(t *testing.T) {
	t.Parallel()

	s := newTestStore()

	// Burn the burst on key "burn".
	allowed, _ := s.CheckKey("burn", 1, 1)
	if !allowed {
		t.Fatalf("setup: first burst request should be allowed")
	}
	// Next request should be denied (burst exhausted).
	allowed, _ = s.CheckKey("burn", 1, 1)
	if allowed {
		t.Fatalf("setup: second immediate request should be denied")
	}

	// Snapshot + Import — this REPLACES the limiter instance, which is
	// the documented L-8 behaviour.
	snap := s.ExportState()
	s.ImportState(snap)

	// After Import, the fresh limiter has a full bucket → request is
	// allowed again. This IS the orphaned-reservation effect: the prior
	// limiter's reservation is gone.
	allowed, _ = s.CheckKey("burn", 1, 1)
	if !allowed {
		t.Errorf("L-8 expected: after ImportState the fresh limiter allows 1 burst-worth of requests. This is documented in RESEARCH §4 — a known trade-off, not a bug.")
	}

	// This test PASSES — its purpose is to fail LOUDLY if a future
	// refactor inadvertently preserves the prior limiter (e.g. by
	// not replacing s.entries wholesale). If you see this test failing
	// after a refactor: either restore the wholesale-replace semantics
	// OR update this test to reflect the new (preserving) semantics.
}

// ---------- Cleanup compatibility ----------

// TestRateLimiterCleanupCompat verifies the existing Cleanup goroutine
// continues to run alongside the new Export/Import API without deadlock
// or data race. Runs both for ~200ms (short enough to keep test fast,
// long enough to interleave operations).
func TestRateLimiterCleanupCompat(t *testing.T) {
	t.Parallel()

	s := newTestStore()
	for i := 0; i < 20; i++ {
		s.CheckKey("compat-key-"+itoa(i), 100, 100)
		s.AllowTokens("compat-tenant-"+itoa(i), 5, 1000000)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Cleanup-style operation: call doCleanup repeatedly (the production
	// Cleanup goroutine sleeps on a 1-minute ticker, which is impractical
	// for a unit test).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.doCleanup()
			}
		}
	}()

	// Concurrent ExportState calls.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.ExportState()
			}
		}
	}()

	// Concurrent ImportState calls (replays a fixed snapshot).
	fixed := s.ExportState()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.ImportState(fixed)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ---------- ExportDelta progress semantics ----------

// TestRateLimiterExportDeltaProgress verifies that ExportDelta only
// emits tenants whose Consumed has increased since the prev snapshot.
func TestRateLimiterExportDeltaProgress(t *testing.T) {
	t.Parallel()

	s := newTestStore()
	s.AllowTokens("ed-t1", 50, 1000000)
	s.AllowTokens("ed-t2", 75, 1000000)

	// First export: prev empty → both tenants reported.
	prev := map[string]int64{}
	d1 := s.ExportDelta(prev)
	if len(d1) != 2 {
		t.Fatalf("first ExportDelta: expected 2 entries, got %d", len(d1))
	}

	// Update prev from d1's reported absolutes. The caller (coordinator)
	// tracks BOTH the "t:<id>" consumed value AND the "e:<id>" epoch so
	// the next ExportDelta can short-circuit when neither has advanced.
	for _, e := range d1 {
		prev[e.KeyID] = e.Consumed
		prev["e:"+e.KeyID[2:]] = e.WindowEpoch
	}

	// Second export with no further activity → empty delta.
	d2 := s.ExportDelta(prev)
	if len(d2) != 0 {
		t.Fatalf("second ExportDelta (no activity): expected 0 entries, got %d", len(d2))
	}

	// Bump only ed-t1; delta should contain ed-t1 only.
	s.AllowTokens("ed-t1", 25, 1000000)
	d3 := s.ExportDelta(prev)
	if len(d3) != 1 {
		t.Fatalf("third ExportDelta (one tenant bumped): expected 1 entry, got %d", len(d3))
	}
	if d3[0].KeyID != "t:ed-t1" {
		t.Errorf("third ExportDelta: expected ed-t1, got %s", d3[0].KeyID)
	}
}

// ---------- Tiny helpers ----------

// itoa avoids importing strconv for a one-line conversion in test names.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
