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
 *                                         bucket state byte-for-byte.
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
 *                                         whose bucket drain time has
 *                                         advanced since the prev snapshot.
 *   TestRateLimiterEpochAdvance         — activity epoch and drain time
 *                                         max-merge independently; neither
 *                                         ever moves backward on receive.
 *   TestRateLimiterModelScopeWireKeys   — "tm:<tenant>|<model>" entries
 *                                         round-trip the wire prefix.
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

	// Populate 50 tenant quotas with varied charge amounts.
	const nTenants = 50
	for i := 0; i < nTenants; i++ {
		tenantID := "rt-tenant-" + itoa(i)
		// AllowTokens populates quotaMap and advances the bucket drain time.
		src.AllowTokens(tenantID, 10+i, 100000) // large budget so no exceed
	}
	// Push one tenant deep into debt to verify the state round-trips: a
	// full-burst charge plus a 10% overrun (6s of drain — comfortably
	// larger than the test's runtime, so the debt cannot self-heal before
	// the assertions run).
	src.AllowTokens("rt-tenant-exceeded", 1000000, 1000000)
	src.AllowTokens("rt-tenant-exceeded", 100000, 1000000)

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
		if atomic.LoadInt64(&srcWE.tatMs) != atomic.LoadInt64(&dstWE.tatMs) {
			t.Errorf("tenant %q drain-time mismatch: src=%d dst=%d",
				tenantID,
				atomic.LoadInt64(&srcWE.tatMs),
				atomic.LoadInt64(&dstWE.tatMs))
		}
		if atomic.LoadInt64(&srcWE.windowEpoch) != atomic.LoadInt64(&dstWE.windowEpoch) {
			t.Errorf("tenant %q windowEpoch mismatch: src=%d dst=%d",
				tenantID,
				atomic.LoadInt64(&srcWE.windowEpoch),
				atomic.LoadInt64(&dstWE.windowEpoch))
		}
	}

	// Verify the over-quota state travels with the drain time: the imported
	// entry has no local limit yet (limits are config, not sync state), so
	// the debt becomes visible the moment a local call publishes the limit.
	dstExceededV, ok := dst.quotaMap.Load("rt-tenant-exceeded")
	if !ok {
		t.Fatalf("rt-tenant-exceeded missing from dst.quotaMap")
	}
	srcExceededV, _ := src.quotaMap.Load("rt-tenant-exceeded")
	if got, want := atomic.LoadInt64(&dstExceededV.(*tokenWindowEntry).tatMs),
		atomic.LoadInt64(&srcExceededV.(*tokenWindowEntry).tatMs); got != want {
		t.Errorf("expected debt drain time to round-trip, got %d want %d", got, want)
	}
	dst.AllowTokens("rt-tenant-exceeded", 1, 1000000) // publish the limit
	if !dst.IsTokenQuotaExceeded("rt-tenant-exceeded") {
		t.Error("imported debt must deny on the receiving node once the limit is known")
	}
}

// ---------- Gossip-delta semantics ----------

// TestRateLimiterApplyGossipDelta verifies the max merge rule and
// idempotency under reordered delta messages (RESEARCH §4 "max" rule +
// I-3 invariant).
func TestRateLimiterApplyGossipDelta(t *testing.T) {
	t.Parallel()

	s := newTestStore()

	// Seed local state: one charge establishes the entry and a base drain
	// time; the deltas below are expressed relative to it.
	const tenantA = "tenant_a"
	s.AllowTokens(tenantA, 100, 1000000)

	v, _ := s.quotaMap.Load(tenantA)
	localEpoch := atomic.LoadInt64(&v.(*tokenWindowEntry).windowEpoch)
	base := atomic.LoadInt64(&v.(*tokenWindowEntry).tatMs)

	// Receive higher drain time: should advance.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: base + 5000},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).tatMs); got != base+5000 {
		t.Errorf("after first delta: expected tat=base+5000, got base%+d", got-base)
	}

	// Receive reordered (older) value: max-merge keeps base+5000.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: base + 1000},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).tatMs); got != base+5000 {
		t.Errorf("after reordered (older) delta: expected tat STAYS at base+5000, got base%+d", got-base)
	}

	// Receive identical value: no-op.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: base + 5000},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).tatMs); got != base+5000 {
		t.Errorf("after identical delta: expected tat=base+5000, got base%+d", got-base)
	}

	// Receive higher value again: advances.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantA, IsTenant: true, WindowEpoch: localEpoch, Consumed: base + 9000},
	})
	if got := atomic.LoadInt64(&v.(*tokenWindowEntry).tatMs); got != base+9000 {
		t.Errorf("after second forward delta: expected tat=base+9000, got base%+d", got-base)
	}
}

// TestRateLimiterEpochAdvance verifies the two monotonic fields merge
// INDEPENDENTLY: a newer activity epoch never retracts the drain time (no
// quota refund from a peer that has merely seen less spend), and an older
// epoch does not block a further-advanced drain time from landing.
func TestRateLimiterEpochAdvance(t *testing.T) {
	t.Parallel()

	s := newTestStore()
	const tenantB = "tenant_b"
	s.AllowTokens(tenantB, 100, 1000000)
	v, _ := s.quotaMap.Load(tenantB)
	we := v.(*tokenWindowEntry)
	localEpoch := atomic.LoadInt64(&we.windowEpoch)
	base := atomic.LoadInt64(&we.tatMs)

	// Newer epoch with a LOWER drain time: epoch advances, drain time must
	// NOT move backward — a peer that has seen less spend is not authority
	// to refund quota.
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantB, IsTenant: true, WindowEpoch: localEpoch + 1, Consumed: base - 4},
	})
	if got := atomic.LoadInt64(&we.tatMs); got != base {
		t.Errorf("after newer-epoch delta: drain time must not retract, got base%+d", got-base)
	}
	if got := atomic.LoadInt64(&we.windowEpoch); got != localEpoch+1 {
		t.Errorf("after newer-epoch delta: expected epoch=%d, got %d", localEpoch+1, got)
	}

	// Older epoch with a HIGHER drain time: epoch stays, but the spend
	// still lands (the fields are independent).
	s.ApplyGossipDelta([]RateLimiterEntry{
		{KeyID: "t:" + tenantB, IsTenant: true, WindowEpoch: localEpoch - 10, Consumed: base + 9999},
	})
	if got := atomic.LoadInt64(&we.tatMs); got != base+9999 {
		t.Errorf("after older-epoch delta: expected tat=base+9999, got base%+d", got-base)
	}
	if got := atomic.LoadInt64(&we.windowEpoch); got != localEpoch+1 {
		t.Errorf("after older-epoch delta: expected epoch STAYS at %d, got %d", localEpoch+1, got)
	}
}

// TestRateLimiterModelScopeWireKeys pins the G6 wire convention: composite
// "tenant|model" quota keys export under the "tm:" prefix, round-trip
// through import, and merge into the same composite map key — while plain
// tenant keys keep their "t:" prefix untouched.
func TestRateLimiterModelScopeWireKeys(t *testing.T) {
	t.Parallel()

	src := newTestStore()
	src.AllowTokens("wk-tenant", 10, 100000)
	src.AllowTokens("wk-tenant|llama-3", 20, 100000)

	var sawTenant, sawModel bool
	for _, e := range src.ExportState() {
		switch e.KeyID {
		case "t:wk-tenant":
			sawTenant = true
		case "tm:wk-tenant|llama-3":
			sawModel = true
		}
	}
	if !sawTenant || !sawModel {
		t.Fatalf("expected both t: and tm: wire keys in export (tenant=%v model=%v)", sawTenant, sawModel)
	}

	dst := newTestStore()
	dst.ImportState(src.ExportState())
	if _, ok := dst.quotaMap.Load("wk-tenant"); !ok {
		t.Fatal("plain tenant key lost in round-trip")
	}
	v, ok := dst.quotaMap.Load("wk-tenant|llama-3")
	if !ok {
		t.Fatal("composite tenant|model key lost in round-trip")
	}
	srcV, _ := src.quotaMap.Load("wk-tenant|llama-3")
	if got, want := atomic.LoadInt64(&v.(*tokenWindowEntry).tatMs),
		atomic.LoadInt64(&srcV.(*tokenWindowEntry).tatMs); got != want {
		t.Errorf("composite key drain time mismatch: got %d want %d", got, want)
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
