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
		src.AllowTokens(tenantID, 10+i, 100000, 0) // large budget so no exceed
	}
	// Push one tenant deep into debt to verify the state round-trips: a
	// full-burst charge plus a 10% overrun (6s of drain — comfortably
	// larger than the test's runtime, so the debt cannot self-heal before
	// the assertions run).
	src.AllowTokens("rt-tenant-exceeded", 1000000, 1000000, 0)
	src.AllowTokens("rt-tenant-exceeded", 100000, 1000000, 0)

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

	// Per-key rows are NOT installed by the import, and this assertion was
	// corrected rather than relaxed. It used to require dst to hold every
	// source key with matching (rps, burst, lastAccess) — a contract the
	// wire cannot honour: the proto RateLimiterEntry has no rate and no
	// burst field, so across a real RateLimiterSync those two always
	// arrive as zero and the rebuilt limiter is discarded by `check` on
	// its next call. What the install actually did was hand the receiver's
	// own live buckets a fresh full burst on every snapshot. Passing the
	// Go struct straight from Export to Import is what hid that: the test
	// never crossed the wire the product uses.
	src.mu.Lock()
	nSrcEntries := len(src.entries)
	src.mu.Unlock()
	if nSrcEntries != nKeys {
		t.Fatalf("setup: expected %d per-key entries on src, got %d", nKeys, nSrcEntries)
	}

	dst.mu.Lock()
	nDstEntries := len(dst.entries)
	dst.mu.Unlock()
	if nDstEntries != 0 {
		t.Errorf("expected the import to leave the receiver's per-key map alone, got %d entries", nDstEntries)
	}

	// The receiver's own per-key enforcement must survive a snapshot: a
	// bucket it has already spent is still spent afterwards.
	if ok, _ := dst.CheckKey("rt-local-key", 1, 1); !ok {
		t.Fatalf("setup: the receiver's first request must be admitted")
	}
	if ok, _ := dst.CheckKey("rt-local-key", 1, 1); ok {
		t.Fatalf("setup: the receiver's burst must be spent")
	}
	dst.ImportState(snap)
	if ok, _ := dst.CheckKey("rt-local-key", 1, 1); ok {
		t.Error("a peer snapshot refilled the receiver's own per-key bucket")
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
	dst.AllowTokens("rt-tenant-exceeded", 1, 1000000, 0) // publish the limit
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
	s.AllowTokens(tenantA, 100, 1000000, 0)

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
	s.AllowTokens(tenantB, 100, 1000000, 0)
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
	src.AllowTokens("wk-tenant", 10, 100000, 0)
	src.AllowTokens("wk-tenant|llama-3", 20, 100000, 0)

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
					s.AllowTokens(tenantID, 1, 1000000, 0)
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

// ---------- the per-key half of an absolute snapshot ----------

// TestRateLimiterImportKeepsLocalBuckets pins the receiving side of I-2: an
// absolute snapshot merges quota state and must leave the receiver's own
// per-key rate limiters untouched.
//
// This assertion is the inverse of the one it replaces. That one required
// the post-import bucket to be FULL again and called it the documented L-8
// orphaned-reservation trade-off, priced at "~1 RPS extra burst per replaced
// key". Two things were wrong with treating that as acceptable. The price
// was per-import, not one-off — in A-A mode every tenth push is an absolute
// snapshot, so a node serving traffic was re-zeroed on that cadence. And
// there was nothing on the other side of the trade: the proto message has
// no rate and no burst field, so the replacement limiters were built from
// zeros and thrown away by `check` on first use. The import could only
// refill the receiver's live limits, never restore the sender's.
func TestRateLimiterImportKeepsLocalBuckets(t *testing.T) {
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

	snap := s.ExportState()
	s.ImportState(snap)

	allowed, _ = s.CheckKey("burn", 1, 1)
	if allowed {
		t.Error("a snapshot import refilled a per-key bucket the local rate limit had already refused")
	}

	// Non-vacuous: the same import still merges quota state, so a failure
	// above cannot be an import that quietly did nothing at all.
	s.AllowTokens("import-live-tenant", 1000000, 1000000, 0)
	s.AllowTokens("import-live-tenant", 100000, 1000000, 0)
	dst := newTestStore()
	dst.AllowTokens("import-live-tenant", 1, 1000000, 0) // publish the limit
	dst.ImportState(s.ExportState())
	if !dst.IsTokenQuotaExceeded("import-live-tenant") {
		t.Error("control: the import no longer carries tenant quota debt either")
	}
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
		s.AllowTokens("compat-tenant-"+itoa(i), 5, 1000000, 0)
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
	s.AllowTokens("ed-t1", 50, 1000000, 0)
	s.AllowTokens("ed-t2", 75, 1000000, 0)

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
	s.AllowTokens("ed-t1", 25, 1000000, 0)
	d3 := s.ExportDelta(prev)
	if len(d3) != 1 {
		t.Fatalf("third ExportDelta (one tenant bumped): expected 1 entry, got %d", len(d3))
	}
	if d3[0].KeyID != "t:ed-t1" {
		t.Errorf("third ExportDelta: expected ed-t1, got %s", d3[0].KeyID)
	}
}

// ---------- Cold-start warmup ----------

// warmupProbe arms a store's cold-start warmup and reports what the
// callback saw. The callback is the node's ONLY outward signal here — the
// cold-open counter and the log line both hang off it — so the test reads
// it rather than the warm flag alone.
type warmupProbe struct {
	store    *RateLimiterStore
	fired    atomic.Int32
	failOpen atomic.Int32
}

func newWarmupProbe(timeout time.Duration) *warmupProbe {
	p := &warmupProbe{store: newTestStore()}
	p.store.StartQuotaWarmup(timeout, func(failOpen bool) {
		p.fired.Add(1)
		if failOpen {
			p.failOpen.Add(1)
		}
	})
	return p
}

// quotaRow is one tenant row shaped like a peer's snapshot entry: a drain
// time well ahead of now, which is what "this tenant has spent" looks like
// on the wire.
func quotaRow(tenant string) RateLimiterEntry {
	return RateLimiterEntry{
		KeyID:       "t:" + tenant,
		IsTenant:    true,
		WindowEpoch: currentQuotaEpoch.Load(),
		Consumed:    quotaNowMs.Load() + 30_000,
	}
}

// TestColdWarmupNeedsQuotaStateNotJustABatch — a node that came up cold
// holds quota-limited admissions until a peer re-teaches it. What counts as
// "re-taught" is the point of this test.
//
// A snapshot does not arrive whole. sendRateLimiterBatch chunks it, each
// chunk is an independent ImportState, and the store's own ExportState
// walks the keyed limiter table before it appends a single quota row. A
// gateway with more keyed limiters than the chunk ceiling therefore
// delivers a first chunk in which every row is one the merge path skips.
//
// Ending the warmup there is worse than early: the callback reports
// failOpen=false, so the cold-open counter stays at zero and the log says
// "warmed from peer state". The node is serving a cold quota window and the
// one series an operator watches for exactly that says it is not.
//
// The control is the same call with one tenant row in it. Without it, "the
// warmup is still running" is equally well explained by a warmup that
// nothing can end.
func TestColdWarmupNeedsQuotaStateNotJustABatch(t *testing.T) {
	t.Parallel()

	keyRows := []RateLimiterEntry{
		{KeyID: "k:key-a", IsTenant: false},
		{KeyID: "u:acme|bob", IsTenant: false},
	}

	t.Run("snapshot chunk carrying no quota row", func(t *testing.T) {
		t.Parallel()
		p := newWarmupProbe(time.Hour)
		p.store.ImportState(keyRows)
		if !p.store.QuotaWarming() {
			t.Error("a snapshot chunk that merged no quota state ended the cold-start warmup: " +
				"the node stopped holding quota-limited admissions having been taught nothing")
		}
		if got := p.fired.Load(); got != 0 {
			t.Errorf("the warmup callback fired %d times on a chunk that taught the node nothing; "+
				"it reports failOpen=false, so the cold-open counter never records the cold window", got)
		}
	})

	t.Run("gossip delta carrying no quota row", func(t *testing.T) {
		t.Parallel()
		p := newWarmupProbe(time.Hour)
		p.store.ApplyGossipDelta(keyRows)
		if !p.store.QuotaWarming() {
			t.Error("a gossip batch that merged no quota state ended the cold-start warmup")
		}
	})

	t.Run("rows the merge path cannot place", func(t *testing.T) {
		t.Parallel()
		// IsTenant is the sender's claim, not a fact: the scope sentinel
		// rides the wire with it set, and any row whose prefix this build
		// does not know lands here too. mergeQuotaEntry drops both. A
		// batch made entirely of them taught this node nothing either.
		p := newWarmupProbe(time.Hour)
		p.store.ImportState([]RateLimiterEntry{
			{KeyID: ScopeSentinelKeyID, IsTenant: true},
			{KeyID: "zz:from-a-newer-build", IsTenant: true},
		})
		if !p.store.QuotaWarming() {
			t.Error("a batch of rows the merge path could not place ended the cold-start warmup")
		}
	})

	t.Run("control: one quota row ends it", func(t *testing.T) {
		t.Parallel()
		p := newWarmupProbe(time.Hour)
		p.store.ImportState(append(append([]RateLimiterEntry{}, keyRows...), quotaRow("acme")))
		if p.store.QuotaWarming() {
			t.Fatal("control failed: a batch with a real quota row did not end the warmup, " +
				"so the results above prove nothing about which batches end it")
		}
		if got, want := p.fired.Load(), int32(1); got != want {
			t.Fatalf("control: warmup callback fired %d times, want %d", got, want)
		}
		if got := p.failOpen.Load(); got != 0 {
			t.Errorf("control: warmup ended with failOpen=%d, want 0 — state DID arrive", got)
		}
	})

	t.Run("control: the deadline still ends it, honestly", func(t *testing.T) {
		t.Parallel()
		// The fix must not turn "wait for state" into "wait forever": a
		// node that is never taught has to fall through to the fail-open
		// window and SAY so.
		p := newWarmupProbe(50 * time.Millisecond)
		p.store.ImportState(keyRows)
		deadline := time.Now().Add(5 * time.Second)
		for p.fired.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if got := p.fired.Load(); got != 1 {
			t.Fatalf("warmup callback fired %d times after the deadline passed, want 1", got)
		}
		if got := p.failOpen.Load(); got != 1 {
			t.Errorf("the deadline ended the warmup with failOpen=%d, want 1 — "+
				"no peer state ever arrived and the cold window must be recorded", got)
		}
		if p.store.QuotaWarming() {
			t.Error("the store is still warming after its deadline expired")
		}
	})
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
