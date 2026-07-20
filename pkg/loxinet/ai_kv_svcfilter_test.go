/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// service-identity filter + zero-hit watchdog
// tests. These drive kvSvcScanInventories — the pure-Go scan core extracted
// from the llb_ai_kv_best_worker CGO export (helper-extraction
// precedent) — plus kvZeroHitWatchdog/kvZeroHitN directly.
//
// Remote gate:
//
//	go test ./pkg/loxinet/ -run 'TestKvSvcFilter|TestKvZeroHit' -count=1
package loxinet

import (
	"strings"
	"testing"
)

// countOf returns how many captured log entries contain sub (companion to the
// kvLogCapture.contains — one-shot WARN assertion needs an
// exact occurrence COUNT, not mere presence).
func (c *kvLogCapture) countOf(sub string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.entries {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// kvSeedSvc builds a kvServiceState with the given per-EP inventories
// (epIdx -> block hashes). Blocks are seeded directly into the inventory set
// (MatchCount/Size read only inv.blocks; the LRU bookkeeping is irrelevant to
// the selector scan under test).
func kvSeedSvc(id uint32, invs map[int][]uint64) *kvServiceState {
	svc := newKvServiceState(id)
	for epIdx, hashes := range invs {
		inv := newKvInventory()
		for _, h := range hashes {
			inv.blocks[h] = struct{}{}
		}
		svc.inventories[epIdx] = inv
	}
	return svc
}

// withKvServices swaps the global registry for the test's fixture and restores
// it on cleanup (the registry is package-global; tests in this package run
// sequentially against it, seeding precedent).
func withKvServices(t *testing.T, svcs map[uint32]*kvServiceState) {
	t.Helper()
	kvServicesMu.Lock()
	old := kvServices
	kvServices = svcs
	kvServicesMu.Unlock()
	t.Cleanup(func() {
		kvServicesMu.Lock()
		kvServices = old
		kvServicesMu.Unlock()
	})
}

// withKvZeroHitCounter swaps the Prometheus counter seam for a recording stub
// and restores it on cleanup. Returns the per-service occurrence counts.
func withKvZeroHitCounter(t *testing.T) map[uint32]*int {
	t.Helper()
	counts := make(map[uint32]*int)
	old := kvZeroHitCounterFn
	kvZeroHitCounterFn = func(svcID uint32) {
		if p, ok := counts[svcID]; ok {
			*p++
			return
		}
		n := 1
		counts[svcID] = &n
	}
	t.Cleanup(func() { kvZeroHitCounterFn = old })
	return counts
}

func kvZeroHitCountFor(counts map[uint32]*int, svcID uint32) int {
	if p, ok := counts[svcID]; ok {
		return *p
	}
	return 0
}

// ---------- SGL-04 service-identity filter ----------

// TestKvSvcFilterScopedSelection is the cross-VIP contamination regression
// (RESEARCH): two services with overlapping content — a svcID-scoped
// scan must score ONLY that service's inventories, even when the OTHER
// service's inventory has strictly higher overlap. Without the filter, service
// B's epIdx (valid only in B's EP space) would win A's lookup.
func TestKvSvcFilterScopedSelection(t *testing.T) {
	h1, h2, h3 := uint64(0xa1), uint64(0xa2), uint64(0xa3)
	svcA := kvSeedSvc(7, map[int][]uint64{0: {h1}})         // overlap 1 on ep0
	svcB := kvSeedSvc(9, map[int][]uint64{1: {h1, h2, h3}}) // overlap 3 on ep1
	withKvServices(t, map[uint32]*kvServiceState{7: svcA, 9: svcB})
	hashes := []uint64{h1, h2, h3}
	mask := uint32(0x3) // ep0 + ep1 both eligible

	// svcID=7: A's ep0 must win with its overlap of 1 — B's higher-overlap
	// ep1 must NOT be reachable.
	bestEp, bestScore, _, _, _ := kvSvcScanInventories(7, hashes, mask, 0, nil, nil, nil, false, false)
	if bestEp != 0 || bestScore != 1 {
		t.Fatalf("svcID=7 scoped scan: got (ep=%d score=%d), want (ep=0 score=1) — cross-VIP contamination (B's inventory leaked into A's lookup)",
			bestEp, bestScore)
	}

	// svcID=9: B's ep1 wins with overlap 3.
	bestEp, bestScore, _, _, _ = kvSvcScanInventories(9, hashes, mask, 0, nil, nil, nil, false, false)
	if bestEp != 1 || bestScore != 3 {
		t.Fatalf("svcID=9 scoped scan: got (ep=%d score=%d), want (ep=1 score=3)", bestEp, bestScore)
	}
}

// TestKvSvcFilterLegacyAllServices regression-locks the svcID==0 seam: the
// legacy all-services cross-service scoring is preserved byte-for-byte (the
// default-off proof — legacy/uninitialized C structs pass 0 and behave as
// today).
func TestKvSvcFilterLegacyAllServices(t *testing.T) {
	h1, h2, h3 := uint64(0xb1), uint64(0xb2), uint64(0xb3)
	svcA := kvSeedSvc(7, map[int][]uint64{0: {h1}})
	svcB := kvSeedSvc(9, map[int][]uint64{1: {h1, h2, h3}})
	withKvServices(t, map[uint32]*kvServiceState{7: svcA, 9: svcB})
	hashes := []uint64{h1, h2, h3}

	// svcID=0: today's cross-service argmax — B's ep1 (overlap 3) wins.
	bestEp, bestScore, _, _, _ := kvSvcScanInventories(0, hashes, 0x3, 0, nil, nil, nil, false, false)
	if bestEp != 1 || bestScore != 3 {
		t.Fatalf("svcID=0 legacy scan: got (ep=%d score=%d), want (ep=1 score=3) — legacy all-services behavior drifted",
			bestEp, bestScore)
	}

	// Mask/exclusion still honored on the legacy path: excluding ep1 leaves
	// A's ep0 as the argmax.
	bestEp, bestScore, _, _, _ = kvSvcScanInventories(0, hashes, 0x3, 0x2, nil, nil, nil, false, false)
	if bestEp != 0 || bestScore != 1 {
		t.Fatalf("svcID=0 legacy scan with ep1 excluded: got (ep=%d score=%d), want (ep=0 score=1)",
			bestEp, bestScore)
	}
}

// TestKvSvcFilterUnknownSvcMiss: a non-zero svcID with no registered service
// is a Tier-1.5 miss (nil scan target set) — never a fall-through to the
// all-services loop.
func TestKvSvcFilterUnknownSvcMiss(t *testing.T) {
	h1 := uint64(0xc1)
	svcB := kvSeedSvc(9, map[int][]uint64{1: {h1}})
	withKvServices(t, map[uint32]*kvServiceState{9: svcB})

	bestEp, bestScore, cands, fleetCands, totalLoad := kvSvcScanInventories(
		5, []uint64{h1}, 0x3, 0, nil, nil, nil, true, true)
	if bestEp != -1 || bestScore != 0 {
		t.Fatalf("unknown svcID=5: got (ep=%d score=%d), want miss (ep=-1 score=0)", bestEp, bestScore)
	}
	if len(cands) != 0 || len(fleetCands) != 0 || totalLoad != 0 {
		t.Fatalf("unknown svcID=5: candidate sets must stay empty (cands=%d fleet=%d totalLoad=%d)",
			len(cands), len(fleetCands), totalLoad)
	}
}

// ---------- zero-hit watchdog ----------

// TestKvZeroHitWatchdogWarnOnceAndCounter pins transition shape at
// the default threshold N=50: 100 consecutive zero-hit lookups fire EXACTLY
// one WARN (the edge) and 51 counter increments (streaks 50..100 inclusive —
// every occurrence at-or-past the threshold); a single hit resets the streak
// and re-arms the one-shot WARN.
func TestKvZeroHitWatchdogWarnOnceAndCounter(t *testing.T) {
	svc := newKvServiceState(3)
	counts := withKvZeroHitCounter(t)
	capt, restore := installKvLogCapture()
	defer restore()

	for i := 0; i < 100; i++ {
		kvZeroHitWatchdog(3, svc, true, 0, 128)
	}
	if got := capt.countOf("[KV_ZEROHIT] service 3:"); got != 1 {
		t.Fatalf("WARN fired %d times across 100 zero-hit lookups; want exactly 1 (transition edge log-flood guard)", got)
	}
	if got := kvZeroHitCountFor(counts, 3); got != 51 {
		t.Fatalf("counter=%d after 100 zero-hits at N=50; want 51 (occurrences at-or-past threshold)", got)
	}

	// A single hit resets the streak and re-arms the WARN.
	kvZeroHitWatchdog(3, svc, true, 2, 128)
	svc.mu.RLock()
	streak, warned := svc.zeroHitStreak, svc.zeroHitWarned
	svc.mu.RUnlock()
	if streak != 0 || warned {
		t.Fatalf("hit did not reset/re-arm: streak=%d warned=%v, want 0/false", streak, warned)
	}
	if got := kvZeroHitCountFor(counts, 3); got != 51 {
		t.Fatalf("hit must not increment the counter: got %d, want 51", got)
	}

	// The next 50 zero-hits cross the threshold again: a SECOND WARN (re-armed
	// edge) and one more counter increment.
	for i := 0; i < 50; i++ {
		kvZeroHitWatchdog(3, svc, true, 0, 128)
	}
	if got := capt.countOf("[KV_ZEROHIT] service 3:"); got != 2 {
		t.Fatalf("WARN count after re-arm cycle = %d, want 2 (one per transition)", got)
	}
	if got := kvZeroHitCountFor(counts, 3); got != 52 {
		t.Fatalf("counter=%d after re-arm cycle, want 52", got)
	}
}

// TestKvZeroHitWatchdogEnvTunable: LOXILB_KV_ZERO_HIT_N parse-or-default —
// valid overrides apply; invalid/zero/negative fall back to 50 and can NEVER
// disable the watchdog.
func TestKvZeroHitWatchdogEnvTunable(t *testing.T) {
	t.Setenv("LOXILB_KV_ZERO_HIT_N", "3")
	if got := kvZeroHitN(); got != 3 {
		t.Fatalf("kvZeroHitN with env=3: got %d, want 3", got)
	}

	svc := newKvServiceState(4)
	counts := withKvZeroHitCounter(t)
	capt, restore := installKvLogCapture()
	defer restore()

	for i := 0; i < 3; i++ {
		kvZeroHitWatchdog(4, svc, true, 0, 16)
	}
	if got := capt.countOf("[KV_ZEROHIT] service 4:"); got != 1 {
		t.Fatalf("WARN at tuned N=3: fired %d times after 3 zero-hits, want 1", got)
	}
	if got := kvZeroHitCountFor(counts, 4); got != 1 {
		t.Fatalf("counter at tuned N=3: got %d after 3 zero-hits, want 1", got)
	}

	for _, bad := range []string{"abc", "0", "-5", "1.5"} {
		t.Setenv("LOXILB_KV_ZERO_HIT_N", bad)
		if got := kvZeroHitN(); got != kvZeroHitNDefault {
			t.Fatalf("kvZeroHitN with invalid env %q: got %d, want default %d (never disabled)",
				bad, got, kvZeroHitNDefault)
		}
	}
}

// TestKvZeroHitWatchdogEmptyInventoryNoOp: an empty/ineligible inventory is an
// EXPECTED miss, not a parity signal — the watchdog must neither grow the
// streak nor WARN nor count.
func TestKvZeroHitWatchdogEmptyInventoryNoOp(t *testing.T) {
	svc := newKvServiceState(6)
	counts := withKvZeroHitCounter(t)
	capt, restore := installKvLogCapture()
	defer restore()

	for i := 0; i < 100; i++ {
		kvZeroHitWatchdog(6, svc, false, 0, 0)
	}
	svc.mu.RLock()
	streak := svc.zeroHitStreak
	svc.mu.RUnlock()
	if streak != 0 {
		t.Fatalf("empty-inventory lookups grew the streak to %d, want 0", streak)
	}
	if got := capt.countOf("[KV_ZEROHIT] service 6:"); got != 0 {
		t.Fatalf("empty-inventory lookups fired %d WARNs, want 0", got)
	}
	if got := kvZeroHitCountFor(counts, 6); got != 0 {
		t.Fatalf("empty-inventory lookups incremented the counter %d times, want 0", got)
	}
}

// TestKvZeroHitWatchdogPerServiceViaScan drives the REAL exit path end-to-end
// through kvSvcScanInventories: in a legacy svcID==0 scan a matching service
// (A) keeps resetting while a broken one (B, non-empty inventory that never
// matches — the page-size-mismatch shape) accumulates its OWN streak; the WARN
// and counter are labeled with B's service ID only (engine-agnostic,
// per-service). A scoped svcID=A scan never touches B's streak.
func TestKvZeroHitWatchdogPerServiceViaScan(t *testing.T) {
	t.Setenv("LOXILB_KV_ZERO_HIT_N", "5")
	h1 := uint64(0xd1)
	svcA := kvSeedSvc(11, map[int][]uint64{0: {h1}})     // always matches
	svcB := kvSeedSvc(12, map[int][]uint64{1: {0xffff}}) // non-empty, never matches
	withKvServices(t, map[uint32]*kvServiceState{11: svcA, 12: svcB})
	counts := withKvZeroHitCounter(t)
	capt, restore := installKvLogCapture()
	defer restore()

	for i := 0; i < 5; i++ {
		kvSvcScanInventories(0, []uint64{h1}, 0x3, 0, nil, nil, nil, false, false)
	}

	svcA.mu.RLock()
	streakA := svcA.zeroHitStreak
	svcA.mu.RUnlock()
	svcB.mu.RLock()
	streakB := svcB.zeroHitStreak
	svcB.mu.RUnlock()
	if streakA != 0 {
		t.Fatalf("matching service A streak=%d, want 0 (per-service reset — another service's zero-hit must not taint A)", streakA)
	}
	if streakB != 5 {
		t.Fatalf("broken service B streak=%d, want 5 (another service's HIT must not mask B's zero-streak)", streakB)
	}
	if got := capt.countOf("[KV_ZEROHIT] service 12:"); got != 1 {
		t.Fatalf("B's WARN fired %d times, want 1", got)
	}
	if got := capt.countOf("[KV_ZEROHIT] service 11:"); got != 0 {
		t.Fatalf("A must not WARN (got %d)", got)
	}
	if got := kvZeroHitCountFor(counts, 12); got != 1 {
		t.Fatalf("B's counter=%d, want 1 (threshold occurrence)", got)
	}
	if got := kvZeroHitCountFor(counts, 11); got != 0 {
		t.Fatalf("A's counter=%d, want 0", got)
	}

	// Scoped scan for A leaves B's watchdog state untouched.
	kvSvcScanInventories(11, []uint64{h1}, 0x3, 0, nil, nil, nil, false, false)
	svcB.mu.RLock()
	streakB2 := svcB.zeroHitStreak
	svcB.mu.RUnlock()
	if streakB2 != 5 {
		t.Fatalf("scoped svcID=11 scan mutated B's streak (%d -> %d)", streakB, streakB2)
	}
}
