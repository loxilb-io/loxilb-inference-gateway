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

// ai_kv_inventory_robustness_test.go — memory-safety units.
//
// Locks the per-EP KV inventory cap + FIFO eviction, the cap-hit
// observability counter and the block-count accounting accuracy
// (TK11). Pure Go, no CGO — run with:
//
//   go test ./pkg/loxinet -run 'TestKvInventoryCap|TestKvEvictionFIFO|TestKvCapHitCounter|TestKvBlocksAccounting' -count=1
//
// Isolation idiom mirrors ai_kv_subscriber_admin_test.go: KvResetAll at the
// top + defer KvResetAll.

package loxinet

import (
	"testing"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
)

// TestKvInventoryCap: adding far more than maxBlocks hashes must never
// let len(blocks) exceed the cap — the inventory is bounded regardless of how
// much a misbehaving publisher floods.
func TestKvInventoryCap(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	inv := newKvInventory()
	inv.maxBlocks = 100 // small test cap (default is kvMaxBlocksDefault)

	// Flood 10x the cap, in batches, all distinct.
	for batch := 0; batch < 10; batch++ {
		hashes := make([]uint64, 100)
		for i := range hashes {
			hashes[i] = uint64(batch*100 + i + 1) // +1 so no hash is 0
		}
		inv.AddBlocks(hashes)
		if got := inv.Size(); got > inv.maxBlocks {
			t.Fatalf("after batch %d: Size()=%d exceeds cap=%d", batch, got, inv.maxBlocks)
		}
	}

	if got := inv.Size(); got != inv.maxBlocks {
		t.Fatalf("after flood: Size()=%d, want exactly cap=%d", got, inv.maxBlocks)
	}
}

// TestKvEvictionFIFO: once the cap is exceeded, the OLDEST-inserted
// blocks are evicted first and the NEWEST blocks are retained. Asserted via
// MatchCount — oldest gone (0), newest present (full).
func TestKvEvictionFIFO(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	inv := newKvInventory()
	inv.maxBlocks = 10

	oldest := []uint64{1, 2, 3, 4, 5}      // inserted first → should be evicted
	middle := []uint64{6, 7, 8, 9, 10}     // straddle
	newest := []uint64{11, 12, 13, 14, 15} // inserted last → should survive

	inv.AddBlocks(oldest)
	inv.AddBlocks(middle)
	inv.AddBlocks(newest) // total 15 > cap 10 → evict 5 oldest

	if got := inv.Size(); got != 10 {
		t.Fatalf("Size()=%d, want 10 (cap)", got)
	}

	// All 5 oldest must be gone.
	if got := inv.MatchCount(oldest); got != 0 {
		t.Errorf("oldest blocks still present: MatchCount(oldest)=%d, want 0", got)
	}
	// All 5 newest must be present.
	if got := inv.MatchCount(newest); got != len(newest) {
		t.Errorf("newest blocks evicted: MatchCount(newest)=%d, want %d", got, len(newest))
	}
	// Middle survives (inserted after oldest, before the overflow line).
	if got := inv.MatchCount(middle); got != len(middle) {
		t.Errorf("middle blocks evicted: MatchCount(middle)=%d, want %d", got, len(middle))
	}
}

// TestKvEvictionFIFO_NoDoubleAppend: re-storing an already-present hash
// must NOT consume a second cap slot or double-append to the ordering structure
// (otherwise a publisher re-announcing the same block would wrongly evict live
// blocks).
func TestKvEvictionFIFO_NoDoubleAppend(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	inv := newKvInventory()
	inv.maxBlocks = 3

	inv.AddBlocks([]uint64{1, 2, 3}) // full at cap
	// Re-store 1 repeatedly — must not evict 2 or 3 and must not grow.
	inv.AddBlocks([]uint64{1})
	inv.AddBlocks([]uint64{1})
	inv.AddBlocks([]uint64{1})

	if got := inv.Size(); got != 3 {
		t.Fatalf("Size()=%d after re-storing existing hash, want 3", got)
	}
	if got := inv.MatchCount([]uint64{1, 2, 3}); got != 3 {
		t.Errorf("re-store evicted live blocks: MatchCount(1,2,3)=%d, want 3", got)
	}

	// Now a genuinely-new hash should evict the oldest (1), since 1's ordering
	// position was never refreshed by the re-stores.
	inv.AddBlocks([]uint64{4})
	if got := inv.Size(); got != 3 {
		t.Fatalf("Size()=%d after one new insert at cap, want 3", got)
	}
	if got := inv.MatchCount([]uint64{1}); got != 0 {
		t.Errorf("oldest (1) not evicted after re-stores: MatchCount(1)=%d, want 0", got)
	}
	if got := inv.MatchCount([]uint64{2, 3, 4}); got != 3 {
		t.Errorf("expected {2,3,4} retained: MatchCount=%d, want 3", got)
	}
}

// TestKvCapHitCounter: the cap-hit eviction counter stays at its
// baseline on a healthy under-cap run and increases by exactly the number of
// evicted blocks on a deliberate overflow. The prometheus counter is process-
// global (KvResetAll does not reset it), so the test uses unique (service, ep)
// labels and asserts deltas.
func TestKvCapHitCounter(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	// --- healthy run: under cap, counter must not move ---
	const svcHealthy, epHealthy = "82001", "0"
	healthy := newKvInventory()
	healthy.maxBlocks = 100
	healthy.svcLabel, healthy.epLabel = svcHealthy, epHealthy

	before := prom.KvInventoryCapHitValue(svcHealthy, epHealthy)
	healthy.AddBlocks([]uint64{1, 2, 3, 4, 5}) // 5 << cap → no eviction
	if got := prom.KvInventoryCapHitValue(svcHealthy, epHealthy); got != before {
		t.Errorf("healthy run moved cap-hit counter: before=%v after=%v, want unchanged", before, got)
	}

	// --- overflow run: counter increases by exactly #evicted ---
	const svcOver, epOver = "82001", "1"
	over := newKvInventory()
	over.maxBlocks = 10
	over.svcLabel, over.epLabel = svcOver, epOver

	start := prom.KvInventoryCapHitValue(svcOver, epOver)
	hashes := make([]uint64, 25) // 25 - 10 cap = 15 evictions
	for i := range hashes {
		hashes[i] = uint64(1000 + i)
	}
	over.AddBlocks(hashes)
	if got := prom.KvInventoryCapHitValue(svcOver, epOver); got != start+15 {
		t.Errorf("cap-hit counter delta wrong: start=%v after=%v, want +15", start, got)
	}
	if got := over.Size(); got != 10 {
		t.Errorf("Size()=%d after overflow, want 10 (cap)", got)
	}
}

// TestKvBlocksAccounting (TK11): Size tracks the true inventory size through
// add / remove / clear / evict — the block-count surface never drifts from the
// real set even during cap-hit bursts.
func TestKvBlocksAccounting(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	inv := newKvInventory()
	inv.maxBlocks = 10

	// add
	inv.AddBlocks([]uint64{1, 2, 3})
	if got := inv.Size(); got != 3 {
		t.Fatalf("after add: Size()=%d, want 3", got)
	}
	// remove
	inv.RemoveBlocks([]uint64{2})
	if got := inv.Size(); got != 2 {
		t.Fatalf("after remove: Size()=%d, want 2", got)
	}
	// add more up to cap
	inv.AddBlocks([]uint64{4, 5, 6, 7, 8, 9, 10, 11}) // now {1,3,4..11} = 10
	if got := inv.Size(); got != 10 {
		t.Fatalf("after fill: Size()=%d, want 10 (cap)", got)
	}
	// evict: push over cap → Size stays pinned at cap
	inv.AddBlocks([]uint64{12, 13, 14})
	if got := inv.Size(); got != 10 {
		t.Fatalf("after evict: Size()=%d, want 10 (cap)", got)
	}
	// clear
	inv.ClearAll()
	if got := inv.Size(); got != 0 {
		t.Fatalf("after clear: Size()=%d, want 0", got)
	}
	// re-add after clear must work (ordering structure was reset, not leaked)
	inv.AddBlocks([]uint64{100, 200})
	if got := inv.Size(); got != 2 {
		t.Fatalf("after re-add post-clear: Size()=%d, want 2", got)
	}
	if got := inv.MatchCount([]uint64{100, 200}); got != 2 {
		t.Errorf("re-added blocks missing: MatchCount=%d, want 2", got)
	}
}
