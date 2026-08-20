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

// Tier-1.5 cold-start seeding tests. These drive kvColdStartSeed — the
// bounded compensation that diverts every Nth per-service Tier-1.5 hit to a
// healthy empty-inventory prefill EP — directly (pure Go, no CGO shim).
//
// Remote gate:
//
//	go test ./pkg/loxinet/ -run 'TestKvColdSeed' -count=1
package loxinet

import (
	"testing"
)


// hashes returns n distinct block hashes — warm fixtures need at least the
// default cold floor (16) to stay warm.
func hashes(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(i + 1)
	}
	return out
}

// coldSeedFixture installs one service (id 7) with the given inventories and
// returns its id. prefillMask/excludedMask are supplied per call site.
func coldSeedFixture(t *testing.T, invs map[int][]uint64) uint32 {
	t.Helper()
	const svcID = uint32(7)
	withKvServices(t, map[uint32]*kvServiceState{svcID: kvSeedSvc(svcID, invs)})
	return svcID
}

// seedSweep calls kvColdStartSeed `calls` times with a fixed context and
// returns the tick indices (1-based) that seeded plus the last seeded EP.
func seedSweep(svcID uint32, prefillMask, excludedMask uint32, bestEp, calls int) (seededAt []int, lastEp int) {
	lastEp = -1
	for i := 1; i <= calls; i++ {
		ep, seeded := kvColdStartSeed(svcID, prefillMask, excludedMask, bestEp)
		if seeded {
			seededAt = append(seededAt, i)
			lastEp = ep
		} else if ep != bestEp {
			// non-seeding calls must return bestEp untouched
			seededAt = append(seededAt, -i)
		}
	}
	return seededAt, lastEp
}

// TestKvColdSeedCadence: ep0 warm, ep1 cold (no inventory entry). With N=4,
// exactly ticks 4 and 8 of 8 divert to ep1; every other call returns the
// original winner untouched.
func TestKvColdSeedCadence(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "4")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	seededAt, lastEp := seedSweep(svcID, 0b11, 0, 0, 8)
	if len(seededAt) != 2 || seededAt[0] != 4 || seededAt[1] != 8 {
		t.Fatalf("expected seeds at ticks [4 8], got %v", seededAt)
	}
	if lastEp != 1 {
		t.Fatalf("expected seed target ep1, got %d", lastEp)
	}
}

// TestKvColdSeedDisabled: explicit N=0 disables the compensation entirely.
func TestKvColdSeedDisabled(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "0")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	if seededAt, _ := seedSweep(svcID, 0b11, 0, 0, 32); len(seededAt) != 0 {
		t.Fatalf("N=0 must never seed, got seeds at %v", seededAt)
	}
}

// TestKvColdSeedNoColdEp: every masked prefill EP has published blocks — the
// tick advances but nothing ever diverts.
func TestKvColdSeedNoColdEp(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "2")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20), 1: hashes(20)})
	if seededAt, _ := seedSweep(svcID, 0b11, 0, 0, 8); len(seededAt) != 0 {
		t.Fatalf("warm fleet must never seed, got seeds at %v", seededAt)
	}
}

// TestKvColdSeedMaskFilter: a cold EP outside the prefill mask, and a cold EP
// in the excluded mask, are both ineligible seed targets.
func TestKvColdSeedMaskFilter(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "2")
	// ep0 warm; ep1 cold but EXCLUDED; ep2 cold but NOT a prefill EP.
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	if seededAt, _ := seedSweep(svcID, 0b011, 0b010, 0, 6); len(seededAt) != 0 {
		t.Fatalf("masked/excluded cold EPs must not be seeded, got %v", seededAt)
	}
}

// TestKvColdSeedEmptyEntryIsCold: an inventory ENTRY that exists with zero
// blocks (a flushed EP whose map entry survived) counts as cold.
func TestKvColdSeedEmptyEntryIsCold(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "3")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20), 1: {}})
	seededAt, lastEp := seedSweep(svcID, 0b11, 0, 0, 3)
	if len(seededAt) != 1 || seededAt[0] != 3 || lastEp != 1 {
		t.Fatalf("empty-entry EP must seed at tick 3 → ep1, got seeds=%v ep=%d", seededAt, lastEp)
	}
}

// TestKvColdSeedLowestIdxWins: with several cold EPs the lowest index is the
// deterministic target.
func TestKvColdSeedLowestIdxWins(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "1")
	// ep0 warm (the hit winner); ep1, ep3 cold.
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	ep, seeded := kvColdStartSeed(svcID, 0b1011, 0, 0)
	if !seeded || ep != 1 {
		t.Fatalf("expected seed → ep1 (lowest cold), got seeded=%v ep=%d", seeded, ep)
	}
}

// TestKvColdSeedLegacySvcZeroSkipped: svcID==0 (legacy all-services scan) has
// no per-service state — seeding is skipped.
func TestKvColdSeedLegacySvcZeroSkipped(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "1")
	coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	if ep, seeded := kvColdStartSeed(0, 0b11, 0, 0); seeded || ep != 0 {
		t.Fatalf("svcID=0 must never seed, got seeded=%v ep=%d", seeded, ep)
	}
}

// TestKvColdSeedSelfLimiting: once the seeded EP's inventory fills (its
// BlockStored events ingested), the diversion stops on its own.
func TestKvColdSeedSelfLimiting(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "2")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	if _, lastEp := seedSweep(svcID, 0b11, 0, 0, 2); lastEp != 1 {
		t.Fatalf("expected the cold ep1 to be seeded at tick 2, got ep=%d", lastEp)
	}
	// ep1 warms up: its (now created) inventory receives blocks.
	kvServicesMu.RLock()
	svc := kvServices[svcID]
	kvServicesMu.RUnlock()
	svc.mu.Lock()
	inv := svc.inventories[1]
	if inv == nil {
		inv = newKvInventory()
		svc.inventories[1] = inv
	}
	for _, h := range hashes(20) {
		inv.blocks[h] = struct{}{}
	}
	svc.mu.Unlock()
	if seededAt, _ := seedSweep(svcID, 0b11, 0, 0, 8); len(seededAt) != 0 {
		t.Fatalf("warmed EP must stop being seeded, got seeds at %v", seededAt)
	}
}

// TestKvColdSeedUnaffectedWinner: on non-seeding ticks the returned EP is the
// caller's winner bit-for-bit — the warm path sees no change.
func TestKvColdSeedUnaffectedWinner(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "1000000")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20)})
	for i := 0; i < 64; i++ {
		if ep, seeded := kvColdStartSeed(svcID, 0b11, 0, 5); seeded || ep != 5 {
			t.Fatalf("non-seeding tick altered the winner: seeded=%v ep=%d", seeded, ep)
		}
	}
}

// TestKvColdSeedTraceBlocksStillCold: a flushed engine can leave a few trace
// blocks behind — an inventory below the cold floor (default 16) is still a
// seed target, because it can never score past the shallow-match guard.
func TestKvColdSeedTraceBlocksStillCold(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "1")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20), 1: hashes(3)})
	ep, seeded := kvColdStartSeed(svcID, 0b11, 0, 0)
	if !seeded || ep != 1 {
		t.Fatalf("trace-block EP must still seed, got seeded=%v ep=%d", seeded, ep)
	}
}

// TestKvColdSeedStrictFloorZero: LOXILB_KV_COLDSTART_MIN_BLOCKS=0 degrades to
// strict empty-only — trace blocks disqualify, a truly empty EP still seeds.
func TestKvColdSeedStrictFloorZero(t *testing.T) {
	t.Setenv("LOXILB_KV_COLDSTART_SEED_N", "1")
	t.Setenv("LOXILB_KV_COLDSTART_MIN_BLOCKS", "0")
	svcID := coldSeedFixture(t, map[int][]uint64{0: hashes(20), 1: hashes(3), 2: {}})
	ep, seeded := kvColdStartSeed(svcID, 0b111, 0, 0)
	if !seeded || ep != 2 {
		t.Fatalf("strict floor must skip trace-block ep1 and seed empty ep2, got seeded=%v ep=%d", seeded, ep)
	}
}
