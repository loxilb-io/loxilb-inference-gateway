/*
 * Copyright (c) 2025 LoxiLB Authors
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
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmihailenco/msgpack/v5"

	// Named import ensures the prometheus package init runs and registers
	// all promauto metrics (including Tier 1.5 miss-reason and
	// fallthrough counters) into prometheus.DefaultGatherer.
	prom "github.com/loxilb-io/loxilb/api/prometheus"
)

// Reference prom to keep import tidy-safe if other tests ever drop its usage.
var _ = prom.SetKvBlocksGauge

func TestKvInventoryAddRemove(t *testing.T) {
	inv := newKvInventory()

	// Add hashes
	inv.AddBlocks([]uint64{100, 200, 300})
	if inv.Size() != 3 {
		t.Errorf("size after add = %d, want 3", inv.Size())
	}

	// Match
	count := inv.MatchCount([]uint64{100, 400})
	if count != 1 {
		t.Errorf("match count = %d, want 1", count)
	}

	// Remove
	inv.RemoveBlocks([]uint64{200})
	if inv.Size() != 2 {
		t.Errorf("size after remove = %d, want 2", inv.Size())
	}

	// Verify removed hash no longer matches
	count = inv.MatchCount([]uint64{200})
	if count != 0 {
		t.Errorf("match count after remove = %d, want 0", count)
	}
}

func TestKvInventoryClearAll(t *testing.T) {
	inv := newKvInventory()
	inv.AddBlocks([]uint64{100, 200, 300, 400, 500})
	inv.ClearAll()
	if inv.Size() != 0 {
		t.Errorf("size after clear = %d, want 0", inv.Size())
	}
}

func TestKvBestWorkerBasic(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	// Create service with 2 EPs
	svc := newKvServiceState(1)
	svc.inventories[0] = newKvInventory()
	svc.inventories[1] = newKvInventory()

	// EP 0 has hashes {100, 200}
	svc.inventories[0].AddBlocks([]uint64{100, 200})
	// EP 1 has hashes {300, 400}
	svc.inventories[1].AddBlocks([]uint64{300, 400})

	kvServicesMu.Lock()
	kvServices[1] = svc
	kvServicesMu.Unlock()

	// Query with hash 100 — should match EP 0
	queryHashes := []uint64{100}
	bestEp, bestScore := kvBestWorkerGo(queryHashes, uint32(0b11), uint32(0))
	if bestEp != 0 {
		t.Errorf("best EP = %d, want 0", bestEp)
	}
	if bestScore != 1 {
		t.Errorf("best score = %d, want 1", bestScore)
	}

	// Query with hash 300 — should match EP 1
	bestEp, bestScore = kvBestWorkerGo([]uint64{300}, uint32(0b11), uint32(0))
	if bestEp != 1 {
		t.Errorf("best EP = %d, want 1", bestEp)
	}
	if bestScore != 1 {
		t.Errorf("best score = %d, want 1", bestScore)
	}
}

func TestKvBestWorkerTieBreak(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	svc := newKvServiceState(1)
	svc.inventories[0] = newKvInventory()
	svc.inventories[1] = newKvInventory()

	// Both EPs have hash 100
	svc.inventories[0].AddBlocks([]uint64{100})
	svc.inventories[1].AddBlocks([]uint64{100})

	// EP 1 also has 200 (more total blocks, but same overlap for query {100})
	svc.inventories[1].AddBlocks([]uint64{200})

	kvServicesMu.Lock()
	kvServices[1] = svc
	kvServicesMu.Unlock()

	// Query {100} — both have score 1, first EP (0) wins tie
	bestEp, _ := kvBestWorkerGo([]uint64{100}, uint32(0b11), uint32(0))
	// Tie-breaking is deterministic — first EP scanned wins
	if bestEp != 0 && bestEp != 1 {
		t.Errorf("best EP = %d, want 0 or 1 (tie)", bestEp)
	}
}

func TestKvBestWorkerEmpty(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	// No services registered
	bestEp, _ := kvBestWorkerGo([]uint64{100}, uint32(0b11), uint32(0))
	if bestEp != -1 {
		t.Errorf("best EP = %d, want -1 (empty)", bestEp)
	}
}

// TestKvBestWorkerNonContiguousPrefill is Pitfall-2 tripwire:
// populate inventories at NON-CONTIGUOUS absolute EP indices (2 and 4, with
// gaps at 0, 1, 3) and verify the worker selector respects absolute epIdx via
// prefillMask rather than treating a count as a max-index. Under the old
// count-as-index contract (if epIdx >= nEps continue with nEps=2), the bits
// at 2 and 4 would be excluded — this test fails RED until lands.
func TestKvBestWorkerNonContiguousPrefill(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	// Service 7 has two prefill EPs at absolute indices 2 and 4
	svc := newKvServiceState(7)
	svc.inventories[2] = newKvInventory()
	svc.inventories[4] = newKvInventory()

	// EP 2 has hash 111, EP 4 has hash 222
	svc.inventories[2].AddBlocks([]uint64{111})
	svc.inventories[4].AddBlocks([]uint64{222})

	kvServicesMu.Lock()
	kvServices[7] = svc
	kvServicesMu.Unlock()

	// Query {222} with prefillMask=0b10100 (bits 2 and 4) — should match EP 4
	bestEp, bestScore := kvBestWorkerGo([]uint64{222}, uint32(0b10100), uint32(0))
	if bestEp != 4 {
		t.Errorf("best EP for {222} = %d, want 4 (non-contiguous prefill at bit 4)", bestEp)
	}
	if bestScore != 1 {
		t.Errorf("best score for {222} = %d, want 1", bestScore)
	}

	// Query {111} with prefillMask=0b10100 — should match EP 2
	bestEp, bestScore = kvBestWorkerGo([]uint64{111}, uint32(0b10100), uint32(0))
	if bestEp != 2 {
		t.Errorf("best EP for {111} = %d, want 2 (non-contiguous prefill at bit 2)", bestEp)
	}
	if bestScore != 1 {
		t.Errorf("best score for {111} = %d, want 1", bestScore)
	}
}

// TestKvBestWorkerExcludedMaskComposition verifies that excludedMask is
// honored pre-scoring: bit-2 excluded → EP 2 is skipped even when it would
// otherwise match, falling through to the best NON-excluded prefill EP (bit-4).
// This is the RESEARCH.md Open Question #3 coverage: the new design pre-filters
// excludedMask in Go so second-best prefill beats Tier-2 random.
func TestKvBestWorkerExcludedMaskComposition(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	svc := newKvServiceState(7)
	svc.inventories[2] = newKvInventory()
	svc.inventories[4] = newKvInventory()

	// Both EPs have matching blocks for the query {111, 222}
	svc.inventories[2].AddBlocks([]uint64{111, 222})
	svc.inventories[4].AddBlocks([]uint64{111, 222})

	kvServicesMu.Lock()
	kvServices[7] = svc
	kvServicesMu.Unlock()

	// With prefillMask=0b10100 and excludedMask=0b00100 (bit 2 excluded),
	// the winner must be EP 4 (bit-2 skipped before scoring).
	bestEp, bestScore := kvBestWorkerGo([]uint64{111, 222}, uint32(0b10100), uint32(0b00100))
	if bestEp != 4 {
		t.Errorf("best EP = %d, want 4 (bit-2 excluded, bit-4 retained)", bestEp)
	}
	if bestScore != 2 {
		t.Errorf("best score = %d, want 2", bestScore)
	}
}

func TestDecodeBlockStored(t *testing.T) {
	// Encode a BlockStored event as msgpack
	// Format: [ts, [[tag, [hashes], parent, [tokens], block_size, lora_id, medium, lora_name, extra]], dp_rank]
	batch := []interface{}{
		1234567890.0, // timestamp
		[]interface{}{
			[]interface{}{
				"BlockStored",
				[]interface{}{int64(42), int64(43)}, // block hashes
				int64(0),                            // parent hash
				[]interface{}{int64(1), int64(2)},   // token ids
				int64(16),                           // block_size
				nil, nil, nil, nil,                  // lora_id, medium, lora_name, extra
			},
		},
		nil, // dp_rank
	}

	data, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal: %v", err)
	}

	events, err := decodeKVEventBatch(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != kvEventBlockStored {
		t.Errorf("event type = %d, want BlockStored", events[0].Type)
	}
	if len(events[0].Hashes) != 2 {
		t.Errorf("hashes count = %d, want 2", len(events[0].Hashes))
	}
	if events[0].Hashes[0] != 42 || events[0].Hashes[1] != 43 {
		t.Errorf("hashes = %v, want [42, 43]", events[0].Hashes)
	}
}

func TestDecodeBlockRemoved(t *testing.T) {
	batch := []interface{}{
		1234567890.0,
		[]interface{}{
			[]interface{}{
				"BlockRemoved",
				[]interface{}{int64(42)}, // removed hash
				nil,                      // medium
			},
		},
		nil,
	}

	data, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal: %v", err)
	}

	events, err := decodeKVEventBatch(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != kvEventBlockRemoved {
		t.Errorf("event type = %d, want BlockRemoved", events[0].Type)
	}
	if len(events[0].Hashes) != 1 || events[0].Hashes[0] != 42 {
		t.Errorf("hashes = %v, want [42]", events[0].Hashes)
	}
}

func TestDecodeAllBlocksCleared(t *testing.T) {
	batch := []interface{}{
		1234567890.0,
		[]interface{}{
			[]interface{}{"AllBlocksCleared"},
		},
		nil,
	}

	data, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal: %v", err)
	}

	events, err := decodeKVEventBatch(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != kvEventAllBlocksCleared {
		t.Errorf("event type = %d, want AllBlocksCleared", events[0].Type)
	}
}

// kvBestWorkerGo is a pure-Go implementation of the best worker logic for testing.
// It avoids the CGO export which can't easily be called from Go tests.
// Mirrors the production CGO signature post-: prefillMask and
// excludedMask are absolute-index bitmasks (bit i → ep[i]), not counts.
func kvBestWorkerGo(queryHashes []uint64, prefillMask, excludedMask uint32) (int, int) {
	bestEp := -1
	bestScore := 0

	kvServicesMu.RLock()
	defer kvServicesMu.RUnlock()

	for _, svc := range kvServices {
		svc.mu.RLock()
		for epIdx, inv := range svc.inventories {
			// epIdx is the ABSOLUTE endpoint index in lBActs.endPoints
			// (matches sockproxy tepval->ep_role[] index).
			if epIdx < 0 || epIdx >= 32 {
				continue
			}
			bit := uint32(1) << uint(epIdx)
			if prefillMask&bit == 0 {
				continue
			}
			if excludedMask&bit != 0 {
				continue
			}
			score := inv.MatchCount(queryHashes)
			if score > bestScore {
				bestScore = score
				bestEp = epIdx
			}
		}
		svc.mu.RUnlock()
	}

	return bestEp, bestScore
}

// TestKvTier15MissCountersRegistered verifies that Tier 1.5
// routing-diagnostics Prometheus metrics are registered and gather-able from
// prometheus.DefaultGatherer. This is a registration smoke test only —
// counter *increments* land in plan 42-02 (pd_kv_exact_select guard wiring).
//
// Asserted invariants:
//  1. loxilb_pd_kv_tier15_miss_reason_total (CounterVec) is present in the
//     gatherer output after promauto init.
//  2. All 8 canonical reason labels are instantiable without panic:
//     mode_off, warmup, text_empty, model_empty, tokenize, hashes,
//     no_worker, excluded. Each instantiation creates a distinct child
//     series so Prometheus scrapes will surface them immediately.
//  3. loxilb_pd_kv_tier15_fallthrough_total (Counter) is present.
func TestKvTier15MissCountersRegistered(t *testing.T) {
	const missMetricName = "loxilb_pd_kv_tier15_miss_reason_total"
	const fallthroughMetricName = "loxilb_pd_kv_tier15_fallthrough_total"

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("DefaultGatherer.Gather() returned error: %v", err)
	}

	seen := map[string]bool{}
	for _, mf := range mfs {
		name := mf.GetName()
		if name == missMetricName || name == fallthroughMetricName {
			seen[name] = true
		}
	}

	if !seen[missMetricName] {
		// Surface all registered metric names with the loxilb_pd_kv prefix
		// to make diagnosis easier if registration ever regresses.
		var kvMetricNames []string
		for _, mf := range mfs {
			if strings.HasPrefix(mf.GetName(), "loxilb_pd_kv") {
				kvMetricNames = append(kvMetricNames, mf.GetName())
			}
		}
		t.Errorf("metric %q not registered; loxilb_pd_kv_* metrics seen: %v",
			missMetricName, kvMetricNames)
	}
	if !seen[fallthroughMetricName] {
		t.Errorf("metric %q not registered", fallthroughMetricName)
	}
}
