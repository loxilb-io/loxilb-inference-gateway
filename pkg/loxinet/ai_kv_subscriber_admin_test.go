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

// ai_kv_subscriber_admin_test.go — provider contract tests.
//
// Covers the DumpKvInventory provider path used by the Admin API handler
// (api/restapi/handler/ai_kv_inventory.go). The Go-side kvInventory is a
// map[uint64]struct{} so iteration order is non-deterministic and block_idx
// in the response is a *synthetic* sequence index, not a semantic position.
// The parity harness sorts by hash_uint64 for multiset
// (sorted-list) equality — these tests therefore assert on the set of
// returned hash_uint64 values, NOT on block_idx ordering.

package loxinet

import (
	"sort"
	"testing"
)

// seedService registers a kvServiceState with one inventory at the given
// epIdx, pre-populated with the supplied hashes. Returns the inventory so
// callers can mutate it further. Tests call KvResetAll before/after to
// guarantee isolation.
func seedService(t *testing.T, serviceID uint32, algo string, epIdx int, hashes []uint64) *kvInventory {
	t.Helper()
	svc := newKvServiceState(serviceID)
	svc.algo = algo
	inv := newKvInventory()
	svc.inventories[epIdx] = inv
	kvServicesMu.Lock()
	kvServices[serviceID] = svc
	kvServicesMu.Unlock()
	if len(hashes) > 0 {
		inv.AddBlocks(hashes)
	}
	return inv
}

// TestDumpKvInventory_NotFound: unknown service_id must return (nil, false)
// so the handler can emit HTTP 404. Also covers the "known service, unknown
// ep_idx" path via a service that has no inventory for the requested ep.
func TestDumpKvInventory_NotFound(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	p := &kvInventoryProviderImpl{}

	t.Run("unknown_service", func(t *testing.T) {
		resp, ok := p.DumpKvInventory(9999, 0)
		if ok {
			t.Errorf("DumpKvInventory(9999, 0) returned ok=true, want false")
		}
		if resp != nil {
			t.Errorf("DumpKvInventory(9999, 0) returned resp=%+v, want nil", resp)
		}
	})

	t.Run("unknown_ep", func(t *testing.T) {
		// Service 1 registered with inventory only at ep 0; querying ep 5 → 404.
		seedService(t, 1, "sha256_cbor", 0, nil)
		resp, ok := p.DumpKvInventory(1, 5)
		if ok {
			t.Errorf("DumpKvInventory(1, 5) returned ok=true, want false (ep 5 not registered)")
		}
		if resp != nil {
			t.Errorf("DumpKvInventory(1, 5) returned resp=%+v, want nil", resp)
		}
	})
}

// TestDumpKvInventory_Empty: service registered with an empty inventory
// must return (resp, true) with Blocks=[] and Total=0 so the handler emits
// HTTP 200 with a valid (empty) JSON body. HashAlgo must be non-empty
// (provider defaults to "sha256_cbor" when service.algo is "").
func TestDumpKvInventory_Empty(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	t.Run("algo_set", func(t *testing.T) {
		KvResetAll()
		seedService(t, 42, "xxhash_cbor", 0, nil)
		p := &kvInventoryProviderImpl{}
		resp, ok := p.DumpKvInventory(42, 0)
		if !ok {
			t.Fatalf("DumpKvInventory(42, 0) returned ok=false, want true")
		}
		if resp == nil {
			t.Fatalf("DumpKvInventory(42, 0) returned resp=nil, want non-nil")
		}
		if resp.ServiceID != 42 {
			t.Errorf("resp.ServiceID = %d, want 42", resp.ServiceID)
		}
		if resp.EpIdx != 0 {
			t.Errorf("resp.EpIdx = %d, want 0", resp.EpIdx)
		}
		if resp.HashAlgo != "xxhash_cbor" {
			t.Errorf("resp.HashAlgo = %q, want %q", resp.HashAlgo, "xxhash_cbor")
		}
		if len(resp.Blocks) != 0 {
			t.Errorf("len(resp.Blocks) = %d, want 0", len(resp.Blocks))
		}
		if resp.Total != 0 {
			t.Errorf("resp.Total = %d, want 0", resp.Total)
		}
	})

	t.Run("algo_empty_defaults_to_sha256_cbor", func(t *testing.T) {
		KvResetAll()
		seedService(t, 43, "", 0, nil)
		p := &kvInventoryProviderImpl{}
		resp, ok := p.DumpKvInventory(43, 0)
		if !ok {
			t.Fatalf("DumpKvInventory(43, 0) returned ok=false, want true")
		}
		if resp == nil {
			t.Fatalf("DumpKvInventory(43, 0) returned resp=nil, want non-nil")
		}
		if resp.HashAlgo == "" {
			t.Errorf("resp.HashAlgo empty; provider must default when service.algo is unset")
		}
		if resp.HashAlgo != "sha256_cbor" {
			t.Errorf("resp.HashAlgo = %q, want %q (vLLM v0.17.0 default)",
				resp.HashAlgo, "sha256_cbor")
		}
	})
}

// TestDumpKvInventory_WithBlocks: inject three hashes via AddBlocks, verify
// Total==3, the set of returned HashUint64 matches the injected set, and
// block_idx values are synthetic (0..total-1) but do NOT assume ordering.
func TestDumpKvInventory_WithBlocks(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	inv := seedService(t, 44, "sha256_cbor", 0, nil)
	inv.AddBlocks([]uint64{0xAAAA, 0xBBBB, 0xCCCC})

	p := &kvInventoryProviderImpl{}
	resp, ok := p.DumpKvInventory(44, 0)
	if !ok {
		t.Fatalf("DumpKvInventory(44, 0) returned ok=false, want true")
	}
	if resp == nil {
		t.Fatalf("DumpKvInventory(44, 0) returned resp=nil, want non-nil")
	}

	if resp.ServiceID != 44 {
		t.Errorf("resp.ServiceID = %d, want 44", resp.ServiceID)
	}
	if resp.EpIdx != 0 {
		t.Errorf("resp.EpIdx = %d, want 0", resp.EpIdx)
	}
	if resp.HashAlgo != "sha256_cbor" {
		t.Errorf("resp.HashAlgo = %q, want %q", resp.HashAlgo, "sha256_cbor")
	}
	if resp.Total != 3 {
		t.Errorf("resp.Total = %d, want 3", resp.Total)
	}
	if len(resp.Blocks) != 3 {
		t.Errorf("len(resp.Blocks) = %d, want 3", len(resp.Blocks))
	}

	// block_idx invariants: 0 <= block_idx < total, and the set of block_idx
	// values must be {0, 1, 2} (synthetic, sequence index).
	seenIdx := make(map[int]bool, 3)
	for _, b := range resp.Blocks {
		if b.BlockIdx < 0 || b.BlockIdx >= resp.Total {
			t.Errorf("BlockIdx = %d out of range [0, %d)", b.BlockIdx, resp.Total)
		}
		if seenIdx[b.BlockIdx] {
			t.Errorf("duplicate BlockIdx = %d", b.BlockIdx)
		}
		seenIdx[b.BlockIdx] = true
	}

	// Multiset equality: sorted slice of returned hashes must equal the
	// sorted slice of injected hashes. Map iteration order is non-deterministic.
	got := make([]uint64, len(resp.Blocks))
	for i, b := range resp.Blocks {
		got[i] = b.HashUint64
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })

	want := []uint64{0xAAAA, 0xBBBB, 0xCCCC}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = 0x%016x, want 0x%016x", i, got[i], want[i])
		}
	}
}
