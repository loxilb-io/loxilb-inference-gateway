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

package loxinet

import (
	"sync"
	"testing"
)

// Every test starts with resetBridgeAllocator so they can run in any order
// under `go test -shuffle=on`. Cross-test state leakage would produce
// false-positive pool exhaustion (Exhaustion test) or non-deterministic VIDs
// (ZeroDigitAlloc / NonNumericAlloc tests which assert VID == BridgeVidStart).
//
// Important: bridge names used for pool-consuming tests MUST contain no
// digits, otherwise the numeric-name preservation branch in
// GetOrAllocBridgeVid short-circuits past the pool (returns the embedded
// number, not a pool slot). The brName helper below generates digit-free
// unique names like "br-a", "br-b", ..., "br-aa", "br-ab", ...
func brName(i int) string {
	// Excel-column style: 0->a, 1->b, ..., 25->z, 26->aa, 27->ab, ...
	s := ""
	i++ // shift so i=0 maps to "a" rather than "" (0 encodes length-0)
	for i > 0 {
		i--
		s = string(rune('a'+(i%26))) + s
		i /= 26
	}
	return "br-" + s
}

func TestBridgeVidAlloc_DockerHardcode(t *testing.T) {
	resetBridgeAllocator()
	got, err := GetOrAllocBridgeVid("docker0")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != 4090 {
		t.Errorf("docker0 got %d, want 4090", got)
	}
	// Ensure no pool slot consumed: a fresh allocator should still give
	// the first pool alloc at BridgeVidStart == 5000.
	vid, err := GetOrAllocBridgeVid("fresh-br")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if vid != BridgeVidStart {
		t.Errorf("first pool alloc got %d, want %d (docker0 must not consume a slot)", vid, BridgeVidStart)
	}
}

func TestBridgeVidAlloc_CniHardcode(t *testing.T) {
	resetBridgeAllocator()
	got, err := GetOrAllocBridgeVid("cni0")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != 4091 {
		t.Errorf("cni0 got %d, want 4091", got)
	}
	// Same no-slot-consumed guarantee as docker0.
	vid, err := GetOrAllocBridgeVid("fresh-br")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if vid != BridgeVidStart {
		t.Errorf("first pool alloc got %d, want %d (cni0 must not consume a slot)", vid, BridgeVidStart)
	}
}

func TestBridgeVidAlloc_NumericName(t *testing.T) {
	resetBridgeAllocator()
	cases := []struct {
		name string
		want int
	}{
		{"br100", 100},
		{"br200", 200},
		{"br4094", 4094},
	}
	for _, c := range cases {
		got, err := GetOrAllocBridgeVid(c.name)
		if err != nil {
			t.Fatalf("%s: unexpected err: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s got %d, want %d", c.name, got, c.want)
		}
	}
	// Confirm no pool slot consumed -- first allocator-backed alloc should
	// still land at BridgeVidStart.
	vid, err := GetOrAllocBridgeVid("fresh-br")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if vid != BridgeVidStart {
		t.Errorf("first pool alloc after 3 numeric names got %d, want %d", vid, BridgeVidStart)
	}
}

func TestBridgeVidAlloc_ZeroDigitAlloc(t *testing.T) {
	resetBridgeAllocator()
	// "br0" has a digit (0) but the numeric preservation guard requires v > 0,
	// so it falls through to the pool.
	vid, err := GetOrAllocBridgeVid("br0")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if vid < BridgeVidStart || vid > BridgeVidStart+BridgeVidCount-1 {
		t.Errorf("br0 got vid %d, want in [%d, %d]", vid, BridgeVidStart, BridgeVidStart+BridgeVidCount-1)
	}
}

func TestBridgeVidAlloc_NonNumericAlloc(t *testing.T) {
	resetBridgeAllocator()
	vid, err := GetOrAllocBridgeVid("br-prod")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if vid < BridgeVidStart || vid > BridgeVidStart+BridgeVidCount-1 {
		t.Errorf("br-prod got vid %d, want in [%d, %d]", vid, BridgeVidStart, BridgeVidStart+BridgeVidCount-1)
	}
	// Also check a wholly non-numeric name ("bridge").
	vid2, err := GetOrAllocBridgeVid("bridge")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if vid2 < BridgeVidStart || vid2 > BridgeVidStart+BridgeVidCount-1 {
		t.Errorf("bridge got vid %d, want in pool range", vid2)
	}
	if vid == vid2 {
		t.Errorf("br-prod and bridge both got %d (distinct names must get distinct VIDs)", vid)
	}
}

func TestBridgeVidAlloc_Idempotent(t *testing.T) {
	resetBridgeAllocator()
	first, err := GetOrAllocBridgeVid("br-prod")
	if err != nil {
		t.Fatalf("first alloc err: %v", err)
	}
	second, err := GetOrAllocBridgeVid("br-prod")
	if err != nil {
		t.Fatalf("second alloc err: %v", err)
	}
	if first != second {
		t.Errorf("idempotency failed: first=%d second=%d (must match)", first, second)
	}
	// A different name must get a different VID.
	other, err := GetOrAllocBridgeVid("br-dev")
	if err != nil {
		t.Fatalf("br-dev alloc err: %v", err)
	}
	if other == first {
		t.Errorf("distinct names collided: br-prod=%d br-dev=%d", first, other)
	}
}

func TestBridgeVidAlloc_ReleaseReuse(t *testing.T) {
	resetBridgeAllocator()
	// Use digit-free names so the numeric-name preservation branch does not
	// short-circuit past the pool. "br-a" / "br-b" have no digits.
	vid, err := GetOrAllocBridgeVid("br-a")
	if err != nil {
		t.Fatalf("alloc br-a err: %v", err)
	}
	if vid < BridgeVidStart || vid > BridgeVidStart+BridgeVidCount-1 {
		t.Fatalf("br-a vid=%d not in pool range", vid)
	}
	if err := ReleaseBridgeVid("br-a"); err != nil {
		t.Fatalf("release br-a err: %v", err)
	}
	// After release, the pool MUST have full capacity again. Fill it to prove
	// the slot returned to the pool (tk.Counter appends freed slots to the
	// back of the free list, so the exact VID order is implementation-defined;
	// the correctness invariant is "total capacity restored").
	names := make([]string, BridgeVidCount)
	for i := 0; i < BridgeVidCount; i++ {
		names[i] = brName(i + 10000) // offset so names don't collide with Exhaustion test
		v, err := GetOrAllocBridgeVid(names[i])
		if err != nil {
			t.Fatalf("post-release fill alloc %d (%s) err: %v (pool not restored)", i, names[i], err)
		}
		if v < BridgeVidStart || v > BridgeVidStart+BridgeVidCount-1 {
			t.Errorf("post-release fill vid %d out of pool range", v)
		}
	}
	// Now exhausted again -- the released slot was accounted for.
	if _, err := GetOrAllocBridgeVid(brName(99999)); err == nil {
		t.Error("expected exhaustion after full post-release fill, got nil")
	}
	// Double-release must be idempotent.
	if err := ReleaseBridgeVid("br-a"); err != nil {
		t.Fatalf("double-release should be no-op, got err: %v", err)
	}
	// Hardcode releases are no-ops.
	if err := ReleaseBridgeVid("docker0"); err != nil {
		t.Errorf("docker0 release should be no-op, got err: %v", err)
	}
	if err := ReleaseBridgeVid("cni0"); err != nil {
		t.Errorf("cni0 release should be no-op, got err: %v", err)
	}
	// Numeric-name release is a no-op (no slot was consumed).
	if err := ReleaseBridgeVid("br100"); err != nil {
		t.Errorf("br100 release should be no-op, got err: %v", err)
	}
	// Never-seen release is a no-op.
	if err := ReleaseBridgeVid("never-existed"); err != nil {
		t.Errorf("never-seen release should be no-op, got err: %v", err)
	}
}

func TestBridgeVidAlloc_Lookup(t *testing.T) {
	resetBridgeAllocator()
	// Unknown name: (0, false) and MUST NOT allocate.
	v, ok := LookupBridgeVid("never-seen")
	if ok {
		t.Errorf("LookupBridgeVid(never-seen) ok=true, want false")
	}
	if v != 0 {
		t.Errorf("LookupBridgeVid(never-seen) vid=%d, want 0", v)
	}
	// Confirm non-allocation: next GetOrAllocBridgeVid for a new name should
	// still get BridgeVidStart (the lookup must not have consumed a slot).
	vid, err := GetOrAllocBridgeVid("fresh")
	if err != nil {
		t.Fatalf("fresh alloc err: %v", err)
	}
	if vid != BridgeVidStart {
		t.Errorf("fresh first alloc got %d, want %d (lookup of never-seen must not allocate)", vid, BridgeVidStart)
	}
	// Hardcode observability via Lookup (no prior Get required).
	if v, ok := LookupBridgeVid("docker0"); !ok || v != 4090 {
		t.Errorf("LookupBridgeVid(docker0) = (%d, %v), want (4090, true)", v, ok)
	}
	if v, ok := LookupBridgeVid("cni0"); !ok || v != 4091 {
		t.Errorf("LookupBridgeVid(cni0) = (%d, %v), want (4091, true)", v, ok)
	}
	// Numeric-name observability via Lookup.
	if v, ok := LookupBridgeVid("br100"); !ok || v != 100 {
		t.Errorf("LookupBridgeVid(br100) = (%d, %v), want (100, true)", v, ok)
	}
	// After allocation, lookup returns the same VID.
	got, err := GetOrAllocBridgeVid("br-prod")
	if err != nil {
		t.Fatalf("alloc br-prod err: %v", err)
	}
	if v, ok := LookupBridgeVid("br-prod"); !ok || v != got {
		t.Errorf("LookupBridgeVid(br-prod) = (%d, %v), want (%d, true)", v, ok, got)
	}
}

func TestBridgeVidAlloc_Exhaustion(t *testing.T) {
	resetBridgeAllocator()
	first := brName(0) // cache for later idempotency check
	for i := 0; i < BridgeVidCount; i++ {
		name := brName(i)
		if _, err := GetOrAllocBridgeVid(name); err != nil {
			t.Fatalf("alloc %d (%s) failed: %v", i, name, err)
		}
	}
	// Next alloc for a new name must fail -- pool exhausted.
	if _, err := GetOrAllocBridgeVid("one-too-many"); err == nil {
		t.Error("expected pool exhaustion error, got nil")
	}
	// Idempotency must still work even when pool is exhausted.
	v1, err := GetOrAllocBridgeVid(first)
	if err != nil {
		t.Fatalf("idempotent lookup of exhausted-pool cached name failed: %v", err)
	}
	if v1 < BridgeVidStart || v1 > BridgeVidStart+BridgeVidCount-1 {
		t.Errorf("cached %s vid=%d, want in pool range", first, v1)
	}
	// Hardcodes must still work even when the pool is exhausted.
	if v, err := GetOrAllocBridgeVid("docker0"); err != nil || v != 4090 {
		t.Errorf("docker0 after exhaustion = (%d, %v), want (4090, nil)", v, err)
	}
	// Release + re-alloc must succeed.
	if err := ReleaseBridgeVid(first); err != nil {
		t.Fatalf("release %s err: %v", first, err)
	}
	if _, err := GetOrAllocBridgeVid("post-release"); err != nil {
		t.Errorf("alloc after release failed: %v", err)
	}
}

func TestBridgeVidAlloc_Concurrent(t *testing.T) {
	resetBridgeAllocator()
	const N = 1000
	var wg sync.WaitGroup
	vids := make([]int, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vids[i], errs[i] = GetOrAllocBridgeVid(brName(i))
		}(i)
	}
	wg.Wait()
	seen := make(map[int]int)
	for i, v := range vids {
		if errs[i] != nil {
			t.Fatalf("alloc %d err: %v", i, errs[i])
		}
		if prev, dup := seen[v]; dup {
			t.Errorf("duplicate vid %d: idx %d and %d", v, prev, i)
		}
		if v < BridgeVidStart || v > BridgeVidStart+BridgeVidCount-1 {
			t.Errorf("vid %d for idx %d is out of pool range [%d, %d]", v, i, BridgeVidStart, BridgeVidStart+BridgeVidCount-1)
		}
		seen[v] = i
	}
	if len(seen) != N {
		t.Errorf("got %d distinct vids, want %d", len(seen), N)
	}
}

func TestBridgeVidAlloc_MaximumVlans(t *testing.T) {
	resetBridgeAllocator()
	if MaximumVlans != 6144 {
		t.Errorf("MaximumVlans = %d, want 6144", MaximumVlans)
	}
	cases := []struct {
		vid  int
		want bool
	}{
		{-1, false},
		{0, false},
		{1, true},
		{100, true},
		{4090, true},
		{4091, true},
		{4094, true},
		{5000, true},
		{6143, true},
		{6144, false},
		{9999, false},
	}
	for _, c := range cases {
		if got := VlanValid(c.vid); got != c.want {
			t.Errorf("VlanValid(%d) = %v, want %v", c.vid, got, c.want)
		}
	}
}
