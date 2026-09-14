/*
 * Copyright (c) 2026 LoxiLB Authors
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

package ratelimit

import (
	"testing"
)

// TestLadderScopeWireKeys pins the wire mapping for the ladder scopes: the
// identity function in both directions, with the two legacy tenant shapes
// unchanged. A regression here silently re-keys live quota state across an
// upgrade.
func TestLadderScopeWireKeys(t *testing.T) {
	cases := []struct {
		mapKey  string
		wireKey string
	}{
		{"tenant-a", "t:tenant-a"},                 // legacy tenant
		{"tenant-a|llama", "tm:tenant-a|llama"},    // legacy tenant|model
		{"uq:t1|alice", "uq:t1|alice"},             // user quota
		{"um:t1|alice|llama", "um:t1|alice|llama"}, // user|model quota
		{"kq:key-1", "kq:key-1"},                   // key TPM
		{"v:10.0.0.1:2040", "v:10.0.0.1:2040"},     // vip shared
	}
	for _, c := range cases {
		if got := QuotaWireKey(c.mapKey); got != c.wireKey {
			t.Errorf("QuotaWireKey(%q) = %q, want %q", c.mapKey, got, c.wireKey)
		}
		back, ok := QuotaMapKey(c.wireKey)
		if !ok || back != c.mapKey {
			t.Errorf("QuotaMapKey(%q) = (%q, %v), want (%q, true)", c.wireKey, back, ok, c.mapKey)
		}
	}
}

// TestQuotaMapKeyRefusesNonQuotaScopes: the sentinel and the two LIMITER
// scopes (k:/u:) must never land in the quota map — on either side of the
// version line. This is exactly the drop an old peer performs on the new
// scopes, so it doubles as the mixed-version safety proof.
func TestQuotaMapKeyRefusesNonQuotaScopes(t *testing.T) {
	for _, wire := range []string{ScopeSentinelKeyID, "ver:999", "k:key-1", "u:t1|alice"} {
		if _, ok := QuotaMapKey(wire); ok {
			t.Errorf("QuotaMapKey(%q) accepted a non-quota scope", wire)
		}
	}
}

// TestSentinelEntryIsInertOnMerge: a sentinel arriving as a quota row (its
// wire shape) merges into nothing — before AND after this build. Feeding it
// straight into both merge paths is the receiver-side half of the proof.
func TestSentinelEntryIsInertOnMerge(t *testing.T) {
	s := New()
	sentinel := RateLimiterEntry{KeyID: ScopeSentinelKeyID, IsTenant: true, WindowEpoch: 99, Consumed: 99}
	s.ImportState([]RateLimiterEntry{sentinel})
	s.ApplyGossipDelta([]RateLimiterEntry{sentinel})
	count := 0
	s.quotaMap.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("the sentinel materialised %d quota entries; it must be inert", count)
	}
}

// TestLadderScopeStateSurvivesPeerSync: a user quota bucket charged into
// debt on one node reads as in-debt on a peer after an export/import round
// trip — the HA merge semantics on the uq: scope. Losing this is what the
// scope-version warning exists to make loud.
func TestLadderScopeStateSurvivesPeerSync(t *testing.T) {
	a := New()
	key := UserQuotaKey("t1", "alice")

	// Drive the bucket into debt on node A (charge over the limit).
	if allowed, _ := a.AllowTokens(key, 150, 100, 0); allowed {
		t.Fatalf("charging 150 against tpm=100 must report debt")
	}
	if !a.IsTokenQuotaExceeded(key) {
		t.Fatalf("node A must read its own debt")
	}

	entries := a.ExportState()
	found := false
	for _, e := range entries {
		if e.KeyID == key {
			if !e.IsTenant {
				t.Fatalf("uq: entry exported with IsTenant=false — old peers would rebuild it as a limiter")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("uq: bucket missing from the export")
	}

	// An imported bucket carries the merged drain time but no limit — the
	// limit is config, not synced state, and is recorded on the receiver's
	// first local charge (the documented one-request grace; same shape the
	// tenant scope has always had). So: import, then one 1-token charge at
	// the configured limit, then the debt must bind.
	b := New()
	b.ImportState(entries)
	if allowed, _ := b.AllowTokens(key, 1, 100, 0); allowed {
		t.Fatalf("node B's first local charge on the merged bucket must land in debt")
	}
	if !b.IsTokenQuotaExceeded(key) {
		t.Fatalf("node B must read the merged debt after its first local charge")
	}

	// The delta path too: a fresh node C learns the debt from a gossip
	// delta, which is what actually runs in A-A mode.
	c := New()
	c.ApplyGossipDelta(entries)
	if allowed, _ := c.AllowTokens(key, 1, 100, 0); allowed {
		t.Fatalf("node C's first local charge on the gossiped bucket must land in debt")
	}
	if !c.IsTokenQuotaExceeded(key) {
		t.Fatalf("node C must read the gossiped debt after its first local charge")
	}
}

// TestCheckUserBucketsAreDistinct: two users' RPS buckets never share
// tokens, and the same user under two tenants is two buckets.
func TestCheckUserBucketsAreDistinct(t *testing.T) {
	s := New()
	if allowed, _ := s.CheckUser("t1", "alice", 1, 0); !allowed {
		t.Fatalf("alice first request must pass")
	}
	if allowed, _ := s.CheckUser("t1", "alice", 1, 0); allowed {
		t.Fatalf("alice second request at rps=1 must be denied")
	}
	if allowed, _ := s.CheckUser("t1", "bob", 1, 0); !allowed {
		t.Fatalf("bob must not share alice's bucket")
	}
	if allowed, _ := s.CheckUser("t2", "alice", 1, 0); !allowed {
		t.Fatalf("alice@t2 must not share alice@t1's bucket")
	}
}

// TestCheckVipSharedIsOneBucket: everything keyless on one service shares
// the bucket; a second service has its own.
func TestCheckVipSharedIsOneBucket(t *testing.T) {
	s := New()
	if allowed, _ := s.CheckVipShared("10.0.0.1:2040", 1); !allowed {
		t.Fatalf("first keyless request must pass")
	}
	if allowed, _ := s.CheckVipShared("10.0.0.1:2040", 1); allowed {
		t.Fatalf("second keyless request must share the first's bucket")
	}
	if allowed, _ := s.CheckVipShared("10.0.0.1:2041", 1); !allowed {
		t.Fatalf("another service must have its own bucket")
	}
	// rps=0: the bucket is opt-in — unlimited when not configured.
	if allowed, _ := s.CheckVipShared("10.0.0.1:2042", 0); !allowed {
		t.Fatalf("unconfigured shared bucket must admit")
	}
}

// TestHasReservedScopePrefix pins the identity-validation vocabulary.
func TestHasReservedScopePrefix(t *testing.T) {
	for _, bad := range []string{"k:x", "u:x", "t:x", "tm:x", "uq:x", "um:x", "kq:x", "v:x", "ver:2"} {
		if !HasReservedScopePrefix(bad) {
			t.Errorf("%q must be rejected as a reserved scope prefix", bad)
		}
	}
	for _, good := range []string{"tenant-a", "alice", "kongsberg", "user@example.com", "velvet", "under_score"} {
		if HasReservedScopePrefix(good) {
			t.Errorf("%q must be accepted", good)
		}
	}
}
