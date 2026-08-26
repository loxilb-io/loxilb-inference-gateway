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

package ratelimit

import (
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// newTestStore returns a RateLimiterStore without starting the cleanup goroutine,
// suitable for use in unit tests.
func newTestStore() *RateLimiterStore {
	return &RateLimiterStore{entries: make(map[string]*limiterEntry)}
}

// pinQuotaClock suspends the package clock goroutine for the duration of the
// test, so bucket refill advances only through advanceQuotaClock and the
// arithmetic under test is deterministic. Tests that pin the clock must not
// call t.Parallel().
func pinQuotaClock(t *testing.T) {
	t.Helper()
	quotaClockFrozen.Store(true)
	t.Cleanup(func() { quotaClockFrozen.Store(false) })
}

// advanceQuotaClock moves the pinned quota clock forward by ms, refilling
// every bucket by the equivalent token amount.
func advanceQuotaClock(ms int64) {
	quotaNowMs.Add(ms)
}

// quotaDebtTokens reads the store's current spent-not-yet-refilled token
// debt for a quota key, the bucket-era analog of the old consumed counter.
func quotaDebtTokens(t *testing.T, s *RateLimiterStore, key string) int64 {
	t.Helper()
	v, ok := s.quotaMap.Load(key)
	if !ok {
		t.Fatalf("quota key %q missing from quotaMap", key)
	}
	e := v.(*tokenWindowEntry)
	return debtTokensOf(atomic.LoadInt64(&e.tatMs), quotaNowMs.Load(), atomic.LoadInt64(&e.limitTokens))
}

// TestBurstAbsorption verifies that a limiter allows exactly burst tokens
// before throttling subsequent requests.
func TestBurstAbsorption(t *testing.T) {
	s := newTestStore()

	const (
		rps   = 1
		burst = 3
	)

	// The first burst requests must all be allowed.
	for i := 0; i < burst; i++ {
		allowed, _ := s.CheckKey("key1", rps, burst)
		if !allowed {
			t.Fatalf("request %d/%d should be allowed within burst", i+1, burst)
		}
	}

	// The next request must be denied because the burst has been absorbed.
	allowed, retry := s.CheckKey("key1", rps, burst)
	if allowed {
		t.Fatal("request after burst should be denied")
	}
	if retry < 1 {
		t.Errorf("retryAfterSecs = %d, want >= 1", retry)
	}
}

// TestSustainedLimit verifies that after the burst is consumed, a subsequent
// request is denied immediately but succeeds after token refill.
func TestSustainedLimit(t *testing.T) {
	s := newTestStore()

	// rps=50, burst=1: one token available every 20 ms.
	allowed, _ := s.CheckKey("key1", 50, 1)
	if !allowed {
		t.Fatal("first request should be allowed")
	}

	// The single token has been consumed; the next immediate request should fail.
	allowed, retry := s.CheckKey("key1", 50, 1)
	if allowed {
		t.Fatal("second immediate request should be denied when burst=1")
	}
	if retry < 1 {
		t.Errorf("retryAfterSecs = %d, want >= 1", retry)
	}

	// Wait long enough for the limiter to regenerate at least one token (50 ms >> 20 ms).
	time.Sleep(50 * time.Millisecond)
	allowed, _ = s.CheckKey("key1", 50, 1)
	if !allowed {
		t.Fatal("request should be allowed after token refill")
	}
}

// TestPerTenantIsolation verifies that throttling one tenant does not affect
// another tenant's independent rate limiter.
func TestPerTenantIsolation(t *testing.T) {
	s := newTestStore()

	// Deplete tenant1's burst (rps=1, burst=1).
	s.CheckTenant("tenant1", 1)
	allowed1, _ := s.CheckTenant("tenant1", 1)
	if allowed1 {
		t.Fatal("tenant1 should be rate-limited after burst is absorbed")
	}

	// tenant2 operates an independent bucket and must still be allowed.
	allowed2, _ := s.CheckTenant("tenant2", 1)
	if !allowed2 {
		t.Fatal("tenant2 should not be affected by tenant1 throttling")
	}
}

// TestZeroRPSSkipsCheck verifies that rps=0 always allows requests without
// creating or consulting a rate limiter.
func TestZeroRPSSkipsCheck(t *testing.T) {
	s := newTestStore()

	for i := 0; i < 100; i++ {
		allowed, retry := s.CheckKey("key1", 0, 0)
		if !allowed {
			t.Fatalf("rps=0 should always allow (key), denied at iteration %d", i)
		}
		if retry != 0 {
			t.Errorf("retry should be 0 for rps=0, got %d", retry)
		}
	}

	for i := 0; i < 100; i++ {
		allowed, retry := s.CheckTenant("tenant1", 0)
		if !allowed {
			t.Fatalf("rps=0 should always allow (tenant), denied at iteration %d", i)
		}
		if retry != 0 {
			t.Errorf("retry should be 0 for rps=0, got %d", retry)
		}
	}
}

// TestUpdateKey verifies that UpdateKey resets the bucket so that requests are
// allowed again immediately after a config change.
func TestUpdateKey(t *testing.T) {
	s := newTestStore()

	// Absorb the only available token.
	s.CheckKey("key1", 1, 1)
	allowed, _ := s.CheckKey("key1", 1, 1)
	if allowed {
		t.Fatal("key1 should be rate-limited before update")
	}

	// UpdateKey creates a fresh bucket with a higher burst.
	s.UpdateKey("key1", 10, 10)
	allowed, _ = s.CheckKey("key1", 10, 10)
	if !allowed {
		t.Fatal("key1 should be allowed after UpdateKey with higher burst")
	}
}

// TestUpdateTenant verifies that UpdateTenant resets the per-tenant bucket.
func TestUpdateTenant(t *testing.T) {
	s := newTestStore()

	// Deplete the tenant bucket (rps=1, burst=1).
	s.CheckTenant("t1", 1)
	allowed, _ := s.CheckTenant("t1", 1)
	if allowed {
		t.Fatal("tenant t1 should be rate-limited before update")
	}

	// UpdateTenant creates a fresh bucket with higher rps.
	s.UpdateTenant("t1", 100)
	allowed, _ = s.CheckTenant("t1", 100)
	if !allowed {
		t.Fatal("tenant t1 should be allowed after UpdateTenant with higher rps")
	}
}

// ============================================================================
// AllowTokens unit tests
// ============================================================================

// TestAllowTokensRefillRate verifies that tokens consumed in one window do not
// carry over into the next window (i.e., the bucket refills at the start of
// each 60-second epoch). We fake the epoch by directly manipulating the entry's
// windowEpoch field through the quotaMap after the first call.
func TestAllowTokensRefillRate(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	// Drain the whole bucket (burst = 100% of the limit by default).
	for i := 0; i < 10; i++ {
		allowed, _ := s.AllowTokens("tenant1", 10, tokensPerMin, 0)
		if !allowed {
			t.Fatalf("iteration %d: expected allowed within quota", i)
		}
	}
	// One more charge puts the bucket in debt (total = 110 > 100).
	allowed, retry := s.AllowTokens("tenant1", 10, tokensPerMin, 0)
	if allowed {
		t.Fatal("should be denied after consuming full quota")
	}
	if retry < 1 {
		t.Errorf("retryAfterSecs = %d, want >= 1", retry)
	}

	// 30 seconds of refill at 100/min returns 50 tokens: from 10 tokens of
	// debt that leaves a level of 40. A 30-token charge fits; the next
	// 20-token charge (level now 10) does not — the budget refills
	// CONTINUOUSLY, there is no minute boundary that resets it wholesale.
	advanceQuotaClock(30_000)
	if allowed, _ = s.AllowTokens("tenant1", 30, tokensPerMin, 0); !allowed {
		t.Fatal("30-token charge should fit the partially refilled bucket")
	}
	if allowed, _ = s.AllowTokens("tenant1", 20, tokensPerMin, 0); allowed {
		t.Fatal("20-token charge should overdraw the partially refilled bucket")
	}
}

// TestNoBoundaryDoubleSpend pins the hole this bucket exists to close: the
// fixed window allowed a tenant to spend the full quota in the last second
// of window N and again in the first second of N+1 — twice the nominal rate
// across a two-second span. With continuous refill there is no boundary to
// straddle: a tenant who just drained the full burst holds exactly
// rate×Δt tokens after any Δt, minute-aligned or not.
func TestNoBoundaryDoubleSpend(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 600

	// Drain the full burst "just before the minute boundary".
	if allowed, _ := s.AllowTokens("tenant1", 600, tokensPerMin, 0); !allowed {
		t.Fatal("draining the full burst from a fresh bucket must be allowed")
	}

	// Two seconds later — where the old window would have granted a fresh
	// 600 — the refill has returned exactly 600/60 × 2 = 20 tokens. Probe
	// admission through ReserveTokens, which unlike the post-hoc charge
	// path does not consume anything on a deny.
	advanceQuotaClock(2_000)
	if allowed, _, _ := s.ReserveTokens("tenant1", 600, tokensPerMin, 0); allowed {
		t.Fatal("full-quota re-spend 2s after draining the bucket must be denied")
	}
	if allowed, _, _ := s.ReserveTokens("tenant1", 21, tokensPerMin, 0); allowed {
		t.Fatal("more than the 2s refill grant must be denied")
	}
	if allowed, _, _ := s.ReserveTokens("tenant1", 20, tokensPerMin, 0); !allowed {
		t.Fatal("exactly the 2s refill grant must be admitted")
	}
}

// TestAllowTokensQuotaExceededDetection verifies that IsTokenQuotaExceeded
// returns true once the per-minute budget is fully consumed.
func TestAllowTokensQuotaExceededDetection(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 50

	if s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("quota should not be exceeded before any consumption")
	}

	// Consume exactly the quota.
	allowed, _ := s.AllowTokens("tenant1", 50, tokensPerMin, 0)
	if !allowed {
		t.Fatal("should be allowed when consuming exactly the quota")
	}
	if s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("quota should not be exceeded when exactly at limit")
	}

	// One more token exceeds the quota.
	allowed, _ = s.AllowTokens("tenant1", 1, tokensPerMin, 0)
	if allowed {
		t.Fatal("should be denied once over quota")
	}
	if !s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("IsTokenQuotaExceeded should return true after quota exceeded")
	}
}

// TestTokenQuotaExceededDrainsWithRefill pins the read-side self-heal rule:
// once a tenant is over quota, EVERY subsequent request is denied at the
// gate, so no charge ever runs to clear a stored flag. The over-quota state
// is therefore derived from the bucket debt, and the continuous refill
// clears it on its own — with NO further AllowTokens calls — as soon as the
// debt has drained.
func TestTokenQuotaExceededDrainsWithRefill(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	// Trip the quota: 10 tokens of debt (6s of refill at 100/min).
	s.AllowTokens("tenant1", 100, tokensPerMin, 0)
	if allowed, _ := s.AllowTokens("tenant1", 10, tokensPerMin, 0); allowed {
		t.Fatal("should be denied over quota")
	}
	if !s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("bucket in debt must read exceeded")
	}

	// Refill drains the debt with no writer running (the denied-tenant
	// reality: requests bounce at the gate before any response could
	// consume tokens).
	advanceQuotaClock(7_000)
	if s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("exceeded must clear on its own once the refill drains the debt")
	}

	// The freshly refilled headroom (~1 token past even) admits a small
	// charge cleanly.
	if allowed, _ := s.AllowTokens("tenant1", 1, tokensPerMin, 0); !allowed {
		t.Fatal("drained bucket should allow a small charge")
	}
}

// TestAllowTokensPerTenantIsolation verifies that exhausting tenant A's quota
// does not affect tenant B's independent budget.
func TestAllowTokensPerTenantIsolation(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	// Exhaust tenant A.
	s.AllowTokens("tenantA", 100, tokensPerMin, 0)
	s.AllowTokens("tenantA", 1, tokensPerMin, 0) // push over quota

	if !s.IsTokenQuotaExceeded("tenantA") {
		t.Fatal("tenantA should be quota-exceeded")
	}

	// Tenant B is completely independent.
	allowed, _ := s.AllowTokens("tenantB", 50, tokensPerMin, 0)
	if !allowed {
		t.Fatal("tenantB should not be affected by tenantA's quota exhaustion")
	}
	if s.IsTokenQuotaExceeded("tenantB") {
		t.Fatal("tenantB quota should not be exceeded")
	}
}

// TestAllowTokensZeroQuotaSkipsCheck verifies that tokensPerMin=0 always allows.
func TestAllowTokensZeroQuotaSkipsCheck(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	for i := 0; i < 100; i++ {
		allowed, retry := s.AllowTokens("tenant1", 1000, 0, 0)
		if !allowed {
			t.Fatalf("tokensPerMin=0 should always allow, denied at iteration %d", i)
		}
		if retry != 0 {
			t.Errorf("retry should be 0 for tokensPerMin=0, got %d", retry)
		}
	}
}

// TestAllowTokensHotPath is constraint test: calls AllowTokens
// 10,000 times under GOMAXPROCS=1 and asserts p99 latency < 1 µs.
//
// Per-call timing with time.Now introduces ~100-200 ns overhead per
// measurement on cloud VMs (vDSO call latency). To get accurate per-call
// latency without measurement noise, we time batches of 100 calls and divide,
// giving the average nanoseconds/call. The p99 of these batch averages is a
// reliable proxy for the single-call p99 on an uncontended hot path.
func TestAllowTokensHotPath(t *testing.T) {
	const (
		calls        = 10_000
		batchSize    = 100
		tokensPerMin = 10_000_000 // large budget so quota never triggers
		p99Target    = 1_000      // nanoseconds per call
	)

	prevGOMAXPROCS := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prevGOMAXPROCS)

	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	// Warm up the entry so it exists in quotaMap before timing.
	s.AllowTokens("t", 1, tokensPerMin, 0)

	batches := calls / batchSize
	batchAvgNs := make([]int64, batches)
	for i := range batchAvgNs {
		start := time.Now()
		for j := 0; j < batchSize; j++ {
			s.AllowTokens("t", 1, tokensPerMin, 0)
		}
		batchAvgNs[i] = time.Since(start).Nanoseconds() / batchSize
	}

	sort.Slice(batchAvgNs, func(i, j int) bool { return batchAvgNs[i] < batchAvgNs[j] })
	p99 := batchAvgNs[int(float64(batches)*0.99)]

	if p99 > p99Target {
		t.Errorf(" hot-path p99 latency = %dns/call, want < %dns/call", p99, p99Target)
	}
	t.Logf("AllowTokens hot-path p99 latency (batch avg): %dns/call (target < %dns/call)", p99, p99Target)
}

// TestCleanupRemovesInactive verifies that the cleanup logic removes entries
// that have been inactive longer than cleanupInactiveAfter.
func TestCleanupRemovesInactive(t *testing.T) {
	s := newTestStore()

	// Seed two entries.
	s.CheckKey("active", 10, 10)
	s.CheckKey("inactive", 10, 10)

	// Backdate the inactive entry's lastAccess beyond the cleanup threshold.
	s.mu.Lock()
	s.entries["k:inactive"].lastAccess = time.Now().Add(-(cleanupInactiveAfter + time.Second))
	s.mu.Unlock()

	s.doCleanup()

	s.mu.Lock()
	_, hasActive := s.entries["k:active"]
	_, hasInactive := s.entries["k:inactive"]
	s.mu.Unlock()

	if !hasActive {
		t.Fatal("active entry should not have been removed by cleanup")
	}
	if hasInactive {
		t.Fatal("inactive entry should have been removed by cleanup")
	}
}

// TestTokenQuotaSnapshot verifies the scrape-time view of the quota map:
// spent-not-yet-refilled tokens and the limit per tenant, no entry for
// unlimited tenants, limit refresh on the next charge, and the spent value
// decaying to 0 through refill alone with no further charges (the
// idle/denied-tenant case the collector exists to report truthfully).
func TestTokenQuotaSnapshot(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	if snap := s.TokenQuotaSnapshot(); len(snap) != 0 {
		t.Fatalf("expected empty snapshot before any charge, got %d entries", len(snap))
	}

	s.AllowTokens("tenant1", 30, 100, 0)
	s.AllowTokens("tenant1", 20, 100, 0)
	// tokensPerMin=0 skips the quota map entirely — no entry to report.
	s.AllowTokens("tenant2", 500, 0, 0)

	snap := s.TokenQuotaSnapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshot entry, got %d", len(snap))
	}
	if snap[0].TenantID != "tenant1" || snap[0].Consumed != 50 || snap[0].Limit != 100 {
		t.Fatalf("unexpected snapshot entry: %+v", snap[0])
	}

	// A quota config change surfaces on the tenant's next charge — and it
	// rescales the whole outstanding debt to the new refill rate: 50 tokens
	// of debt at 100/min is 30s of drain time, which at 200/min prices as
	// 100 tokens; plus 10 charged at 200/min = 110.
	s.AllowTokens("tenant1", 10, 200, 0)
	snap = s.TokenQuotaSnapshot()
	if snap[0].Consumed != 110 || snap[0].Limit != 200 {
		t.Fatalf("expected consumed=110 limit=200 after config change, got %+v", snap[0])
	}

	// Refill with NO further charges: the spent value must decay to 0 (the
	// quota refilled on its own) while the limit stays known.
	advanceQuotaClock(60_000)
	snap = s.TokenQuotaSnapshot()
	if len(snap) != 1 || snap[0].Consumed != 0 || snap[0].Limit != 200 {
		t.Fatalf("expected consumed=0 limit=200 after refill, got %+v", snap)
	}
}

// TestReserveTokensAdmission pins the pre-admission contract: a reservation
// that fits (consumed + reserved + want <= limit) is admitted; one that does
// not is denied BEFORE dispatch. A reservation denial must NOT latch the
// exceeded flag — it is a function of this request's size, and a smaller
// request from the same tenant must still be admissible in the same window.
func TestReserveTokensAdmission(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 1000

	allowed, _, ep := s.ReserveTokens("tenant1", 600, tokensPerMin, 0)
	if !allowed || ep == 0 {
		t.Fatalf("first reservation within quota must be admitted (allowed=%v epoch=%d)", allowed, ep)
	}

	// 600 reserved + 500 wanted > 1000: deny.
	allowed, retry, ep2 := s.ReserveTokens("tenant1", 500, tokensPerMin, 0)
	if allowed {
		t.Fatal("reservation exceeding the window headroom must be denied")
	}
	if retry <= 0 {
		t.Fatal("denied reservation must carry a retry-after hint")
	}
	if ep2 != 0 {
		t.Fatal("denied reservation must not return a settleable epoch")
	}

	// The deny must not latch: the gate's stage-3 latch check would otherwise
	// bounce every request until rollover.
	if s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("reservation denial must not latch the exceeded flag")
	}

	// A smaller request still fits (600 + 300 <= 1000) — and the denied
	// reservation must not have leaked its claim into the counter.
	allowed, _, _ = s.ReserveTokens("tenant1", 300, tokensPerMin, 0)
	if !allowed {
		t.Fatal("smaller reservation must be admitted after a larger one was denied")
	}
}

// TestReserveSettleReleasesAndCharges verifies the reconcile half of the
// contract: settlement replaces the pessimistic reservation with the real
// charge, crediting the difference back promptly so bursty tenants do not
// starve.
func TestReserveSettleReleasesAndCharges(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 1000

	allowed, _, ep := s.ReserveTokens("tenant1", 500, tokensPerMin, 0)
	if !allowed {
		t.Fatal("reservation should be admitted")
	}

	// Completion finished far short of max_tokens: actual charge 100.
	if allowed, _ := s.SettleTokens("tenant1", 100, 500, ep, tokensPerMin, 0); !allowed {
		t.Fatal("settlement within quota should be allowed")
	}

	// The freed 400 must be reusable at once: 100 consumed + 900 wanted = 1000.
	allowed, _, _ = s.ReserveTokens("tenant1", 900, tokensPerMin, 0)
	if !allowed {
		t.Fatal("released reservation headroom must be reusable immediately")
	}
}

// TestSettleChargeLatchesWhenOverQuota verifies settlement keeps AllowTokens'
// latch semantics: a real charge that tips the tenant over quota latches the
// exceeded flag for the gate's post-hoc stage-3 check.
func TestSettleChargeLatchesWhenOverQuota(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	_, _, ep := s.ReserveTokens("tenant1", 50, tokensPerMin, 0)
	// The engine produced more than reserved (client under-declared max_tokens
	// or the estimate ran hot): the real charge wins and latches.
	allowed, retry := s.SettleTokens("tenant1", 150, 50, ep, tokensPerMin, 0)
	if allowed || retry <= 0 {
		t.Fatalf("over-quota settlement must deny and latch (allowed=%v retry=%d)", allowed, retry)
	}
	if !s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("over-quota settlement must latch the exceeded flag")
	}
}

// TestSettleSkipsReleaseAfterRollover pins the epoch-tag rule: a reservation
// made in window N must not be released from window N+1's counter — the
// rollover already wiped it, and releasing again would steal a claim held by
// the new window's in-flight requests.
func TestSettleSkipsReleaseAfterRollover(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 1000

	s.ReserveTokens("tenant1", 400, tokensPerMin, 0)

	// Roll the window over (the epoch-advance simulation used throughout this
	// file), then let a NEW request win the reset and record its claim. The
	// global epoch counter cannot be advanced from a test, so the first
	// reservation's tag is made stale RELATIVE to the entry: after the forced
	// rollover it reads as freshEp-1, one window behind the entry's current
	// window — exactly the state a real rollover leaves behind.
	v, _ := s.quotaMap.Load("tenant1")
	e := v.(*tokenWindowEntry)
	atomic.StoreInt64(&e.windowEpoch, atomic.LoadInt64(&e.windowEpoch)-1)
	_, _, freshEp := s.ReserveTokens("tenant1", 300, tokensPerMin, 0)
	staleEp := freshEp - 1
	if got := atomic.LoadInt64(&e.reserved); got != 300 {
		t.Fatalf("rollover winner must seed reserved with its own claim only, got %d", got)
	}

	// Settling the STALE reservation must charge but not release.
	s.SettleTokens("tenant1", 50, 400, staleEp, tokensPerMin, 0)
	if got := atomic.LoadInt64(&e.reserved); got != 300 {
		t.Fatalf("stale-epoch settlement must not touch the new window's reserved, got %d", got)
	}
	if got := quotaDebtTokens(t, s, "tenant1"); got != 50 {
		t.Fatalf("stale-epoch settlement must still charge the actual tokens, got %d", got)
	}
}

// TestReserveOversizeNeverAdmits verifies a request whose declared ceiling
// exceeds the whole per-minute quota is denied even in a fresh window, and
// records no phantom claim while doing so.
func TestReserveOversizeNeverAdmits(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	allowed, _, ep := s.ReserveTokens("tenant1", 500, tokensPerMin, 0)
	if allowed || ep != 0 {
		t.Fatal("reservation larger than the whole quota must be denied with no epoch")
	}
	// The failed admission must not consume headroom.
	if allowed, _, _ := s.ReserveTokens("tenant1", 100, tokensPerMin, 0); !allowed {
		t.Fatal("full-quota reservation must be admitted after an oversize deny")
	}
}

// TestReserveZeroConfigSkips verifies the no-quota and nothing-to-reserve
// short-circuits: always admitted, nothing recorded, epoch 0.
func TestReserveZeroConfigSkips(t *testing.T) {
	pinQuotaClock(t)
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	if allowed, _, ep := s.ReserveTokens("tenant1", 1000, 0, 0); !allowed || ep != 0 {
		t.Fatal("tokensPerMin=0 must skip reservation and admit")
	}
	if allowed, _, ep := s.ReserveTokens("tenant1", 0, 100, 0); !allowed || ep != 0 {
		t.Fatal("want=0 must skip reservation and admit")
	}
	// SettleTokens with no reservation degenerates to a plain charge.
	if allowed, _ := s.SettleTokens("tenant1", 50, 0, 0, 100, 0); !allowed {
		t.Fatal("degenerate settlement within quota must be allowed")
	}
	if _, ok := s.quotaMap.Load("tenant1"); !ok {
		t.Fatal("degenerate settlement must still create the charge entry")
	}
	if got := quotaDebtTokens(t, s, "tenant1"); got != 50 {
		t.Fatalf("degenerate settlement must charge 50, got %d", got)
	}
}

// TestReservedClampNeverNegative pins the double-release defense: releasing
// the same reservation twice (a C-side settle raced with a teardown path)
// must floor the counter at zero, never grant phantom headroom.
func TestReservedClampNeverNegative(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 1000

	_, _, ep := s.ReserveTokens("tenant1", 200, tokensPerMin, 0)
	s.SettleTokens("tenant1", 10, 200, ep, tokensPerMin, 0)
	s.SettleTokens("tenant1", 10, 200, ep, tokensPerMin, 0) // double settle

	v, _ := s.quotaMap.Load("tenant1")
	e := v.(*tokenWindowEntry)
	if got := atomic.LoadInt64(&e.reserved); got != 0 {
		t.Fatalf("reserved must clamp at 0 after double release, got %d", got)
	}
	// Admission math must still be sound: 20 consumed, 0 reserved → 980 fits.
	if allowed, _, _ := s.ReserveTokens("tenant1", 980, tokensPerMin, 0); !allowed {
		t.Fatal("admission after double release must use clamped (not negative) reserved")
	}
}

// TestAllowTokensRolloverZeroesReserved verifies the plain-charge rollover
// path also wipes stale reservations — a tenant whose requests all settle
// through AllowTokens (no reservations recorded) must not carry a dead claim
// from a previous window into admission arithmetic.
func TestAllowTokensRolloverZeroesReserved(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 1000

	s.ReserveTokens("tenant1", 900, tokensPerMin, 0)

	v, _ := s.quotaMap.Load("tenant1")
	e := v.(*tokenWindowEntry)
	atomic.StoreInt64(&e.windowEpoch, atomic.LoadInt64(&e.windowEpoch)-1)

	// A plain charge wins the rollover reset.
	s.AllowTokens("tenant1", 100, tokensPerMin, 0)
	if got := atomic.LoadInt64(&e.reserved); got != 0 {
		t.Fatalf("AllowTokens rollover must zero reserved, got %d", got)
	}
	if allowed, _, _ := s.ReserveTokens("tenant1", 900, tokensPerMin, 0); !allowed {
		t.Fatal("new window must admit against consumed only (100 + 900 <= 1000)")
	}
}

// TestCleanupEvictsIdleQuotaEntries pins the quota-map half of doCleanup: a
// tenant whose windowEpoch is the eviction horizon (or more) behind the
// current epoch is dropped — reclaiming both the map entry and its
// scrape-time metric series — while a recently active tenant survives, and
// an evicted tenant's next charge simply recreates it from zero.
func TestCleanupEvictsIdleQuotaEntries(t *testing.T) {
	pinQuotaClock(t)
	s := newTestStore()

	s.AllowTokens("fresh", 10, 100, 0)
	s.AllowTokens("idle", 10, 100, 0)

	// Backdate the idle tenant to exactly the eviction horizon.
	v, ok := s.quotaMap.Load("idle")
	if !ok {
		t.Fatal("idle tenant missing from quotaMap after charge")
	}
	e := v.(*tokenWindowEntry)
	atomic.StoreInt64(&e.windowEpoch,
		currentQuotaEpoch.Load()-quotaEvictAfterWindows)

	s.doCleanup()

	if _, ok := s.quotaMap.Load("idle"); ok {
		t.Fatal("idle tenant should have been evicted from quotaMap")
	}
	if _, ok := s.quotaMap.Load("fresh"); !ok {
		t.Fatal("fresh tenant must survive quota-map eviction")
	}
	for _, u := range s.TokenQuotaSnapshot() {
		if u.TenantID == "idle" {
			t.Fatal("evicted tenant must disappear from TokenQuotaSnapshot")
		}
	}

	// One window shy of the horizon must NOT be evicted.
	v, _ = s.quotaMap.Load("fresh")
	e = v.(*tokenWindowEntry)
	atomic.StoreInt64(&e.windowEpoch,
		currentQuotaEpoch.Load()-quotaEvictAfterWindows+1)
	s.doCleanup()
	if _, ok := s.quotaMap.Load("fresh"); !ok {
		t.Fatal("tenant inside the eviction horizon must not be evicted")
	}

	// A returning tenant restarts from a full bucket.
	if allowed, _ := s.AllowTokens("idle", 10, 100, 0); !allowed {
		t.Fatal("returning tenant must be re-admitted after eviction")
	}
	if _, ok = s.quotaMap.Load("idle"); !ok {
		t.Fatal("returning tenant must be recreated in quotaMap")
	}
	if c := quotaDebtTokens(t, s, "idle"); c != 10 {
		t.Fatalf("recreated tenant should hold only the new charge, got %d", c)
	}
}

// TestQuotaWarmupPeerEndsWarming pins the cold-start happy path: a store in
// the warming state blocks nothing forever — the FIRST received peer batch
// (snapshot or gossip delta) flips it warm and reports failOpen=false, and
// the outcome callback fires exactly once even when the deadline timer and
// further batches follow.
func TestQuotaWarmupPeerEndsWarming(t *testing.T) {
	s := newTestStore()
	var calls int32
	var lastFailOpen atomic.Bool
	s.StartQuotaWarmup(50*time.Millisecond, func(failOpen bool) {
		atomic.AddInt32(&calls, 1)
		lastFailOpen.Store(failOpen)
	})
	if !s.QuotaWarming() {
		t.Fatal("store must report warming after StartQuotaWarmup")
	}

	s.ImportState([]RateLimiterEntry{{
		KeyID: "t:tenant1", IsTenant: true,
		WindowEpoch: currentQuotaEpoch.Load(), Consumed: 40,
	}})
	if s.QuotaWarming() {
		t.Fatal("peer snapshot must end the warmup")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("outcome callback should have fired once, got %d", n)
	}
	if lastFailOpen.Load() {
		t.Fatal("peer-warmed outcome must report failOpen=false")
	}

	// Let the deadline pass and feed another batch: no second callback.
	time.Sleep(80 * time.Millisecond)
	s.ApplyGossipDelta([]RateLimiterEntry{{
		KeyID: "t:tenant1", IsTenant: true,
		WindowEpoch: currentQuotaEpoch.Load(), Consumed: 50,
	}})
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("outcome callback must be single-shot, got %d calls", n)
	}
}

// TestQuotaWarmupTimeoutFailsOpen pins the bounded-wait contract: with no
// peer batch inside the deadline the store flips warm on its own and the
// outcome callback reports failOpen=true — the signal the caller must turn
// into a metric so a cold fail-open window is never silent.
func TestQuotaWarmupTimeoutFailsOpen(t *testing.T) {
	s := newTestStore()
	done := make(chan bool, 1)
	s.StartQuotaWarmup(20*time.Millisecond, func(failOpen bool) { done <- failOpen })

	select {
	case failOpen := <-done:
		if !failOpen {
			t.Fatal("deadline expiry must report failOpen=true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("warmup deadline never fired")
	}
	if s.QuotaWarming() {
		t.Fatal("store must be warm after the deadline")
	}
}

// TestQuotaWarmupDisabled pins the opt-in default: without StartQuotaWarmup
// (or with a non-positive timeout) the store is warm from construction and
// peer batches change nothing about that.
func TestQuotaWarmupDisabled(t *testing.T) {
	s := newTestStore()
	if s.QuotaWarming() {
		t.Fatal("a fresh store must not be warming by default")
	}
	s.StartQuotaWarmup(0, func(bool) { t.Fatal("disabled warmup must never fire its callback") })
	if s.QuotaWarming() {
		t.Fatal("timeout<=0 must leave the store warm")
	}
	s.ImportState(nil)
}

// TestBurstTokensForPerTenantOverride pins the resolution order of the
// capacity knob: a tenant value wins, zero falls back to the process-wide
// default, and an out-of-range tenant value is clamped rather than trusted —
// a bad row in the database must be no more dangerous than a bad environment
// variable.
func TestBurstTokensForPerTenantOverride(t *testing.T) {
	saved := quotaBurstPct
	quotaBurstPct = 100
	defer func() { quotaBurstPct = saved }()

	cases := []struct {
		name  string
		limit int64
		pct   int64
		want  int64
	}{
		{"zero falls back to the process default", 1000, 0, 1000},
		{"negative falls back too", 1000, -5, 1000},
		{"tenant override halves the bucket", 1000, 50, 500},
		{"tenant override widens the bucket", 1000, 300, 3000},
		{"above the ceiling clamps to max", 1000, 99999, 1000 * quotaBurstMaxPct / 100},
		{"the smallest accepted override is the floor", 1000, quotaBurstMinPct, 10},
		{"a bucket never rounds down to zero", 10, 1, 1},
	}
	for _, c := range cases {
		if got := burstTokensFor(c.limit, c.pct); got != c.want {
			t.Errorf("%s: burstTokensFor(%d, %d) = %d, want %d", c.name, c.limit, c.pct, got, c.want)
		}
	}
}

// TestReserveTokensHonoursPerTenantBurst is the behavioural half: the same
// request that a default-capacity tenant is admitted for must be refused for
// a tenant whose configured burst cannot hold it. Without the knob reaching
// the bucket, both calls would be admitted and the config would be decorative.
func TestReserveTokensHonoursPerTenantBurst(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}
	const tokensPerMin = 1000

	// Default capacity (100%): a 900-token claim fits inside the bucket.
	if allowed, _, _ := s.ReserveTokens("wide", 900, tokensPerMin, 0); !allowed {
		t.Fatal("900 of a 1000 TPM quota must be admitted at the default burst")
	}

	// Same quota, capacity narrowed to 50%: the bucket only holds 500, so the
	// claim can never be satisfied and must be denied outright.
	allowed, retry, ep := s.ReserveTokens("narrow", 900, tokensPerMin, 50)
	if allowed {
		t.Fatal("900 tokens must be denied for a tenant whose burst holds 500")
	}
	if retry <= 0 {
		t.Fatal("denied reservation must carry a retry-after hint")
	}
	if ep != 0 {
		t.Fatal("a claim larger than the bucket must not be recorded")
	}

	// The narrowed tenant is not broken, only narrower: a claim that fits its
	// bucket is still admitted.
	if allowed, _, _ := s.ReserveTokens("narrow", 400, tokensPerMin, 50); !allowed {
		t.Fatal("400 tokens must still be admitted at a 50% burst of 1000 TPM")
	}
}

// TestIsTokenQuotaExceededUsesStoredBurst proves the knob survives the trip
// through the entry. IsTokenQuotaExceeded is handed a key and nothing else —
// no service to ask for config — so if the charge did not publish the tenant's
// capacity onto the entry, the debt threshold would silently revert to the
// process-wide default for every read the request gate makes.
func TestIsTokenQuotaExceededUsesStoredBurst(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}
	const tokensPerMin = 600

	// 900 tokens against a 600 TPM quota. At the default 100% capacity the
	// bucket holds 600, so the charge lands 300 beyond empty — in debt.
	if allowed, _ := s.AllowTokens("dflt", 900, tokensPerMin, 0); allowed {
		t.Fatal("a charge past the default burst must report debt")
	}
	if !s.IsTokenQuotaExceeded("dflt") {
		t.Fatal("gate must see the debt the charge just reported")
	}

	// Same charge, same quota, capacity widened to 300%: the bucket holds
	// 1800, so 900 sits comfortably inside it and the gate must stay open.
	if allowed, _ := s.AllowTokens("wide", 900, tokensPerMin, 300); !allowed {
		t.Fatal("a charge inside a widened burst must not report debt")
	}
	if s.IsTokenQuotaExceeded("wide") {
		t.Fatal("gate read the default capacity instead of the tenant's stored one")
	}
}
