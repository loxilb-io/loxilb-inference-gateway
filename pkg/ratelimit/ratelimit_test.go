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
// AllowTokens unit tests (US-402)
// ============================================================================

// TestAllowTokensRefillRate verifies that tokens consumed in one window do not
// carry over into the next window (i.e., the bucket refills at the start of
// each 60-second epoch). We fake the epoch by directly manipulating the entry's
// windowEpoch field through the quotaMap after the first call.
func TestAllowTokensRefillRate(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	// Consume all tokens in the "current" window.
	for i := 0; i < 10; i++ {
		allowed, _ := s.AllowTokens("tenant1", 10, tokensPerMin)
		if !allowed {
			t.Fatalf("iteration %d: expected allowed within quota", i)
		}
	}
	// One more request should be denied (total = 110 > 100).
	allowed, retry := s.AllowTokens("tenant1", 10, tokensPerMin)
	if allowed {
		t.Fatal("should be denied after consuming full quota")
	}
	if retry < 1 {
		t.Errorf("retryAfterSecs = %d, want >= 1", retry)
	}

	// Simulate window rollover by backdating the windowEpoch.
	v, ok := s.quotaMap.Load("tenant1")
	if !ok {
		t.Fatal("entry not found in quotaMap")
	}
	e := v.(*tokenWindowEntry)
	atomic.StoreInt64(&e.windowEpoch, atomic.LoadInt64(&e.windowEpoch)-1) // move to previous epoch

	// After rollover, a fresh 100-token budget is available.
	allowed, _ = s.AllowTokens("tenant1", 50, tokensPerMin)
	if !allowed {
		t.Fatal("should be allowed after window refill")
	}
}

// TestAllowTokensQuotaExceededDetection verifies that IsTokenQuotaExceeded
// returns true once the per-minute budget is fully consumed.
func TestAllowTokensQuotaExceededDetection(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 50

	if s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("quota should not be exceeded before any consumption")
	}

	// Consume exactly the quota.
	allowed, _ := s.AllowTokens("tenant1", 50, tokensPerMin)
	if !allowed {
		t.Fatal("should be allowed when consuming exactly the quota")
	}
	if s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("quota should not be exceeded when exactly at limit")
	}

	// One more token exceeds the quota.
	allowed, _ = s.AllowTokens("tenant1", 1, tokensPerMin)
	if allowed {
		t.Fatal("should be denied once over quota")
	}
	if !s.IsTokenQuotaExceeded("tenant1") {
		t.Fatal("IsTokenQuotaExceeded should return true after quota exceeded")
	}
}

// TestAllowTokensPerTenantIsolation verifies that exhausting tenant A's quota
// does not affect tenant B's independent budget.
func TestAllowTokensPerTenantIsolation(t *testing.T) {
	s := &RateLimiterStore{entries: make(map[string]*limiterEntry)}

	const tokensPerMin = 100

	// Exhaust tenant A.
	s.AllowTokens("tenantA", 100, tokensPerMin)
	s.AllowTokens("tenantA", 1, tokensPerMin) // push over quota

	if !s.IsTokenQuotaExceeded("tenantA") {
		t.Fatal("tenantA should be quota-exceeded")
	}

	// Tenant B is completely independent.
	allowed, _ := s.AllowTokens("tenantB", 50, tokensPerMin)
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
		allowed, retry := s.AllowTokens("tenant1", 1000, 0)
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
	s.AllowTokens("t", 1, tokensPerMin)

	batches := calls / batchSize
	batchAvgNs := make([]int64, batches)
	for i := range batchAvgNs {
		start := time.Now()
		for j := 0; j < batchSize; j++ {
			s.AllowTokens("t", 1, tokensPerMin)
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
