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

// Package ratelimit provides an in-memory, goroutine-safe token-bucket rate
// limiter store for the AI Gateway data plane. Limiters are created on demand
// and removed by a background cleanup goroutine after a period of inactivity.
package ratelimit

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	// cleanupInactiveAfter is the inactivity duration after which an entry is
	// removed by the background Cleanup goroutine.
	cleanupInactiveAfter = 10 * time.Minute

	// cleanupInterval is how often the background Cleanup goroutine runs.
	cleanupInterval = time.Minute

	// epochInterval is the duration of one token-quota accounting window.
	epochInterval = time.Minute
)

// currentQuotaEpoch is an atomically updated counter incremented every
// epochInterval by the init goroutine. AllowTokens compares the per-entry
// windowEpoch against this value to detect window rollovers without calling
// time.Now on every hot-path invocation (: no syscall per call).
var currentQuotaEpoch atomic.Int64

func init() {
	// Initialise the epoch counter before any calls to AllowTokens.
	currentQuotaEpoch.Store(time.Now().Unix() / int64(epochInterval.Seconds()))
	go func() {
		ticker := time.NewTicker(epochInterval)
		defer ticker.Stop()
		for range ticker.C {
			currentQuotaEpoch.Store(time.Now().Unix() / int64(epochInterval.Seconds()))
		}
	}()
}

// limiterEntry holds a token-bucket rate limiter together with its current
// configuration and the time it was last accessed.
type limiterEntry struct {
	limiter    *rate.Limiter
	rps        int
	burst      int
	lastAccess time.Time
}

// RateLimiterStore is a goroutine-safe collection of per-ID token-bucket rate
// limiters. Entries are created on demand and identified by a string key.
type RateLimiterStore struct {
	mu       sync.Mutex
	entries  map[string]*limiterEntry
	quotaMap sync.Map // map[string]*tokenWindowEntry for per-tenant token quota
}

// tokenWindowEntry tracks per-tenant token consumption in 60-second epochs.
// All mutable fields use atomic operations to satisfy the data-plane hot-path
// constraint: no mutex contention per call.
type tokenWindowEntry struct {
	windowEpoch int64 // floor(unixSeconds / 60), updated via CAS
	consumed    int64 // tokens consumed in current window, updated via Add
	limitTokens int64 // tokens-per-minute quota seen on the last charge; read by TokenQuotaSnapshot
	exceeded    int32 // 1 = quota exceeded for this window, 0 = within quota
}

// New creates a new RateLimiterStore and starts the background Cleanup goroutine.
func New() *RateLimiterStore {
	s := &RateLimiterStore{
		entries: make(map[string]*limiterEntry),
	}
	go s.Cleanup()
	return s
}

// CheckKey tests whether a request associated with keyID is within the
// configured per-key rate limit.
//
// rps is the allowed rate (requests per second). burst is the maximum burst
// size; if burst <= 0 it defaults to rps. If rps <= 0, the check is skipped
// and the request is allowed unconditionally.
//
// Returns (true, 0) when the request is allowed, or (false, retryAfterSecs)
// when it is rate-limited.
func (s *RateLimiterStore) CheckKey(keyID string, rps, burst int) (allowed bool, retryAfterSecs int) {
	if rps <= 0 {
		return true, 0
	}
	if burst <= 0 {
		burst = rps
	}
	return s.check("k:"+keyID, rps, burst)
}

// CheckTenant tests whether a request associated with tenantID is within the
// configured per-tenant rate limit.
//
// rps is the allowed rate (requests per second); burst is implicitly set to
// rps. If rps <= 0, the check is skipped and the request is allowed
// unconditionally.
//
// Returns (true, 0) when the request is allowed, or (false, retryAfterSecs)
// when it is rate-limited.
func (s *RateLimiterStore) CheckTenant(tenantID string, rps int) (allowed bool, retryAfterSecs int) {
	if rps <= 0 {
		return true, 0
	}
	return s.check("t:"+tenantID, rps, rps)
}

// UpdateKey replaces (or creates) the per-key rate limiter with a fresh bucket
// configured for the new rps and burst values. If burst <= 0, it defaults to
// rps. Call this whenever the key-level rate limit config changes so that the
// in-memory bucket is reset immediately.
func (s *RateLimiterStore) UpdateKey(keyID string, rps, burst int) {
	if burst <= 0 {
		burst = rps
	}
	s.update("k:"+keyID, rps, burst)
}

// UpdateTenant replaces (or creates) the per-tenant rate limiter with a fresh
// bucket configured for rps requests per second. Call this whenever the
// tenant-level rate limit config changes.
func (s *RateLimiterStore) UpdateTenant(tenantID string, rps int) {
	s.update("t:"+tenantID, rps, rps)
}

// AllowTokens records consumption of count tokens against the tenant's per-minute
// quota. tokensPerMin is the configured limit; if <= 0 the check is skipped and
// all calls are allowed.
//
// The function uses atomic operations only (no mutex) to satisfy the data-plane
// hot-path constraint. Tokens refill effectively at tokensPerMin/60
// tokens per second because the accounting window resets every 60 seconds.
//
// Returns (true, 0) when the total tokens consumed so far in the current
// 60-second window do not exceed tokensPerMin.
// Returns (false, retryAfterSecs) when the total exceeds the quota; the
// exceeded flag is set so that the NEXT request's llb_ai_ratelimit_check can
// return decision=3 (HTTP 429) without interrupting the current response.
func (s *RateLimiterStore) AllowTokens(tenantID string, count, tokensPerMin int) (allowed bool, retryAfterSecs int) {
	if tokensPerMin <= 0 || count <= 0 {
		return true, 0
	}

	// Fast path: Load without allocation when the entry already exists.
	// LoadOrStore would allocate a new tokenWindowEntry on every call even when
	// the key is present, violating "no heap alloc per call" constraint.
	v, ok := s.quotaMap.Load(tenantID)
	if !ok {
		v, _ = s.quotaMap.LoadOrStore(tenantID, &tokenWindowEntry{})
	}
	e := v.(*tokenWindowEntry)

	// Publish the limit for scrape-time utilization reads. Plain store: the
	// last charge's view of the config is exactly what the collector should
	// report, and a racing config change resolves on the next charge.
	atomic.StoreInt64(&e.limitTokens, int64(tokensPerMin))

	// Read the pre-computed epoch from the atomic counter updated by the init
	// goroutine every epochInterval. This avoids a time.Now syscall on every
	// hot-path invocation, satisfying (no syscall per call).
	epoch := currentQuotaEpoch.Load()

	// Window rollover: if the current epoch is newer than stored, try to reset.
	// CAS ensures only one goroutine wins the reset; losers proceed with the
	// already-reset values.
	stored := atomic.LoadInt64(&e.windowEpoch)
	if epoch > stored && atomic.CompareAndSwapInt64(&e.windowEpoch, stored, epoch) {
		atomic.StoreInt64(&e.consumed, int64(count))
		// Check if the very first request in the new window already exceeds quota.
		if int64(count) > int64(tokensPerMin) {
			atomic.StoreInt32(&e.exceeded, 1)
			return false, int(epochInterval.Seconds())
		}
		atomic.StoreInt32(&e.exceeded, 0)
		return true, 0
	}

	// Consume tokens atomically.
	newTotal := atomic.AddInt64(&e.consumed, int64(count))
	if newTotal > int64(tokensPerMin) {
		atomic.StoreInt32(&e.exceeded, 1)
		return false, int(epochInterval.Seconds())
	}
	return true, 0
}

// IsTokenQuotaExceeded reports whether the named tenant's token quota is
// currently exceeded. Called by the request-path gate (llb_ai_ratelimit_check)
// to block the next request when the previous response consumed too many tokens.
//
// The exceeded latch belongs to ONE quota window: when the epoch has advanced
// past the window that set it, the quota has refilled and the latch is stale.
// The staleness check must live HERE, on the read side — a tenant whose every
// request is denied at the gate never completes a response, so AllowTokens
// (the only writer that clears the flag) never runs again and the tenant
// would otherwise stay denied forever after one trip.
//
// This function uses only atomic operations (no mutex) to satisfy.
func (s *RateLimiterStore) IsTokenQuotaExceeded(tenantID string) bool {
	if v, ok := s.quotaMap.Load(tenantID); ok {
		e := v.(*tokenWindowEntry)
		if atomic.LoadInt32(&e.exceeded) != 1 {
			return false
		}
		if currentQuotaEpoch.Load() > atomic.LoadInt64(&e.windowEpoch) {
			return false
		}
		return true
	}
	return false
}

// TokenQuotaUsage is a point-in-time view of one tenant's token-quota window,
// returned by TokenQuotaSnapshot for scrape-time metric export.
type TokenQuotaUsage struct {
	TenantID string
	// Consumed is the token count charged in the CURRENT accounting window.
	// An entry whose window has rolled over since the tenant's last charge
	// reads 0: the quota has refilled even though AllowTokens (the only
	// writer that resets the counter) has not run again.
	Consumed int64
	// Limit is the tokens-per-minute quota observed on the tenant's most
	// recent charge. A config change surfaces here on the next charge.
	Limit int64
}

// TokenQuotaSnapshot walks the per-tenant quota map and returns one entry per
// tenant with a known quota limit. It is the read side of the same atomic
// fields the AllowTokens hot path writes — no mutex, the same point-in-time
// semantics as ExportState's quotaMap walk. Entries created by peer-state
// import have no recorded limit until their first local charge and are
// skipped: a utilization ratio cannot be computed without a denominator.
func (s *RateLimiterStore) TokenQuotaSnapshot() []TokenQuotaUsage {
	epoch := currentQuotaEpoch.Load()
	var out []TokenQuotaUsage
	s.quotaMap.Range(func(k, v any) bool {
		tenantID, ok := k.(string)
		if !ok {
			return true
		}
		e, ok := v.(*tokenWindowEntry)
		if !ok {
			return true
		}
		limit := atomic.LoadInt64(&e.limitTokens)
		if limit <= 0 {
			return true
		}
		consumed := atomic.LoadInt64(&e.consumed)
		if atomic.LoadInt64(&e.windowEpoch) < epoch {
			consumed = 0
		}
		out = append(out, TokenQuotaUsage{TenantID: tenantID, Consumed: consumed, Limit: limit})
		return true
	})
	return out
}

// Cleanup runs in a loop and removes entries that have been inactive for longer
// than cleanupInactiveAfter. It is started as a goroutine by New and runs
// until the process exits.
func (s *RateLimiterStore) Cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.doCleanup()
	}
}

// check is the shared implementation used by CheckKey and CheckTenant.
func (s *RateLimiterStore) check(id string, rps, burst int) (bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[id]
	if !ok || e.rps != rps || e.burst != burst {
		// Create a fresh limiter when the entry is new or the config has changed.
		e = &limiterEntry{
			limiter: rate.NewLimiter(rate.Limit(rps), burst),
			rps:     rps,
			burst:   burst,
		}
		s.entries[id] = e
	}
	e.lastAccess = time.Now()

	r := e.limiter.Reserve()
	if !r.OK() {
		// Limiter cannot grant a token at all (e.g. burst=0 was somehow set).
		return false, 1
	}
	delay := r.Delay()
	if delay > 0 {
		// Token not immediately available; cancel the reservation and advise retry.
		r.Cancel()
		secs := max(int(math.Ceil(delay.Seconds())), 1)
		return false, secs
	}
	return true, 0
}

// update is the shared implementation used by UpdateKey and UpdateTenant.
// It always creates a fresh limiter so that config changes take effect
// immediately with a full initial bucket.
func (s *RateLimiterStore) update(id string, rps, burst int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = &limiterEntry{
		limiter:    rate.NewLimiter(rate.Limit(rps), burst),
		rps:        rps,
		burst:      burst,
		lastAccess: time.Now(),
	}
}

// doCleanup removes all entries whose lastAccess time predates the inactivity
// threshold. It is called by the Cleanup goroutine on each tick.
func (s *RateLimiterStore) doCleanup() {
	cutoff := time.Now().Add(-cleanupInactiveAfter)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.entries {
		if e.lastAccess.Before(cutoff) {
			delete(s.entries, id)
		}
	}
}
