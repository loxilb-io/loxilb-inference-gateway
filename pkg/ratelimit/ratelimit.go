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
	"os"
	"strconv"
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

	// epochInterval is the duration of one token-quota activity epoch. The
	// smooth bucket refills continuously (it has no accounting window), but
	// the minute grid remains the unit for idle-entry eviction, for expiring
	// reservations orphaned by aborted requests, and for the retry-advice
	// cap on denials.
	epochInterval = time.Minute

	// quotaEvictFloorWindows is the smallest allowed idle-eviction horizon.
	// Anything under two windows could evict a tenant whose current window
	// simply has not seen its first charge yet.
	quotaEvictFloorWindows = 2

	// quotaEvictDefaultWindows is the idle-eviction horizon when the
	// LLB_AI_QUOTA_EVICT_WINDOWS environment knob is unset: a tenant whose
	// last quota activity is this many whole windows in the past is dropped
	// from the quota map (matches the 10-minute posture of the RPS entries).
	quotaEvictDefaultWindows = 10

	// quotaClockInterval is the refresh period of the coarse millisecond
	// clock the bucket arithmetic reads instead of calling time.Now on the
	// hot path. Staleness only delays refill by up to one period, which is
	// the conservative direction.
	quotaClockInterval = 100 * time.Millisecond

	// quotaBurstDefaultPct is the bucket capacity as a percentage of the
	// tokens-per-minute limit when LLB_AI_QUOTA_BURST_PCT is unset. 100
	// means a fully idle tenant can spend one whole minute's quota at once
	// — the same instantaneous allowance the fixed window granted — while
	// sustained spend is still bounded by the continuous refill rate.
	quotaBurstDefaultPct = 100

	// quotaBurstMinPct / quotaBurstMaxPct clamp the burst knob. The floor
	// keeps a request no larger than 1% of the per-minute quota admittable;
	// the ceiling bounds the credit a long-idle tenant can accumulate.
	quotaBurstMinPct = 1
	quotaBurstMaxPct = 1000

	// msPerMinute is the refill-arithmetic time base: a tokens-per-minute
	// limit refills one token every 60000/limit milliseconds.
	msPerMinute = 60_000
)

// quotaEvictAfterWindows is the effective idle-eviction horizon in whole
// quota windows, resolved once at init from LLB_AI_QUOTA_EVICT_WINDOWS.
var quotaEvictAfterWindows int64 = quotaEvictDefaultWindows

// quotaBurstPct is the bucket capacity in percent of the tokens-per-minute
// limit, resolved once at init from LLB_AI_QUOTA_BURST_PCT.
var quotaBurstPct int64 = quotaBurstDefaultPct

// currentQuotaEpoch is the current minute of the activity-epoch grid,
// refreshed by the clock goroutine. Entries stamp it on every charge or
// reservation; eviction and reservation expiry compare against it without
// calling time.Now on the hot path (no syscall per call).
var currentQuotaEpoch atomic.Int64

// quotaNowMs is the coarse monotonic-enough wall clock (Unix milliseconds)
// the bucket refill arithmetic reads on the hot path, refreshed every
// quotaClockInterval by the clock goroutine.
var quotaNowMs atomic.Int64

// quotaClockFrozen suspends the clock goroutine's stores so tests can pin
// quotaNowMs / currentQuotaEpoch to deterministic values. Never set in
// production code.
var quotaClockFrozen atomic.Bool

func init() {
	// Resolve the quota-map eviction horizon. Clamped to the floor so a
	// misconfigured knob can never evict a live window.
	if v := os.Getenv("LLB_AI_QUOTA_EVICT_WINDOWS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			quotaEvictAfterWindows = max(n, quotaEvictFloorWindows)
		}
	}
	// Resolve the burst knob, clamped so a misconfigured value can neither
	// make every request unadmittable nor grant unbounded stored credit.
	if v := os.Getenv("LLB_AI_QUOTA_BURST_PCT"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			quotaBurstPct = min(max(n, quotaBurstMinPct), quotaBurstMaxPct)
		}
	}
	// Initialise both clocks before any calls to AllowTokens.
	now := time.Now()
	currentQuotaEpoch.Store(now.Unix() / int64(epochInterval.Seconds()))
	quotaNowMs.Store(now.UnixMilli())
	go func() {
		ticker := time.NewTicker(quotaClockInterval)
		defer ticker.Stop()
		for range ticker.C {
			if quotaClockFrozen.Load() {
				continue
			}
			t := time.Now()
			quotaNowMs.Store(t.UnixMilli())
			currentQuotaEpoch.Store(t.Unix() / int64(epochInterval.Seconds()))
		}
	}()
}

// burstTokensFor is the bucket capacity for a tokens-per-minute limit: the
// most a fully idle tenant can spend instantaneously. Never below one token
// so that a configured quota always admits some request.
func burstTokensFor(limit int64) int64 {
	return max(limit*quotaBurstPct/100, 1)
}

// refillCeilMs is the time, in milliseconds rounded up, that `tokens` take
// to refill at `limit` tokens per minute. Rounding up makes the charge side
// conservative: a charge can never be free.
func refillCeilMs(tokens, limit int64) int64 {
	return (tokens*msPerMinute + limit - 1) / limit
}

// debtTokensOf converts a bucket's virtual-drain-time debt back into
// tokens: how much of the bucket's capacity is currently spent and not yet
// refilled. Zero when the drain time has already passed (bucket full or
// refilling toward full). Truncation rounds the debt down — the fail-open
// direction.
func debtTokensOf(tatMs, nowMs, limit int64) int64 {
	if tatMs <= nowMs {
		return 0
	}
	return (tatMs - nowMs) * limit / msPerMinute
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

	// warmState is the token-quota cold-start posture: quotaWarm (default —
	// quota checks run normally) or quotaWarming (this node restarted with
	// empty quota state and is waiting, bounded, for a peer to re-teach it).
	// Written only by the CAS-once transition in endQuotaWarmup.
	warmState atomic.Int32
	// warmDone is the single-shot warmup-outcome callback registered by
	// StartQuotaWarmup. Invoked exactly once (the endQuotaWarmup CAS
	// guarantees it), with failOpen=true when the warmup deadline expired
	// before any peer state arrived. Immutable after StartQuotaWarmup.
	warmDone func(failOpen bool)
}

// Token-quota warm states (RateLimiterStore.warmState).
const (
	quotaWarm    int32 = 0 // normal operation (the zero value: cold-start handling is opt-in)
	quotaWarming int32 = 1 // bounded wait for peer state after a cold start
)

// tokenWindowEntry tracks one quota key's smooth token bucket. All mutable
// fields use atomic operations to satisfy the data-plane hot-path
// constraint: no mutex contention per call.
//
// The bucket is stored in the virtual-drain-time form: tatMs is the absolute
// wall-clock millisecond at which the bucket would return to full. The live
// level is burst - (tatMs-now)*limit/60000, so a tatMs at or behind now
// means a full bucket, now+burstMs means empty, and anything later is debt —
// the over-quota state the gate latches on. A charge advances tatMs by the
// charged tokens' refill time; idle time drains the debt continuously, which
// is what closes the fixed window's boundary-burst hole: spend is bounded by
// burst + rate*Δt over EVERY interval, not per minute-aligned window.
//
// tatMs only ever moves forward, so peer-sync merges stay the same
// take-the-max shape the fixed window's monotonic consumed counter had.
type tokenWindowEntry struct {
	// windowEpoch is the minute (floor(unixSeconds/60)) of the entry's most
	// recent charge or reservation, updated via CAS. It is not part of the
	// bucket arithmetic: it drives idle eviction, expires reservations
	// orphaned by aborted requests (the epoch advance zeroes reserved), and
	// rides the sync wire's WindowEpoch slot as an activity stamp.
	windowEpoch int64
	// tatMs is the bucket state: the absolute Unix millisecond at which the
	// bucket's outstanding spend is fully refilled. Monotonic via CAS.
	// Carried in the sync wire's Consumed slot; because all peers share the
	// wall-clock time base, max-merge unions two nodes' views of the same
	// tenant exactly as it did for the per-window counter. HA peers must
	// therefore run the same gateway version — an old peer would read a
	// millisecond timestamp as a token count.
	tatMs int64
	// reserved holds tokens promised to in-flight requests (prompt estimate +
	// max_tokens, reserved at admission and released when the real charge
	// settles). It is NODE-LOCAL state: never exported on the peer-sync wire
	// (RateLimiterEntry stays untouched) — a reservation is a transient claim
	// on THIS node's admission decision, not consumed quota. It is zeroed
	// when windowEpoch advances, which bounds any reservation orphaned by an
	// aborted request to one 60-second epoch, exactly as the fixed window's
	// rollover reset did.
	reserved    int64
	limitTokens int64 // tokens-per-minute quota seen on the last charge; read by TokenQuotaSnapshot
}

// touchQuotaEpoch stamps the entry's activity epoch with the current minute.
// The winner of the minute-advance CAS also expires the previous epoch's
// reservations: any claim still outstanding after a whole minute belongs to
// an aborted request that will never settle (its settlement, if it does
// arrive, carries the stale epoch tag and skips the release).
func touchQuotaEpoch(e *tokenWindowEntry) {
	epoch := currentQuotaEpoch.Load()
	stored := atomic.LoadInt64(&e.windowEpoch)
	if epoch > stored && atomic.CompareAndSwapInt64(&e.windowEpoch, stored, epoch) {
		atomic.StoreInt64(&e.reserved, 0)
	}
}

// chargeTat advances the entry's virtual drain time by count tokens' refill
// time and returns the new value. The floor clamp at now expires idle
// credit beyond a full bucket; the CAS loop keeps the advance monotonic
// under concurrent charges.
func chargeTat(e *tokenWindowEntry, count, limit, nowMs int64) int64 {
	inc := refillCeilMs(count, limit)
	for {
		cur := atomic.LoadInt64(&e.tatMs)
		next := max(cur, nowMs) + inc
		if atomic.CompareAndSwapInt64(&e.tatMs, cur, next) {
			return next
		}
	}
}

// New creates a new RateLimiterStore and starts the background Cleanup goroutine.
func New() *RateLimiterStore {
	s := &RateLimiterStore{
		entries: make(map[string]*limiterEntry),
	}
	go s.Cleanup()
	return s
}

// StartQuotaWarmup puts the store into the token-quota warming state for at
// most timeout: a node that restarts loses its in-memory quota counters, so
// until a peer re-teaches it (the first received sync batch — ImportState or
// ApplyGossipDelta — ends the warmup) the admission gate treats every
// quota-limited tenant as not-yet-decidable rather than silently fail-open.
//
// onDone is invoked exactly once when the warmup ends: failOpen=false when
// peer state arrived in time, failOpen=true when the deadline expired first
// and the node is now serving a cold window fail-open — the caller must make
// that visible (metric + log), because a silently cold node is
// indistinguishable from a healthy one.
//
// Call BEFORE the store is registered with the sync coordinator, and only
// once, at store construction time: a peer batch that lands between
// registration and a later StartQuotaWarmup would have its warm signal
// dropped. A timeout <= 0 is a no-op (the store stays warm).
func (s *RateLimiterStore) StartQuotaWarmup(timeout time.Duration, onDone func(failOpen bool)) {
	if timeout <= 0 {
		return
	}
	s.warmDone = onDone
	s.warmState.Store(quotaWarming)
	time.AfterFunc(timeout, func() { s.endQuotaWarmup(true) })
}

// QuotaWarming reports whether the store is still waiting for peer quota
// state after a cold start. Atomic read — safe on the hot path.
func (s *RateLimiterStore) QuotaWarming() bool {
	return s.warmState.Load() == quotaWarming
}

// endQuotaWarmup performs the CAS-once warming→warm transition and fires the
// outcome callback. Races between the deadline timer and a peer batch are
// settled by the CAS: whichever caller wins reports its outcome, the loser
// is a no-op.
func (s *RateLimiterStore) endQuotaWarmup(failOpen bool) {
	if !s.warmState.CompareAndSwap(quotaWarming, quotaWarm) {
		return
	}
	if s.warmDone != nil {
		s.warmDone(failOpen)
	}
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

// AllowTokens records consumption of count tokens against the key's
// per-minute quota. tokensPerMin is the configured limit; if <= 0 the check
// is skipped and all calls are allowed.
//
// The function uses atomic operations only (no mutex) to satisfy the
// data-plane hot-path constraint. The bucket refills continuously at
// tokensPerMin per minute up to the burst capacity; the charge always
// lands (this is the post-hoc settlement side — the tokens are already
// spent), and the return value reports whether the bucket is now in debt.
//
// Returns (true, 0) while the bucket stays at or above empty.
// Returns (false, retryAfterSecs) when the charge drove the bucket into
// debt; the gate's next IsTokenQuotaExceeded read then denies the tenant
// until the refill drains the debt — a smooth recovery at the refill rate
// rather than the fixed window's whole-minute cliff.
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
	limit := int64(tokensPerMin)
	atomic.StoreInt64(&e.limitTokens, limit)
	touchQuotaEpoch(e)

	nowMs := quotaNowMs.Load()
	newTat := chargeTat(e, int64(count), limit, nowMs)

	burst := burstTokensFor(limit)
	burstMs := refillCeilMs(burst, limit)
	if debtMs := newTat - nowMs; debtMs > burstMs {
		// Bucket in debt. Advise retrying when the refill has drained the
		// debt back to empty (the earliest moment a further request could
		// possibly be admitted), capped at one epoch.
		retry := int(min((debtMs-burstMs+999)/1000, int64(epochInterval.Seconds())))
		return false, max(retry, 1)
	}
	return true, 0
}

// ReserveTokens claims want tokens of the tenant's per-minute quota for an
// admitted request BEFORE it is dispatched to a backend, so an over-quota
// request is denied while it is still cheap — before the GPU burns its
// prompt. The claim is settled (released and replaced by the real charge)
// by SettleTokens when the response completes.
//
// Admission denies when the bucket's current level cannot cover every
// outstanding claim plus this one. A denial does NOT put the bucket in
// debt: it is a function of THIS request's size, and a smaller request
// from the same tenant may still fit — the debt state remains the post-hoc
// consume path's mechanism.
//
// Returns (allowed, retryAfterSecs, resEpoch). resEpoch tags the minute the
// reservation was made in and must be echoed to SettleTokens; 0 means no
// reservation was recorded (no quota configured or nothing to reserve) and
// settlement degenerates to a plain charge. Atomic-only, same hot-path
// constraints as AllowTokens.
func (s *RateLimiterStore) ReserveTokens(tenantID string, want, tokensPerMin int) (allowed bool, retryAfterSecs int, resEpoch int64) {
	if tokensPerMin <= 0 || want <= 0 {
		return true, 0, 0
	}

	v, ok := s.quotaMap.Load(tenantID)
	if !ok {
		v, _ = s.quotaMap.LoadOrStore(tenantID, &tokenWindowEntry{})
	}
	e := v.(*tokenWindowEntry)

	limit := int64(tokensPerMin)
	atomic.StoreInt64(&e.limitTokens, limit)
	touchQuotaEpoch(e)

	burst := burstTokensFor(limit)
	if int64(want) > burst {
		// Larger than the whole bucket: can never be admitted. Deny
		// without recording the claim (nothing will settle it).
		return false, int(epochInterval.Seconds()), 0
	}

	// Admit iff the current bucket level covers every outstanding claim
	// plus this one. The level read and the claim add are two separate
	// atomics — a racing charge in the gap makes the admission at worst
	// one response too generous, the same tolerance the fixed window had.
	level := burst - debtTokensOf(atomic.LoadInt64(&e.tatMs), quotaNowMs.Load(), limit)
	newReserved := atomic.AddInt64(&e.reserved, int64(want))
	if newReserved > level {
		// Roll the claim back with a floor at zero: a concurrent epoch
		// advance may already have wiped it, and a plain subtract would
		// then eat a claim other in-flight requests legitimately hold.
		reservedSubClamp(e, int64(want))
		// Advise retrying once the refill has grown the level enough to
		// cover the shortfall, capped at one epoch.
		deficit := newReserved - level
		retry := int(min((deficit*60+limit-1)/limit, int64(epochInterval.Seconds())))
		return false, max(retry, 1), 0
	}
	return true, 0, currentQuotaEpoch.Load()
}

// SettleTokens replaces a request's admission-time reservation with the
// response's real token charge: the reservation (reservedAmt, tagged with
// the resEpoch ReserveTokens returned) is released, then actual tokens are
// charged with full AllowTokens semantics — the exceeded latch, window
// rollover and limit publication all behave exactly as a plain charge.
//
// The release is skipped when the reservation's window has already rolled
// over (resEpoch behind the entry's current window): the rollover reset
// wiped the claim, and releasing it here would steal a claim held by the
// new window's in-flight requests. reservedAmt<=0 or resEpoch==0 mean no
// reservation was recorded; the call degenerates to AllowTokens.
func (s *RateLimiterStore) SettleTokens(tenantID string, actual, reservedAmt int, resEpoch int64, tokensPerMin int) (allowed bool, retryAfterSecs int) {
	if reservedAmt > 0 && resEpoch > 0 {
		if v, ok := s.quotaMap.Load(tenantID); ok {
			e := v.(*tokenWindowEntry)
			if atomic.LoadInt64(&e.windowEpoch) == resEpoch {
				reservedSubClamp(e, int64(reservedAmt))
			}
		}
	}
	if actual <= 0 {
		return true, 0
	}
	return s.AllowTokens(tenantID, actual, tokensPerMin)
}

// reservedSubClamp releases amt from e.reserved without letting it go
// negative. The CAS loop matters: an epoch advance can zero the counter
// between the load and the store, and a blind AddInt64(-amt) would push it
// below zero, granting the tenant phantom headroom on the next admission.
func reservedSubClamp(e *tokenWindowEntry, amt int64) {
	for {
		cur := atomic.LoadInt64(&e.reserved)
		next := cur - amt
		if next < 0 {
			next = 0
		}
		if atomic.CompareAndSwapInt64(&e.reserved, cur, next) {
			return
		}
	}
}

// IsTokenQuotaExceeded reports whether the named quota key's bucket is
// currently in debt. Called by the request-path gate (llb_ai_ratelimit_check)
// to block the next request when a previous response consumed too many tokens.
//
// The over-quota state is DERIVED, not latched: the bucket is in debt while
// its virtual drain time sits more than one full burst beyond now, and the
// continuous refill clears that condition on its own as time passes. That
// keeps the fixed window's read-side lesson — a tenant whose every request
// is denied at the gate never completes a response, so no writer would ever
// clear a stored flag — with no stored flag to clear.
//
// This function uses only atomic operations (no mutex).
func (s *RateLimiterStore) IsTokenQuotaExceeded(tenantID string) bool {
	if v, ok := s.quotaMap.Load(tenantID); ok {
		e := v.(*tokenWindowEntry)
		limit := atomic.LoadInt64(&e.limitTokens)
		if limit <= 0 {
			return false
		}
		burstMs := refillCeilMs(burstTokensFor(limit), limit)
		return atomic.LoadInt64(&e.tatMs)-quotaNowMs.Load() > burstMs
	}
	return false
}

// TokenQuotaUsage is a point-in-time view of one quota key's token bucket,
// returned by TokenQuotaSnapshot for scrape-time metric export.
type TokenQuotaUsage struct {
	TenantID string
	// Consumed is the spent, not-yet-refilled portion of the bucket in
	// tokens: zero for a full bucket, the burst capacity when empty, more
	// while in post-hoc debt. The continuous refill drains it on its own,
	// so an idle tenant's value decays toward zero without any writer
	// running again.
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
	nowMs := quotaNowMs.Load()
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
		used := debtTokensOf(atomic.LoadInt64(&e.tatMs), nowMs, limit)
		out = append(out, TokenQuotaUsage{TenantID: tenantID, Consumed: used, Limit: limit})
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
// threshold, then evicts idle tenant quota windows. It is called by the
// Cleanup goroutine on each tick.
func (s *RateLimiterStore) doCleanup() {
	cutoff := time.Now().Add(-cleanupInactiveAfter)
	s.mu.Lock()
	for id, e := range s.entries {
		if e.lastAccess.Before(cutoff) {
			delete(s.entries, id)
		}
	}
	s.mu.Unlock()

	// Quota-map eviction runs strictly AFTER the mutex release: the walk is
	// lock-free (sync.Map + atomic loads, delete-during-Range is defined
	// behaviour) and must stay that way — holding s.mu across it would
	// reintroduce the ExportState-style stall on every concurrent check call.
	//
	// An entry whose windowEpoch is quotaEvictAfterWindows or more whole
	// windows behind the current epoch has seen no charge, reservation or
	// peer-sync update for at least that long: its consumed count reads 0
	// on every path (rolled-over window), its exceeded latch is stale, and
	// any reservation it carries is from an expired epoch that settlement
	// already ignores. Dropping it also retires the tenant's scrape-time
	// utilization/limit series (TokenQuotaSnapshot no longer sees the key) —
	// the metric-cardinality half of the same leak.
	//
	// A request racing this eviction can at worst charge the orphaned entry
	// it already holds a pointer to; the next call recreates the key with a
	// zero counter. That under-counts one response for a tenant that was
	// idle for the whole horizon — bounded, fail-open, and preferable to any
	// lock on the hot path.
	epoch := currentQuotaEpoch.Load()
	s.quotaMap.Range(func(k, v any) bool {
		e, ok := v.(*tokenWindowEntry)
		if !ok {
			return true
		}
		if epoch-atomic.LoadInt64(&e.windowEpoch) >= quotaEvictAfterWindows {
			s.quotaMap.Delete(k)
		}
		return true
	})
}
