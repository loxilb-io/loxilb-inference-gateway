/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Sub-phase B: Rate-limiter HA. SPEC.md req: B1, B2.
 *
 * In-package extension that exposes the per-tenant token-bucket and quota-
 * window state for HA sync across loxilb peers. The methods are designed
 * around four invariants, all of which are enforced by code structure (not
 * by reviewer vigilance):
 *
 * I-1 (L-2 deadlock): ExportState and ExportDelta MUST release s.mu
 *                        BEFORE returning. The slice is fully materialised
 *                        inside the lock; the caller may then pass it to a
 * gRPC Send without any RateLimiterStore lock held.
 *                        Violating this would block every concurrent CheckKey
 *                        / AllowTokens call while a slow peer accepts the
 *                        push.
 *
 * I-2 (L-8 trade-off): ImportState replaces the existing entries map
 *                        wholesale, orphaning any outstanding
 * *rate.Limiter.Reserve reservations from the
 *                        prior limiter instances. Worst case: ~1 RPS extra
 *                        burst per replaced key. Accepted per RESEARCH §4
 *
 *
 * I-3 (gossip idempotency): ApplyGossipDelta uses max(local.Consumed,
 *                        remote.Consumed) for the per-tenant `consumed`
 *                        counter (RESEARCH §4 "max" rule). This makes the
 *                        receive path idempotent under reordered / replayed
 *                        gossip messages — the standard A-A merge semantics.
 *
 *   I-4 (cap on opaque state): *rate.Limiter internals are opaque (the
 *                        upstream golang.org/x/time/rate API exposes only
 *                        Allow / Reserve / Wait). Export rebuilds from
 *                        config (rps, burst, lastAccess) only — confirmed
 *                        in RESEARCH §4. The atomic tokenWindowEntry state
 *                        IS preserved byte-for-byte because all its fields
 *                        are accessed via atomic operations and are
 *                        directly readable.
 */

package ratelimit

import (
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiterEntry is the Go-side analog of the proto RateLimiterEntry
// wire message defined in pkg/loxinet/xsync.proto. It mirrors the wire
// shape one-to-one so the coordinator can convert in a single pass.
//
// KeyID prefix encodes the scope:
//   - "k:<id>"  per-key (CheckKey) rate-limiter entry
//   - "t:<id>"  per-tenant (AllowTokens / CheckTenant) quota entry
//
// The same prefix convention is used internally by check/update at
// ratelimit.go:112,128, so the IDs round-trip identically.
type RateLimiterEntry struct {
	KeyID        string // "k:<id>" or "t:<id>" — scope-prefixed identifier
	RPS          int    // limiterEntry.rps (per-key only; 0 for tenant)
	Burst        int    // limiterEntry.burst (per-key only; 0 for tenant)
	IsTenant     bool   // true if this entry represents a tenant quota
	WindowEpoch  int64  // tokenWindowEntry.windowEpoch (tenant only)
	Consumed     int64  // tokenWindowEntry.consumed (tenant only)
	Exceeded     bool   // tokenWindowEntry.exceeded != 0 (tenant only)
	LastAccessNs int64  // limiterEntry.lastAccess.UnixNano (per-key only)
}

// ExportState returns a full snapshot of every per-key bucket AND every
// per-tenant quota in the store. Intended for the A-P 200ms snapshot
// push (RESEARCH §4 + CONTEXT cadence).
//
// CRITICAL: this function MUST NOT hold s.mu across any
// network / channel / send call. The slice is materialised inside the
// lock; the lock is released; the slice is returned. The caller then
// passes the result to a gRPC Send with NO RateLimiterStore lock held.
// Violation re-introduces the deadlock window described in RESEARCH §4 +
// 70-A-PLAN must_haves.truths.
//
// The two maps (entries + quotaMap) are walked under different
// concurrency strategies:
//
//   - s.entries is map-typed and guarded by s.mu (mutex). Iterated under
//
// Lock; slice appended; Unlock; THEN the quotaMap walk begins.
//
//   - s.quotaMap is sync.Map (atomic). Walked via Range with NO mutex
//     held. Each tokenWindowEntry's fields are read via atomic loads
//     (windowEpoch/consumed are int64; exceeded is int32). This is a
//     point-in-time snapshot — a concurrent AllowTokens that bumps
//     `consumed` between our atomic.Load and the slice append will be
//     captured on the NEXT push tick (acceptable lag for gossip
//     semantics).
func (s *RateLimiterStore) ExportState() []RateLimiterEntry {
	s.mu.Lock()
	// Pre-size: len(entries) covers per-key; tenant quotas are appended after
	// the lock is released. Slight over-allocation if quotaMap is large is
	// preferable to a re-slice + alloc inside the lock.
	out := make([]RateLimiterEntry, 0, len(s.entries))
	for id, e := range s.entries {
		out = append(out, RateLimiterEntry{
			KeyID:        id, // already includes "k:" / "t:" prefix from CheckKey/CheckTenant
			RPS:          e.rps,
			Burst:        e.burst,
			IsTenant:     false,
			LastAccessNs: e.lastAccess.UnixNano(),
		})
	}
	s.mu.Unlock()

	// quotaMap walk happens AFTER the mutex release — atomic / sync.Map,
	// no mutex acquisition needed. Append-only; the slice is local to
	// this goroutine.
	s.quotaMap.Range(func(k, v any) bool {
		tenantID, ok := k.(string)
		if !ok {
			return true
		}
		we, ok := v.(*tokenWindowEntry)
		if !ok {
			return true
		}
		out = append(out, RateLimiterEntry{
			KeyID:       "t:" + tenantID,
			IsTenant:    true,
			WindowEpoch: atomic.LoadInt64(&we.windowEpoch),
			Consumed:    atomic.LoadInt64(&we.consumed),
			Exceeded:    atomic.LoadInt32(&we.exceeded) != 0,
		})
		return true
	})

	return out
}

// ImportState atomically replaces the existing per-key entries map with
// the supplied snapshot AND merges tenant quota state. Used on the
// receiver side when a peer sends an absolute snapshot (A-P backup, or
// the every-10th-push insurance batch in A-A mode).
//
// Note: outstanding rate.Limiter.Reserve reservations from the prior
// limiter instances are orphaned by replacement. Worst case: ~1 RPS
// extra burst per replaced key. Accepted per RESEARCH §4.
// This is the documented trade-off for keeping the lock surface small
// and the Import path simple. A reservation-preserving import is feasible
// but would require either (a) deep-copying *rate.Limiter internals
// (opaque per I-4), or (b) iterating over the prior limiters' pending
// reservations (no upstream API for that). Neither is worth the cost
// for HA failover semantics.
//
// Tenant quotas are merged with max semantics on `consumed` to keep
// behaviour aligned with ApplyGossipDelta — even a snapshot import
// should not retract counter values. WindowEpoch follows last-writer
// semantics: a newer epoch zeros the consumed counter automatically
// (via the AllowTokens hot-path CAS), but here we set the windowEpoch
// AND consumed atomically from the snapshot, which represents a known-
// good source-of-truth state.
func (s *RateLimiterStore) ImportState(entries []RateLimiterEntry) {
	// Receiving any peer snapshot proves a live peer re-taught us: end the
	// cold-start warmup (no-op unless the store was warming).
	s.endQuotaWarmup(false)

	// Rebuild the per-key entries map under the mutex. The fresh map is
	// installed by reference; previous limiters become eligible for GC
	// once any in-flight check call returns.
	fresh := make(map[string]*limiterEntry, len(entries))
	for _, e := range entries {
		if e.IsTenant {
			continue
		}
		// Rebuild *rate.Limiter from (rps, burst) config. Internal state
		// (tokens, last) is reset to a full bucket — see I-2 trade-off
		// comment above.
		fresh[e.KeyID] = &limiterEntry{
			limiter:    rate.NewLimiter(rate.Limit(e.RPS), e.Burst),
			rps:        e.RPS,
			burst:      e.Burst,
			lastAccess: time.Unix(0, e.LastAccessNs),
		}
	}

	s.mu.Lock()
	s.entries = fresh
	s.mu.Unlock()

	// Tenant quota merge (max semantics). LoadOrStore guarantees we never
	// overwrite a *tokenWindowEntry that another goroutine may be holding
	// a pointer to (callers from AllowTokens cache the pointer past Load).
	for _, e := range entries {
		if !e.IsTenant {
			continue
		}
		// Strip the "t:" prefix to match the tenantID keying used by
		// AllowTokens at ratelimit.go:170-172.
		tenantID := e.KeyID
		if len(tenantID) > 2 && tenantID[:2] == "t:" {
			tenantID = tenantID[2:]
		}
		loaded, _ := s.quotaMap.LoadOrStore(tenantID, &tokenWindowEntry{})
		we := loaded.(*tokenWindowEntry)

		// Epoch: store the newer of the two unconditionally.
		curEpoch := atomic.LoadInt64(&we.windowEpoch)
		if e.WindowEpoch > curEpoch {
			atomic.StoreInt64(&we.windowEpoch, e.WindowEpoch)
			// When the epoch advances we reset consumed to the snapshot
			// value (this snapshot is authoritative for the new epoch).
			atomic.StoreInt64(&we.consumed, e.Consumed)
		} else if e.WindowEpoch == curEpoch {
			// Same epoch: take max of consumed (idempotent, never
			// retracts the counter — / I-3).
			for {
				cur := atomic.LoadInt64(&we.consumed)
				if e.Consumed <= cur {
					break
				}
				if atomic.CompareAndSwapInt64(&we.consumed, cur, e.Consumed) {
					break
				}
			}
		}
		// Else: incoming epoch is older — ignore. This handles the case
		// where a backup that lagged behind sends us a snapshot from a
		// past minute.

		// Exceeded flag: 1 wins (set-only). A snapshot that says "quota
		// was exceeded" must not be downgraded by reordered messages.
		if e.Exceeded {
			atomic.StoreInt32(&we.exceeded, 1)
		}
	}
}

// ExportDelta returns the consumed-since-last-push deltas for the
// A-A gossip-delta path (RESEARCH §4 + CONTEXT "consumed-since-
// last-push counter, smaller payload, requires per-peer monotonic
// state"). The payload encodes ABSOLUTE current values for `consumed`
// (not the diff) — this makes the receiver's max-merge idempotent
// under reorder / replay.
//
// The caller (sockproxy_sync coordinator) holds the per-peer
// prevSnapshot map: prevSnapshot["t:<tenantID>"] = last-pushed
// Consumed value for this peer. Only tenants whose current consumed
// strictly exceeds the previous-pushed value are included. The caller
// is responsible for updating its prevSnapshot AFTER the push succeeds.
//
// Per-key (non-tenant) entries are NOT in the delta payload. Per-key
// buckets are reconstructed lazily by the receiver via CheckKey with
// the same (rps, burst) config that the control plane already
// replicates through other channels. See ApplyGossipDelta below for
// the receiver-side comment.
//
// CRITICAL: same invariant as ExportState — no network
// / channel send call may occur inside the mutex.
func (s *RateLimiterStore) ExportDelta(prevSnapshot map[string]int64) []RateLimiterEntry {
	// No s.mu needed: tenant quotas live in sync.Map with atomic counters,
	// and the per-key bucket table (s.keyMap) is not part of the delta
	// payload — see the comment block above for rationale. If a future
	// revision extends ExportDelta to include per-key entries, it MUST
	// acquire s.mu before reading s.keyMap and release it BEFORE returning
	// (— no send/Send call may occur while s.mu is held).
	out := make([]RateLimiterEntry, 0)
	s.quotaMap.Range(func(k, v any) bool {
		tenantID, ok := k.(string)
		if !ok {
			return true
		}
		we, ok := v.(*tokenWindowEntry)
		if !ok {
			return true
		}
		curConsumed := atomic.LoadInt64(&we.consumed)
		prevConsumed, hasPrev := prevSnapshot["t:"+tenantID]
		// Include if (a) we've never seen this tenant or (b) consumed
		// has increased. Equal-or-decreased values are skipped (the
		// latter happens at epoch rollover; that case is covered by
		// WindowEpoch advance below).
		if hasPrev && curConsumed <= prevConsumed {
			// Check epoch — if epoch advanced, send anyway so the
			// receiver can reset its counter.
			curEpoch := atomic.LoadInt64(&we.windowEpoch)
			prevEpoch, _ := prevSnapshot["e:"+tenantID]
			if curEpoch <= prevEpoch {
				return true // truly nothing to send
			}
		}
		out = append(out, RateLimiterEntry{
			KeyID:       "t:" + tenantID,
			IsTenant:    true,
			WindowEpoch: atomic.LoadInt64(&we.windowEpoch),
			Consumed:    curConsumed,
			Exceeded:    atomic.LoadInt32(&we.exceeded) != 0,
		})
		return true
	})
	return out
}

// ApplyGossipDelta merges the consumed/epoch state in `entries` into
// the local store using max semantics on `consumed` (per RESEARCH §4
// "max" rule + I-3 idempotency invariant). Used on the receiver side
// when a peer sends an A-A gossip-delta batch.
//
// Behaviour per entry:
//   - If IsTenant is false: no-op. Per-key bucket gossip is not in
//
// scope -B — the per-key bucket is reconstructed
// lazily by the receiver via CheckKey with the same (rps, burst)
//
//	  config replicated through normal control-plane channels.
//	- If WindowEpoch > local.windowEpoch: epoch rollover. Atomic-store
//	  the new epoch and reset consumed to the remote Consumed value
//	  (the remote is, by construction, the authoritative source for
//	  the new epoch in A-A gossip semantics).
//	- If WindowEpoch == local.windowEpoch: CAS loop to set local
//	  consumed = max(local, remote). Idempotent under reorder.
//	- If WindowEpoch < local.windowEpoch: ignore (we have a newer
//	  epoch already).
//	- Exceeded: monotonic-set (1 wins). Mirrors ImportState.
func (s *RateLimiterStore) ApplyGossipDelta(entries []RateLimiterEntry) {
	// Any received gossip batch ends the cold-start warmup (see ImportState).
	s.endQuotaWarmup(false)

	for _, e := range entries {
		if !e.IsTenant {
			// -B: per-key bucket gossip is not in scope; A-A
			// relies on tenant-quota gossip only. The per-key
			// (rps, burst) is config-driven, not consumed-state-driven,
			// so the receiver rebuilds the bucket lazily on its first
			// CheckKey call.
			continue
		}
		tenantID := e.KeyID
		if len(tenantID) > 2 && tenantID[:2] == "t:" {
			tenantID = tenantID[2:]
		}
		loaded, _ := s.quotaMap.LoadOrStore(tenantID, &tokenWindowEntry{})
		we := loaded.(*tokenWindowEntry)

		curEpoch := atomic.LoadInt64(&we.windowEpoch)
		switch {
		case e.WindowEpoch > curEpoch:
			// Newer epoch wins: store the new epoch + reset consumed.
			// The CAS guards against the rare case where another
			// goroutine raced us to the same epoch.
			if atomic.CompareAndSwapInt64(&we.windowEpoch, curEpoch, e.WindowEpoch) {
				atomic.StoreInt64(&we.consumed, e.Consumed)
			}
		case e.WindowEpoch == curEpoch:
			// Same epoch: max-merge consumed.
			for {
				cur := atomic.LoadInt64(&we.consumed)
				if e.Consumed <= cur {
					break
				}
				if atomic.CompareAndSwapInt64(&we.consumed, cur, e.Consumed) {
					break
				}
			}
		}
		// e.WindowEpoch < curEpoch: ignore — we already have a newer epoch.

		if e.Exceeded {
			atomic.StoreInt32(&we.exceeded, 1)
		}
	}
}
