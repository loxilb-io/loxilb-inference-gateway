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
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiterEntry is the Go-side analog of the proto RateLimiterEntry
// wire message defined in pkg/loxinet/xsync.proto. It mirrors the wire
// shape one-to-one so the coordinator can convert in a single pass.
//
// KeyID prefix encodes the scope:
//   - "k:<id>"             per-key (CheckKey) rate-limiter entry
//   - "t:<id>"             per-tenant (AllowTokens / CheckTenant) quota entry
//   - "tm:<id>|<model>"    per-tenant-per-model quota entry
//
// The quota scopes extend by prefix only — never by new wire fields (the
// proto message has a reserved CurrentTokens slot documented wire-incompat).
//
// Since the smooth-bucket change, a quota entry's Consumed slot carries the
// bucket's virtual drain time (tokenWindowEntry.tatMs, Unix milliseconds)
// rather than a per-window token count, and WindowEpoch carries the entry's
// last-activity minute. Both remain monotonic, so the max-merge receive
// path is unchanged in shape. Mixed-version HA peering is NOT supported
// across this change: an old peer would read the millisecond value as a
// token count and latch every synced tenant over-quota. Upgrade all sync
// peers together.
type RateLimiterEntry struct {
	KeyID        string // "k:<id>", "t:<id>" or "tm:<id>|<model>" — scope-prefixed identifier
	RPS          int    // limiterEntry.rps (per-key only; 0 for tenant)
	Burst        int    // limiterEntry.burst (per-key only; 0 for tenant)
	IsTenant     bool   // true if this entry represents a tenant/model quota
	WindowEpoch  int64  // tokenWindowEntry.windowEpoch — last-activity minute (quota only)
	Consumed     int64  // tokenWindowEntry.tatMs — bucket virtual drain time in Unix ms (quota only)
	Exceeded     bool   // derived at export: bucket in debt (quota only; ignored on receive)
	LastAccessNs int64  // limiterEntry.lastAccess.UnixNano (per-key only)
}

// QuotaWireKey maps a quotaMap key to its scope-prefixed sync-wire KeyID:
// plain tenant keys get "t:", composite "tenant|model" keys get "tm:".
func QuotaWireKey(mapKey string) string {
	if strings.Contains(mapKey, "|") {
		return "tm:" + mapKey
	}
	return "t:" + mapKey
}

// QuotaMapKey strips the scope prefix from a quota sync-wire KeyID,
// returning the quotaMap key and whether the prefix was a known quota
// scope.
func QuotaMapKey(wireKeyID string) (string, bool) {
	if rest, ok := strings.CutPrefix(wireKeyID, "tm:"); ok {
		return rest, true
	}
	if rest, ok := strings.CutPrefix(wireKeyID, "t:"); ok {
		return rest, true
	}
	return wireKeyID, false
}

// quotaEntryInDebt derives the wire Exceeded bit at export time: the bucket
// is over quota while its drain time is more than one burst beyond now.
// Entries that never saw a local charge have no limit and read false.
func quotaEntryInDebt(we *tokenWindowEntry, nowMs int64) bool {
	limit := atomic.LoadInt64(&we.limitTokens)
	if limit <= 0 {
		return false
	}
	return atomic.LoadInt64(&we.tatMs)-nowMs > refillCeilMs(burstTokensFor(limit), limit)
}

// mergeQuotaEntry folds one received quota entry into the local store with
// take-the-max semantics on both monotonic fields: the activity minute and
// the bucket drain time. Max on the drain time is the union of the two
// nodes' admitted spend — idempotent under replay and reorder, and it can
// only make the local node more conservative, never mint headroom. The
// wire Exceeded bit is ignored: debt is derived from the merged drain time,
// so importing it arrives for free and a stale flag can never wrongly deny.
func (s *RateLimiterStore) mergeQuotaEntry(e RateLimiterEntry) {
	mapKey, ok := QuotaMapKey(e.KeyID)
	if !ok {
		return
	}
	loaded, _ := s.quotaMap.LoadOrStore(mapKey, &tokenWindowEntry{})
	we := loaded.(*tokenWindowEntry)

	for {
		cur := atomic.LoadInt64(&we.windowEpoch)
		if e.WindowEpoch <= cur || atomic.CompareAndSwapInt64(&we.windowEpoch, cur, e.WindowEpoch) {
			break
		}
	}
	for {
		cur := atomic.LoadInt64(&we.tatMs)
		if e.Consumed <= cur || atomic.CompareAndSwapInt64(&we.tatMs, cur, e.Consumed) {
			break
		}
	}
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
	nowMs := quotaNowMs.Load()
	s.quotaMap.Range(func(k, v any) bool {
		mapKey, ok := k.(string)
		if !ok {
			return true
		}
		we, ok := v.(*tokenWindowEntry)
		if !ok {
			return true
		}
		out = append(out, RateLimiterEntry{
			KeyID:       QuotaWireKey(mapKey),
			IsTenant:    true,
			WindowEpoch: atomic.LoadInt64(&we.windowEpoch),
			Consumed:    atomic.LoadInt64(&we.tatMs),
			Exceeded:    quotaEntryInDebt(we, nowMs),
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

	// Quota merge. LoadOrStore inside mergeQuotaEntry guarantees we never
	// overwrite a *tokenWindowEntry that another goroutine may be holding
	// a pointer to (callers from AllowTokens cache the pointer past Load).
	// Both monotonic fields take the max (I-3 idempotency) — with the
	// bucket in drain-time form even an absolute snapshot merges this way,
	// because a LOWER remote drain time only means the remote node has
	// seen less spend, never that quota should be refunded.
	for _, e := range entries {
		if !e.IsTenant {
			continue
		}
		s.mergeQuotaEntry(e)
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
	nowMs := quotaNowMs.Load()
	s.quotaMap.Range(func(k, v any) bool {
		mapKey, ok := k.(string)
		if !ok {
			return true
		}
		we, ok := v.(*tokenWindowEntry)
		if !ok {
			return true
		}
		wireKey := QuotaWireKey(mapKey)
		curTat := atomic.LoadInt64(&we.tatMs)
		prevTat, hasPrev := prevSnapshot[wireKey]
		// Include if (a) we've never pushed this key or (b) the bucket
		// drain time advanced (i.e. the key was charged since the last
		// push). The drain time is monotonic, so an idle key is skipped
		// forever without any epoch special-casing — but the activity
		// minute is still compared so a reservation-only touch (which
		// advances the epoch, not the drain time) propagates too.
		if hasPrev && curTat <= prevTat {
			curEpoch := atomic.LoadInt64(&we.windowEpoch)
			prevEpoch := prevSnapshot["e:"+mapKey]
			if curEpoch <= prevEpoch {
				return true // truly nothing to send
			}
		}
		out = append(out, RateLimiterEntry{
			KeyID:       wireKey,
			IsTenant:    true,
			WindowEpoch: atomic.LoadInt64(&we.windowEpoch),
			Consumed:    curTat,
			Exceeded:    quotaEntryInDebt(we, nowMs),
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
//	- If IsTenant is true: mergeQuotaEntry — take-the-max on both the
//	  activity minute and the bucket drain time (monotonic fields, I-3
//	  idempotent under reorder/replay). The wire Exceeded bit is
//	  ignored; debt is derived from the merged drain time.
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
		s.mergeQuotaEntry(e)
	}
}
