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
	"sync/atomic"
	"time"
)

// TensorRT-LLM drain ownership (engine-contracts/adr/DEC-007-trt-drain-ownership.md).
//
// /kv_cache_events is a DESTRUCTIVE read: events leave the server-side queue
// when fetched, so two consumers each see a disjoint, incomplete stream and
// neither can detect the loss from its own view. The gateway therefore owns
// exactly one consumer per (service, EP) drain and manages a cursor/epoch
// recording consumption progress and ownership generation.
//
// Enforcement is DETECTION-based: the upstream API offers no lease, so
// ownership is proven continuously by event_id continuity. The engine issues
// monotonically increasing event_ids; a hole in the sequence means events
// were consumed by someone else (or lost) — the affected inventory is
// invalidated rather than continued on a known-incomplete stream, and the
// fault is recorded here for the attestation plane to fence on. An event_id
// at or below the cursor without a preceding "created" announcement means
// the stream's identity is no longer the one this epoch anchored to
// (competing consumer replay, or an engine restart that lost its
// announcement) — same treatment, distinct reason.
//
// Faults are STICKY until the engine announces a fresh cache ("created"
// event) or the stream re-acquires (rule recreate / subscriber restart):
// after a hole, only a from-scratch cache is provably complete. The perf
// cost of holding the fence until then is deliberate — DEC-007's stated
// consequence is that external tooling pointed at a gateway-managed drain
// triggers gap fencing.
//
// Epochs are process-global monotonic. Rules do not survive a gateway
// restart and the attestation controller is single-writer per rule, so a
// fresh process (or HA takeover, which re-creates rules on the new owner)
// always re-acquires with a fresh epoch before consuming — the ADR's
// transfer rule. AcquiredAt is recorded for cross-node attribution.

// kvTrtllmOwnerState is one endpoint drain's ownership record.
type kvTrtllmOwnerState struct {
	epoch      uint64
	acquiredAt time.Time

	cursorSet bool
	cursor    uint64 // last observed event_id (valid when cursorSet)

	faulted     bool
	faultReason string // KvTrtllmFault* (bounded; becomes a status/metric label)
	faultAt     time.Time

	gaps uint64 // holes in the event_id sequence observed this epoch
	dups uint64 // regressions/duplicates without a created announcement
}

// KvTrtllmOwnershipReceipt is the read-model the attestation plane and
// status surfaces consume. A binding with Faulted=true (or with no receipt
// at all for a subscribed trtllm EP) must not hold READY.
type KvTrtllmOwnershipReceipt struct {
	Epoch       uint64
	AcquiredAt  time.Time
	Cursor      uint64
	CursorSet   bool
	Faulted     bool
	FaultReason string
	FaultAt     time.Time
	Gaps        uint64
	Dups        uint64
}

const (
	// KvTrtllmFaultSequenceGap: a hole in the drained event_id sequence —
	// events this consumer never saw were removed from the queue.
	KvTrtllmFaultSequenceGap = "drain_sequence_gap"
	// KvTrtllmFaultOwnershipLost: event_id at or below the cursor with no
	// created announcement — the stream is not the one this epoch anchored.
	KvTrtllmFaultOwnershipLost = "drain_ownership_lost"
)

// kvTrtllmOwnerEpoch is the process-global monotonic epoch allocator.
var kvTrtllmOwnerEpoch atomic.Uint64

var kvTrtllmOwnerReg = struct {
	sync.Mutex
	m map[kvTrtllmSvcEp]*kvTrtllmOwnerState
}{m: make(map[kvTrtllmSvcEp]*kvTrtllmOwnerState)}

// kvTrtllmOwnershipAcquire opens a fresh ownership epoch for one endpoint
// drain, replacing any prior state (a re-acquire clears a standing fault —
// the caller is starting a new stream whose inventory begins empty).
func kvTrtllmOwnershipAcquire(serviceID uint32, epIdx int) uint64 {
	epoch := kvTrtllmOwnerEpoch.Add(1)
	st := &kvTrtllmOwnerState{epoch: epoch, acquiredAt: time.Now()}
	kvTrtllmOwnerReg.Lock()
	kvTrtllmOwnerReg.m[kvTrtllmSvcEp{serviceID, epIdx}] = st
	kvTrtllmOwnerReg.Unlock()
	return epoch
}

// kvTrtllmOwnershipForget drops one endpoint's ownership state (subscriber
// teardown). ForgetAll drops every EP of a service (rule delete).
func kvTrtllmOwnershipForget(serviceID uint32, epIdx int) {
	kvTrtllmOwnerReg.Lock()
	delete(kvTrtllmOwnerReg.m, kvTrtllmSvcEp{serviceID, epIdx})
	kvTrtllmOwnerReg.Unlock()
}

func kvTrtllmOwnershipForgetAll(serviceID uint32) {
	kvTrtllmOwnerReg.Lock()
	for k := range kvTrtllmOwnerReg.m {
		if k.svc == serviceID {
			delete(kvTrtllmOwnerReg.m, k)
		}
	}
	kvTrtllmOwnerReg.Unlock()
}

// kvTrtllmOwnershipObserve advances the cursor for one drained envelope and
// returns ("", true) when the stream remains contiguous. On a continuity
// violation it records the fault and returns (reason, false) — the caller
// must invalidate the inventory it built from this stream. A "created"
// announcement legitimately re-anchors the cursor AND clears a standing
// fault: the engine cache is from-scratch, so the stream is complete again
// by construction.
//
// Observing an endpoint that never acquired is a wiring defect upstream;
// it is treated as an implicit acquire so the stream still gets continuity
// protection, but the receipt then dates ownership from mid-stream.
func kvTrtllmOwnershipObserve(serviceID uint32, epIdx int, eventID uint64, created bool) (string, bool) {
	key := kvTrtllmSvcEp{serviceID, epIdx}
	kvTrtllmOwnerReg.Lock()
	defer kvTrtllmOwnerReg.Unlock()
	st := kvTrtllmOwnerReg.m[key]
	if st == nil {
		st = &kvTrtllmOwnerState{epoch: kvTrtllmOwnerEpoch.Add(1), acquiredAt: time.Now()}
		kvTrtllmOwnerReg.m[key] = st
	}

	if created {
		st.cursor, st.cursorSet = eventID, true
		st.faulted, st.faultReason = false, ""
		return "", true
	}
	if !st.cursorSet {
		st.cursor, st.cursorSet = eventID, true
		return "", true
	}
	switch {
	case eventID == st.cursor+1:
		st.cursor = eventID
		return "", true
	case eventID > st.cursor+1:
		st.gaps++
		st.cursor = eventID
		st.faulted, st.faultReason, st.faultAt = true, KvTrtllmFaultSequenceGap, time.Now()
		return KvTrtllmFaultSequenceGap, false
	default: // eventID <= st.cursor
		st.dups++
		st.cursor = eventID
		st.faulted, st.faultReason, st.faultAt = true, KvTrtllmFaultOwnershipLost, time.Now()
		return KvTrtllmFaultOwnershipLost, false
	}
}

// KvTrtllmOwnership returns the ownership receipt for one endpoint drain.
// ok=false means no state exists (never subscribed, or torn down).
func KvTrtllmOwnership(serviceID uint32, epIdx int) (KvTrtllmOwnershipReceipt, bool) {
	kvTrtllmOwnerReg.Lock()
	defer kvTrtllmOwnerReg.Unlock()
	st := kvTrtllmOwnerReg.m[kvTrtllmSvcEp{serviceID, epIdx}]
	if st == nil {
		return KvTrtllmOwnershipReceipt{}, false
	}
	return KvTrtllmOwnershipReceipt{
		Epoch:       st.epoch,
		AcquiredAt:  st.acquiredAt,
		Cursor:      st.cursor,
		CursorSet:   st.cursorSet,
		Faulted:     st.faulted,
		FaultReason: st.faultReason,
		FaultAt:     st.faultAt,
		Gaps:        st.gaps,
		Dups:        st.dups,
	}, true
}
