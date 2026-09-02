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
	"strings"
	"testing"
)

// Drain-ownership continuity (DEC-007): the TRT event drain is a destructive
// read, so a hole or regression in the event_id sequence is evidence the
// gateway is not the sole consumer — the inventory must be invalidated, the
// fault recorded, and only an engine-announced fresh cache restores a
// provably-complete stream.

func TestTrtllmOwnershipContiguousStream(t *testing.T) {
	const svc, ep = 9101, 0
	kvTrtllmOwnershipAcquire(svc, ep)
	defer kvTrtllmOwnershipForget(svc, ep)

	for _, id := range []uint64{5, 6, 7} {
		if reason, ok := kvTrtllmOwnershipObserve(svc, ep, id, false); !ok {
			t.Fatalf("contiguous event %d faulted: %s", id, reason)
		}
	}
	r, ok := KvTrtllmOwnership(svc, ep)
	if !ok || r.Faulted || r.Gaps != 0 || r.Dups != 0 || !r.CursorSet || r.Cursor != 7 {
		t.Fatalf("clean stream receipt wrong: %+v ok=%v", r, ok)
	}
}

func TestTrtllmOwnershipGapFaultsAndSticks(t *testing.T) {
	const svc, ep = 9102, 0
	kvTrtllmOwnershipAcquire(svc, ep)
	defer kvTrtllmOwnershipForget(svc, ep)

	kvTrtllmOwnershipObserve(svc, ep, 5, false)
	reason, ok := kvTrtllmOwnershipObserve(svc, ep, 8, false)
	if ok || reason != KvTrtllmFaultSequenceGap {
		t.Fatalf("gap 5->8 not faulted: ok=%v reason=%q", ok, reason)
	}
	// The stream re-anchors and continues, but the fault is STICKY: a
	// post-gap contiguous event must not launder the incomplete history.
	if reason, ok := kvTrtllmOwnershipObserve(svc, ep, 9, false); !ok {
		t.Fatalf("re-anchored event 9 refused: %s", reason)
	}
	r, _ := KvTrtllmOwnership(svc, ep)
	if !r.Faulted || r.FaultReason != KvTrtllmFaultSequenceGap || r.Gaps != 1 {
		t.Fatalf("gap fault not sticky in receipt: %+v", r)
	}
}

func TestTrtllmOwnershipRegressionFaults(t *testing.T) {
	const svc, ep = 9103, 0
	kvTrtllmOwnershipAcquire(svc, ep)
	defer kvTrtllmOwnershipForget(svc, ep)

	kvTrtllmOwnershipObserve(svc, ep, 5, false)
	reason, ok := kvTrtllmOwnershipObserve(svc, ep, 5, false)
	if ok || reason != KvTrtllmFaultOwnershipLost {
		t.Fatalf("duplicate event_id not faulted as ownership loss: ok=%v reason=%q", ok, reason)
	}
	r, _ := KvTrtllmOwnership(svc, ep)
	if !r.Faulted || r.Dups != 1 {
		t.Fatalf("regression receipt wrong: %+v", r)
	}
}

func TestTrtllmOwnershipCreatedReanchorsAndClears(t *testing.T) {
	const svc, ep = 9104, 0
	kvTrtllmOwnershipAcquire(svc, ep)
	defer kvTrtllmOwnershipForget(svc, ep)

	kvTrtllmOwnershipObserve(svc, ep, 5, false)
	kvTrtllmOwnershipObserve(svc, ep, 9, false) // gap → fault
	if reason, ok := kvTrtllmOwnershipObserve(svc, ep, 0, true); !ok {
		t.Fatalf("created announcement refused: %s", reason)
	}
	r, _ := KvTrtllmOwnership(svc, ep)
	if r.Faulted || r.Cursor != 0 || !r.CursorSet {
		t.Fatalf("created did not re-anchor+clear: %+v", r)
	}
	if r.Gaps != 1 {
		t.Fatalf("history counter must survive the clear: %+v", r)
	}
}

func TestTrtllmOwnershipAcquireForgetLifecycle(t *testing.T) {
	const svc, ep = 9105, 0
	e1 := kvTrtllmOwnershipAcquire(svc, ep)
	kvTrtllmOwnershipObserve(svc, ep, 5, false)
	kvTrtllmOwnershipObserve(svc, ep, 9, false) // fault
	e2 := kvTrtllmOwnershipAcquire(svc, ep)     // re-acquire = fresh stream
	if e2 <= e1 {
		t.Fatalf("epoch not monotonic: %d then %d", e1, e2)
	}
	r, ok := KvTrtllmOwnership(svc, ep)
	if !ok || r.Faulted || r.CursorSet || r.Gaps != 0 {
		t.Fatalf("re-acquire did not reset state: %+v ok=%v", r, ok)
	}
	kvTrtllmOwnershipForgetAll(svc)
	if _, ok := KvTrtllmOwnership(svc, ep); ok {
		t.Fatal("receipt survived ForgetAll")
	}
}

// TestTrtllmDecoderGapInvalidatesInventory: an owner-bound decoder that sees
// an event_id hole must emit AllBlocksCleared in-band (the inventory built
// from the incomplete stream may hold phantom blocks) and reset its
// translation chain so post-fault blocks re-anchor from scratch.
func TestTrtllmDecoderGapInvalidatesInventory(t *testing.T) {
	const svc, ep = 9106, 0
	d := newTrtllmWireDecoder(32)
	d.bindOwner(svc, ep)
	defer kvTrtllmOwnershipForget(svc, ep)

	if evs := trtDecode(t, d, trtllmFixtureStoredFull); len(evs) != 1 || evs[0].Type != kvEventBlockStored {
		t.Fatalf("seed stored event: %+v", evs)
	}

	// Same stored payload re-labeled event_id 8: a hole (6,7 missing).
	gapped := strings.Replace(trtllmFixtureStoredFull, `"event_id": 5`, `"event_id": 8`, 1)
	evs := trtDecode(t, d, gapped)
	if len(evs) != 1 || evs[0].Type != kvEventAllBlocksCleared {
		t.Fatalf("gap must invalidate via AllBlocksCleared, got %+v", evs)
	}
	if d.stats.ownerFaults.Load() != 1 {
		t.Fatalf("ownerFaults=%d want 1", d.stats.ownerFaults.Load())
	}
	r, _ := KvTrtllmOwnership(svc, ep)
	if !r.Faulted || r.Gaps != 1 {
		t.Fatalf("registry missed the decoder fault: %+v", r)
	}

	// The chain reset must hold: a child chaining to the pre-fault parent
	// is unchained now (event_id 9 = contiguous after the re-anchor at 8).
	chained := strings.Replace(trtllmFixtureStoredPartialChained, `"event_id": 6`, `"event_id": 9`, 1)
	if evs := trtDecode(t, d, chained); len(evs) != 0 {
		t.Fatalf("pre-fault parent must be unchained after invalidation, got %+v", evs)
	}
	if d.stats.unchained.Load() == 0 {
		t.Fatal("unchained drop not counted")
	}
}

// TestTrtllmDecoderUnboundKeepsLegacyBehavior: a decoder that never bound an
// owner (standalone decode paths, fixtures) must not synthesize
// invalidations — continuity enforcement is owner-scoped by design.
func TestTrtllmDecoderUnboundKeepsLegacyBehavior(t *testing.T) {
	d := newTrtllmWireDecoder(32)
	trtDecode(t, d, trtllmFixtureStoredFull)
	gapped := strings.Replace(trtllmFixtureStoredFull, `"event_id": 5`, `"event_id": 8`, 1)
	evs := trtDecode(t, d, gapped)
	// Same stored root translates as a stored event again (dup keys are the
	// inventory's problem), never as an invalidation.
	if len(evs) != 1 || evs[0].Type != kvEventBlockStored {
		t.Fatalf("unbound decoder changed behavior: %+v", evs)
	}
	if d.stats.ownerFaults.Load() != 0 {
		t.Fatal("unbound decoder recorded an ownership fault")
	}
}
