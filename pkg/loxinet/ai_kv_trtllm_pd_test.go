/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loxinet

import (
	"net"
	"sync"
	"testing"
)

// The trtllm event drain is a destructive read owned per subscribed
// endpoint. Under P/D disaggregation only prefill endpoints (epRole 1)
// carry subscribers, so the attestation endpoint set — built from
// kvSubscriberTargets at registration — must be prefill-only: the
// drain-ownership gate consulting a decode endpoint would fail closed
// forever on a stream that endpoint legitimately never consumes. These
// tests pin that construction and the ladder behavior on top of it.

// TestKvTrtllmPdSubscriberAndAttestSetLockstep pins the two pure
// functions the mode-1 registration path composes: subscriber targets
// select exactly the prefill endpoints, and the decode counterparts
// surface only through kvAttestDecodeEPs with their original endpoint
// indexes intact.
func TestKvTrtllmPdSubscriberAndAttestSetLockstep(t *testing.T) {
	eps := []ruleLBEp{
		{xIP: net.ParseIP("10.0.0.11"), xPort: 8355, epRole: 1},
		{xIP: net.ParseIP("10.0.0.10"), xPort: 8355, epRole: 2},
		{xIP: net.ParseIP("10.0.0.12"), xPort: 8355, epRole: 1},
	}

	targets := kvSubscriberTargets(1, eps)
	if len(targets) != 2 || targets[0] != 0 || targets[1] != 2 {
		t.Fatalf("mode-1 subscriber targets = %v, want prefill indexes [0 2]", targets)
	}

	dec := kvAttestDecodeEPs(true, eps)
	if len(dec) != 1 {
		t.Fatalf("decode counterparts = %+v, want exactly the epRole-2 endpoint", dec)
	}
	if dec[0].EpIdx != 1 || dec[0].IP != "10.0.0.10" || dec[0].Port != 8355 {
		t.Fatalf("decode counterpart = %+v, want EpIdx 1 at 10.0.0.10:8355", dec[0])
	}

	// A converged rule must surface no counterparts at all — the pair
	// context is a P/D-only concept.
	if got := kvAttestDecodeEPs(false, eps); got != nil {
		t.Fatalf("non-P/D rule grew decode counterparts: %+v", got)
	}
}

// trtllmPdHarness shapes the shared attest harness as a P/D trtllm rule:
// two prefill endpoints in the attest set (indexes 0 and 2, mirroring a
// rule whose index-1 endpoint is the decode counterpart) and an
// ownership fake that records which endpoint indexes the gate consults.
func trtllmPdHarness(t *testing.T) (*attestHarness, *kvAttestController, func() map[int]int) {
	t.Helper()
	h := newAttestHarness(t)
	h.info.engine = "trtllm"
	h.info.pdMode = true
	h.info.decodeEPs = []KvAttestEndpoint{{EpIdx: 1, IP: "10.0.0.10", Port: 8355}}
	adapter := h.adapter
	h.deps.adapterFor = func(engine string) kvAttestAdapter {
		if engine == "trtllm" {
			return adapter
		}
		return nil
	}
	h.deps.endpoints = func(svcID uint32) []KvAttestEndpoint {
		return []KvAttestEndpoint{
			{EpIdx: 0, IP: "10.0.0.11", Port: 8355},
			{EpIdx: 2, IP: "10.0.0.12", Port: 8355},
		}
	}
	var mu sync.Mutex
	queried := map[int]int{}
	h.deps.drainOwnership = func(svcID uint32, epIdx int) (KvTrtllmOwnershipReceipt, bool) {
		mu.Lock()
		queried[epIdx]++
		mu.Unlock()
		if epIdx != 0 && epIdx != 2 {
			// A decode endpoint has no drain stream: answering "no
			// receipt" here is what the real registry would do, and the
			// ladder would then hold the rule fenced forever. Reaching
			// this branch at all is the defect this suite exists to pin.
			return KvTrtllmOwnershipReceipt{}, false
		}
		return KvTrtllmOwnershipReceipt{Epoch: 1, CursorSet: true, Cursor: 7}, true
	}
	snapshot := func() map[int]int {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[int]int, len(queried))
		for k, v := range queried {
			out[k] = v
		}
		return out
	}
	return h, newKvAttestController(h.info, h.deps), snapshot
}

// TestKvAttestTrtllmPdLadderPrefillOwnershipOnly: a P/D trtllm rule with a
// decode counterpart on the rule earns READY, and the drain-ownership
// gate consults ONLY the prefill endpoints the subscriber plane actually
// binds. If the gate ever asks about the decode endpoint the fake answers
// "no receipt" and the ladder fences — so READY here proves both halves.
func TestKvAttestTrtllmPdLadderPrefillOwnershipOnly(t *testing.T) {
	h, c, queried := trtllmPdHarness(t)
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateReady {
		t.Fatalf("enforced = %s, want READY (events %v)", c.enforced, h.rec.list())
	}
	q := queried()
	if q[1] != 0 {
		t.Fatalf("ownership gate consulted the decode endpoint (queries %v)", q)
	}
	if q[0] == 0 || q[2] == 0 {
		t.Fatalf("ownership gate skipped a prefill endpoint (queries %v)", q)
	}
}

// TestKvAttestTrtllmPdPrefillFaultStillFences: the prefill-only scoping
// must not weaken the gate — a faulted PREFILL receipt under pdMode
// fences the rule with the receipt's typed reason exactly as it does
// converged.
func TestKvAttestTrtllmPdPrefillFaultStillFences(t *testing.T) {
	h, c, _ := trtllmPdHarness(t)
	h.deps.drainOwnership = func(svcID uint32, epIdx int) (KvTrtllmOwnershipReceipt, bool) {
		if epIdx == 2 {
			return KvTrtllmOwnershipReceipt{Faulted: true, FaultReason: KvTrtllmFaultSequenceGap}, true
		}
		return KvTrtllmOwnershipReceipt{Epoch: 1, CursorSet: true, Cursor: 7}, true
	}
	c = newKvAttestController(h.info, h.deps)
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateProfileValidated {
		t.Fatalf("enforced = %s, want PROFILE_VALIDATED (events %v)", c.enforced, h.rec.list())
	}
	if len(c.reasons) == 0 || c.reasons[0] != KvTrtllmFaultSequenceGap {
		t.Fatalf("reasons = %v, want typed %s", c.reasons, KvTrtllmFaultSequenceGap)
	}
	if h.rec.count("apply:1") != 0 {
		t.Fatalf("eligible=1 written under a prefill ownership fault: %v", h.rec.list())
	}
}
