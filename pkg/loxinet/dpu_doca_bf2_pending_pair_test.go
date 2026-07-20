//go:build !doca

/*
 * Copyright (c) 2022 NetLOX Inc
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
	"errors"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// fakePtr returns a non-nil unsafe.Pointer for use as a synthetic DOCA handle.
// The pointer never gets dereferenced — it only distinguishes the "forward"
// entry handle from the "reply" entry handle in test assertions. Each key is
// interned to a real allocation so the same key always yields the same
// pointer without any uintptr-to-pointer conversion.
var (
	fakePtrMu  sync.Mutex
	fakePtrTab = map[uintptr]unsafe.Pointer{}
)

func fakePtr(v uintptr) unsafe.Pointer {
	fakePtrMu.Lock()
	defer fakePtrMu.Unlock()
	p, ok := fakePtrTab[v]
	if !ok {
		p = unsafe.Pointer(new(byte))
		fakePtrTab[v] = p
	}
	return p
}

// init seeds resolveFlowMACsFn with an always-succeed default for the
// pairing-lifecycle tests in this file. P51-02: with
// buildPairedFlowParams now exercising the resolver via this seam, the
// lifecycle tests must reach the docaEntryAddBasicFn add path. Tests that
// assert resolver-input invariants override this default
// in dpu_doca_bf2_resolve_test.go.
func init() {
	resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
		return 1, [6]byte{}, [6]byte{}, true
	}
}

// resetPairTestState clears the package-level injectable seams between sub-tests.
//
// P51-02 update: also resets resolveFlowMACsFn to a default
// always-succeed mock (same-subnet path: never falls back to FIB). The
// pairing-lifecycle tests (TestPhase51_PairOrDispatch_OrderIndependent,
// _AtomicRollback_OnReplyFailure, _PairedOffload_BothEntriesBookkept) do NOT
// assert on the resolver; the resolver-input invariants
// have dedicated coverage in dpu_doca_bf2_resolve_test.go.
func resetPairTestState() {
	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
		return nil, nil, ErrNotSupported
	}
	docaEntryRemoveDirectFn = DocaEntryRemoveDirect
	docaEntryRemoveFn = DocaEntryRemove
	resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
		return 1, [6]byte{}, [6]byte{}, true
	}
}

// TestPhase51_PairOrDispatch_OrderIndependent — : forward-first and
// reply-first arrival orders both result in exactly one paired dispatch.
func TestPhase51_PairOrDispatch_OrderIndependent(t *testing.T) {
	defer resetPairTestState()

	// Forward-first ordering.
	d := &DpDocaBf2{
		pendingPair:  make(map[string]*pendingPair),
		entries:      make(map[string]*docaOffloadEntry),
		bidirEnabled: true,
	}
	dispatchCount := 0
	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
		// Increment when both directions add successfully — count by tracking the
		// reply-direction add as the "dispatch complete" signal.
		if direction == "reply" {
			dispatchCount++
		}
		return fakePtr(0xdead), fakePtr(0xbeef), nil
	}

	fwd := dnatForwardCT()
	rev := dnatReplyCT()

	d.pairOrDispatch(fwd, 0)
	if dispatchCount != 0 {
		t.Fatalf("expected 0 dispatches after only forward, got %d", dispatchCount)
	}
	d.pairOrDispatch(rev, 0)
	if dispatchCount != 1 {
		t.Fatalf("expected 1 dispatch after pair completes, got %d", dispatchCount)
	}

	// Map drains to zero after dispatch.
	if len(d.pendingPair) != 0 {
		t.Fatalf("pendingPair should be empty post-dispatch, got %d entries", len(d.pendingPair))
	}

	// Reply-first ordering: reset state.
	d2 := &DpDocaBf2{
		pendingPair:  make(map[string]*pendingPair),
		entries:      make(map[string]*docaOffloadEntry),
		bidirEnabled: true,
	}
	dispatchCount = 0
	d2.pairOrDispatch(rev, 0)
	if dispatchCount != 0 {
		t.Fatalf("reply-first: expected 0 dispatches yet, got %d", dispatchCount)
	}
	d2.pairOrDispatch(fwd, 0)
	if dispatchCount != 1 {
		t.Fatalf("reply-first: expected 1 dispatch, got %d", dispatchCount)
	}
	if len(d2.pendingPair) != 0 {
		t.Fatalf("reply-first: pendingPair should be empty post-dispatch, got %d", len(d2.pendingPair))
	}
}

// TestPhase51_AtomicRollback_OnReplyFailure — : forward succeeds, reply
// DocaEntryAddBasic returns error; assert forward entry removed via
// DocaEntryRemoveDirect (NOT DocaEntryRemove — RESEARCH §Anti-Patterns line 374);
// entries map empty.
func TestPhase51_AtomicRollback_OnReplyFailure(t *testing.T) {
	defer resetPairTestState()

	d := &DpDocaBf2{
		pendingPair:  make(map[string]*pendingPair),
		entries:      make(map[string]*docaOffloadEntry),
		bidirEnabled: true,
	}

	addCalls := 0
	removeDirectCalls := 0
	removeCallsBare := 0 // bare DocaEntryRemove must NEVER be called (Blocker 1 invariant)

	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
		addCalls++
		if addCalls == 2 {
			return nil, nil, errors.New("simulated reply add fail")
		}
		return fakePtr(0xa1), fakePtr(0xb2), nil
	}
	docaEntryRemoveDirectFn = func(pipe, entry unsafe.Pointer) error {
		removeDirectCalls++
		return nil
	}
	docaEntryRemoveFn = func(pipe, entry unsafe.Pointer) error {
		removeCallsBare++
		return nil
	}

	d.pairOrDispatch(dnatForwardCT(), 0)
	d.pairOrDispatch(dnatReplyCT(), 0)

	if addCalls != 2 {
		t.Fatalf("expected 2 add calls, got %d", addCalls)
	}
	if removeDirectCalls != 1 {
		t.Fatalf("expected 1 rollback DocaEntryRemoveDirect call, got %d", removeDirectCalls)
	}
	if removeCallsBare != 0 {
		t.Fatalf("Blocker 1 / RESEARCH line 374: bare DocaEntryRemove must NOT be used in paired rollback; got %d calls", removeCallsBare)
	}
	if len(d.entries) != 0 {
		t.Fatalf("entries map should be empty after rollback, got %d", len(d.entries))
	}
	// pendingPair must also be empty — the pair was extracted before dispatch attempted.
	if len(d.pendingPair) != 0 {
		t.Fatalf("pendingPair should be empty post-dispatch (even on rollback), got %d", len(d.pendingPair))
	}
}

// TestPhase51_ConnKey_Symmetric — : forward and reply events for the
// same connection produce the same connKey across all 3 LB modes.
func TestPhase51_ConnKey_Symmetric(t *testing.T) {
	cases := []struct {
		name     string
		fwd, rev *DpCtInfo
	}{
		{"DNAT", dnatForwardCT(), dnatReplyCT()},
		{"OneArm", oneArmForwardCT(), oneArmReplyCT()},
		{"FullNAT", fullNATForwardCT(), fullNATReplyCT()},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fk := connKeyFromEvent(tc.fwd)
			rk := connKeyFromEvent(tc.rev)
			if fk == "" || rk == "" {
				t.Fatalf("empty connKey: fwd=%q rev=%q", fk, rk)
			}
			if fk != rk {
				t.Fatalf("connKey asymmetric: fwd=%q rev=%q", fk, rk)
			}
		})
	}
}

// TestPhase51_GC_StaleHalfPair — : forward arrives, reply never; assert
// entry removed after gcPendingPairs(30s) call past 30s elapsed.
func TestPhase51_GC_StaleHalfPair(t *testing.T) {
	defer resetPairTestState()

	d := &DpDocaBf2{
		pendingPair:  make(map[string]*pendingPair),
		entries:      make(map[string]*docaOffloadEntry),
		bidirEnabled: true,
	}
	d.pairOrDispatch(dnatForwardCT(), 0)
	if len(d.pendingPair) != 1 {
		t.Fatalf("expected 1 pending after forward-only, got %d", len(d.pendingPair))
	}
	// Simulate 31s elapsed by directly mutating arrivedAt.
	for _, p := range d.pendingPair {
		p.arrivedAt = time.Now().Add(-31 * time.Second)
	}
	d.gcPendingPairs(30 * time.Second)
	if len(d.pendingPair) != 0 {
		t.Fatalf("expected GC sweep, got %d entries", len(d.pendingPair))
	}
}

// TestPhase51_PairedOffload_BothEntriesBookkept — verifies success path:
// entries map holds two records keyed by forward and reply flowKey, each
// tagged with its Direction.
func TestPhase51_PairedOffload_BothEntriesBookkept(t *testing.T) {
	defer resetPairTestState()

	d := &DpDocaBf2{
		pendingPair:  make(map[string]*pendingPair),
		entries:      make(map[string]*docaOffloadEntry),
		bidirEnabled: true,
	}
	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
		// Return distinct fake pointers so the bookkeeping uses the right pair.
		switch direction {
		case "forward":
			return fakePtr(0x1111), fakePtr(0x1110), nil
		case "reply":
			return fakePtr(0x2222), fakePtr(0x2220), nil
		}
		return nil, nil, errors.New("unknown direction")
	}

	d.pairOrDispatch(dnatForwardCT(), 0)
	d.pairOrDispatch(dnatReplyCT(), 0)
	if len(d.entries) != 2 {
		t.Fatalf("expected 2 entries (fwd+rev), got %d", len(d.entries))
	}
	var sawFwd, sawRev bool
	for _, oe := range d.entries {
		if oe.Direction == "forward" {
			sawFwd = true
		}
		if oe.Direction == "reply" {
			sawRev = true
		}
	}
	if !sawFwd || !sawRev {
		t.Fatalf("missing direction tags: fwd=%v rev=%v", sawFwd, sawRev)
	}
}

// === Fixture helpers ===

// dnatForwardCT returns the DNAT (default mode) forward CT shape:
//
//	client -> VIP, NAT to backend, NatRIP unset (no SNAT).
func dnatForwardCT() *DpCtInfo {
	return &DpCtInfo{
		SIP:      net.ParseIP("10.99.0.2"),
		DIP:      net.ParseIP("20.20.20.1"),
		Sport:    50898,
		Dport:    5201,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 1,
		RuleID:   1,
		NatIP:    net.ParseIP("31.31.31.1"),
		NatPort:  5201,
	}
}

// dnatReplyCT returns the DNAT reply CT shape:
//
//	backend -> client, SNAT back to VIP, NatRIP unset.
func dnatReplyCT() *DpCtInfo {
	return &DpCtInfo{
		SIP:      net.ParseIP("31.31.31.1"),
		DIP:      net.ParseIP("10.99.0.2"),
		Sport:    5201,
		Dport:    50898,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 2,
		RuleID:   1,
		NatIP:    net.ParseIP("20.20.20.1"),
		NatPort:  5201,
	}
}

// oneArmForwardCT — OneArm forward shape: forward identical to DNAT but with
// NatRIP=loxilb-VIP-side-IP for SNAT-to-VIP (FullNAT/OneArm pattern).
func oneArmForwardCT() *DpCtInfo {
	return &DpCtInfo{
		SIP:      net.ParseIP("10.99.0.2"),
		DIP:      net.ParseIP("20.20.20.1"),
		Sport:    50898,
		Dport:    5201,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 1,
		RuleID:   1,
		NatIP:    net.ParseIP("31.31.31.1"),
		NatPort:  5201,
		NatRIP:   net.ParseIP("31.31.31.254"), // loxilb backend-side IP
	}
}

// oneArmReplyCT — OneArm reply shape: backend -> loxilb-IP, NatIP=VIP for
// reverse SNAT, NatRIP=client for reverse DNAT.
func oneArmReplyCT() *DpCtInfo {
	return &DpCtInfo{
		SIP:      net.ParseIP("31.31.31.1"),
		DIP:      net.ParseIP("31.31.31.254"),
		Sport:    5201,
		Dport:    50898,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 2,
		RuleID:   1,
		NatIP:    net.ParseIP("20.20.20.1"),
		NatPort:  5201,
		NatRIP:   net.ParseIP("10.99.0.2"),
	}
}

// fullNATForwardCT — FullNAT forward shape: same as OneArm forward.
func fullNATForwardCT() *DpCtInfo {
	return oneArmForwardCT()
}

// fullNATReplyCT — FullNAT reply shape: same as OneArm reply.
func fullNATReplyCT() *DpCtInfo {
	return oneArmReplyCT()
}
