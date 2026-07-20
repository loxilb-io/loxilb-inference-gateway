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

// per-direction CT pipe split and aggregate utilization.
//
// These tests codify the acceptance contract plan 03:
//
//   1. TestDocaGetCTRevPipe — the new DocaGetCTRevPipe Go binding exists and,
//      under the !doca build, the stub returns nil (mirrors DocaGetCTFwdPipe stub).
//   2. TestPairedLBFlowOffload_ReplyPipe — pairedLBFlowOffload routes the reply
//      branch onto a DIFFERENT pipe handle than the forward branch. The seam
//      docaEntryAddBasicFn (declared in dpu_doca_bf2_stub.go for !doca builds)
//      is overridden so the test can return distinguishable forward vs reply
//      pipe pointers and assert the bookkeeping records them per direction.
//      BOTH directions retain pipeKey="ct" (closed enum).
// 3. TestDocaCTPipeUtilization_Aggregate — Option A: the utilization
//      gauge denominator is docaDefaultTCPPipeCapacityAggregate=32768 (forward
//      g_ct_fwd_pipe + reply g_ct_rev_pipe, each at g_ct_pipe_capacity*2=16384).
//      countEntriesForPipe(d.entries, "ct") aggregates forward+reply because
// keeps pipeKey="ct" for both directions.
//
// -06 (TX-2): DocaGetCTPipe references in comments renamed to
// DocaGetCTFwdPipe to track the C-side rename completed.
//
// TDD discipline: this file is authored of plan 52-03 BEFORE the
// production-code edits in Tasks 2-4. RED state on the first commit; turns
// GREEN incrementally as each follow-on task lands.

package loxinet

import (
	"fmt"
	"net"
	"testing"
	"unsafe"

	"github.com/vishvananda/netlink"
)

// TestDocaGetCTRevPipe — under !doca the stub MUST return nil, mirroring
// DocaGetCTFwdPipe's stub. RED initially because DocaGetCTRevPipe doesn't exist
// yet; GREEN after (cgo_stub.go) lands the stub.
func TestDocaGetCTRevPipe(t *testing.T) {
	if got := DocaGetCTRevPipe(); got != nil {
		t.Fatalf("DocaGetCTRevPipe() under !doca: got %v, want nil", got)
	}
}

// TestPairedLBFlowOffload_ReplyPipe — assert both directions use the SAME unified CT pipe.
//
// CT_REV is permanently unreachable with repr_matching_en=0 (port_meta always 0).
// Both fdnat (forward) and fsnat (reply) entries are installed in g_ct_pipe.
// CT_5TUPLE_PIPE is BIDIRECTIONAL so it accepts both directions; the 5-tuples
// are disjoint so there is no collision risk.
//
// The seam docaEntryAddBasicFn returns fwdPipeFake for both directions to mirror
// the production code calling DocaEntryAddBasic(pipe, ...) in both branches.
// Both d.entries values must record the same pipe handle; pipeKey="ct" for both.
func TestPairedLBFlowOffload_ReplyPipe(t *testing.T) {
	// Synthetic pipe handle — stand-in for g_ct_pipe under !doca.
	// Both forward and reply use the same pipe (unified CT pipe).
	fwdPipeFake := fakePtr(0xCA01)

	origFn := docaEntryAddBasicFn
	defer func() { docaEntryAddBasicFn = origFn }()
	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (entry, pipe unsafe.Pointer, err error) {
		// Both directions return the same fwdPipeFake — mirrors production code
		// calling DocaEntryAddBasic(pipe, ...) for both forward and reply.
		pipe = fwdPipeFake
		entry = fakePtr(0xE000 + uintptr(len(direction)))
		return entry, pipe, nil
	}

	d := &DpDocaBf2{
		pendingPair:  make(map[string]*pendingPair),
		entries:      make(map[string]*docaOffloadEntry),
		bidirEnabled: true,
	}
	fwd := dnatForwardCT()
	rev := dnatReplyCT()

	if err := d.pairedLBFlowOffload(fwd, rev, 0); err != nil {
		t.Fatalf("pairedLBFlowOffload: %v", err)
	}

	// Bookkeeping invariant — : both entries keep pipeKey="ct";
	// unified pipe: both directions use the SAME pipe handle (g_ct_pipe).
	fwdKey := fwd.Key()
	revKey := rev.Key()
	fwdEntry, ok := d.entries[fwdKey]
	if !ok {
		t.Fatalf("forward entry missing in d.entries (key=%q)", fwdKey)
	}
	revEntry, ok := d.entries[revKey]
	if !ok {
		t.Fatalf("reply entry missing in d.entries (key=%q)", revKey)
	}
	if fwdEntry.pipe != fwdPipeFake {
		t.Errorf("forward entry pipe = %p, want %p (g_ct_pipe stand-in)", fwdEntry.pipe, fwdPipeFake)
	}
	if revEntry.pipe != fwdPipeFake {
		t.Errorf("reply entry pipe = %p, want %p (g_ct_pipe stand-in — unified, same as forward)", revEntry.pipe, fwdPipeFake)
	}
	if fwdEntry.pipeKey != "ct" {
		t.Errorf("forward entry pipeKey = %q, want %q", fwdEntry.pipeKey, "ct")
	}
	if revEntry.pipeKey != "ct" {
		t.Errorf("reply entry pipeKey = %q, want %q (must NOT be \"ct_rev\")", revEntry.pipeKey, "ct")
	}
}

// TestDocaCTPipeUtilization_Aggregate — Option A: aggregate denominator.
//
// With N forward and M reply entries (both pipeKey="ct"), the entries-for-pipe
// counter must return N+M (keeps both directions under "ct"). The
// utilization denominator constant exposed in pkg/loxinet must be 32768 — the
// aggregate of g_ct_pipe (16384) + g_ct_rev_pipe (16384).
//
// RED initially because docaDefaultTCPPipeCapacityAggregate doesn't exist yet.
// GREEN after lands the constant + denominator update.
func TestDocaCTPipeUtilization_Aggregate(t *testing.T) {
	const N = 3
	const M = 5
	d := &DpDocaBf2{entries: make(map[string]*docaOffloadEntry)}
	for i := 0; i < N; i++ {
		d.entries[fmt.Sprintf("fwd-%d", i)] = &docaOffloadEntry{
			pipe: fakePtr(uintptr(0xAA00 + i)), pipeKey: "ct", Direction: "forward",
		}
	}
	for i := 0; i < M; i++ {
		d.entries[fmt.Sprintf("rev-%d", i)] = &docaOffloadEntry{
			pipe: fakePtr(uintptr(0xBB00 + i)), pipeKey: "ct", Direction: "reply",
		}
	}

	gotCount := countEntriesForPipe(d.entries, "ct")
	if gotCount != N+M {
		t.Errorf("countEntriesForPipe(\"ct\"): got %d, want %d (forward+reply aggregate)", gotCount, N+M)
	}

	// Option A: aggregate denominator across both per-direction pipes.
	const wantCap = 32768
	if docaDefaultTCPPipeCapacityAggregate != wantCap {
		t.Errorf("docaDefaultTCPPipeCapacityAggregate: got %d, want %d (2 pipes × g_ct_pipe_capacity*2)",
			docaDefaultTCPPipeCapacityAggregate, wantCap)
	}
}

// === : route fwd/rev pair install + sibling-cascade teardown ===
//
// These tests exercise the !doca mirrors of RouteFlowOffload / LBFlowRemove /
// handleAgedEntry (dpu_doca_bf2_stub.go), which reproduce the testable
// control-flow contract of the DOCA-build twins in dpu_doca_bf2.go. They
// codify : a non-NAT routed flow must HW-offload BOTH directions
// (forward on g_ct_fwd_pipe, reverse on g_ct_rev_pipe), atomically, with
// teardown of either half cascading to the sibling so g_ct_rev_pipe cannot
// leak. Style mirrors TestPairedLBFlowOffload_ReplyPipe above.

// routeCT returns a non-NAT (pure L3 routing) established CT shape:
// client 10.99.0.2 → server 31.31.31.1, no NatFlags
func routeCT() *DpCtInfo {
	return &DpCtInfo{
		SIP:    net.ParseIP("10.99.0.2"),
		DIP:    net.ParseIP("31.31.31.1"),
		Sport:  50898,
		Dport:  5201,
		Proto:  "tcp",
		CState: "est",
		PKey:   []byte{0xde, 0xad, 0xbe, 0xef},
	}
}

// saveRouteSeams snapshots the package-level seams route tests
// mutate and returns a restore func for defer. Mirrors the discipline of
// resetPairTestState (dpu_doca_bf2_pending_pair_test.go).
func saveRouteSeams() func() {
	origAdd := docaEntryAddBasicFn
	origRmDirect := docaEntryRemoveDirectFn
	origRm := docaEntryRemoveFn
	origResolve := resolveFlowMACsFn
	origFwdPipe := docaGetCTFwdPipeFn
	origRevPipe := docaGetCTRevPipeFn
	origRouteGet := routeGetFn
	return func() {
		docaEntryAddBasicFn = origAdd
		docaEntryRemoveDirectFn = origRmDirect
		docaEntryRemoveFn = origRm
		resolveFlowMACsFn = origResolve
		docaGetCTFwdPipeFn = origFwdPipe
		docaGetCTRevPipeFn = origRevPipe
		routeGetFn = origRouteGet
	}
}

// hermeticRouteGet pins routeGetFn to "no FIB rows" so nextHopForFlow
// deterministically falls back to the flow's own dst — the resolveFlowMACsFn
// spy then sees the literal flow IPs, not whatever the host's netlink returns.
func hermeticRouteGet() {
	routeGetFn = func(net.IP) ([]netlink.Route, error) { return nil, nil }
}

// resolveAlwaysOK is the default MAC/port resolver spy: every ARP target
// resolves on port 1. Tests that need a miss override it locally.
func resolveAlwaysOK(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
	return 1, [6]byte{}, [6]byte{}, true
}

// TestRouteFlowOffload_InstallsReversePipe — a non-NAT routed flow installs
// TWO DOCA entries: a forward entry on g_ct_fwd_pipe and a reverse entry on
// g_ct_rev_pipe, with swapped 5-tuple and cross-linked siblingKeys.
func TestRouteFlowOffload_InstallsReversePipe(t *testing.T) {
	defer saveRouteSeams()()
	hermeticRouteGet()

	fwdPipeFake := fakePtr(0xCF01)
	revPipeFake := fakePtr(0xCF02)
	docaGetCTFwdPipeFn = func() unsafe.Pointer { return fwdPipeFake }
	docaGetCTRevPipeFn = func() unsafe.Pointer { return revPipeFake }
	resolveFlowMACsFn = resolveAlwaysOK

	type addCall struct {
		dir          string
		dip, sip     string
		dport, sport uint16
	}
	var calls []addCall
	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
		calls = append(calls, addCall{direction, ct.DIP.String(), ct.SIP.String(), ct.Dport, ct.Sport})
		return fakePtr(uintptr(0xE000 + len(calls))), nil, nil
	}

	d := &DpDocaBf2{entries: make(map[string]*docaOffloadEntry)}
	ct := routeCT()
	if err := d.RouteFlowOffload(ct, 7); err != nil {
		t.Fatalf("RouteFlowOffload: %v", err)
	}

	// Exactly two DocaEntryAddBasic calls: forward then reverse.
	if len(calls) != 2 {
		t.Fatalf("docaEntryAddBasicFn calls = %d, want 2 (forward + reverse)", len(calls))
	}
	if calls[0].dir != "forward" {
		t.Errorf("call[0] direction = %q, want \"forward\"", calls[0].dir)
	}
	// Forward call carries the original 5-tuple.
	if calls[0].dip != ct.DIP.String() || calls[0].sip != ct.SIP.String() ||
		calls[0].dport != ct.Dport || calls[0].sport != ct.Sport {
		t.Errorf("forward call 5-tuple = %s:%d→%s:%d, want %s:%d→%s:%d",
			calls[0].sip, calls[0].sport, calls[0].dip, calls[0].dport,
			ct.SIP, ct.Sport, ct.DIP, ct.Dport)
	}
	if calls[1].dir != "reply" {
		t.Errorf("call[1] direction = %q, want \"reply\"", calls[1].dir)
	}
	// Reverse call carries the swapped 5-tuple (identity rewrite — no NAT).
	if calls[1].dip != ct.SIP.String() || calls[1].sip != ct.DIP.String() ||
		calls[1].dport != ct.Sport || calls[1].sport != ct.Dport {
		t.Errorf("reverse call 5-tuple = %s:%d→%s:%d, want swapped %s:%d→%s:%d",
			calls[1].sip, calls[1].sport, calls[1].dip, calls[1].dport,
			ct.DIP, ct.Dport, ct.SIP, ct.Sport)
	}

	fwdKey := ct.Key()
	revC := *ct
	revC.DIP, revC.SIP = ct.SIP, ct.DIP
	revC.Dport, revC.Sport = ct.Sport, ct.Dport
	revKey := revC.Key()
	if revKey == fwdKey {
		t.Fatalf("test fixture degenerate: forward and reverse keys equal (%q)", fwdKey)
	}

	fwd, ok := d.entries[fwdKey]
	if !ok {
		t.Fatalf("forward entry missing in d.entries (key=%q)", fwdKey)
	}
	rev, ok := d.entries[revKey]
	if !ok {
		t.Fatalf("reverse entry missing in d.entries (key=%q)", revKey)
	}

	// Reverse entry installs on g_ct_rev_pipe; forward on g_ct_fwd_pipe.
	if fwd.pipe != fwdPipeFake {
		t.Errorf("forward entry pipe = %p, want %p (g_ct_fwd_pipe)", fwd.pipe, fwdPipeFake)
	}
	if rev.pipe != revPipeFake {
		t.Errorf("reverse entry pipe = %p, want %p (g_ct_rev_pipe)", rev.pipe, revPipeFake)
	}
	// siblingKeys cross-link the pair so teardown of either cascades.
	if fwd.siblingKey != revKey {
		t.Errorf("forward siblingKey = %q, want %q", fwd.siblingKey, revKey)
	}
	if rev.siblingKey != fwdKey {
		t.Errorf("reverse siblingKey = %q, want %q", rev.siblingKey, fwdKey)
	}
	// Direction tags populated (closes the Direction=="" gap for route entries);
	// pipeKey stays the closed-enum "route" for both halves (AllRouteStats).
	if fwd.Direction != "forward" || rev.Direction != "reply" {
		t.Errorf("Direction tags = (%q,%q), want (forward,reply)", fwd.Direction, rev.Direction)
	}
	if fwd.pipeKey != "route" || rev.pipeKey != "route" {
		t.Errorf("pipeKey = (%q,%q), want (route,route)", fwd.pipeKey, rev.pipeKey)
	}
}

// TestRouteFlowOffload_SiblingCascade — tearing down one half of a route pair
// tears down the sibling too, through BOTH teardown paths: LBFlowRemove (eBPF
// CT expiry, non-Direct removal) and handleAgedEntry (DOCA aging, Direct
// removal). g_ct_rev_pipe must not leak the reverse entry.
func TestRouteFlowOffload_SiblingCascade(t *testing.T) {
	// installPair installs a route fwd/rev pair into d and returns the keys.
	// Caller must have already snapshot-restored the seams via saveRouteSeams.
	installPair := func(t *testing.T, d *DpDocaBf2) (fwdKey, revKey string) {
		t.Helper()
		hermeticRouteGet()
		docaGetCTFwdPipeFn = func() unsafe.Pointer { return fakePtr(0xCF01) }
		docaGetCTRevPipeFn = func() unsafe.Pointer { return fakePtr(0xCF02) }
		resolveFlowMACsFn = resolveAlwaysOK
		var n int
		docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
			n++
			return fakePtr(uintptr(0xE000 + n)), nil, nil
		}
		ct := routeCT()
		if err := d.RouteFlowOffload(ct, 0); err != nil {
			t.Fatalf("installPair RouteFlowOffload: %v", err)
		}
		revC := *ct
		revC.DIP, revC.SIP = ct.SIP, ct.DIP
		revC.Dport, revC.Sport = ct.Sport, ct.Dport
		return ct.Key(), revC.Key()
	}

	t.Run("LBFlowRemove cascades to sibling", func(t *testing.T) {
		defer saveRouteSeams()()
		d := &DpDocaBf2{entries: make(map[string]*docaOffloadEntry)}
		fwdKey, revKey := installPair(t, d)

		var removed int
		docaEntryRemoveFn = func(pipe, entry unsafe.Pointer) error {
			removed++
			return nil
		}
		if err := d.LBFlowRemove(routeCT()); err != nil {
			t.Fatalf("LBFlowRemove: %v", err)
		}
		if removed != 2 {
			t.Errorf("docaEntryRemoveFn calls = %d, want 2 (forward + cascaded sibling)", removed)
		}
		if _, ok := d.entries[fwdKey]; ok {
			t.Error("forward entry still present after LBFlowRemove")
		}
		if _, ok := d.entries[revKey]; ok {
			t.Error("reverse (sibling) entry still present after LBFlowRemove — leaked on g_ct_rev_pipe")
		}
	})

	t.Run("handleAgedEntry cascades to sibling", func(t *testing.T) {
		defer saveRouteSeams()()
		d := &DpDocaBf2{entries: make(map[string]*docaOffloadEntry)}
		fwdKey, revKey := installPair(t, d)

		var removed int
		docaEntryRemoveDirectFn = func(pipe, entry unsafe.Pointer) error {
			removed++
			return nil
		}
		// DOCA aging evicts by userCtx — drive with the forward entry's userCtx.
		fwdEntry, ok := d.entries[fwdKey]
		if !ok {
			t.Fatalf("forward entry missing before aging (key=%q)", fwdKey)
		}
		d.handleAgedEntry(fwdEntry.userCtx)
		if removed != 2 {
			t.Errorf("docaEntryRemoveDirectFn calls = %d, want 2 (forward + cascaded sibling)", removed)
		}
		if _, ok := d.entries[fwdKey]; ok {
			t.Error("forward entry still present after handleAgedEntry")
		}
		if _, ok := d.entries[revKey]; ok {
			t.Error("reverse (sibling) entry still present after handleAgedEntry — leaked on g_ct_rev_pipe")
		}
	})
}

// TestRouteFlowOffload_Atomicity — the route pair install is both-or-neither:
// an unresolved reverse ARP installs nothing; a reverse add-failure rolls back
// the already-installed forward entry. No half-offloaded flow is ever left.
func TestRouteFlowOffload_Atomicity(t *testing.T) {
	t.Run("reverse ARP unresolved — neither entry installs", func(t *testing.T) {
		defer saveRouteSeams()()
		hermeticRouteGet()
		docaGetCTFwdPipeFn = func() unsafe.Pointer { return fakePtr(0xCF01) }
		docaGetCTRevPipeFn = func() unsafe.Pointer { return fakePtr(0xCF02) }
		// Forward (toward server 31.31.31.1) resolves; reverse (toward client
		// 10.99.0.2) does not.
		resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
			if ip.Equal(net.ParseIP("10.99.0.2")) {
				return 0, [6]byte{}, [6]byte{}, false
			}
			return 1, [6]byte{}, [6]byte{}, true
		}
		var adds int
		docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
			adds++
			return fakePtr(uintptr(0xE000 + adds)), nil, nil
		}
		d := &DpDocaBf2{entries: make(map[string]*docaOffloadEntry)}
		if err := d.RouteFlowOffload(routeCT(), 0); err != nil {
			t.Fatalf("RouteFlowOffload: %v (want nil — flow deferred to eBPF)", err)
		}
		if adds != 0 {
			t.Errorf("docaEntryAddBasicFn calls = %d, want 0 (no half-install on reverse ARP miss)", adds)
		}
		if len(d.entries) != 0 {
			t.Errorf("d.entries has %d entries, want 0", len(d.entries))
		}
	})

	t.Run("reverse add fails — forward rolled back", func(t *testing.T) {
		defer saveRouteSeams()()
		hermeticRouteGet()
		docaGetCTFwdPipeFn = func() unsafe.Pointer { return fakePtr(0xCF01) }
		docaGetCTRevPipeFn = func() unsafe.Pointer { return fakePtr(0xCF02) }
		resolveFlowMACsFn = resolveAlwaysOK
		var adds int
		docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
			adds++
			if direction == "reply" {
				return nil, nil, ErrNotSupported // reverse add fails
			}
			return fakePtr(uintptr(0xE000 + adds)), nil, nil
		}
		var rollbacks int
		docaEntryRemoveDirectFn = func(pipe, entry unsafe.Pointer) error {
			rollbacks++
			return nil
		}
		d := &DpDocaBf2{entries: make(map[string]*docaOffloadEntry)}
		err := d.RouteFlowOffload(routeCT(), 0)
		if err == nil {
			t.Fatal("RouteFlowOffload: want error on reverse add failure, got nil")
		}
		if adds != 2 {
			t.Errorf("docaEntryAddBasicFn calls = %d, want 2 (forward + failed reverse)", adds)
		}
		if rollbacks != 1 {
			t.Errorf("docaEntryRemoveDirectFn (forward rollback) calls = %d, want 1", rollbacks)
		}
		if len(d.entries) != 0 {
			t.Errorf("d.entries has %d entries, want 0 (forward must be rolled back)", len(d.entries))
		}
	})
}
