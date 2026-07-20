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
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// resolveFlowMACsCall records one invocation of the resolveFlowMACsFn spy.
// Tests in this file inject a spy via the package-level resolveFlowMACsFn seam
// (declared in dpu_doca_bf2_helpers.go) so invariants can
// be asserted without the DOCA toolchain.
type resolveFlowMACsCall struct {
	ip net.IP
}

// newTestDpDocaBf2 builds a minimal DpDocaBf2 for paired-offload tests under
// !doca. P51-02. The struct fields populated here mirror the subset
// the !doca-build pairedLBFlowOffload (in dpu_doca_bf2_stub.go) and the
// build-tag-agnostic helpers (in dpu_doca_bf2_helpers.go) actually touch.
func newTestDpDocaBf2() *DpDocaBf2 {
	return &DpDocaBf2{
		entries:      make(map[string]*docaOffloadEntry),
		pendingPair:  make(map[string]*pendingPair),
		bidirEnabled: true,
	}
}

// TestPhase51_ReplyARPTarget_IsForwardSIP — : for DNAT/OneArm/FullNAT, the
// reply-direction resolveFlowMACsFn call inside pairedLBFlowOffload receives
// fwd.SIP (the client IP) — NOT rev.DIP. This is the architectural payload of
func TestPhase51_ReplyARPTarget_IsForwardSIP(t *testing.T) {
	defer resetPairTestState()

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
			var calls []resolveFlowMACsCall
			origResolve := resolveFlowMACsFn
			resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
				// Defensive copy — net.IP is a slice; storing the slot directly
				// risks aliasing if callers reuse buffers. Tests benefit from
				// independent samples.
				ipCopy := append(net.IP(nil), ip...)
				calls = append(calls, resolveFlowMACsCall{ip: ipCopy})
				return 1, [6]byte{}, [6]byte{}, true
			}
			defer func() { resolveFlowMACsFn = origResolve }()

			d := newTestDpDocaBf2()
			_ = d.pairedLBFlowOffload(tc.fwd, tc.rev, 0)

			// The reply branch MUST have called resolveFlowMACsFn with fwd.SIP.
			// The reply branch MUST NOT have called resolveFlowMACsFn with
			// rev.DIP unless rev.DIP coincidentally equals fwd.SIP (DNAT mode:
			// rev.DIP == client IP == fwd.SIP — the equality is benign).
			var sawReplyTarget bool
			var sawWrongTarget bool
			for _, c := range calls {
				if c.ip.Equal(tc.fwd.SIP) {
					sawReplyTarget = true
				}
				if c.ip.Equal(tc.rev.DIP) && !tc.rev.DIP.Equal(tc.fwd.SIP) {
					sawWrongTarget = true
				}
			}
			if !sawReplyTarget {
				t.Fatalf(" violation: reply branch did not call resolveFlowMACs(fwd.SIP=%s); got calls=%v",
					tc.fwd.SIP, calls)
			}
			if sawWrongTarget {
				t.Fatalf(" violation: reply branch called resolveFlowMACs(rev.DIP=%s) — today's broken pattern (b2a8084 / 415305f)",
					tc.rev.DIP)
			}
		})
	}
}

// TestPhase51_ReplyARP_FIBFallback — happy path: when the direct
// resolveFlowMACs(fwd.SIP) call returns ok=false, the reply branch retries
// ONCE via nextHopForFlow(fwd.SIP) and re-invokes the resolver with the FIB
// gateway. Cross-subnet clients reach the offload path via this fallback.
func TestPhase51_ReplyARP_FIBFallback(t *testing.T) {
	defer resetPairTestState()

	fwd := dnatForwardCT()
	rev := dnatReplyCT()

	// Forward call (fwd.NatIP=31.31.31.1) succeeds.
	// Reply direct call (fwd.SIP=10.99.0.2) misses → triggers FIB.
	// Reply FIB call returns gw=10.99.0.1; resolver retry succeeds.
	gw := net.ParseIP("10.99.0.1")
	var resolveCalls []net.IP
	var nextHopCalls []net.IP

	origResolve := resolveFlowMACsFn
	resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
		resolveCalls = append(resolveCalls, append(net.IP(nil), ip...))
		if ip.Equal(fwd.SIP) {
			return 0, [6]byte{}, [6]byte{}, false
		}
		return 1, [6]byte{}, [6]byte{}, true
	}
	defer func() { resolveFlowMACsFn = origResolve }()

	origRouteGet := routeGetFn
	routeGetFn = func(dst net.IP) ([]netlink.Route, error) {
		nextHopCalls = append(nextHopCalls, append(net.IP(nil), dst...))
		return []netlink.Route{{Gw: gw}}, nil
	}
	defer func() { routeGetFn = origRouteGet }()

	d := newTestDpDocaBf2()
	_ = d.pairedLBFlowOffload(fwd, rev, 0)

	// nextHopForFlow MUST have been called for the reply direction with fwd.SIP.
	var fibForReply bool
	for _, ip := range nextHopCalls {
		if ip.Equal(fwd.SIP) {
			fibForReply = true
		}
	}
	if !fibForReply {
		t.Fatalf(" fallback: nextHopForFlow(fwd.SIP=%s) was not invoked; nextHopCalls=%v",
			fwd.SIP, nextHopCalls)
	}

	// resolveFlowMACsFn MUST have been retried with the FIB gateway IP.
	var sawGw bool
	for _, ip := range resolveCalls {
		if ip.Equal(gw) {
			sawGw = true
		}
	}
	if !sawGw {
		t.Fatalf(" fallback: resolveFlowMACs not re-invoked with FIB gw=%s; resolveCalls=%v",
			gw, resolveCalls)
	}
}

// TestPhase51_SameSubnet_NoFIBWrap — anti-c15fd32 / CONTEXT
// success-criterion-10: when the direct resolveFlowMACs call succeeds,
// nextHopForFlow MUST NOT be invoked. This is the same-subnet fast path; any
// regression that wraps every resolution in a FIB lookup is the c15fd32 /
// 415305f anti-pattern that broke OneArm/FullNAT in two prior reverts.
func TestPhase51_SameSubnet_NoFIBWrap(t *testing.T) {
	defer resetPairTestState()

	fwd := oneArmForwardCT()
	rev := oneArmReplyCT()

	var nextHopCalls []net.IP

	origResolve := resolveFlowMACsFn
	resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
		// Always succeed — no FIB fallback should ever fire.
		return 1, [6]byte{}, [6]byte{}, true
	}
	defer func() { resolveFlowMACsFn = origResolve }()

	origRouteGet := routeGetFn
	routeGetFn = func(dst net.IP) ([]netlink.Route, error) {
		nextHopCalls = append(nextHopCalls, append(net.IP(nil), dst...))
		return []netlink.Route{{Gw: net.ParseIP("10.99.0.1")}}, nil
	}
	defer func() { routeGetFn = origRouteGet }()

	d := newTestDpDocaBf2()
	_ = d.pairedLBFlowOffload(fwd, rev, 0)

	if len(nextHopCalls) != 0 {
		t.Fatalf("c15fd32 anti-pattern regression: nextHopForFlow called %d time(s) when direct ARP succeeded; calls=%v",
			len(nextHopCalls), nextHopCalls)
	}
}
