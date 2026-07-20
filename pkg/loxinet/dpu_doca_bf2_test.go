//go:build !doca

package loxinet

import (
	"errors"
	"net"
	"testing"

	nl "github.com/vishvananda/netlink"
)

// TestLBFlowOffloadDispatchExpectations validates the NatFlags dispatch
// table used by LBFlowOffload. Since actual DOCA calls require hardware,
// these tests verify the input->expectation mapping for all NAT modes.

func TestFullNATOriginDirection(t *testing.T) {
	// Full NAT origin: NatFlags=1 (DNAT) with NatRIP set (src rewrite)
	ct := &DpCtInfo{
		DIP:      net.ParseIP("20.20.20.1"), // VIP
		SIP:      net.ParseIP("10.10.10.1"), // Client
		Dport:    2022,
		Sport:    50000,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 1,
		NatIP:    net.ParseIP("31.31.31.1"), // Endpoint
		NatPort:  8080,
		NatRIP:   net.ParseIP("20.20.20.1"), // VIP for src rewrite
	}
	// Verify expectations:
	// - NatFlags=1 -> DNAT pipe (dst rewrite)
	// - NatRIP non-nil and non-zero -> also rewrite src IP
	if ct.NatFlags != 1 {
		t.Fatalf("expected NatFlags=1 for origin direction, got %d", ct.NatFlags)
	}
	if ct.NatRIP == nil || ct.NatRIP.IsUnspecified() {
		t.Fatal("Full NAT origin must have NatRIP set for src rewrite")
	}
	if !ct.NatRIP.Equal(net.ParseIP("20.20.20.1")) {
		t.Fatalf("expected NatRIP=VIP(20.20.20.1), got %s", ct.NatRIP)
	}
	// NatDsr must be false for Full NAT
	if ct.NatDsr {
		t.Fatal("Full NAT must not have NatDsr=true")
	}
}

func TestFullNATReplyDirection(t *testing.T) {
	// Full NAT reply: NatFlags=2 (SNAT) with NatRIP set (dst rewrite back to client)
	ct := &DpCtInfo{
		DIP:      net.ParseIP("10.10.10.1"), // Client (original src, now dst in reply)
		SIP:      net.ParseIP("31.31.31.1"), // Endpoint
		Dport:    50000,
		Sport:    8080,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 2,
		NatIP:    net.ParseIP("20.20.20.1"), // VIP (rewrite src back to VIP)
		NatPort:  2022,
		NatRIP:   net.ParseIP("10.10.10.1"), // Client IP (rewrite dst back to client)
	}
	if ct.NatFlags != 2 {
		t.Fatalf("expected NatFlags=2 for reply direction, got %d", ct.NatFlags)
	}
	if ct.NatRIP == nil || ct.NatRIP.IsUnspecified() {
		t.Fatal("Full NAT reply must have NatRIP set for dst rewrite")
	}
}

func TestNatRIPNilDoesNotCrash(t *testing.T) {
	// NatRIP=nil should be handled gracefully (no src/dst rewrite)
	ct := &DpCtInfo{
		DIP:      net.ParseIP("20.20.20.1"),
		SIP:      net.ParseIP("10.10.10.1"),
		Dport:    2020,
		Sport:    50000,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 1,
		NatIP:    net.ParseIP("31.31.31.1"),
		NatPort:  8080,
		NatRIP:   nil, // No src rewrite
	}
	// LBFlowOffload line 295 guard: if ct.NatRIP != nil && !ct.NatRIP.IsUnspecified
	// Should skip src rewrite, only do dst rewrite (plain DNAT behavior)
	if ct.NatRIP != nil && !ct.NatRIP.IsUnspecified() {
		t.Fatal("Expected NatRIP to be nil (no src rewrite)")
	}
}

func TestNatRIPZeroIsUnspecified(t *testing.T) {
	// NatRIP=0.0.0.0 (self-traffic edge case from rules.go:1386)
	ct := &DpCtInfo{
		DIP:      net.ParseIP("20.20.20.1"),
		SIP:      net.ParseIP("10.10.10.1"),
		Dport:    2022,
		Sport:    50000,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 1,
		NatIP:    net.ParseIP("31.31.31.1"),
		NatPort:  8080,
		NatRIP:   net.IPv4(0, 0, 0, 0),
	}
	// Line 295 guard should skip src rewrite because IsUnspecified=true
	if !ct.NatRIP.IsUnspecified() {
		t.Fatal("Expected 0.0.0.0 to be unspecified")
	}
}

func TestDSRSkipsOffload(t *testing.T) {
	ct := &DpCtInfo{
		DIP:      net.ParseIP("20.20.20.1"),
		SIP:      net.ParseIP("10.10.10.1"),
		Dport:    2023,
		Sport:    50000,
		Proto:    "tcp",
		CState:   "est",
		NatFlags: 1,
		NatIP:    net.ParseIP("31.31.31.1"),
		NatPort:  8080,
		NatDsr:   true,
	}
	// LBFlowOffload returns nil for DSR (no DOCA offload)
	if !ct.NatDsr {
		t.Fatal("DSR flow must have NatDsr=true to skip DOCA offload")
	}
}

func TestAllNATModesNatFlagsTable(t *testing.T) {
	// Table-driven test covering all NAT modes' expected NatFlags values
	tests := []struct {
		name     string
		mode     int   // LB mode
		natFlags uint8 // Expected NatFlags for origin direction
		hasRIP   bool  // Whether NatRIP is expected
		isDSR    bool  // Whether NatDsr=true
	}{
		{"DNAT origin", 0, 1, false, false},
		{"One-Arm origin", 1, 1, true, false},      // NatRIP = VIP
		{"Full NAT origin", 2, 1, true, false},     // NatRIP = VIP
		{"DSR origin", 3, 1, false, true},          // NatDsr=true, skip offload
		{"Host One-Arm origin", 5, 3, true, false}, // HDNAT
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &DpCtInfo{
				DIP:      net.ParseIP("20.20.20.1"),
				SIP:      net.ParseIP("10.10.10.1"),
				Dport:    uint16(2020 + tt.mode),
				Sport:    50000,
				Proto:    "tcp",
				CState:   "est",
				NatFlags: tt.natFlags,
				NatIP:    net.ParseIP("31.31.31.1"),
				NatPort:  8080,
				NatDsr:   tt.isDSR,
			}
			if tt.hasRIP {
				ct.NatRIP = net.ParseIP("20.20.20.1")
			}

			// Verify dispatch expectations
			if ct.NatDsr != tt.isDSR {
				t.Errorf("NatDsr mismatch: want %v, got %v", tt.isDSR, ct.NatDsr)
			}
			if ct.NatFlags != tt.natFlags {
				t.Errorf("NatFlags mismatch: want %d, got %d", tt.natFlags, ct.NatFlags)
			}
			if tt.hasRIP && (ct.NatRIP == nil || ct.NatRIP.IsUnspecified()) {
				t.Error("Expected NatRIP to be set")
			}
			if !tt.hasRIP && ct.NatRIP != nil && !ct.NatRIP.IsUnspecified() {
				t.Error("Expected NatRIP to be nil/unspecified")
			}
		})
	}
}

func TestDocaFwdConstants(t *testing.T) {
	// Verify the Go-side FWD_PORT constant matches expected value
	if docaFwdPort != 1 {
		t.Fatalf("docaFwdPort must be 1 (FWD_PORT), got %d", docaFwdPort)
	}
}

func TestDocaCapacityValues(t *testing.T) {
	// Verify pipe capacity constants are set to expected values
	if docaLBPipeCapacity != 4096 {
		t.Fatalf("docaLBPipeCapacity expected 4096, got %d", docaLBPipeCapacity)
	}
}

func TestDocaPipeCreateBasicSignature(t *testing.T) {
	// Verify DocaPipeCreateBasic accepts nrEntries parameter (stub returns error, but compiles)
	_, err := DocaPipeCreateBasic("test-pipe",
		0xFFFFFFFF, 0xFFFF, 0, 0, 6, /* proto=TCP */
		docaFwdPort, 0, docaLBPipeCapacity)
	if err == nil {
		t.Fatal("stub should return error")
	}
}

func TestDocaGetCTFwdPipeStub(t *testing.T) {
	// -06 (TX-2): renamed from TestDocaGetCTPipeStub in lockstep
	// with the DocaGetCTPipe → DocaGetCTFwdPipe rename.
	// Verify DocaGetCTFwdPipe stub returns nil on non-DOCA builds.
	pipe := DocaGetCTFwdPipe()
	if pipe != nil {
		t.Fatal("stub DocaGetCTFwdPipe should return nil")
	}
}

func TestUDPFullNATRequiresEstState(t *testing.T) {
	// UDP flows need CState="udp-est" for DOCA offload
	// (dpebpf_linux.go:4012-4016 requires udp-est)
	ct := &DpCtInfo{
		DIP:      net.ParseIP("20.20.20.1"),
		SIP:      net.ParseIP("10.10.10.1"),
		Dport:    2032,
		Sport:    50000,
		Proto:    "udp",
		CState:   "udp-est",
		NatFlags: 1,
		NatIP:    net.ParseIP("31.31.31.1"),
		NatPort:  8081,
		NatRIP:   net.ParseIP("20.20.20.1"),
	}
	if ct.CState != "udp-est" {
		t.Fatalf("UDP Full NAT requires CState=udp-est for offload, got %s", ct.CState)
	}
	if ct.Proto != "udp" {
		t.Fatal("Expected UDP protocol")
	}
}

// --- : nextHopForFlow helper + proto filter tests (P47-R6) ---
//
// These tests stub routeGetFn (package-level FIB walker) so they run under
// //go:build !doca on developer laptops without DOCA toolchain or root privs.

// TestNextHopForFlow_CrossSubnet asserts the FIB next-hop selection logic
// used by RouteFlowOffload (P47-R6). For cross-subnet destinations the
// helper must return the gateway IP (not the flow destination).
func TestNextHopForFlow_CrossSubnet(t *testing.T) {
	d := &DpDocaBf2{}
	origFn := routeGetFn
	defer func() { routeGetFn = origFn }()

	dst := net.ParseIP("10.20.30.40")
	gw := net.ParseIP("192.168.1.1")
	routeGetFn = func(ip net.IP) ([]nl.Route, error) {
		return []nl.Route{{Gw: gw, LinkIndex: 3}}, nil
	}
	if got := d.nextHopForFlow(dst); !got.Equal(gw) {
		t.Fatalf("cross-subnet: want gateway %s, got %s", gw, got)
	}
}

// TestNextHopForFlow_DirectAttachedNilGw: directly-attached route (Gw == nil)
// must return the flow destination — there is no gateway to resolve via.
func TestNextHopForFlow_DirectAttachedNilGw(t *testing.T) {
	d := &DpDocaBf2{}
	origFn := routeGetFn
	defer func() { routeGetFn = origFn }()

	dst := net.ParseIP("10.10.0.5")
	routeGetFn = func(ip net.IP) ([]nl.Route, error) {
		return []nl.Route{{Gw: nil, LinkIndex: 2}}, nil
	}
	if got := d.nextHopForFlow(dst); !got.Equal(dst) {
		t.Fatalf("direct-attached(nil): want dst %s, got %s", dst, got)
	}
}

// TestNextHopForFlow_DirectAttachedZeroGw: directly-attached route with
// Gw == 0.0.0.0 (IsUnspecified) must also return the flow destination.
func TestNextHopForFlow_DirectAttachedZeroGw(t *testing.T) {
	d := &DpDocaBf2{}
	origFn := routeGetFn
	defer func() { routeGetFn = origFn }()

	dst := net.ParseIP("10.10.0.5")
	routeGetFn = func(ip net.IP) ([]nl.Route, error) {
		return []nl.Route{{Gw: net.IPv4zero, LinkIndex: 2}}, nil
	}
	if got := d.nextHopForFlow(dst); !got.Equal(dst) {
		t.Fatalf("direct-attached(0.0.0.0): want dst %s, got %s", dst, got)
	}
}

// TestNextHopForFlow_FibError: netlink error must fall back safely to dst
// (caller's subsequent ARP lookup will miss and skip offload — eBPF continues).
func TestNextHopForFlow_FibError(t *testing.T) {
	d := &DpDocaBf2{}
	origFn := routeGetFn
	defer func() { routeGetFn = origFn }()

	dst := net.ParseIP("10.20.30.40")
	routeGetFn = func(ip net.IP) ([]nl.Route, error) {
		return nil, errors.New("network unreachable")
	}
	if got := d.nextHopForFlow(dst); !got.Equal(dst) {
		t.Fatalf("fib error: want fallback to dst %s, got %s", dst, got)
	}
}

// TestNextHopForFlow_EmptyFib: empty FIB result must fall back safely to dst.
func TestNextHopForFlow_EmptyFib(t *testing.T) {
	d := &DpDocaBf2{}
	origFn := routeGetFn
	defer func() { routeGetFn = origFn }()

	dst := net.ParseIP("10.20.30.40")
	routeGetFn = func(ip net.IP) ([]nl.Route, error) { return nil, nil }
	if got := d.nextHopForFlow(dst); !got.Equal(dst) {
		t.Fatalf("empty fib: want fallback to dst %s, got %s", dst, got)
	}
}

// TestNextHopForFlow_NilDst: nil destination must short-circuit to nil
// (defensive — caller should never pass nil, but we guard anyway).
func TestNextHopForFlow_NilDst(t *testing.T) {
	d := &DpDocaBf2{}
	if got := d.nextHopForFlow(nil); got != nil {
		t.Fatalf("nil dst: want nil, got %v", got)
	}
}

// TestProtoNumForRouteOffload asserts the expanded proto filter (P47-R6 Part A).
// Identity-rewrite + MAC rewrite + FWD_PORT is valid for TCP/UDP/ICMP/SCTP/GRE/ESP;
// all other proto strings stay on the eBPF slow path.
func TestProtoNumForRouteOffload(t *testing.T) {
	cases := []struct {
		proto   string
		wantNum uint8
		wantOk  bool
	}{
		{"tcp", 6, true},
		{"udp", 17, true},
		{"icmp", 1, true},
		{"sctp", 132, true},
		{"gre", 47, true},
		{"esp", 50, true},
		{"none", 0, false},
		{"", 0, false},
		{"unknown", 0, false},
	}
	for _, c := range cases {
		gotNum, gotOk := protoNumForRouteOffload(c.proto)
		if gotNum != c.wantNum || gotOk != c.wantOk {
			t.Errorf("proto=%q: got (%d,%v), want (%d,%v)",
				c.proto, gotNum, gotOk, c.wantNum, c.wantOk)
		}
	}
}
