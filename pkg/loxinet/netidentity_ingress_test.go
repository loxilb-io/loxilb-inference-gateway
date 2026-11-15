/*
 * Copyright (c) 2026 LoxiLB Authors
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
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/aikey"
)

// nidTunnels is the node's IPsec tunnels for a test: tunnel name -> VTI.
type nidTunnels map[string]string

func (m nidTunnels) vti(name string) (string, bool) {
	v, ok := m[name]
	return v, ok && v != ""
}

func nidAlias(name, tenant string, m cmn.NetIdentityMatch, svcs ...string) *cmn.NetIdentityMod {
	return &cmn.NetIdentityMod{Name: name, Tenant: tenant, Match: m, Services: svcs}
}

// The three aliases are other spellings of an interface match: each is
// accepted alone, stored as given, and held to its range.
func TestNetIdentityAliasNormalize(t *testing.T) {
	for _, c := range []struct {
		name  string
		match cmn.NetIdentityMatch
		field string // "" = accepted
	}{
		{"vlan", cmn.NetIdentityMatch{Vlan: 20}, ""},
		{"vlan-max", cmn.NetIdentityMatch{Vlan: 4094}, ""},
		{"vni", cmn.NetIdentityMatch{Vni: 1001}, ""},
		{"vni-max", cmn.NetIdentityMatch{Vni: 1<<24 - 1}, ""},
		{"tunnel", cmn.NetIdentityMatch{IPsecTunnel: " branch-1 "}, ""},
		{"vlan-high", cmn.NetIdentityMatch{Vlan: 4095}, "match.vlan"},
		{"vlan-negative", cmn.NetIdentityMatch{Vlan: -1}, "match.vlan"},
		{"vni-high", cmn.NetIdentityMatch{Vni: 1 << 24}, "match.vni"},
		{"vni-negative", cmn.NetIdentityMatch{Vni: -7}, "match.vni"},
		{"tunnel-bad", cmn.NetIdentityMatch{IPsecTunnel: "a b"}, "match.ipsec_tunnel"},
		{"tunnel-slash", cmn.NetIdentityMatch{IPsecTunnel: "../x"}, "match.ipsec_tunnel"},
		{"vlan-and-vni", cmn.NetIdentityMatch{Vlan: 20, Vni: 1001}, "match"},
		{"vlan-and-if", cmn.NetIdentityMatch{Vlan: 20, IngressIf: "vlan20"}, "match"},
		{"tunnel-and-cidr", cmn.NetIdentityMatch{IPsecTunnel: "b", CIDR: []string{"10.0.0.0/8"}}, "match"},
		{"nothing", cmn.NetIdentityMatch{}, "match"},
	} {
		out, err := netidNormalize(nidAlias("b", "t", c.match))
		if c.field == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
				continue
			}
			want := c.match
			want.IPsecTunnel = strings.TrimSpace(want.IPsecTunnel)
			if !reflect.DeepEqual(out.Match, want) {
				t.Errorf("%s: stored as %+v, want %+v", c.name, out.Match, want)
			}
			continue
		}
		var ve *cmn.ValidationError
		if !errors.As(err, &ve) || ve.Field != c.field {
			t.Errorf("%s: got %v, want a validation error on %s", c.name, err, c.field)
		}
	}
}

// credential: network stands on a network boundary: any interface match,
// by name or by alias, and never an address range.
func TestNetIdentityCredentialNetworkTakesAnyInterfaceMatch(t *testing.T) {
	for _, m := range []cmn.NetIdentityMatch{
		{IngressIf: "vlan20"}, {Vlan: 20}, {Vni: 1001}, {IPsecTunnel: "branch-1"},
	} {
		pm := nidAlias("b", "t", m)
		pm.Credential = cmn.NetIdentityCredentialNetwork
		if _, err := netidNormalize(pm); err != nil {
			t.Errorf("%+v: refused: %v", m, err)
		}
	}
	pm := nidCIDR("b", "t", []string{"10.20.0.0/24"})
	pm.Credential = cmn.NetIdentityCredentialNetwork
	var ve *cmn.ValidationError
	if _, err := netidNormalize(pm); !errors.As(err, &ve) || ve.Field != "credential" {
		t.Errorf("a cidr match with credential network: got %v, want a validation error on credential", err)
	}
}

// An alias resolves to this node's interface for it, and a connection that
// arrived on that interface is its tenant's.
func TestNetIdentityAliasResolvesToItsInterface(t *testing.T) {
	ifs := nidIfs{"vlan20": 5, "vxlan1001": 7, "vti100": 9, "eth0": 2}
	h, _ := newNidHolder(ifs)
	h.tunnelIf = nidTunnels{"branch-1": "vti100", "no-mark": ""}.vti

	mustAdd(t, h, nidAlias("line", "t-line", cmn.NetIdentityMatch{Vlan: 20}, nidSvcA))
	mustAdd(t, h, nidAlias("grade", "t-grade", cmn.NetIdentityMatch{Vni: 1001}, nidSvcA))
	mustAdd(t, h, nidAlias("branch", "t-branch", cmn.NetIdentityMatch{IPsecTunnel: "branch-1"}, nidSvcA))
	mustAdd(t, h, nidAlias("nomark", "t-nomark", cmn.NetIdentityMatch{IPsecTunnel: "no-mark"}, nidSvcA))
	mustAdd(t, h, nidAlias("unknown", "t-unknown", cmn.NetIdentityMatch{IPsecTunnel: "elsewhere"}, nidSvcA))

	for idx, want := range map[int]string{5: "t-line", 7: "t-grade", 9: "t-branch", 2: "", 0: "", 11: ""} {
		if got := nidTenant(t, h, "10.9.9.9", idx, nidSvcA); got != want {
			t.Errorf("ingress index %d: tenant %q, want %q", idx, got, want)
		}
	}
	// The same interface on another service is not this binding's.
	if got := nidTenant(t, h, "10.9.9.9", 5, nidSvcB); got != "" {
		t.Errorf("another service: tenant %q", got)
	}
	// What the snapshot was compiled with, by binding.
	want := map[string]int{"line": 5, "grade": 7, "branch": 9, "nomark": 0, "unknown": 0}
	if !reflect.DeepEqual(h.ifSeen, want) {
		t.Errorf("compiled with %v, want %v", h.ifSeen, want)
	}
}

// An alias with a fixed interface name claims that interface: the same
// interface under another spelling and another tenant is the 409 two
// bindings of one interface get.
func TestNetIdentityAliasClaimsItsInterface(t *testing.T) {
	h, _ := newNidHolder(nidIfs{"vlan20": 5})
	mustAdd(t, h, nidAlias("by-vlan", "t-a", cmn.NetIdentityMatch{Vlan: 20}, nidSvcA))

	if code, err := h.BindingAdd(nidIf("by-name", "t-b", "vlan20", nidSvcA)); code != NetIdentityConflictErr || err == nil {
		t.Fatalf("the same interface by name for another tenant: code %d err %v", code, err)
	}
	if code, err := h.BindingAdd(nidAlias("by-vni", "t-b", cmn.NetIdentityMatch{Vni: 20}, nidSvcA)); err != nil {
		t.Fatalf("another interface was refused: code %d err %v", code, err)
	}
	// Same tenant under the other spelling: accepted, as any duplicate is.
	mustAdd(t, h, nidIf("by-name", "t-a", "vlan20", nidSvcA))
	// Another service is another claim.
	mustAdd(t, h, nidIf("by-name-b", "t-b", "vlan20", nidSvcB))
	// Two tunnels are two claims; one tunnel twice for two tenants is one.
	mustAdd(t, h, nidAlias("tun-1", "t-a", cmn.NetIdentityMatch{IPsecTunnel: "branch-1"}, nidSvcA))
	mustAdd(t, h, nidAlias("tun-2", "t-b", cmn.NetIdentityMatch{IPsecTunnel: "branch-2"}, nidSvcA))
	if code, _ := h.BindingAdd(nidAlias("tun-1b", "t-b", cmn.NetIdentityMatch{IPsecTunnel: "branch-1"}, nidSvcA)); code != NetIdentityConflictErr {
		t.Fatalf("one tunnel for two tenants: code %d", code)
	}
}

// A binding whose interface is missing says so, by whichever field it was
// written with, and a tunnel with nothing behind it says that instead.
func TestNetIdentityMissingInterfaceWarningNamesTheField(t *testing.T) {
	h, _ := newNidHolder(nidIfs{"vlan20": 5, "vti100": 9})
	h.tunnelIf = nidTunnels{"branch-1": "vti100", "later": "vti200"}.vti
	for _, c := range []struct {
		match cmn.NetIdentityMatch
		want  string // "" = no warning
	}{
		{cmn.NetIdentityMatch{Vlan: 20}, ""},
		{cmn.NetIdentityMatch{IPsecTunnel: "branch-1"}, ""},
		{cmn.NetIdentityMatch{Vlan: 30}, `match.vlan: no interface "vlan30"`},
		{cmn.NetIdentityMatch{Vni: 1001}, `match.vni: no interface "vxlan1001"`},
		{cmn.NetIdentityMatch{IngressIf: "eth9"}, `match.ingress_if: no interface "eth9"`},
		{cmn.NetIdentityMatch{IPsecTunnel: "later"}, `match.ipsec_tunnel: no interface "vti200"`},
		{cmn.NetIdentityMatch{IPsecTunnel: "nowhere"}, `match.ipsec_tunnel: IPsec tunnel "nowhere" is not configured`},
	} {
		got := h.BindingWarning(nidAlias("b", "t", c.match))
		if c.want == "" && got != "" {
			t.Errorf("%+v: unexpected warning %q", c.match, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%+v: warning %q does not say %q", c.match, got, c.want)
		}
	}
}

// The interfaces behind the bindings change under them: one that appears
// starts matching, one that is re-created is followed by name to its new
// index and the old index stops matching, one that goes away matches
// nothing, and nothing of it needs a configuration change.
func TestNetIdentityRefreshFollowsTheInterfaces(t *testing.T) {
	ifs := nidIfs{}
	tun := nidTunnels{}
	h, dp := newNidHolder(ifs)
	h.tunnelIf = tun.vti

	pm := nidAlias("line", "t-line", cmn.NetIdentityMatch{Vlan: 20}, nidSvcA)
	pm.Credential = cmn.NetIdentityCredentialNetwork
	mustAdd(t, h, pm)
	mustAdd(t, h, nidAlias("branch", "t-branch", cmn.NetIdentityMatch{IPsecTunnel: "branch-1"}, nidSvcA))

	// Stored before the interface exists: bound, matching nothing.
	if bound, _ := dp.has(nidSvcA); !bound {
		t.Fatal("the service is not bound")
	}
	if got := nidTenant(t, h, "10.1.1.1", 5, nidSvcA); got != "" {
		t.Fatalf("before the interface exists: tenant %q", got)
	}
	// Nor does a connection whose interface is not known: index 0 is "not
	// read", never the interface a missing name stands for.
	if got := nidTenant(t, h, "10.1.1.1", 0, nidSvcA); got != "" {
		t.Fatalf("a connection with no interface read matched a binding whose interface is missing: tenant %q", got)
	}
	if h.refresh() {
		t.Fatal("a refresh with nothing changed reported a change")
	}

	// It appears.
	ifs["vlan20"] = 5
	if !h.refresh() {
		t.Fatal("the interface appeared and the refresh saw nothing")
	}
	if got := nidTenant(t, h, "10.1.1.1", 5, nidSvcA); got != "t-line" {
		t.Fatalf("after it appeared: tenant %q", got)
	}
	if h.refresh() {
		t.Fatal("a second refresh reported a change")
	}

	// It is removed and created again: a new index under the same name.
	ifs["vlan20"] = 12
	if !h.refresh() {
		t.Fatal("the interface was re-created and the refresh saw nothing")
	}
	if got := nidTenant(t, h, "10.1.1.1", 12, nidSvcA); got != "t-line" {
		t.Fatalf("the new index: tenant %q", got)
	}
	if got := nidTenant(t, h, "10.1.1.1", 5, nidSvcA); got != "" {
		t.Fatalf("the old index still answers: tenant %q", got)
	}

	// The tunnel is configured, then its VTI appears.
	tun["branch-1"] = "vti100"
	if h.refresh() {
		t.Fatal("a tunnel with no interface yet changed the snapshot")
	}
	ifs["vti100"] = 20
	if !h.refresh() {
		t.Fatal("the VTI appeared and the refresh saw nothing")
	}
	if got := nidTenant(t, h, "10.1.1.1", 20, nidSvcA); got != "t-branch" {
		t.Fatalf("the tunnel: tenant %q", got)
	}

	// The interface goes away: no match, no failure, the service stays
	// bound (a credential: network request is then answered 401 by the
	// gate, as for any source with no binding).
	delete(ifs, "vlan20")
	if !h.refresh() {
		t.Fatal("the interface went away and the refresh saw nothing")
	}
	if got := nidTenant(t, h, "10.1.1.1", 12, nidSvcA); got != "" {
		t.Fatalf("after it went away: tenant %q", got)
	}
	if bound, _ := dp.has(nidSvcA); !bound {
		t.Fatal("the service lost its binding with the interface")
	}
	if got := nidTenant(t, h, "10.1.1.1", 20, nidSvcA); got != "t-branch" {
		t.Fatalf("the other binding was disturbed: tenant %q", got)
	}
	// The tunnel is deleted: its VTI may linger, the binding does not.
	delete(tun, "branch-1")
	if !h.refresh() {
		t.Fatal("the tunnel went away and the refresh saw nothing")
	}
	if got := nidTenant(t, h, "10.1.1.1", 20, nidSvcA); got != "" {
		t.Fatalf("after the tunnel went away: tenant %q", got)
	}
}

// A failure while the interfaces are read leaves the snapshot in place and
// the process running; the next round reads them again.
func TestNetIdentityRefreshSurvivesAFailure(t *testing.T) {
	ifs := nidIfs{"vlan20": 5}
	fail := false
	dp := &nidDP{}
	h := newNetIdentityH(dp.publish, func(name string) (int, bool) {
		if fail {
			panic("interface table unreadable")
		}
		return ifs.index(name)
	})
	mustAdd(t, h, nidAlias("line", "t-line", cmn.NetIdentityMatch{Vlan: 20}, nidSvcA))

	ifs["vlan20"] = 9
	fail = true
	if h.refresh() {
		t.Fatal("a failed refresh reported a change")
	}
	if got := nidTenant(t, h, "10.1.1.1", 5, nidSvcA); got != "t-line" {
		t.Fatalf("the snapshot in place was lost: tenant %q", got)
	}
	// The lock was released: the next round runs and follows the change.
	fail = false
	if !h.refresh() {
		t.Fatal("the next refresh did not follow the change")
	}
	if got := nidTenant(t, h, "10.1.1.1", 9, nidSvcA); got != "t-line" {
		t.Fatalf("after the failure cleared: tenant %q", got)
	}
}

// The data plane reads a connection's ingress interface only while a
// binding matches on one: the switch goes on before the first snapshot that
// needs it and off after the last one is gone.
func TestNetIdentityInterfaceSwitchFollowsTheBindings(t *testing.T) {
	h, _ := newNidHolder(nidIfs{"vlan20": 5})
	var mu sync.Mutex
	var steps []string
	on := false
	h.publishIfMatch = func(v bool) { on = v }
	h.step = func(stage string) {
		mu.Lock()
		defer mu.Unlock()
		if stage == "ifmatch" {
			stage += map[bool]string{true: "-on", false: "-off"}[on]
		}
		steps = append(steps, stage)
	}
	take := func() []string {
		mu.Lock()
		defer mu.Unlock()
		s := steps
		steps = nil
		return s
	}

	mustAdd(t, h, nidCIDR("addr", "t", []string{"10.20.0.0/24"}, nidSvcA))
	if on || h.hasIf.Load() {
		t.Fatal("an address binding switched the interface read on")
	}
	take()

	mustAdd(t, h, nidAlias("line", "t", cmn.NetIdentityMatch{Vlan: 20}, nidSvcA))
	if !on || !h.hasIf.Load() {
		t.Fatal("an interface binding did not switch the read on")
	}
	if got := take(); len(got) == 0 || got[0] != "ifmatch-on" {
		t.Fatalf("switching on: stages %v, want the switch before the snapshot", got)
	}

	// A second one changes nothing about the switch.
	mustAdd(t, h, nidAlias("ghost", "t", cmn.NetIdentityMatch{IPsecTunnel: "nowhere"}, nidSvcA))
	for _, s := range take() {
		if strings.HasPrefix(s, "ifmatch") {
			t.Fatalf("the switch was written again: %s", s)
		}
	}

	// An interface binding that matches nothing still keeps it on: its
	// interface may appear.
	if _, err := h.BindingDel("line"); err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("the switch went off with an interface binding left")
	}
	take()
	if _, err := h.BindingDel("ghost"); err != nil {
		t.Fatal(err)
	}
	if on || h.hasIf.Load() {
		t.Fatal("the switch stayed on with no interface binding left")
	}
	got := take()
	if len(got) == 0 || got[len(got)-1] != "ifmatch-off" {
		t.Fatalf("switching off: stages %v, want the switch after the snapshot", got)
	}
}

// The refresher: a port event wakes it, it does its round and nothing more,
// and it does not look at all while no binding matches on an interface.
func TestNetIdentityRefresherRunsOnAPortEvent(t *testing.T) {
	var mu sync.Mutex
	ifs := nidIfs{}
	reads := 0
	dp := &nidDP{}
	h := newNetIdentityH(dp.publish, func(name string) (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		return ifs.index(name)
	})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		h.refresher(time.Hour, stop)
		close(done)
	}()
	defer func() {
		close(stop)
		<-done
	}()
	kick := func() {
		select {
		case h.kick <- struct{}{}:
		default:
		}
	}
	readsNow := func() int {
		mu.Lock()
		defer mu.Unlock()
		return reads
	}

	// No interface binding: an event is taken and nothing is read.
	mustAdd(t, h, nidCIDR("addr", "t", []string{"10.20.0.0/24"}, nidSvcA))
	before := readsNow()
	kick()
	kick()
	time.Sleep(50 * time.Millisecond)
	if got := readsNow(); got != before {
		t.Fatalf("with no interface binding the refresher read interfaces %d times", got-before)
	}

	mustAdd(t, h, nidAlias("line", "t-line", cmn.NetIdentityMatch{Vlan: 20}, nidSvcA))
	mu.Lock()
	ifs["vlan20"] = 5
	mu.Unlock()
	kick()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ans, rc := netidAnswerFor(h, "10.1.1.1", 5, nidSvcA, ""); rc == 0 && ans.matched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the port event did not reach the resolver")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A port event with no holder yet, or with the refresher busy, is dropped
// without blocking its caller, which may hold the configuration lock.
func TestNetIdentityPortEventNeverBlocks(t *testing.T) {
	prev := netidActive.Load()
	defer netidActive.Store(prev)

	netidActive.Store(nil)
	NetIdentityPortEvent()

	h, _ := newNidHolder(nidIfs{})
	netidActive.Store(h)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			NetIdentityPortEvent() // nobody reads h.kick
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a port event blocked with no refresher running")
	}
	if len(h.kick) != 1 {
		t.Fatalf("pending wake-ups: %d, want one", len(h.kick))
	}
}

// The bound set says which services forward identity: those drop the
// X-Auth-* headers a client sends. A service forwards when a binding that
// names it does.
func TestNetIdentityBoundSetCarriesForward(t *testing.T) {
	fwd := func(pm *cmn.NetIdentityMod) cmn.NetIdentityMod { pm.ForwardIdentity = true; return *pm }
	plain := func(pm *cmn.NetIdentityMod) cmn.NetIdentityMod { return *pm }

	nb := netidBoundOf(map[string]cmn.NetIdentityMod{
		"a": fwd(nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA)),
		"b": plain(nidCIDR("b", "t", []string{"10.2.0.0/16"}, nidSvcA, nidSvcB)),
	})
	for svc, want := range map[string]bool{nidSvcA: true, nidSvcB: false, nidSvcC: false} {
		if got := nb.forwards(svc); got != want {
			t.Errorf("listed: %s forwards %v, want %v", svc, got, want)
		}
	}
	if bound, _ := nb.has(nidSvcB); !bound {
		t.Error("listed: a bound service that does not forward reads as unbound")
	}

	// Every service bound, one forwarding: that one only, and it stays
	// named although every service is bound.
	nb = netidBoundOf(map[string]cmn.NetIdentityMod{
		"a": fwd(nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA)),
		"g": plain(nidCIDR("g", "t", []string{"10.0.0.0/8"})),
	})
	if !nb.all || !nb.forwards(nidSvcA) || nb.forwards(nidSvcB) {
		t.Errorf("all bound, one forwards: %+v", nb)
	}
	if bound, _ := nb.has(nidSvcB); !bound {
		t.Error("all bound: another service reads as unbound")
	}

	// The flag follows the service list and nothing else: a binding that
	// names no service is refused with forward_identity, and were one in the
	// set all the same, no service it does not name would forward.
	nb = netidBoundOf(map[string]cmn.NetIdentityMod{
		"a": fwd(nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA)),
		"g": fwd(nidCIDR("g", "t", []string{"10.0.0.0/8"})),
	})
	if !nb.all || !nb.forwards(nidSvcA) || nb.forwards(nidSvcB) || nb.forwards(nidSvcC) || len(nb.fwd) != 1 {
		t.Errorf("a binding of every service widened the forward flag: %+v", nb)
	}

	// Two sets that differ only in who forwards are not equal, so the data
	// plane is told.
	x := netidBoundOf(map[string]cmn.NetIdentityMod{"a": plain(nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA))})
	y := netidBoundOf(map[string]cmn.NetIdentityMod{"a": fwd(nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA))})
	if x.equal(y) || y.equal(x) || !y.equal(y) {
		t.Error("equal does not see the forward flag")
	}
	// While the snapshot goes from one to the other the flags are the next
	// set's: a service that starts forwarding drops client headers from the
	// first step on.
	if m := x.meet(y); !m.forwards(nidSvcA) {
		t.Errorf("meet towards a forwarding set: %+v", m)
	}
	if m := y.meet(x); m.forwards(nidSvcA) {
		t.Errorf("meet towards a plain set: %+v", m)
	}
}

// Turning forward_identity on for a stored binding reaches the data plane
// although nothing else about the bound set changed.
func TestNetIdentityForwardChangeIsPublished(t *testing.T) {
	h, dp := newNidHolder(nidIfs{})
	pm := nidCIDR("line", "t-line", []string{"10.20.0.0/24"}, nidSvcA)
	mustAdd(t, h, pm)
	writes := dp.writes
	if dp.bound.forwards(nidSvcA) {
		t.Fatal("a plain binding forwards")
	}
	pm.ForwardIdentity = true
	mustAdd(t, h, pm)
	if dp.writes == writes || !dp.bound.forwards(nidSvcA) {
		t.Fatalf("forward_identity on: writes %d -> %d, forwards %v", writes, dp.writes, dp.bound.forwards(nidSvcA))
	}
	ans, _ := netidAnswerFor(h, "10.20.0.7", 0, nidSvcA, "")
	if !ans.matched || !ans.forward {
		t.Fatalf("the resolver's answer: %+v", ans)
	}
	writes = dp.writes
	pm.ForwardIdentity = false
	mustAdd(t, h, pm)
	if dp.writes == writes || dp.bound.forwards(nidSvcA) {
		t.Fatal("forward_identity off did not reach the data plane")
	}
}

func nidRule(vip string, port uint16, apiKeyAuth string, sse bool, sockMap uint8) *ruleEnt {
	r := &ruleEnt{apiKeyAuth: apiKeyAuth, sseMode: sse, sockMapMode: sockMap}
	r.tuples.l3Dst.addr = net.IPNet{IP: net.ParseIP(vip), Mask: net.CIDRMask(32, 32)}
	r.tuples.l4Dst.valMin = port
	return r
}

// A binding that promises what a service cannot keep is refused by name,
// before it is stored: credential: network or forward_identity on a rule
// that is not an AI-gateway service and whose request direction the kernel
// carries. An AI-gateway service is not refused whatever its sockMapMode,
// nor is a service with no rule yet.
func TestNetIdentityRefusedOnASockmapService(t *testing.T) {
	R := newTestRuleH()
	R.tables[RtLB].eMap["plain-both"] = nidRule("20.20.20.1", 8090, "", false, 1)
	R.tables[RtLB].eMap["plain-request"] = nidRule("20.20.20.1", 8091, "", false, 2)
	R.tables[RtLB].eMap["plain-response"] = nidRule("20.20.20.1", 8092, "", false, 3)
	R.tables[RtLB].eMap["plain-off"] = nidRule("20.20.20.1", 8093, "", false, 0)
	R.tables[RtLB].eMap["ai-key"] = nidRule("20.20.20.1", 8081, "required", false, 1)
	R.tables[RtLB].eMap["ai-sse"] = nidRule("20.20.20.1", 8080, "", true, 0)

	bind := func(cred string, fwd bool, svcs ...string) *cmn.NetIdentityMod {
		pm := nidAlias("b", "t", cmn.NetIdentityMatch{Vlan: 20}, svcs...)
		pm.Credential = cred
		pm.ForwardIdentity = fwd
		return pm
	}
	for _, c := range []struct {
		name    string
		pm      *cmn.NetIdentityMod
		field   string // "" = accepted
		refused string // the service named in the refusal
	}{
		{"sockmap both, not an AI service", bind("network", false, "20.20.20.1:8090"), "credential", "20.20.20.1:8090"},
		{"sockmap request", bind("Network", false, "20.20.20.1:8091"), "credential", "20.20.20.1:8091"},
		{"one of several", bind("network", false, "20.20.20.1:8081", "20.20.20.1:8091"), "credential", "20.20.20.1:8091"},
		{"two of several: the first in order", bind("network", false, "20.20.20.1:8091", "20.20.20.1:8090"), "credential", "20.20.20.1:8090"},
		{"forward_identity on the sockmap service", bind("", true, "20.20.20.1:8090"), "forward_identity", "20.20.20.1:8090"},
		{"both asked: named as the credential", bind("network", true, "20.20.20.1:8091"), "credential", "20.20.20.1:8091"},
		{"forward_identity with no service is left to validation", bind("", true), "", ""},
		{"sockmap response only", bind("network", true, "20.20.20.1:8092"), "", ""},
		{"sockmap off", bind("network", true, "20.20.20.1:8093"), "", ""},
		{"an AI-gateway service", bind("network", true, "20.20.20.1:8081", "20.20.20.1:8080"), "", ""},
		{"no rule yet", bind("network", true, "20.20.20.9:1"), "", ""},
		{"credential network on every AI service", bind("network", false), "", ""},
		{"neither asked, on the sockmap service", bind("", false, "20.20.20.1:8090"), "", ""},
		{"a malformed service is left to validation", bind("network", true, "not-a-service"), "", ""},
	} {
		err := R.netidSockMapErr(c.pm)
		if c.field == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		var ve *cmn.ValidationError
		if !errors.As(err, &ve) || ve.Field != c.field || !strings.Contains(err.Error(), c.refused) ||
			!strings.Contains(err.Error(), "sockMapMode") {
			t.Errorf("%s: got %v, want a validation error on %s naming %s", c.name, err, c.field, c.refused)
		}
	}
	if err := R.netidSockMapErr(nil); err != nil {
		t.Errorf("nil binding: %v", err)
	}
}

// forward_identity is kept to the services the operator named: a binding
// that names none is refused, whatever else it says.
func TestNetIdentityForwardNeedsServices(t *testing.T) {
	h, dp := newNidHolder(nidIfs{"vlan20": 5})
	for _, pm := range []*cmn.NetIdentityMod{
		nidCIDR("g", "t", []string{"10.0.0.0/8"}),
		nidIf("line", "t", "vlan20"),
	} {
		pm.ForwardIdentity = true
		rc, err := h.BindingAdd(pm)
		var ve *cmn.ValidationError
		if rc != NetIdentityArgErr || !errors.As(err, &ve) || ve.Field != "forward_identity" ||
			!strings.Contains(err.Error(), "forward_identity needs services") {
			t.Errorf("%s: rc %d, err %v", pm.Name, rc, err)
		}
	}
	if dp.writes != 0 || len(h.bindings) != 0 {
		t.Fatalf("a refused binding left something: %d writes, %d stored", dp.writes, len(h.bindings))
	}
	// The same binding without the flag, and with a service, are both fine.
	mustAdd(t, h, nidCIDR("g", "t", []string{"10.0.0.0/8"}))
	pm := nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA)
	pm.ForwardIdentity = true
	mustAdd(t, h, pm)
	if !dp.bound.forwards(nidSvcA) || dp.bound.forwards(nidSvcB) {
		t.Fatalf("forwards: %+v", dp.bound)
	}
	// Turning the flag on for the stored binding of every service is the
	// same refusal, and leaves it as it was.
	g := nidCIDR("g", "t", []string{"10.0.0.0/8"})
	g.ForwardIdentity = true
	if _, err := h.BindingAdd(g); err == nil || h.bindings["g"].ForwardIdentity {
		t.Fatalf("replace with the flag and no service: err %v, stored %+v", err, h.bindings["g"])
	}
}

// Past what the data plane's service set holds, it answers for every
// service at once. With a forwarding binding that would strip on services
// nobody named, so the binding that crosses the size is refused; without
// one nothing is.
func TestNetIdentityForwardRefusedPastTheServiceSet(t *testing.T) {
	many := func(name string, from, n int) *cmn.NetIdentityMod {
		svcs := make([]string, 0, n)
		for i := from; i < from+n; i++ {
			svcs = append(svcs, fmt.Sprintf("30.%d.%d.1:80", i/250, i%250))
		}
		return nidCIDR(name, "t", []string{fmt.Sprintf("10.%d.0.0/16", from/250+1)}, svcs...)
	}
	fill := func(h *NetIdentityH, n int) {
		for i := 0; i < n; i += 250 {
			k := n - i
			if k > 250 {
				k = 250
			}
			mustAdd(t, h, many(fmt.Sprintf("p%d", i), i, k))
		}
	}
	h, _ := newNidHolder(nidIfs{})
	fill(h, netidBoundSvcMax-1)
	fw := nidCIDR("fw", "t", []string{"10.200.0.0/16"}, "40.0.0.1:80")
	fw.ForwardIdentity = true
	mustAdd(t, h, fw) // exactly the size: kept to the named service
	over := nidCIDR("over", "t", []string{"10.201.0.0/16"}, "40.0.0.2:80")
	rc, err := h.BindingAdd(over)
	var ve *cmn.ValidationError
	if rc != NetIdentityArgErr || !errors.As(err, &ve) || ve.Field != "services" {
		t.Fatalf("a plain binding past the size beside a forwarding one: rc %d, err %v", rc, err)
	}
	if _, stored := h.bindings["over"]; stored {
		t.Fatal("the refused binding is stored")
	}

	// The other order: the set is past the size, then a binding asks to forward.
	h, _ = newNidHolder(nidIfs{})
	fill(h, netidBoundSvcMax+1)
	rc, err = h.BindingAdd(fw)
	if rc != NetIdentityArgErr || !errors.As(err, &ve) || ve.Field != "forward_identity" {
		t.Fatalf("forward_identity past the size: rc %d, err %v", rc, err)
	}
	// Nothing forwards: nothing is refused.
	mustAdd(t, h, over)
}

// A rule that would carry a service's request direction in the kernel is
// refused while a binding that forwards identity, or admits by the network,
// names the service, and the refusal names the binding.
func TestNetIdentityRuleRefusedOnAForwardingBinding(t *testing.T) {
	h, _ := newNidHolder(nidIfs{"vlan20": 5})
	fw := nidCIDR("zz-fwd", "t", []string{"10.1.0.0/16"}, nidSvcA)
	fw.ForwardIdentity = true
	mustAdd(t, h, fw)
	fw2 := nidCIDR("aa-fwd", "t", []string{"10.2.0.0/16"}, nidSvcA)
	fw2.ForwardIdentity = true
	mustAdd(t, h, fw2)
	cred := nidIf("cred", "t", "vlan20", nidSvcB)
	cred.Credential = cmn.NetIdentityCredentialNetwork
	mustAdd(t, h, cred)
	mustAdd(t, h, nidCIDR("plain", "t", []string{"10.3.0.0/16"}, nidSvcC))
	mustAdd(t, h, nidCIDR("global", "t", []string{"10.4.0.0/16"}))

	for _, c := range []struct {
		name    string
		svc     string
		aiGw    bool
		mode    uint8
		binding string // "" = accepted
		what    string
	}{
		{"both, forwarding binding: the first in name order", nidSvcA, false, 1, "aa-fwd", "forward_identity"},
		{"request", nidSvcA, false, 2, "aa-fwd", "forward_identity"},
		{"credential network", nidSvcB, false, 1, "cred", "credential: network"},
		{"response only", nidSvcA, false, 3, "", ""},
		{"off", nidSvcA, false, 0, "", ""},
		{"an AI-gateway rule", nidSvcA, true, 1, "", ""},
		{"a plain binding names the service", nidSvcC, false, 1, "", ""},
		{"only a binding of every service applies", "50.0.0.1:80", false, 1, "", ""},
		{"no service identity", "", false, 1, "", ""},
	} {
		err := netidRuleSockMapErr(h, c.svc, c.aiGw, c.mode)
		if c.binding == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		var ve *cmn.ValidationError
		if !errors.As(err, &ve) || ve.Field != "sockMapMode" ||
			!strings.Contains(err.Error(), "binding "+c.binding+" ") ||
			!strings.Contains(err.Error(), c.what) || !strings.Contains(err.Error(), c.svc) {
			t.Errorf("%s: got %v, want a validation error on sockMapMode naming %s and %s", c.name, err, c.binding, c.what)
		}
	}
	if err := netidRuleSockMapErr(nil, nidSvcA, false, 1); err != nil {
		t.Errorf("no holder: %v", err)
	}
	// The binding gone, the rule is accepted.
	for _, n := range []string{"aa-fwd", "zz-fwd"} {
		if _, err := h.BindingDel(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := netidRuleSockMapErr(h, nidSvcA, false, 1); err != nil {
		t.Errorf("after the bindings are deleted: %v", err)
	}
}

// A forwarding binding and a rule that carries the same service's requests
// in the kernel never both get in, whichever asks first and however the two
// interleave: each side checks and stores under the configuration mutex.
func TestNetIdentityBindingAndSockmapRuleNeverBothAccepted(t *testing.T) {
	const svc = "20.20.20.1:8090"
	var cfg sync.RWMutex
	for i := 0; i < 100; i++ {
		R := newTestRuleH()
		h, _ := newNidHolder(nidIfs{})
		pm := nidCIDR("fw", "t", []string{"10.1.0.0/16"}, svc)
		pm.ForwardIdentity = true

		var wg sync.WaitGroup
		var bindErr, ruleErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, bindErr = netidAddUnderConfig(&cfg, R, h, pm)
		}()
		go func() {
			defer wg.Done()
			<-start
			// What a rule add does: the check, then the store, under the
			// configuration mutex.
			cfg.Lock()
			defer cfg.Unlock()
			if ruleErr = netidRuleSockMapErr(h, svc, false, 1); ruleErr == nil {
				R.tables[RtLB].eMap["plain"] = nidRule("20.20.20.1", 8090, "", false, 1)
			}
		}()
		close(start)
		wg.Wait()

		_, bound := h.bindings["fw"]
		_, ruled := R.tables[RtLB].eMap["plain"]
		if (bindErr == nil) != bound || (ruleErr == nil) != ruled {
			t.Fatalf("round %d: answers and state disagree: binding err %v stored %v, rule err %v stored %v",
				i, bindErr, bound, ruleErr, ruled)
		}
		if bound == ruled {
			t.Fatalf("round %d: binding stored %v and rule stored %v: exactly one may get in", i, bound, ruled)
		}
	}
}

// Either order, one after the other: the binding that comes after the
// kernel-carried rule is refused with the rule's service named, and the rule
// that comes after the binding is refused with the binding named.
func TestNetIdentityBindingAndSockmapRuleEitherOrder(t *testing.T) {
	const svc = "20.20.20.1:8090"
	var cfg sync.RWMutex
	pm := nidCIDR("fw", "t", []string{"10.1.0.0/16"}, svc)
	pm.ForwardIdentity = true

	R := newTestRuleH()
	h, _ := newNidHolder(nidIfs{})
	R.tables[RtLB].eMap["plain"] = nidRule("20.20.20.1", 8090, "", false, 1)
	rc, err := netidAddUnderConfig(&cfg, R, h, pm)
	if rc != NetIdentityArgErr || err == nil || !strings.Contains(err.Error(), svc) || len(h.bindings) != 0 {
		t.Fatalf("the binding after the rule: rc %d, err %v, stored %d", rc, err, len(h.bindings))
	}
	// No rule table to ask (a gateway still starting): the binding is stored.
	if _, err := netidAddUnderConfig(&cfg, nil, h, pm); err != nil || len(h.bindings) != 1 {
		t.Fatalf("with no rule table: err %v, stored %d", err, len(h.bindings))
	}

	R = newTestRuleH()
	h, _ = newNidHolder(nidIfs{})
	if _, err := netidAddUnderConfig(&cfg, R, h, pm); err != nil {
		t.Fatal(err)
	}
	if err := netidRuleSockMapErr(h, svc, false, 1); err == nil || !strings.Contains(err.Error(), "binding fw ") {
		t.Fatalf("the rule after the binding: %v", err)
	}
}

// A binding stored on a gateway with no key store says so: the requests it
// gives a tenant would be refused.
func TestNetIdentityWarnsWithoutAKeyStore(t *testing.T) {
	savedH, savedK := mh.NetIdentity, mh.AIKeyService.Load()
	t.Cleanup(func() { mh.NetIdentity = savedH; mh.AIKeyService.Store(savedK) })
	h, _ := newNidHolder(nidIfs{})
	mh.NetIdentity = h
	pm := nidCIDR("a", "t", []string{"10.1.0.0/16"}, nidSvcA)
	mustAdd(t, h, pm)
	na := &NetAPIStruct{}
	mh.AIKeyService.Store(nil)
	if got := na.NetAINetIdentityWarning(pm); got != netidNoKeyStoreWarning {
		t.Errorf("no key store: %q", got)
	}
	mh.AIKeyService.Store(&aikey.Service{})
	if got := na.NetAINetIdentityWarning(pm); got != "" {
		t.Errorf("with a key store: %q", got)
	}
	if got := netidJoinWarning("", netidNoKeyStoreWarning); got != netidNoKeyStoreWarning {
		t.Errorf("alone: %q", got)
	}
	got := netidJoinWarning("first", netidNoKeyStoreWarning)
	if got != "first; warning: "+netidNoKeyStoreWarning {
		t.Errorf("after another: %q", got)
	}
	for _, word := range []string{"key store", "--aikey-db", "503", "policy_store_unavailable"} {
		if !strings.Contains(netidNoKeyStoreWarning, word) {
			t.Errorf("the warning does not say %q", word)
		}
	}
}

// The rule add itself asks: a plain rule that would run sockMapMode both on
// a service a forwarding binding names is refused before anything is
// touched, with the binding named.
func TestNetIdentityAddLbRuleRefusedOnAForwardingBinding(t *testing.T) {
	savedEn, savedH := mh.sockMapEn, mh.NetIdentity
	t.Cleanup(func() { mh.sockMapEn, mh.NetIdentity = savedEn, savedH })
	mh.sockMapEn = true
	h, _ := newNidHolder(nidIfs{})
	mh.NetIdentity = h
	pm := nidCIDR("fw", "t", []string{"10.1.0.0/16"}, "10.10.10.254:8090")
	pm.ForwardIdentity = true
	mustAdd(t, h, pm)

	R := &RuleH{}
	R.tables[RtLB].eMap = map[string]*ruleEnt{}
	eps := []cmn.LbEndPointArg{{EpIP: "10.20.0.1", EpPort: 80, Weight: 1}}
	for _, mode := range []string{"both", "request"} {
		serv := cmn.LbServiceArg{ServIP: "10.10.10.254", ServPort: 8090, Proto: "tcp", Mode: cmn.LBModeFullProxy, SockMapMode: mode}
		rc, err := R.AddLbRule(serv, nil, nil, nil, eps)
		var ve *cmn.ValidationError
		if rc != RuleArgsErr || !errors.As(err, &ve) || ve.Field != "sockMapMode" ||
			!strings.Contains(err.Error(), "binding fw ") || !strings.Contains(err.Error(), "10.10.10.254:8090") {
			t.Errorf("sockMapMode %s: rc %d, err %v", mode, rc, err)
		}
	}
	if len(R.tables[RtLB].eMap) != 0 {
		t.Fatalf("a refused rule left %d entries", len(R.tables[RtLB].eMap))
	}
}

// The binding is stored while the configuration mutex is still held: a rule
// add, which takes it exclusively, cannot run between the question about
// the rules and the store.
func TestNetIdentityBindingStoredWithTheConfigMutexHeld(t *testing.T) {
	var cfg sync.RWMutex
	h, _ := newNidHolder(nidIfs{})
	stages := 0
	h.step = func(string) {
		stages++
		if cfg.TryLock() {
			cfg.Unlock()
			t.Error("the configuration mutex is free while the binding is being stored")
		}
	}
	pm := nidCIDR("fw", "t", []string{"10.1.0.0/16"}, nidSvcA)
	pm.ForwardIdentity = true
	if _, err := netidAddUnderConfig(&cfg, newTestRuleH(), h, pm); err != nil {
		t.Fatal(err)
	}
	if stages == 0 {
		t.Fatal("the store told no stage: the check above did not run")
	}
	if !cfg.TryLock() {
		t.Fatal("the configuration mutex is still held after the store")
	}
	cfg.Unlock()
}
