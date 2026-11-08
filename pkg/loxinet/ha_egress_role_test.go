package loxinet

import (
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"net"
	"testing"
)

func TestHAEgressPeerPreservesStandaloneAdvertisement(t *testing.T) {
	oldBGP, oldNodes, oldKa := mh.bgp, opts.Opts.ClusterNodes, opts.Opts.Ka
	defer func() { mh.bgp, opts.Opts.ClusterNodes, opts.Opts.Ka = oldBGP, oldNodes, oldKa }()
	opts.Opts.ClusterNodes, opts.Opts.Ka = "none", "none"
	c := &pendingPathClient{}
	h := &GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{}}
	mh.bgp = h
	h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.23"})
	if len(c.paths) != 1 {
		t.Fatalf("standalone precondition: %d paths", len(c.paths))
	}
	ch := &CIStateH{NodeMap: map[string]*ClusterNode{}}
	// Local loopback avoids any VXLAN/netlink mutation. Egress peers never
	// enter the CT-sync peer queue, regardless of local/remote addressing.
	if _, err := ch.ClusterNodeAdd(cmn.ClusterNodeMod{Addr: net.ParseIP("127.0.0.1"), Egress: true}); err != nil {
		t.Fatal(err)
	}
	h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.24"})
	if len(c.paths) != 2 {
		t.Fatalf("egress-only peer suppressed standalone BGP advertisement: got %d paths, want 2", len(c.paths))
	}
	h.reAdvertise = true
	h.goBGPHouseKeeper()
	if len(c.paths) != 4 {
		t.Fatalf("egress-only peer blocked reconnect replay: got %d paths, want 4", len(c.paths))
	}
	if h.requireRole.Load() {
		t.Fatal("egress-only peer enabled sticky HA gate")
	}
}

func TestHACTPeerDoesNotEnableRoleManagement(t *testing.T) {
	oldBGP, oldDP, oldNodes, oldKa := mh.bgp, mh.dp, opts.Opts.ClusterNodes, opts.Opts.Ka
	defer func() { mh.bgp, mh.dp, opts.Opts.ClusterNodes, opts.Opts.Ka = oldBGP, oldDP, oldNodes, oldKa }()
	opts.Opts.ClusterNodes, opts.Opts.Ka = "none", "none"
	c := &pendingPathClient{}
	h := &GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{}}
	mh.bgp = h
	mh.dp = &DpH{ToDpCh: make(chan interface{}, 4)}
	ch := &CIStateH{NodeMap: map[string]*ClusterNode{}}
	if _, err := ch.ClusterNodeAdd(cmn.ClusterNodeMod{Addr: net.ParseIP("127.0.0.1"), Egress: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ClusterNodeAdd(cmn.ClusterNodeMod{Addr: net.ParseIP("192.0.2.2")}); err != nil {
		t.Fatal(err)
	}
	if h.requireRole.Load() || len(mh.dp.ToDpCh) != 1 {
		t.Fatal("CT peer changed role policy or did not queue registration")
	}
	h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.24"})
	h.reAdvertise = true
	h.goBGPHouseKeeper()
	if len(c.paths) != 2 {
		t.Fatal("CT-only peer blocked active-active advertisements/replay")
	}
	if _, err := ch.ClusterNodeDelete(cmn.ClusterNodeMod{Addr: net.ParseIP("192.0.2.2")}); err != nil {
		t.Fatal(err)
	}
	if h.requireRole.Load() {
		t.Fatal("removing CT-only peer enabled role management")
	}
	h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.25"})
	if len(c.paths) != 3 {
		t.Fatal("deleting CT-only peer changed advertisement policy")
	}
}
