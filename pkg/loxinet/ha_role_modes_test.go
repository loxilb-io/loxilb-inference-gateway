package loxinet

import (
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"net"
	"testing"
)

func TestHAAdvertisementDeploymentModes(t *testing.T) {
	oldNodes, oldKa, oldPeer, oldBGP := opts.Opts.ClusterNodes, opts.Opts.Ka, opts.Opts.BgpPeerMode, mh.bgp
	defer func() {
		opts.Opts.ClusterNodes, opts.Opts.Ka, opts.Opts.BgpPeerMode, mh.bgp = oldNodes, oldKa, oldPeer, oldBGP
	}()
	for _, tc := range []struct {
		name, cluster, ka   string
		peer, managed, want bool
	}{
		{"standalone", "none", "none", false, false, true},
		{"ct-only-active-active-ecmp", "192.0.2.2", "none", false, false, true},
		{"kube-loxilb-without-setRoles", "192.0.2.2", "none", false, false, true},
		{"cli-cluster-without-ka", "192.0.2.2", "none", false, false, true},
		{"egress-only", "none", "none", false, false, true},
		{"bgp-peer-mode-policy", "none", "none", true, false, true},
		{"ka-managed", "192.0.2.2", "192.0.2.2:192.0.2.1", false, false, false},
		{"bfd-managed-signal", "none", "none", false, true, false},
		{"cistate-managed-signal", "192.0.2.2", "none", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts.Opts.ClusterNodes, opts.Opts.Ka, opts.Opts.BgpPeerMode = tc.cluster, tc.ka, tc.peer
			c := &pendingPathClient{}
			h := &GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{}}
			h.requireRole.Store(tc.managed)
			mh.bgp = h
			h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.23"})
			if got := len(c.paths) > 0; got != tc.want {
				t.Fatalf("undefined role advertisement=%v want=%v", got, tc.want)
			}
			before := len(c.paths)
			h.reAdvertise = true
			h.goBGPHouseKeeper()
			if got := len(c.paths) > before; got != tc.want {
				t.Fatal("reconnect replay bypassed mode policy")
			}
		})
	}
}

func TestHAValidCIStateRequestEnablesStickyRoleManagement(t *testing.T) {
	old := mh.bgp
	defer func() { mh.bgp = old }()
	h := &GoBgpH{}
	mh.bgp = h
	ch := &CIStateH{StateMap: map[string]int{cmn.CIUnDefStateString: cmn.CIStateNotDefined}, ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: {State: cmn.CIStateNotDefined, StateStr: cmn.CIUnDefStateString, Vip: net.IPv4zero}}}
	if _, err := ch.CIStateUpdate(cmn.HASMod{Instance: cmn.CIDefault, State: cmn.CIUnDefStateString, Vip: net.IPv4zero}); err != nil {
		t.Fatal(err)
	}
	if !h.requireRole.Load() {
		t.Fatal("unchanged NotDefined request did not activate the role gate")
	}
	h.requireRole.Store(false)
	if _, err := ch.CIStateUpdate(cmn.HASMod{Instance: cmn.CIDefault, State: "INVALID"}); err == nil {
		t.Fatal("invalid role accepted")
	}
	if h.requireRole.Load() {
		t.Fatal("invalid role activated the gate")
	}
}
