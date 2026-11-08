/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package loxinet

import (
	"context"
	"net"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type withdrawPathClient struct {
	pendingPathClient
	deletes []*api.DeletePathRequest
}

func (c *withdrawPathClient) DeletePath(_ context.Context, r *api.DeletePathRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.deletes = append(c.deletes, r)
	return &emptypb.Empty{}, nil
}

func newWithdrawTestSpeaker(c *withdrawPathClient) *GoBgpH {
	return &GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{cmn.CIDefault: {vip: net.IPv4zero, hastate: cmn.CIStateMaster, rules: map[string]int{}}}}
}

func TestBGPWithdrawUsesAdvertisedFamily(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		afi  api.Family_Afi
		bits uint32
	}{
		{"192.0.2.101", api.Family_AFI_IP, 32},
		{"2001:db8::101", api.Family_AFI_IP6, 128},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			c := &withdrawPathClient{}
			h := newWithdrawTestSpeaker(c)
			h.AddBGPRule(cmn.CIDefault, []string{tc.ip})
			if len(c.paths) != 1 {
				t.Fatalf("initial advertisement count=%d", len(c.paths))
			}
			h.DelBGPRule(cmn.CIDefault, []string{tc.ip})
			if len(c.deletes) != 1 {
				t.Fatalf("withdrawal count=%d", len(c.deletes))
			}
			path := c.deletes[0].Path
			for _, attr := range path.Pattrs {
				var asPath api.AsPathAttribute
				if attr.UnmarshalTo(&asPath) == nil {
					t.Error("withdrawal attached AS_PATH to a locally originated path")
				}
			}
			if path.Family.Afi != tc.afi || path.Family.Safi != api.Family_SAFI_UNICAST {
				t.Errorf("withdraw family=%v, want %v/unicast", path.Family, tc.afi)
			}
			var prefix api.IPAddressPrefix
			if err := path.Nlri.UnmarshalTo(&prefix); err != nil || prefix.PrefixLen != tc.bits || !net.ParseIP(prefix.Prefix).Equal(net.ParseIP(tc.ip)) {
				t.Errorf("withdraw prefix=%v err=%v", &prefix, err)
			}
		})
	}
}

func TestBGPWithdrawSharedAddressSpellings(t *testing.T) {
	const canonical = "2001:db8::106"
	const expanded = "2001:0db8:0000:0000:0000:0000:0000:0106"
	c := &withdrawPathClient{}
	h := newWithdrawTestSpeaker(c)
	h.AddBGPRule(cmn.CIDefault, []string{expanded})
	h.AddBGPRule(cmn.CIDefault, []string{canonical})
	if len(c.paths) != 1 {
		t.Errorf("one shared prefix advertised %d times", len(c.paths))
	}
	h.DelBGPRule(cmn.CIDefault, []string{canonical})
	if len(c.deletes) != 0 {
		t.Errorf("withdrew while another owner remains: %d", len(c.deletes))
	}
	if got := h.ciMap[cmn.CIDefault].rules; len(got) != 1 || got[canonical] != 1 {
		t.Errorf("remaining shared ownership=%v", got)
	}
	h.DelBGPRule(cmn.CIDefault, []string{expanded})
	if len(c.deletes) != 1 {
		t.Errorf("last owner withdrawal count=%d", len(c.deletes))
	}
	before := len(c.paths)
	h.reAdvertise = true
	h.goBGPHouseKeeper()
	if len(c.paths) != before {
		t.Error("deleted prefix returned on replay")
	}
}

func TestBGPWithdrawIgnoresAbsentOwnership(t *testing.T) {
	c := &withdrawPathClient{}
	h := newWithdrawTestSpeaker(c)
	h.DelBGPRule(cmn.CIDefault, []string{"192.0.2.101"})
	if len(c.deletes) != 0 {
		t.Fatal("withdrew a prefix with no LB owner")
	}
}

func TestBGPWithdrawDisconnectedCanonicalIntent(t *testing.T) {
	c := &withdrawPathClient{}
	h := newWithdrawTestSpeaker(c)
	h.AddBGPRule(cmn.CIDefault, []string{"2001:0db8:0:0:0:0:0:101"})
	h.state = BGPDisconnected
	h.DelBGPRule(cmn.CIDefault, []string{"2001:db8::101"})
	h.state = BGPConnected
	before := len(c.paths)
	h.reAdvertise = true
	h.goBGPHouseKeeper()
	if len(c.paths) != before {
		t.Error("prefix deleted while disconnected returned on replay")
	}
	if len(h.ciMap[cmn.CIDefault].rules) != 0 {
		t.Error("disconnected deletion retained exhausted intent")
	}
}

func TestBGPWithdrawRecoveryCanonicalReferences(t *testing.T) {
	refs := liveBGPAdvertisements([]cmn.LbRuleMod{
		{Serv: cmn.LbServiceArg{ServIP: "2001:0db8:0:0:0:0:0:106", Bgp: true}, SecIPs: []cmn.LbSecIPArg{{SecIP: "2001:0db8:0:0:0:0:0:107"}}},
		{Serv: cmn.LbServiceArg{ServIP: "2001:db8::106", Bgp: true}, SecIPs: []cmn.LbSecIPArg{{SecIP: "2001:db8::107"}}},
		{Serv: cmn.LbServiceArg{ServIP: "192.0.2.101", Bgp: true}},
		{Serv: cmn.LbServiceArg{ServIP: "::ffff:192.0.2.101", Bgp: true}},
		{Serv: cmn.LbServiceArg{ServIP: "2001:db8::108"}},
	})
	if len(refs) != 3 || refs["2001:db8::106"] != 2 || refs["2001:db8::107"] != 2 || refs["192.0.2.101"] != 2 {
		t.Fatalf("recovery split equivalent route ownership: %v", refs)
	}
	c := &withdrawPathClient{}
	h := newWithdrawTestSpeaker(c)
	h.ciMap[cmn.CIDefault].rules = refs
	h.DelBGPRule(cmn.CIDefault, []string{"2001:db8::106", "2001:db8::107"})
	if len(c.deletes) != 0 {
		t.Fatal("recovered shared prefix withdrawn with another owner remaining")
	}
	h.DelBGPRule(cmn.CIDefault, []string{"2001:0db8:0:0:0:0:0:106", "2001:0db8:0:0:0:0:0:107"})
	if len(c.deletes) != 2 || len(refs) != 1 {
		t.Fatalf("recovered last-owner deletion: withdrawals=%d refs=%v", len(c.deletes), refs)
	}
}

func assertBGPFlagChangeRejected(t *testing.T, stored, requested bool) {
	t.Helper()
	oldZone := mh.zr
	rules := newTestRuleH()
	mh.zr = &Zone{Rules: rules}
	t.Cleanup(func() { mh.zr = oldZone })
	_, prefix, _ := net.ParseCIDR("192.0.2.141/32")
	tuples := ruleTuples{l3Dst: ruleIPTuple{*prefix}, l4Prot: rule8Tuple{6, 255}, l4Dst: rule16RTuple{22141, 22141, true}}
	rule := &ruleEnt{bgp: stored, tuples: tuples}
	rules.tables[RtLB].eMap[tuples.ruleKey()] = rule
	args := cmn.LbServiceArg{ServIP: "192.0.2.141", ServPort: 22141, Proto: "tcp", Bgp: requested}
	rc, err := (&NetAPIStruct{}).NetLbRuleAdd(&cmn.LbRuleMod{Serv: args})
	if rc != RuleArgsErr || err == nil || !strings.Contains(err.Error(), "bgp flag cannot be changed on an existing rule; delete and re-create") {
		t.Fatalf("flag change stored=%v requested=%v: rc=%d err=%v", stored, requested, rc, err)
	}
	if rules.GetLBRuleByServArgs(args) != rule || rule.bgp != stored {
		t.Fatal("rejected update mutated the stored rule")
	}
}

func TestBGPWithdrawRejectsEnablingExistingRule(t *testing.T) {
	assertBGPFlagChangeRejected(t, false, true)
}

func TestBGPWithdrawRejectsDisablingExistingRule(t *testing.T) {
	assertBGPFlagChangeRejected(t, true, false)
}
