/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package loxinet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
)

type pendingPathClient struct {
	api.GobgpApiClient
	paths []*api.AddPathRequest
}

func (c *pendingPathClient) AddPath(_ context.Context, r *api.AddPathRequest, _ ...grpc.CallOption) (*api.AddPathResponse, error) {
	c.paths = append(c.paths, r)
	return &api.AddPathResponse{}, nil
}
func TestBGPLateReadvertiseSkipsDeletedAndWaitsForGroup(t *testing.T) {
	c := &pendingPathClient{}
	h := GoBgpH{client: c, localAs: 65122, state: BGPConnected, reAdvertise: true, ciMap: map[string]*goCI{"llb": {vip: net.IPv4zero, hastate: cmn.CIStateMaster, rules: map[string]int{"127.0.0.23": 1, "127.0.0.24": 0}}}}
	d := snapshot.NewDocument(cmn.Version, "test", snapshot.TriggerManual)
	d.IncludedDomains = []string{snapshot.DomainBGP}
	d.Domains.BGP.GlobalConfig = &cmn.GoBGPGlobalConfig{LocalAs: 65122, RouterID: "192.0.2.22"}
	raw, err := snapshot.Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	e := snapshot.NewEngine(nil, cmn.Version, "test", t.TempDir())
	if _, err = e.PreparePendingBGP(raw, []string{snapshot.DomainBGP}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = snapshot.StopBGPRecovery(ctx)
		defer snapshot.LockBGPRecovery()()
		snapshot.ResolvePendingBGP()
	})
	h.goBGPHouseKeeper()
	if len(c.paths) != 0 || !h.reAdvertise {
		t.Fatal("advertised before BGP group completed")
	}
	func() { defer snapshot.LockBGPRecovery()(); snapshot.ResolvePendingBGP() }()
	h.goBGPHouseKeeper()
	h.goBGPHouseKeeper()
	if len(c.paths) != 1 || h.reAdvertise {
		t.Fatalf("late/deleted advertisements: %d", len(c.paths))
	}
	var prefix api.IPAddressPrefix
	if err = c.paths[0].Path.Nlri.UnmarshalTo(&prefix); err != nil || prefix.Prefix != "127.0.0.23" {
		t.Fatalf("wrong late prefix: %v %v", prefix, err)
	}
}

type cancellingSpeakerClient struct {
	api.GobgpApiClient
	started chan struct{}
}

func (c *cancellingSpeakerClient) GetBgp(ctx context.Context, _ *api.GetBgpRequest, _ ...grpc.CallOption) (*api.GetBgpResponse, error) {
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestBGPRecoveryRPCCancelsAtShutdown(t *testing.T) {
	old := mh.shutdownCtx
	ctx, cancel := context.WithCancel(context.Background())
	mh.shutdownCtx = ctx
	defer func() { cancel(); mh.shutdownCtx = old }()
	c := &cancellingSpeakerClient{started: make(chan struct{})}
	h := GoBgpH{client: c}
	done := make(chan error, 1)
	go func() { _, err := h.BGPGlobalConfigGet(); done <- err }()
	<-c.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RPC cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("speaker RPC outlived workers shutdown")
	}
}

func TestBGPRecoveryRebuildsReferencesFromCurrentRules(t *testing.T) {
	rules := []cmn.LbRuleMod{
		{Serv: cmn.LbServiceArg{ServIP: "192.0.2.1", ServPort: 80, Bgp: true}, SecIPs: []cmn.LbSecIPArg{{SecIP: "192.0.2.2"}}},
		{Serv: cmn.LbServiceArg{ServIP: "192.0.2.1", ServPort: 443, Bgp: true}},
		{Serv: cmn.LbServiceArg{ServIP: "192.0.2.3", ServPort: 80, Bgp: false}},
	}
	refs := liveBGPAdvertisements(rules)
	if refs["192.0.2.1"] != 2 || refs["192.0.2.2"] != 1 || len(refs) != 2 {
		t.Fatalf("advertisement ownership: %v", refs)
	}
	// Removing one sharing rule retains the route; removing both removes it.
	refs = liveBGPAdvertisements(rules[1:])
	if refs["192.0.2.1"] != 1 || refs["192.0.2.2"] != 0 {
		t.Fatalf("partial deletion: %v", refs)
	}
	refs = liveBGPAdvertisements(rules[2:])
	if len(refs) != 0 {
		t.Fatalf("deleted/non-BGP routes resurrected: %v", refs)
	}
}

func TestBGPDeleteOwnershipLookupUsesDeletePortIdentity(t *testing.T) {
	for _, proto := range []struct {
		name   string
		number uint8
	}{{"tcp", 6}, {"sctp", 132}} {
		for _, upper := range []uint16{20523, 20525} {
			_, prefix, _ := net.ParseCIDR("127.0.0.23/32")
			tuples := ruleTuples{l3Dst: ruleIPTuple{*prefix}, l4Prot: rule8Tuple{proto.number, 255}, l4Dst: rule16RTuple{20523, upper, true}}
			rule := &ruleEnt{bgp: true, tuples: tuples, secIP: []ruleLBSIP{{sIP: net.ParseIP("127.0.0.24")}}}
			rules := newTestRuleH()
			rules.tables[RtLB].eMap[tuples.ruleKey()] = rule
			spellings := []uint16{upper}
			if upper == 20523 {
				spellings = append(spellings, 0)
			}
			for _, max := range spellings {
				serv := cmn.LbServiceArg{ServIP: "127.0.0.23", ServPort: 20523, ServPortMax: max, Proto: proto.name}
				if got := rules.GetLBRuleByServArgs(serv); got != rule {
					t.Errorf("%s port %d-%d: delete ownership lookup missed stored rule", proto.name, serv.ServPort, max)
				}
				if proto.name == "sctp" {
					ips := rules.GetLBRuleSecIPs(serv)
					if len(ips) != 1 || ips[0] != "127.0.0.24" {
						t.Errorf("secondary IP withdrawal lookup missed %d-%d: %v", serv.ServPort, max, ips)
					}
				}
			}
		}
	}
}
