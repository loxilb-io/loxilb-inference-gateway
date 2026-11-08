/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package loxinet

import (
	"net"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
)

func TestHABootRoleGateBlocksLBReplayBeforeSavedBFD(t *testing.T) {
	oldKa, oldBGP, oldHas := opts.Opts.Ka, mh.bgp, mh.has
	defer func() { opts.Opts.Ka, mh.bgp, mh.has = oldKa, oldBGP, oldHas }()
	opts.Opts.Ka = "none"
	for _, order := range []string{"legacy-lb-before-ci", "snapshot-lb-after-ci"} {
		t.Run(order, func(t *testing.T) {
			c := &pendingPathClient{}
			h := &GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{}, bootRolePending: true}
			ch := &CIStateH{Bs: new(bfd.Struct), ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: {State: cmn.CIStateNotDefined, StateStr: cmn.CIUnDefStateString}}}
			mh.bgp, mh.has = h, ch
			if order == "snapshot-lb-after-ci" {
				h.finishRoleInit()
				h.releaseBootRoleGate(false) // BFD-bearing snapshot replay is still running.
			}
			h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.23"})
			h.reAdvertise = true
			h.mtx.Lock()
			h.advertiseAllVIPs(cmn.CIDefault) // Connected-speaker replay has the same gate.
			h.mtx.Unlock()
			if order == "legacy-lb-before-ci" {
				h.releaseBootRoleGate(true) // LB replay settled before CISpawn loaded BFD.
			}
			if len(c.paths) != 0 || !h.bootRolePending {
				t.Fatalf("advertised before both boot loaders settled: paths=%d pending=%v", len(c.paths), h.bootRolePending)
			}
			_, _, err := ch.bfdSessionAddArgs(cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP("192.0.2.2"), SourceIP: net.ParseIP("192.0.2.1"), RetryCount: 3})
			if err != nil {
				t.Fatal(err)
			}
			if !h.requireRole.Load() {
				t.Fatal("BFD did not enable role management")
			}
			h.finishRoleInit()
			h.releaseBootRoleGate(true)
			h.goBGPHouseKeeper()
			if len(c.paths) != 0 || h.bootRolePending {
				t.Fatal("boot completion authorized an undefined BFD role")
			}
			h.UpdateCIState(cmn.CIDefault, cmn.CIStateMaster, net.IPv4zero)
			if len(c.paths) != 1 {
				t.Fatalf("MASTER did not replay the deferred VIP: %d paths", len(c.paths))
			}
		})
	}
}

func TestHABootRoleGateReplaysUnmanagedModes(t *testing.T) {
	oldNodes, oldKa := opts.Opts.ClusterNodes, opts.Opts.Ka
	defer func() { opts.Opts.ClusterNodes, opts.Opts.Ka = oldNodes, oldKa }()
	opts.Opts.Ka = "none"
	for _, mode := range []string{"standalone", "ct-only-active-active", "kube-without-setRoles", "cli-cluster-without-ka", "egress-only"} {
		for _, order := range []string{"ci-first", "config-first"} {
			t.Run(mode+"/"+order, func(t *testing.T) {
				opts.Opts.ClusterNodes = "192.0.2.2"
				if mode == "standalone" || mode == "egress-only" {
					opts.Opts.ClusterNodes = "none"
				}
				c := &pendingPathClient{}
				h := &GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{}, bootRolePending: true}
				h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.23"})
				if len(c.paths) != 0 {
					t.Fatal("boot replay advertised too early")
				}
				if order == "ci-first" {
					h.finishRoleInit()
					h.releaseBootRoleGate(false)
				} else {
					h.releaseBootRoleGate(true)
				}
				if !h.bootRolePending {
					t.Fatal("one loader completion released both gates")
				}
				h.finishRoleInit()
				h.releaseBootRoleGate(true)
				h.goBGPHouseKeeper()
				h.goBGPHouseKeeper()
				if len(c.paths) != 1 || h.requireRole.Load() || h.bootRolePending {
					t.Fatalf("unmanaged replay: paths=%d roleManaged=%v bootPending=%v", len(c.paths), h.requireRole.Load(), h.bootRolePending)
				}
			})
		}
	}
}
