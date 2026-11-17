// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"net"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestBFDManagedL2RoleRejectsExternalOverride(t *testing.T) {
	old := mh.has
	t.Cleanup(func() { mh.has = old })
	role := &ClusterInstance{State: cmn.CIStateBackup, StateStr: cmn.CIBackupStateString}
	mh.has = &CIStateH{
		l2PairPeer: "192.0.2.10",
		ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: role},
	}
	api := &NetAPIStruct{}
	for _, state := range []string{cmn.CIMasterStateString, cmn.CIUnDefStateString, cmn.CIBackupStateString} {
		_, err := api.NetCIStateMod(&cmn.HASMod{Instance: cmn.CIDefault, State: state, Vip: net.IPv4zero})
		if got, want := err == nil, state == cmn.CIBackupStateString; got != want {
			t.Errorf("external request for %s accepted=%t, want %t", state, got, want)
		}
		if role.StateStr != cmn.CIBackupStateString {
			t.Fatalf("effective election role unexpectedly changed: %s", role.StateStr)
		}
	}
}
