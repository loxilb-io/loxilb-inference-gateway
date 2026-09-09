/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func chwblExistingRule(sel cmn.EpSelect) *ruleEnt {
	return &ruleEnt{
		act:                  ruleAct{action: &ruleLBActs{sel: sel, mode: cmn.LBModeFullProxy}},
		chwblPrefixHashLevel: 3, chwblPrefixHashFlags: 0xc8,
		chwblMeanLoadFactor: 210, chwblReplication: 512,
		chwblEnableCacheSalt: true,
	}
}

func chwblEndpoints(weights ...uint8) []ruleLBEp {
	eps := make([]ruleLBEp, len(weights))
	for i := range weights {
		eps[i].weight = weights[i]
	}
	return eps
}

func TestResolveCHWBLContractCreateDefaults(t *testing.T) {
	serv := cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelCHWBL}
	if err := resolveCHWBLContract(&serv, nil, chwblEndpoints(1, 1)); err != nil {
		t.Fatal(err)
	}
	if serv.CHWBLPrefixHashLevel != 1 || serv.CHWBLPrefixHashFlags != 0 ||
		serv.CHWBLMeanLoadFactor != 175 || serv.CHWBLReplication != 256 ||
		serv.CHWBLEnableCacheSalt {
		t.Fatalf("unexpected defaults: %+v", serv)
	}
}

func TestResolveCHWBLContractReplacePreservesOmissionsAndHonorsResets(t *testing.T) {
	existing := chwblExistingRule(cmn.LbSelCHWBL)
	preserve := cmn.LbServiceArg{
		Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelCHWBL,
		CHWBLPresenceTracked: true,
		// Simulate values materialized by a generated client despite raw omission.
		CHWBLPrefixHashLevel: 1, CHWBLMeanLoadFactor: 175, CHWBLReplication: 256,
	}
	if err := resolveCHWBLContract(&preserve, existing, chwblEndpoints(1)); err != nil {
		t.Fatal(err)
	}
	if preserve.CHWBLPrefixHashLevel != 3 || preserve.CHWBLPrefixHashFlags != 0xc8 ||
		preserve.CHWBLMeanLoadFactor != 210 || preserve.CHWBLReplication != 512 ||
		!preserve.CHWBLEnableCacheSalt {
		t.Fatalf("replace omission did not preserve: %+v", preserve)
	}

	reset := cmn.LbServiceArg{
		Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelCHWBL,
		CHWBLPrefixHashLevel: 1, CHWBLPrefixHashLevelPresent: true,
		CHWBLPrefixHashFlags: 0, CHWBLPrefixHashFlagsPresent: true,
		CHWBLMeanLoadFactor: 175, CHWBLMeanLoadFactorPresent: true,
		CHWBLReplication: 256, CHWBLReplicationPresent: true,
		CHWBLEnableCacheSalt: false, CHWBLEnableCacheSaltPresent: true,
	}
	if err := resolveCHWBLContract(&reset, existing, chwblEndpoints(1)); err != nil {
		t.Fatal(err)
	}
	if reset.CHWBLPrefixHashLevel != 1 || reset.CHWBLPrefixHashFlags != 0 ||
		reset.CHWBLMeanLoadFactor != 175 || reset.CHWBLReplication != 256 ||
		reset.CHWBLEnableCacheSalt {
		t.Fatalf("explicit reset not honored: %+v", reset)
	}
}

func TestResolveCHWBLContractRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name string
		serv cmn.LbServiceArg
		eps  []ruleLBEp
		want string
	}{
		{"wrong selector", cmn.LbServiceArg{Sel: cmn.LbSelRr, CHWBLReplication: 256}, chwblEndpoints(1), "require mode=4"},
		{"flags above level", cmn.LbServiceArg{Mode: 4, Sel: 8, CHWBLPrefixHashLevel: 1, CHWBLPrefixHashFlags: 0x20, CHWBLMeanLoadFactor: 175, CHWBLReplication: 256}, chwblEndpoints(1), "above"},
		{"salt bit absent", cmn.LbServiceArg{Mode: 4, Sel: 8, CHWBLPrefixHashLevel: 1, CHWBLPrefixHashFlags: 1, CHWBLMeanLoadFactor: 175, CHWBLReplication: 256, CHWBLEnableCacheSalt: true}, chwblEndpoints(1), "bit 3"},
		{"wrr budget too small", cmn.LbServiceArg{Mode: 4, Sel: 10, CHWBLPrefixHashLevel: 1, CHWBLMeanLoadFactor: 175, CHWBLReplication: 1}, chwblEndpoints(1, 1), "positive-weight endpoint count"},
		{"wrr zero weights", cmn.LbServiceArg{Mode: 4, Sel: 10, CHWBLPrefixHashLevel: 1, CHWBLMeanLoadFactor: 175, CHWBLReplication: 256}, chwblEndpoints(0, 0), "positive-weight endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolveCHWBLContract(&tt.serv, nil, tt.eps)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestGetLBConsolidatedEPsDoesNotMutateInputs(t *testing.T) {
	old := chwblEndpoints(1)
	old[0].inActiveEP = true
	newEps := chwblEndpoints(2)
	oldBefore := snapshotLBEndpoints(old)
	newBefore := snapshotLBEndpoints(newEps)
	getLBConsolidatedEPs(old, newEps, cmn.LBOPAdd)
	if old[0].weight != oldBefore[0].weight || old[0].chkVal != oldBefore[0].chkVal ||
		old[0].inActiveEP != oldBefore[0].inActiveEP {
		t.Fatalf("old input mutated: before=%+v after=%+v", oldBefore[0], old[0])
	}
	if newEps[0].weight != newBefore[0].weight || newEps[0].chkVal != newBefore[0].chkVal {
		t.Fatalf("new input mutated: before=%+v after=%+v", newBefore[0], newEps[0])
	}
}
