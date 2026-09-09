/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package handler

import (
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"
)

func int64p(v int64) *int64 { return &v }
func boolp(v bool) *bool    { return &v }

func TestCHWBLArgumentsAdmissionAndPresence(t *testing.T) {
	raw := []byte(`{"serviceArguments":{"chwbl_prefix_hash_level":1,"chwbl_prefix_hash_flags":0,"chwbl_mean_load_factor":175,"chwbl_replication":256,"chwbl_enable_cache_salt":false}}`)
	pres, err := parseLoadbalancerRequestPresence(raw)
	if err != nil {
		t.Fatal(err)
	}
	args := &models.LoadbalanceEntryServiceArguments{
		Mode: 4, Sel: 8, ChwblPrefixHashLevel: int64p(1),
		ChwblPrefixHashFlags: int64p(0), ChwblMeanLoadFactor: 175,
		ChwblReplication: 256, ChwblEnableCacheSalt: boolp(false),
	}
	if err := pres.validateCHWBLArguments(args); err != nil {
		t.Fatal(err)
	}
	var dst cmn.LbServiceArg
	pres.applyCHWBLArguments(&dst, args)
	if !dst.CHWBLPrefixHashLevelPresent || !dst.CHWBLPrefixHashFlagsPresent ||
		!dst.CHWBLMeanLoadFactorPresent || !dst.CHWBLReplicationPresent ||
		!dst.CHWBLEnableCacheSaltPresent {
		t.Fatalf("presence bits not propagated: %+v", dst)
	}
}

func TestCHWBLArgumentsRejectInvalidContract(t *testing.T) {
	tests := []struct {
		name string
		args models.LoadbalanceEntryServiceArguments
		want string
	}{
		{"wrong mode", models.LoadbalanceEntryServiceArguments{Mode: 0, Sel: 8, ChwblReplication: 256}, "require mode=4"},
		{"wrong selector", models.LoadbalanceEntryServiceArguments{Mode: 4, Sel: 0, ChwblReplication: 256}, "require mode=4"},
		{"flags above level", models.LoadbalanceEntryServiceArguments{Mode: 4, Sel: 8, ChwblPrefixHashLevel: int64p(1), ChwblPrefixHashFlags: int64p(0x20)}, "above"},
		{"salt without flag", models.LoadbalanceEntryServiceArguments{Mode: 4, Sel: 8, ChwblPrefixHashLevel: int64p(1), ChwblPrefixHashFlags: int64p(1), ChwblEnableCacheSalt: boolp(true)}, "bit 3"},
	}
	pres, err := parseLoadbalancerRequestPresence([]byte(`{"serviceArguments":{"chwbl_replication":256}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pres.validateCHWBLArguments(&tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestCHWBLNullAndPatchFieldsRejected(t *testing.T) {
	for _, field := range chwblRequestKeys {
		t.Run(field, func(t *testing.T) {
			pres, err := parseLoadbalancerRequestPresence([]byte(`{"serviceArguments":{"` + field + `":null}}`))
			if err != nil {
				t.Fatal(err)
			}
			if err := pres.validateCHWBLArguments(&models.LoadbalanceEntryServiceArguments{}); err == nil ||
				!strings.Contains(err.Error(), "must not be null") {
				t.Fatalf("null error=%v", err)
			}
			if err := pres.validateUnsupportedCHWBLPatch(); err == nil ||
				!strings.Contains(err.Error(), "PATCH does not support field") {
				t.Fatalf("patch error=%v", err)
			}
		})
	}
}

func TestSerializeCHWBLRuleReturnsEffectiveValuesForBothSelectors(t *testing.T) {
	for _, sel := range []cmn.EpSelect{cmn.LbSelCHWBL, cmn.LbSelWRRHash} {
		got := serializeLBRule(cmn.LbRuleMod{Serv: cmn.LbServiceArg{
			Sel: sel, CHWBLPrefixHashLevel: 1, CHWBLPrefixHashFlags: 0,
			CHWBLMeanLoadFactor: 175, CHWBLReplication: 256,
			CHWBLEnableCacheSalt: false,
		}}).ServiceArguments
		if got.ChwblPrefixHashLevel == nil || *got.ChwblPrefixHashLevel != 1 ||
			got.ChwblPrefixHashFlags == nil || *got.ChwblPrefixHashFlags != 0 ||
			got.ChwblMeanLoadFactor != 175 || got.ChwblReplication != 256 ||
			got.ChwblEnableCacheSalt == nil || *got.ChwblEnableCacheSalt {
			t.Fatalf("selector %d readback lost effective CHWBL values: %+v", sel, got)
		}
	}
}
