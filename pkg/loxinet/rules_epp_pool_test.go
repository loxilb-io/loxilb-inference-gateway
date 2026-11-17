/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"fmt"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// completion check, end to end through the real data plane:
// a fullproxy rule that names an EPP lands its mode word, deadline and
// rule identity in the sockproxy pool (dp_proxy_tacts -> llb_conv_nat2proxy
// -> proxy_add_entry), and a rule without an EPP leaves them zero. Needs
// the loxinet harness (TestMain -> loxiNetInit, root): skipped otherwise.
func TestEppRuleReachesProxyPool(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	eps := []cmn.LbEndPointArg{{EpIP: "127.0.0.1", EpPort: 28081, Weight: 1}}
	cases := []struct {
		name     string
		port     uint16
		serv     cmn.LbServiceArg
		wantMode uint8
		wantMs   uint32
	}{
		{"fail close default", 28080, cmn.LbServiceArg{EppEndpoint: "127.0.0.1:9002"}, eppDpModeFailClose, cmn.EppDefaultTimeoutMs},
		{"fail open explicit", 28082, cmn.LbServiceArg{EppEndpoint: "127.0.0.1:9002", EppFailureMode: cmn.EppFailureModeFailOpen, EppTimeoutMs: 1500}, eppDpModeFailOpen, 1500},
		{"no epp", 28084, cmn.LbServiceArg{}, eppDpModeOff, 0},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			serv := tt.serv
			serv.ServIP, serv.ServPort, serv.Proto = "127.0.0.1", tt.port, "tcp"
			serv.Mode, serv.Sel = cmn.LBModeFullProxy, cmn.LbSelRr
			if _, err := eppTestAddRule(serv, eps); err != nil {
				t.Fatalf("add fullproxy rule: %v", err)
			}
			defer eppTestDeleteRule(serv)

			ruleNum := eppTestRuleMark(fmt.Sprintf("%s:%d:%s", serv.ServIP, serv.ServPort, serv.Proto))
			if ruleNum == 0 {
				t.Fatal("rule number not found after add")
			}
			pools, mode, ms := DpEppCfgGet(uint32(ruleNum))
			if pools == 0 {
				t.Fatalf("no sockproxy pool carries rule %d as epp_svc_id", ruleNum)
			}
			if mode != tt.wantMode || ms != tt.wantMs {
				t.Fatalf("pool holds mode=%d timeout=%d, want mode=%d timeout=%d", mode, ms, tt.wantMode, tt.wantMs)
			}
		})
	}
}
