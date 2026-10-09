/*
 * Copyright (c) 2026 NetLOX Inc
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
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A kernel-enforced security control asked for in proxy-only mode must be
// refused with the typed error the handler maps to HTTP 400 — never the
// silent "Success" the datapath's have_noebpf early return used to produce.
// These run with mh.disBPF set and no datapath handle at all, so a path
// that reached the datapath would panic rather than pass.
func wantProxyOnlyRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("proxy-only accepted %s", what)
	}
	var ruleArg *cmn.RuleArgumentError
	if !errors.As(err, &ruleArg) {
		t.Fatalf("%s: want RuleArgumentError (HTTP 400), got %T: %v", what, err, err)
	}
}

func TestNetFwRuleAddRefusedInProxyOnly(t *testing.T) {
	saved := mh.disBPF
	mh.disBPF = true
	t.Cleanup(func() { mh.disBPF = saved })
	na := NetAPIInit(false)
	_, err := na.NetFwRuleAdd(&cmn.FwRuleMod{
		Rule: cmn.FwRuleArg{SrcIP: "11.11.11.2/32", DstIP: "0.0.0.0/0"},
		Opts: cmn.FwOptArg{Drop: true},
	})
	wantProxyOnlyRefusal(t, "a firewall rule", err)
}

func TestNetIPFilterAddRefusedInProxyOnly(t *testing.T) {
	saved := mh.disBPF
	mh.disBPF = true
	t.Cleanup(func() { mh.disBPF = saved })
	na := NetAPIInit(false)
	_, err := na.NetIPFilterAdd(&cmn.IPFilterMod{
		FilterType: "blacklist", CIDR: "11.11.11.2/32", Priority: 200, Action: "drop",
	})
	wantProxyOnlyRefusal(t, "an ip filter rule", err)
}

// bgp-peer mode keeps its own, older refusal: the proxy-only check must not
// change which error that path returns.
func TestNetFwRuleAddBgpPeerModeStillRefused(t *testing.T) {
	saved := mh.disBPF
	mh.disBPF = true
	t.Cleanup(func() { mh.disBPF = saved })
	na := NetAPIInit(true)
	if _, err := na.NetFwRuleAdd(&cmn.FwRuleMod{}); err == nil {
		t.Fatalf("bgp-peer mode accepted a firewall rule")
	}
}
