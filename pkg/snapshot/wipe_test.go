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

package snapshot

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestWipeDeletesEveryDomainInReverseOrder(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1"}}
	hooks.lbRules = []cmn.LbRuleMod{{Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80}}}

	results, err := Wipe(hooks, nil)
	if err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if len(results) != len(Registry) {
		t.Fatalf("expected %d results (one per domain), got %d", len(Registry), len(results))
	}
	// results must be reported in delete order: loadbalancer before endpoint.
	if results[0].Domain != DomainCert || results[len(results)-1].Domain != DomainEndpoint {
		t.Fatalf("expected delete order (cert ... endpoint), got: %v", domainsOf(results))
	}

	// The actual hook calls must show loadbalancer's delete-side Get
	// happening before endpoint's.
	lbIdx := callIndex(hooks.Calls, "NetLbRuleGet")
	epIdx := callIndex(hooks.Calls, "NetEpHostGet")
	if lbIdx < 0 || epIdx < 0 || lbIdx > epIdx {
		t.Fatalf("expected loadbalancer deleted (Get at %d) before endpoint (Get at %d), calls: %v", lbIdx, epIdx, hooks.Calls)
	}

	if len(hooks.endpoints) != 0 {
		t.Fatalf("expected endpoints wiped, got: %+v", hooks.endpoints)
	}
	if len(hooks.lbRules) != 0 {
		t.Fatalf("expected lb rules wiped, got: %+v", hooks.lbRules)
	}
}

func TestWipeCollectsErrorsAndStillAttemptsEveryDomain(t *testing.T) {
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "1.2.3.4/32"}}}
	hooks.bfds = []cmn.BFDMod{{Instance: "bfd1"}}
	hooks.endpoints = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1"}}
	hooks.policies = []cmn.PolMod{{Ident: "pol1"}}

	hooks.failNext("NetFwRuleDel", errors.New("simulated firewall delete failure"))
	hooks.failNext("NetBFDDel", errors.New("simulated bfd delete failure"))

	results, err := Wipe(hooks, []string{DomainEndpoint, DomainFirewall, DomainPolicy, DomainBFD})
	if err == nil {
		t.Fatalf("expected a combined error from the two injected failures")
	}
	if !strings.Contains(err.Error(), "firewall") || !strings.Contains(err.Error(), "bfd") {
		t.Fatalf("combined error should name both failing domains, got: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("expected a result for every selected domain despite failures, got %d: %+v", len(results), results)
	}

	// Despite firewall and bfd failing, endpoint and policy (domains on
	// both sides of them in delete order) must still have been attempted --
	// a wipe must attempt everything, not abort mid-wipe.
	if len(hooks.endpoints) != 0 {
		t.Fatalf("expected endpoint still wiped despite other domains' failures, got: %+v", hooks.endpoints)
	}
	if len(hooks.policies) != 0 {
		t.Fatalf("expected policy still wiped despite other domains' failures, got: %+v", hooks.policies)
	}
	// The failing domains' live items remain (their Del calls failed).
	if len(hooks.fwRules) != 1 {
		t.Fatalf("expected firewall rule to remain (delete failed), got: %+v", hooks.fwRules)
	}
	if len(hooks.bfds) != 1 {
		t.Fatalf("expected bfd instance to remain (delete failed), got: %+v", hooks.bfds)
	}
}

func TestWipeFirewallSrcChkExclusion(t *testing.T) {
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{
		{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32"}, Opts: cmn.FwOptArg{Mark: srcChkFwMark}},
		{Rule: cmn.FwRuleArg{SrcIP: "2.2.2.2/32"}, Opts: cmn.FwOptArg{Mark: 0}},
	}

	results, err := Wipe(hooks, []string{DomainFirewall})
	if err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if len(results) != 1 || results[0].Deleted != 1 {
		t.Fatalf("expected exactly 1 deletion (SrcChk rule excluded), got: %+v", results)
	}
	if len(hooks.fwRules) != 1 || hooks.fwRules[0].Opts.Mark != srcChkFwMark {
		t.Fatalf("expected only the SrcChk-marked rule to survive the wipe, got: %+v", hooks.fwRules)
	}
}

func TestWipeComponentsFiltering(t *testing.T) {
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "1.2.3.4/32"}}}
	hooks.endpoints = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1"}}

	results, err := Wipe(hooks, []string{DomainFirewall})
	if err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if len(results) != 1 || results[0].Domain != DomainFirewall {
		t.Fatalf("expected exactly 1 result for firewall only, got: %+v", results)
	}
	if len(hooks.fwRules) != 0 {
		t.Fatalf("expected firewall wiped, got: %+v", hooks.fwRules)
	}
	if len(hooks.endpoints) != 1 {
		t.Fatalf("components filter must not touch endpoint, got: %+v", hooks.endpoints)
	}
	for _, c := range hooks.Calls {
		if strings.Contains(c, "EpHost") {
			t.Fatalf("components filter must not call any endpoint hook, got: %s", c)
		}
	}
}

func TestWipeUnknownComponentErrors(t *testing.T) {
	hooks := newMockHooks()
	_, err := Wipe(hooks, []string{"not-a-real-domain"})
	if err == nil {
		t.Fatalf("expected an error for an unknown domain")
	}
	if !strings.Contains(err.Error(), "not-a-real-domain") {
		t.Fatalf("error should name the offending domain, got: %v", err)
	}
}

// TestWipeNeverTouchesClusterState locks down §4.1's cluster/HA exclusion
// at the Wipe entrypoint: Registry (and therefore Wipe, which is entirely
// Registry-driven) has no "cluster" domain and the Hooks interface exposes
// no cluster/HA method at all, so no components value -- not even an
// (invalid) explicit "cluster" -- can make Wipe reach cluster state.
func TestWipeNeverTouchesClusterState(t *testing.T) {
	for _, e := range Registry {
		if e.Name == "cluster" {
			t.Fatalf("cluster must never be part of the registry Wipe drives")
		}
	}

	hooksType := reflect.TypeOf((*Hooks)(nil)).Elem()
	for i := 0; i < hooksType.NumMethod(); i++ {
		name := hooksType.Method(i).Name
		if strings.Contains(strings.ToLower(name), "cistate") || strings.Contains(strings.ToLower(name), "cluster") {
			t.Fatalf("Hooks must expose no cluster/HA method (found %s) -- Wipe must never be able to reach cluster state", name)
		}
	}

	// Explicitly requesting "cluster" as a component must fail loudly
	// (Select's unknown-domain error), not silently no-op or reach some
	// other cluster path.
	if _, err := Wipe(newMockHooks(), []string{"cluster"}); err == nil {
		t.Fatalf(`expected Wipe(..., []string{"cluster"}) to error (unknown domain), not silently succeed`)
	}
}

func domainsOf(items []WipeItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Domain
	}
	return out
}

func callIndex(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}
