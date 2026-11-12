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
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func netIdentityFixture() []cmn.NetIdentityMod {
	return []cmn.NetIdentityMod{
		{
			Name: "line-1", Match: cmn.NetIdentityMatch{CIDR: []string{"10.20.0.0/24"}},
			Services: []string{"20.20.20.1:8080"}, Tenant: "line-1", AllowedModels: []string{"llama-3.1-8b"},
			Enforce: cmn.NetIdentityEnforceStrict, Credential: cmn.NetIdentityCredentialNone,
			PriorityClass: cmn.NetIdentityClassStandard, FailMode: cmn.NetIdentityFailClosed,
		},
		{
			Name: "zone-b", Match: cmn.NetIdentityMatch{IngressIf: "vlan200"}, Tenant: "zone-b",
			Enforce: cmn.NetIdentityEnforceAdvisory, Credential: cmn.NetIdentityCredentialNetwork,
			ForwardIdentity: true, PriorityClass: cmn.NetIdentityClassSheddable, FailMode: cmn.NetIdentityFailNeutral,
		},
	}
}

// The three other spellings of an interface match, one binding each.
func netIdentityAliasFixture() []cmn.NetIdentityMod {
	return []cmn.NetIdentityMod{
		{Name: "by-tunnel", Match: cmn.NetIdentityMatch{IPsecTunnel: "branch-1"}, Tenant: "branch",
			Credential: cmn.NetIdentityCredentialNetwork},
		{Name: "by-vlan", Match: cmn.NetIdentityMatch{Vlan: 20}, Tenant: "line-1"},
		{Name: "by-vni", Match: cmn.NetIdentityMatch{Vni: 1001}, Tenant: "grade-c"},
	}
}

// TestNetIdentityAliasesRoundTrip: a binding written with vlan, vni or
// ipsec_tunnel is captured and restored as written, never as the interface
// name the alias stood for on the node that captured it.
func TestNetIdentityAliasesRoundTrip(t *testing.T) {
	src := newMockHooks()
	src.netIDs = netIdentityAliasFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainNetIdentity})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	raw := encodeDoc(t, doc)
	flat := strings.ReplaceAll(strings.ReplaceAll(string(raw), " ", ""), "\n", "")
	for _, field := range []string{`"match":{"ipsec_tunnel":"branch-1"}`, `"match":{"vlan":20}`, `"match":{"vni":1001}`} {
		if !strings.Contains(flat, field) {
			t.Errorf("the encoded document lacks %s", field)
		}
	}
	if strings.Contains(flat, "ingress_if") {
		t.Errorf("an alias was captured as an interface name: %s", flat)
	}

	hooks := newMockHooks()
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	if !reflect.DeepEqual(hooks.netIDs, netIdentityAliasFixture()) {
		t.Fatalf("live bindings after the restore: %+v", hooks.netIDs)
	}
}

// TestNetIdentityRoundTrip: the bindings a capture reads are the bindings a
// restore leaves, every field, through the encoded document.
func TestNetIdentityRoundTrip(t *testing.T) {
	src := newMockHooks()
	src.netIDs = netIdentityFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainNetIdentity})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("a document with bindings rides schema %s, want %s", doc.SchemaVersion, SchemaVersion)
	}
	raw := encodeDoc(t, doc)
	for _, field := range []string{`"netidentity"`, `"ingress_if":"vlan200"`, `"fail_mode":"closed"`,
		`"credential":"network"`, `"forward_identity":true`, `"priority_class":"sheddable"`, `"allowed_models"`} {
		if !strings.Contains(strings.ReplaceAll(strings.ReplaceAll(string(raw), " ", ""), "\n", ""), field) {
			t.Errorf("the encoded document lacks %s", field)
		}
	}

	// A restore replaces what is live: a binding under a name the document
	// has takes the document's content, one it does not have goes.
	hooks := newMockHooks()
	hooks.netIDs = []cmn.NetIdentityMod{
		{Name: "line-1", Match: cmn.NetIdentityMatch{CIDR: []string{"192.0.2.0/24"}}, Tenant: "someone-else"},
		{Name: "stale", Match: cmn.NetIdentityMatch{CIDR: []string{"198.51.100.0/24"}}, Tenant: "stale"},
	}
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	if !reflect.DeepEqual(hooks.netIDs, netIdentityFixture()) {
		t.Fatalf("live bindings after the restore: %+v", hooks.netIDs)
	}
}

// TestNetIdentityAppliesBeforeAndIsDeletedAfterTheRules: a restored service
// is bound from its first request, and on the way down it does not outlive
// its bindings.
func TestNetIdentityAppliesBeforeAndIsDeletedAfterTheRules(t *testing.T) {
	src := newMockHooks()
	src.netIDs = netIdentityFixture()
	src.lbRules = []cmn.LbRuleMod{{Serv: cmn.LbServiceArg{ServIP: "20.20.20.1", ServPort: 8080, Proto: "tcp"}}}
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainNetIdentity, DomainLoadBalancer})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	hooks := newMockHooks()
	hooks.netIDs = netIdentityFixture()
	hooks.lbRules = append([]cmn.LbRuleMod(nil), src.lbRules...)
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(encodeDoc(t, doc), RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	ruleDel, bindDel := callIndex(hooks.Calls, "NetLbRuleDel"), callIndex(hooks.Calls, "NetAINetIdentityDel")
	bindAdd, ruleAdd := callIndex(hooks.Calls, "NetAINetIdentityAdd"), callIndex(hooks.Calls, "NetLbRuleAdd")
	if ruleDel < 0 || bindDel < 0 || bindAdd < 0 || ruleAdd < 0 {
		t.Fatalf("the restore skipped a step: rule del %d, binding del %d, binding add %d, rule add %d",
			ruleDel, bindDel, bindAdd, ruleAdd)
	}
	if !(ruleDel < bindDel && bindDel < bindAdd && bindAdd < ruleAdd) {
		t.Fatalf("order: rule del %d, binding del %d, binding add %d, rule add %d", ruleDel, bindDel, bindAdd, ruleAdd)
	}
}

// TestRestoreRollsBackWhenABindingIsRefused: a binding the node refuses
// fails the restore, and the bindings that were live come back.
func TestRestoreRollsBackWhenABindingIsRefused(t *testing.T) {
	src := newMockHooks()
	src.netIDs = netIdentityFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainNetIdentity})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	before := []cmn.NetIdentityMod{
		{Name: "live", Match: cmn.NetIdentityMatch{CIDR: []string{"192.0.2.0/24"}}, Tenant: "live"},
	}
	hooks := newMockHooks()
	hooks.netIDs = append([]cmn.NetIdentityMod(nil), before...)
	hooks.failNext("NetAINetIdentityAdd", errors.New("refused: match.cidr: host bits set"))
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(encodeDoc(t, doc), RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back, got %+v", res)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), DomainNetIdentity) {
		t.Fatalf("the error does not name the domain: %v", res.Errors)
	}
	if !reflect.DeepEqual(hooks.netIDs, before) {
		t.Fatalf("live bindings after the rollback: %+v", hooks.netIDs)
	}
}

// TestRestoreOfAnOlderDocumentLeavesTheBindings: a document written before
// the domain existed never captured the bindings, so restoring it removes
// none of the live ones.
func TestRestoreOfAnOlderDocumentLeavesTheBindings(t *testing.T) {
	raw, err := os.ReadFile(goldenPath("1.10"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	defer SetNodeSecretForTest(goldenNodeSecret)()

	hooks := newMockHooks()
	hooks.netIDs = netIdentityFixture()
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	if call := containsCallSubstring(hooks.Calls, "NetAINetIdentityDel", "NetAINetIdentityAdd"); call != "" {
		t.Fatalf("a document that predates the domain touched the bindings: %s", call)
	}
	if !reflect.DeepEqual(hooks.netIDs, netIdentityFixture()) {
		t.Fatalf("live bindings after the restore: %+v", hooks.netIDs)
	}
}

// TestDocumentOfANewerSchemaIsRefusedByAnOlderGate: the minor-version gate
// is what keeps a build that predates the domain from restoring a document
// without its bindings. The gate itself is the decoder's; this pins that a
// document one minor ahead of this build is refused, which is what 1.11
// is to a 1.10 build.
func TestDocumentOfANewerSchemaIsRefusedByAnOlderGate(t *testing.T) {
	doc := sampleDocument()
	major, minor, _ := ParseSchemaVersion(SchemaVersion)
	doc.SchemaVersion = fmt.Sprintf("%d.%d", major, minor+1)
	hooks := newMockHooks()
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(encodeDoc(t, doc), RestoreOptions{Mode: ModeDryRun})
	if err == nil && (res == nil || res.Compatible) {
		t.Fatalf("a document of a newer minor was accepted: %+v", res)
	}
	if call := firstMutatingCall(hooks.Calls); call != "" {
		t.Fatalf("a refused document reached the node: %s", call)
	}
}
