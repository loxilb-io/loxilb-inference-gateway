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

// Restore-fidelity regression suite: the defects this file pins were all
// silent -- a domain invisible to PLAN/VERIFY arithmetic, a partial
// document wiping domains it never covered, a VERIFY that counted items
// but never compared them, a Get aliasing live state into captured
// documents. Each test here was proven RED against the pre-fix code.

package snapshot

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// --- kvexactbinding visibility in PLAN/VERIFY ---

func kvBindingDoc(n int) *Document {
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainKvExactBinding}
	for i := 0; i < n; i++ {
		doc.Domains.KvExactBinding = append(doc.Domains.KvExactBinding, cmn.KvExactBindingMod{
			RuleIdent: "rule-" + string(rune('a'+i)),
		})
	}
	return doc
}

// TestPlanCountsKvExactBinding: a document with N bindings must PLAN
// to_apply=N for the kvexactbinding domain. Before the countDomain fix the
// domain was invisible: to_apply was always 0, so every later VERIFY of
// the domain passed vacuously.
func TestPlanCountsKvExactBinding(t *testing.T) {
	hooks := newMockHooks()
	raw := encodeDoc(t, kvBindingDoc(2))

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(res.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	found := false
	for _, p := range res.Plan {
		if p.Domain == DomainKvExactBinding {
			found = true
			if p.ToApply != 2 {
				t.Fatalf("kvexactbinding plan to_apply = %d, want 2 (domain invisible to countDomain)", p.ToApply)
			}
		}
	}
	if !found {
		t.Fatalf("kvexactbinding missing from plan: %+v", res.Plan)
	}
}

// TestVerifyCatchesDroppedKvBinding: a commit restore whose backend
// silently drops one binding must FAIL verify and roll back. Selection is
// restricted to the kvexactbinding domain so the Get-call sequence is
// deterministic: PLAN(#1), PRESERVE(#2), wipe enumeration(#3), VERIFY(#4).
func TestVerifyCatchesDroppedKvBinding(t *testing.T) {
	hooks := newMockHooks()
	raw := encodeDoc(t, kvBindingDoc(2))

	hooks.overrideGetLenAtCall("NetKvExactBindingGet", 4, 1)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit, Components: []string{DomainKvExactBinding}})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back after a dropped binding, got %q (errors: %v)", res.Result, res.Errors)
	}
	if containsCallSubstring([]string{strings.Join(res.Errors, "|")}, "kvexactbinding") == "" {
		t.Fatalf("expected a kvexactbinding verify error, got: %v", res.Errors)
	}
}

// --- included_domains: partial documents must not wipe omitted domains ---

// TestPartialRestoreDoesNotWipeOmittedDomains is the headline negative
// test: a document covering ONLY the loadbalancer domain, committed with
// default selection, onto a gateway that also has firewall and session
// config. Before included_domains, default selection meant "all domains":
// the restore wiped everything and re-applied only the loadbalancer -- the
// firewall and session config was destroyed.
func TestPartialRestoreDoesNotWipeOmittedDomains(t *testing.T) {
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "2.2.2.2/32", DstIP: "3.3.3.3/32"}}}
	hooks.sessions = []cmn.SessionMod{{Ident: "sess-live"}}

	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainLoadBalancer}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}},
	}}
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %q (errors: %v)", res.Result, res.Errors)
	}

	if len(hooks.fwRules) != 1 {
		t.Fatalf("firewall config wiped by a document that never covered it: %+v", hooks.fwRules)
	}
	if len(hooks.sessions) != 1 || hooks.sessions[0].Ident != "sess-live" {
		t.Fatalf("session config wiped by a document that never covered it: %+v", hooks.sessions)
	}
	if len(hooks.lbRules) != 1 {
		t.Fatalf("covered domain not applied: %+v", hooks.lbRules)
	}
	// The plan must cover exactly the document's domains -- nothing else
	// was eligible for wipe or apply.
	if len(res.Plan) != 1 || res.Plan[0].Domain != DomainLoadBalancer {
		t.Fatalf("plan should cover exactly the included domain, got: %+v", res.Plan)
	}
}

// TestRestoreRefusesComponentOutsideCoverage: explicitly requesting a
// component the document does not cover is an error, not a silent no-op.
func TestRestoreRefusesComponentOutsideCoverage(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainLoadBalancer}
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit, Components: []string{DomainFirewall}})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "not covered") {
		t.Fatalf("expected a coverage refusal, got: %+v", res)
	}
	if got := firstMutatingCall(hooks.Calls); got != "" {
		t.Fatalf("nothing may be mutated on a refused restore, saw %q", got)
	}
}

// TestValidateRejectsUndeclaredContent: a document carrying firewall
// content while declaring only loadbalancer coverage is torn or
// hand-edited -- VALIDATE must refuse it before anything is planned.
func TestValidateRejectsUndeclaredContent(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainLoadBalancer}
	doc.Domains.Firewall = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "2.2.2.2/32", DstIP: "3.3.3.3/32"}}}
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(res.Errors) == 0 || !strings.Contains(strings.Join(res.Errors, "|"), "not listed in included_domains") {
		t.Fatalf("expected an undeclared-content refusal, got: %+v", res)
	}
	if got := firstMutatingCall(hooks.Calls); got != "" {
		t.Fatalf("nothing may be mutated on a refused restore, saw %q", got)
	}
}

// TestValidateRequiresIncludedDomains: a current-schema document with the
// coverage declaration stripped fails closed.
func TestValidateRequiresIncludedDomains(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = nil
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "included_domains") {
		t.Fatalf("expected an included_domains refusal, got: %+v", res)
	}
}

// TestMigrationStampsFullCoverageOn11Docs: a 1.1 document (no
// included_domains) restores with its historical full-coverage semantics.
func TestMigrationStampsFullCoverageOn11Docs(t *testing.T) {
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.SchemaVersion = "1.1"
	doc.IncludedDomains = nil
	if err := ApplyMigrations(doc); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("expected migration chain to reach %q, got %q", SchemaVersion, doc.SchemaVersion)
	}
	if len(doc.IncludedDomains) != len(Registry) {
		t.Fatalf("expected full coverage stamped, got %v", doc.IncludedDomains)
	}
}

// TestMigrationKeepsNewDomainsOutOf12Coverage: a 1.2 document declared
// its coverage explicitly and never captured L7 policies or CORS config,
// so migrating it to 1.3 must NOT widen included_domains -- restoring an
// old document must leave the live state of the new domains untouched.
// The absent l7policy payload is normalized to its empty value; the
// absent cors payload stays nil (nil is the meaningful "unconfigured"
// value for that singleton).
func TestMigrationKeepsNewDomainsOutOf12Coverage(t *testing.T) {
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.SchemaVersion = "1.2"
	pre := make([]string, 0, len(Registry))
	for _, name := range DomainNames() {
		if name != DomainL7Policy && name != DomainCORS &&
			name != DomainTracing && name != DomainCert {
			pre = append(pre, name)
		}
	}
	doc.IncludedDomains = pre
	doc.Domains.L7Policy = nil
	doc.Domains.CORS = nil
	doc.Domains.Tracing = nil
	doc.Domains.Cert = nil
	if err := ApplyMigrations(doc); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("expected migration to %q, got %q", SchemaVersion, doc.SchemaVersion)
	}
	for _, name := range doc.IncludedDomains {
		if name == DomainL7Policy || name == DomainCORS ||
			name == DomainTracing || name == DomainCert {
			t.Fatalf("1.2->1.3 migration widened coverage to %q: %v", name, doc.IncludedDomains)
		}
	}
	if doc.Domains.L7Policy == nil {
		t.Fatalf("migration left l7policy payload nil (want normalized empty)")
	}
	if doc.Domains.CORS != nil {
		t.Fatalf("migration invented cors config: %+v", doc.Domains.CORS)
	}
	if doc.Domains.Tracing != nil {
		t.Fatalf("migration invented tracing config: %+v", doc.Domains.Tracing)
	}
}

// TestPreserveDocDeclaresSelection: the PRESERVE-stage document written
// before a components-filtered commit must declare exactly that selection,
// so restoring it later cannot wipe domains it never captured.
func TestPreserveDocDeclaresSelection(t *testing.T) {
	hooks := newMockHooks()
	e := newTestEngine(hooks, t.TempDir())
	preDoc, err := e.stagePreserve(mustSelect(t, []string{DomainFirewall, DomainSession}))
	if err != nil {
		t.Fatalf("stagePreserve: %v", err)
	}
	want := []string{DomainFirewall, DomainSession}
	if len(preDoc.IncludedDomains) != 2 || preDoc.IncludedDomains[0] != want[0] || preDoc.IncludedDomains[1] != want[1] {
		t.Fatalf("pre-restore doc coverage = %v, want %v", preDoc.IncludedDomains, want)
	}
}

func mustSelect(t *testing.T, components []string) []DomainEntry {
	t.Helper()
	sel, err := Select(components)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	return sel
}

// --- digest VERIFY: field-level corruption is no longer invisible ---

// TestVerifyCatchesFieldCorruption: the backend keeps the right NUMBER of
// items but corrupts a field (here: the stored LB rule's endpoint weight
// changes between apply and verify). Count-only VERIFY passed this;
// the digest must fail it and roll back.
func TestVerifyCatchesFieldCorruption(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainLoadBalancer}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080, Weight: 10}},
	}}
	raw := encodeDoc(t, doc)

	// Corrupt the stored rule right before VERIFY re-Gets it: selection is
	// one domain, so calls are PLAN(#1), PRESERVE(#2), wipe(#3), VERIFY(#4).
	// The corrupted Eps slice is reassigned fresh -- the mock's shallow Add
	// copy shares the nested backing array with the document, and an
	// in-place write would corrupt BOTH sides identically, hiding the drift
	// this test exists to catch.
	hooks.mutateAtCall("NetLbRuleGet", 4, func() {
		eps := append([]cmn.LbEndPointArg(nil), hooks.lbRules[0].Eps...)
		eps[0].Weight = 99
		hooks.lbRules[0].Eps = eps
	})

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back on field corruption, got %q (errors: %v)", res.Result, res.Errors)
	}
	if !strings.Contains(strings.Join(res.Errors, "|"), "content mismatch") {
		t.Fatalf("expected a content-mismatch verify error, got: %v", res.Errors)
	}
}

// TestVerifyIgnoresVolatileFields: runtime fields the backend fills in
// (endpoint probe state, LB endpoint counters, BGP session state) must NOT
// fail the digest -- desired state is what VERIFY compares.
func TestVerifyIgnoresVolatileFields(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainEndpoint, DomainLoadBalancer, DomainBGP}
	doc.Domains.Endpoint = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1", ProbeType: "tcp"}}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}},
	}}
	doc.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{{Addr: "10.0.0.2", RemoteAS: 65001, State: "ESTABLISHED", Uptime: "00:42:00"}}
	raw := encodeDoc(t, doc)

	// After apply, the "backend" reports runtime values the document
	// didn't carry.
	hooks.mutateAtCall("NetEpHostGet", 4, func() {
		hooks.endpoints[0].CurrState = "up"
		hooks.endpoints[0].AvgDelay = "1ms"
	})
	hooks.mutateAtCall("NetLbRuleGet", 4, func() {
		eps := append([]cmn.LbEndPointArg(nil), hooks.lbRules[0].Eps...)
		eps[0].State = "active"
		eps[0].Counters = "10:2048"
		hooks.lbRules[0].Eps = eps
	})

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("volatile runtime fields must not fail verify, got %q (errors: %v)", res.Result, res.Errors)
	}
}

// TestDomainDigestOrderInsensitive: backend enumeration order must not
// change a domain's digest.
func TestDomainDigestOrderInsensitive(t *testing.T) {
	a := &Domains{Firewall: []cmn.FwRuleMod{
		{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32", DstIP: "2.2.2.2/32"}},
		{Rule: cmn.FwRuleArg{SrcIP: "3.3.3.3/32", DstIP: "4.4.4.4/32"}},
	}}
	b := &Domains{Firewall: []cmn.FwRuleMod{
		{Rule: cmn.FwRuleArg{SrcIP: "3.3.3.3/32", DstIP: "4.4.4.4/32"}},
		{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32", DstIP: "2.2.2.2/32"}},
	}}
	da, err := DomainDigest(DomainFirewall, a)
	if err != nil {
		t.Fatalf("DomainDigest: %v", err)
	}
	db, err := DomainDigest(DomainFirewall, b)
	if err != nil {
		t.Fatalf("DomainDigest: %v", err)
	}
	if da != db {
		t.Fatalf("digest depends on enumeration order: %s vs %s", da, db)
	}
	c := &Domains{Firewall: []cmn.FwRuleMod{
		{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32", DstIP: "2.2.2.2/32"}},
		{Rule: cmn.FwRuleArg{SrcIP: "3.3.3.3/32", DstIP: "9.9.9.9/32"}},
	}}
	dc, err := DomainDigest(DomainFirewall, c)
	if err != nil {
		t.Fatalf("DomainDigest: %v", err)
	}
	if dc == da {
		t.Fatalf("digest failed to distinguish different content")
	}
}

// --- securityrate capture hygiene ---

// TestSecurityRateCaptureCopiesAndStripsStats: capture must deep-copy (a
// later live mutation cannot rewrite the captured document) and must not
// persist runtime counters.
func TestSecurityRateCaptureCopiesAndStripsStats(t *testing.T) {
	hooks := newMockHooks()
	hooks.secRate = &cmn.SecurityRateState{
		Config: cmn.SecurityRateConfig{SYNEnabled: true, SYNThreshold: 100},
		Stats:  cmn.SecurityRateStats{},
	}
	hooks.secRate.Stats.SYNBlocked = 42

	doc := &Document{}
	if err := getSecurityRate(hooks, doc); err != nil {
		t.Fatalf("getSecurityRate: %v", err)
	}
	if doc.Domains.SecurityRate == nil {
		t.Fatalf("expected securityrate captured")
	}
	if doc.Domains.SecurityRate == hooks.secRate {
		t.Fatalf("capture aliased the live state pointer")
	}
	if doc.Domains.SecurityRate.Stats.SYNBlocked != 0 {
		t.Fatalf("runtime counters persisted into the document: %+v", doc.Domains.SecurityRate.Stats)
	}
	if !doc.Domains.SecurityRate.Config.SYNEnabled || doc.Domains.SecurityRate.Config.SYNThreshold != 100 {
		t.Fatalf("config lost in capture: %+v", doc.Domains.SecurityRate.Config)
	}

	// Mutating live state after capture must not change the document.
	hooks.secRate.Config.SYNThreshold = 999
	if doc.Domains.SecurityRate.Config.SYNThreshold != 100 {
		t.Fatalf("captured document changed when live state changed (aliasing)")
	}
}

// --- registry hygiene ---

// TestApplyOrderReturnsCopy: mutating ApplyOrder's result must not corrupt
// the package-global registry order.
func TestApplyOrderReturnsCopy(t *testing.T) {
	got := ApplyOrder()
	got[0], got[1] = got[1], got[0]
	if Registry[0].Name != DomainEndpoint {
		t.Fatalf("ApplyOrder leaked the registry backing array; Registry[0] is now %q", Registry[0].Name)
	}
}

// --- boot restore vs subsystem startup ordering ---

// TestBootPlanNeverReadsLiveState: the Boot variant's PLAN stage must not
// call any Get hook -- the datapath is empty at boot by the same premise
// that skips PRESERVE and the wipe, and a boot-time Get can race an
// optional subsystem (gobgpd) that is not listening yet. Discovered live:
// a BGP-enabled gateway quarantined its snapshot on EVERY boot because
// PLAN's bgp Get hit the still-starting gobgpd.
func TestBootPlanNeverReadsLiveState(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainLoadBalancer}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}},
	}}
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Boot: true})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("boot restore failed: %+v", res)
	}
	for _, call := range hooks.Calls {
		if call == "NetLbRuleGet" {
			t.Fatalf("boot PLAN read live state before apply; calls: %v", hooks.Calls)
		}
		if strings.HasPrefix(call, "NetLbRuleAdd") {
			break // apply started -- later Gets (VERIFY) are expected
		}
	}
	if len(res.Plan) != 1 || res.Plan[0].ToApply != 1 || res.Plan[0].ToDelete != 0 {
		t.Fatalf("boot plan should report to_apply from the doc and to_delete=0, got %+v", res.Plan)
	}
}

// TestSubsystemUnavailableCoversGrpcTransport: gRPC-backed subsystems
// (gobgpd) surface "not up yet" as a transport error; the tolerance
// classifier must treat it as unavailable, not as a hard failure.
func TestSubsystemUnavailableCoversGrpcTransport(t *testing.T) {
	err := fmt.Errorf(`rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:50052: connect: connection refused"`)
	if !isSubsystemUnavailable(err) {
		t.Fatalf("gRPC Unavailable transport error not classified as subsystem-unavailable")
	}
	if isSubsystemUnavailable(fmt.Errorf("some real apply failure")) {
		t.Fatalf("classifier over-matches")
	}
}

// --- capture canonicalization: desired state only, deterministic bytes ---

// TestCaptureStripsRuntimeMeasurements: probe delay measurements and
// current health are runtime data -- persisting them churned the document
// checksum on every idle capture (observed live).
func TestCaptureStripsRuntimeMeasurements(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{
		HostName: "10.0.0.1", Name: "ep1", ProbeType: "ping",
		MinDelay: "1ms", AvgDelay: "2ms", MaxDelay: "3ms", CurrState: "up",
	}}
	doc, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	ep := doc.Domains.Endpoint[0]
	if ep.MinDelay != "" || ep.AvgDelay != "" || ep.MaxDelay != "" || ep.CurrState != "" {
		t.Fatalf("runtime probe measurements persisted into the document: %+v", ep)
	}
	if ep.HostName != "10.0.0.1" || ep.ProbeType != "ping" {
		t.Fatalf("desired state lost in normalization: %+v", ep)
	}
}

// TestCaptureIsEnumerationOrderStable: two captures of an unchanged
// gateway must produce the identical domains payload even when the
// backend enumerates rules in a different order (map iteration) --
// observed live as byte-churning snapshots on an idle gateway.
func TestCaptureIsEnumerationOrderStable(t *testing.T) {
	ruleA := cmn.LbRuleMod{Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps: []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}}}
	ruleB := cmn.LbRuleMod{Serv: cmn.LbServiceArg{ServIP: "2.2.2.2", ServPort: 81, Proto: "tcp"},
		Eps: []cmn.LbEndPointArg{{EpIP: "10.0.0.2", EpPort: 8081}}}

	hooks := newMockHooks()
	hooks.lbRules = []cmn.LbRuleMod{ruleA, ruleB}
	doc1, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	hooks.lbRules = []cmn.LbRuleMod{ruleB, ruleA} // backend re-ordered
	doc2, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	j1, _ := json.Marshal(doc1.Domains)
	j2, _ := json.Marshal(doc2.Domains)
	if string(j1) != string(j2) {
		t.Fatalf("captured payload depends on backend enumeration order:\n%s\nvs\n%s", j1, j2)
	}
}

// TestBootApplyFailureDoesNotRollBack: a failed boot apply leaves the
// partially applied state for the next retry to converge over -- rolling
// back between attempts made replayed config flap in and out for the
// whole retry window and let the rollback's own wipe fail against a
// still-starting subsystem, escalating a startup race to ROLLBACK-FAILED
// plus a quarantined snapshot (observed live on a BGP-enabled gateway).
func TestBootApplyFailureDoesNotRollBack(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainEndpoint, DomainLoadBalancer}
	doc.Domains.Endpoint = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1"}}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}},
	}}
	raw := encodeDoc(t, doc)

	hooks.failNext("NetLbRuleAdd", fmt.Errorf("rpc error: code = Unknown desc = bgp server hasn't started yet"))

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Boot: true})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result == ResultRolledBack || res.Result == ResultRollbackFailed {
		t.Fatalf("boot apply failure must not roll back, got %q", res.Result)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("apply failure must be reported")
	}
	if call := containsCallSubstring(hooks.Calls, "Del"); call != "" {
		t.Fatalf("boot failure path must not wipe partial state, saw %q", call)
	}
	if len(hooks.endpoints) != 1 {
		t.Fatalf("partially applied state must survive for the retry, endpoints=%+v", hooks.endpoints)
	}

	// The retry converges: the real backend answers the endpoint
	// re-apply with its idempotent "already exists" convention (the mock
	// must be told to), the boot apply tolerates it, and the previously
	// failed rule applies cleanly now.
	hooks.failNext("NetEpHostAdd", fmt.Errorf("already exists"))
	res2, err := e.Restore(raw, RestoreOptions{Boot: true})
	if err != nil {
		t.Fatalf("retry Restore: %v", err)
	}
	if res2.Result != ResultOK {
		t.Fatalf("boot retry over partial state failed: %+v", res2)
	}
	if len(hooks.lbRules) != 1 || len(hooks.endpoints) != 1 {
		t.Fatalf("retry did not converge: rules=%d endpoints=%d", len(hooks.lbRules), len(hooks.endpoints))
	}
}

// --- BGP transport fidelity end-to-end through the registry ---

// TestBGPNeighborTransportRoundTrip: a neighbor with non-default
// RemotePort and MultiHop survives get -> apply -> get field-identical.
func TestBGPNeighborTransportRoundTrip(t *testing.T) {
	hooks := newMockHooks()
	doc := &Document{}
	doc.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{{Addr: "10.0.0.7", RemoteAS: 65020, RemotePort: 1790, MultiHop: true}}

	if _, _, err := applyBGP(hooks, doc, false); err != nil {
		t.Fatalf("applyBGP: %v", err)
	}
	after := &Document{}
	if err := getBGP(hooks, after); err != nil {
		t.Fatalf("getBGP: %v", err)
	}
	if len(after.Domains.BGP.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %+v", after.Domains.BGP.Neighbors)
	}
	n := after.Domains.BGP.Neighbors[0]
	if n.RemotePort != 1790 || !n.MultiHop {
		t.Fatalf("transport config lost in round-trip: %+v", n)
	}
}
