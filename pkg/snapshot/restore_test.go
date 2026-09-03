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
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// restoreDoc builds a Document carrying one item in endpoint, loadbalancer
// (referencing the endpoint), firewall
// and policy -- enough domains to exercise ordering/rollback without
// touching the known-gap domains (ipsec certificates, bgp global_config --
// see doc.go/registry.go comments) in happy-path fixtures, per the task's
// guidance to avoid those in happy paths.
func restoreDoc(gatewayVersion string) *Document {
	doc := NewDocument(gatewayVersion, "test-host", TriggerManual)
	doc.Domains.Endpoint = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1"}}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}},
	}}
	doc.Domains.Firewall = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "2.2.2.2/32", DstIP: "3.3.3.3/32"}}}
	doc.Domains.Policy = []cmn.PolMod{{Ident: "pol1"}}
	return doc
}

func encodeDoc(t *testing.T, doc *Document) []byte {
	t.Helper()
	b, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func newTestEngine(hooks Hooks, dir string) *Engine {
	return &Engine{
		Hooks:          hooks,
		GatewayVersion: "0.9.8.6-beta",
		Hostname:       "test-host",
		PreRestoreDir:  dir,
	}
}

func containsCallSubstring(calls []string, substrs ...string) string {
	for _, c := range calls {
		for _, s := range substrs {
			if strings.Contains(c, s) {
				return c
			}
		}
	}
	return ""
}

// mutatingCall reports whether call is a mutating hook invocation (Add/Del,
// or one of the two singleton Set hooks) as opposed to a read-only Get --
// a plain substring match on "Set" would false-positive on e.g.
// "NetGoBGPPolicyDefinedSetGet" (the domain name "DefinedSet" contains
// "Set"), so this checks the method name itself, not an arbitrary
// substring of it.
func mutatingCall(call string) bool {
	method := call
	if idx := strings.Index(call, ":"); idx >= 0 {
		method = call[:idx]
	}
	if strings.HasSuffix(method, "Add") || strings.HasSuffix(method, "Del") {
		return true
	}
	return method == "NetSecurityRateSet" || method == "NetIPsecConfigSet" || method == "NetGoBGPGCAdd"
}

func firstMutatingCall(calls []string) string {
	for _, c := range calls {
		if mutatingCall(c) {
			return c
		}
	}
	return ""
}

// --- stage gating ---

func TestRestoreValidateFailureNeverReachesPlanOrApply(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	doc.SchemaVersion = "2.0" // different major -- CheckSchemaVersion must refuse
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Compatible {
		t.Fatalf("expected Compatible=false for a different major schema_version")
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected a schema-version error")
	}
	if res.Plan != nil {
		t.Fatalf("PLAN must not run after a VALIDATE failure, got: %+v", res.Plan)
	}
	if len(hooks.Calls) != 0 {
		t.Fatalf("VALIDATE failure must reach zero hook calls (no Get/Add/Del), got: %v", hooks.Calls)
	}
	if res.Result != "" {
		t.Fatalf("expected no Result on a VALIDATE failure, got %q", res.Result)
	}
}

// Regression for the G-8/G-9 E2E boot failure (2026-07-20): a captured
// document normally carries LB rules whose endpoints are ALL rule-managed
// (auto-created by NetLbRuleAdd, filtered out of the endpoint domain by the
// RuleManaged capture rule) -- the endpoint domain being empty is the
// expected shape, NOT a dangling reference, and must validate.
func TestValidateAcceptsLbWithOnlyRuleManagedEndpoints(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("0.9.8.6-beta", "h", TriggerManual)
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{{
		Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80},
		Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.99", EpPort: 8080}}, // no endpoint entry: rule-managed
	}}
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("expected no validation errors for a rule-managed-only LB doc, got: %v", res.Errors)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ResultOK, got %+v", res)
	}
}

func TestRestoreChecksumTamperFailsAtParse(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)
	tampered := bytes.Replace(raw, []byte(`"pol1"`), []byte(`"pol2"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatalf("test fixture bug: tamper did not change any bytes")
	}

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(tampered, RestoreOptions{Mode: ModeDryRun})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected a checksum verification error")
	}
	if len(hooks.Calls) != 0 {
		t.Fatalf("PARSE failure must reach zero hook calls, got: %v", hooks.Calls)
	}
}

// --- dry-run ---

func TestRestoreDryRunNeverMutates(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "9.9.9.9", Name: "existing-ep"}}
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Mode != string(ModeDryRun) {
		t.Fatalf("expected mode dry-run, got %q", res.Mode)
	}
	if !res.Compatible {
		t.Fatalf("expected compatible=true")
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ResultOK for a clean dry-run, got %+v", res)
	}
	if len(res.Plan) != len(Registry) {
		t.Fatalf("expected a plan row per domain, got %d", len(res.Plan))
	}
	if res.PreRestoreSnapshotPersisted != "" {
		t.Fatalf("dry-run must never persist a pre-restore snapshot, got %q", res.PreRestoreSnapshotPersisted)
	}
	if call := firstMutatingCall(hooks.Calls); call != "" {
		t.Fatalf("dry-run must not mutate anything, but saw call: %s (all calls: %v)", call, hooks.Calls)
	}

	// Sanity: the plan reflects reality (existing-ep live, ep1 to be applied).
	for _, p := range res.Plan {
		if p.Domain == DomainEndpoint {
			if p.ToDelete != 1 || p.ToApply != 1 {
				t.Fatalf("endpoint plan = %+v, want ToDelete=1 ToApply=1", p)
			}
		}
	}
}

// --- ordering (endpoint before loadbalancer; delete order reversed) ---

func TestStageApplyOrdering(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "9.9.9.9", Name: "old-ep"}}
	hooks.lbRules = []cmn.LbRuleMod{{Serv: cmn.LbServiceArg{ServIP: "8.8.8.8", ServPort: 53}}}
	doc := restoreDoc("0.9.8.6-beta")

	e := &Engine{Hooks: hooks}
	errs, _ := e.stageApply(doc, ApplyOrder(), false)
	if len(errs) != 0 {
		t.Fatalf("stageApply: %v", errs)
	}

	delLbIdx := callIndex(hooks.Calls, "NetLbRuleDel")
	delEpIdx := callIndex(hooks.Calls, "NetEpHostDel")
	if delLbIdx < 0 || delEpIdx < 0 || delLbIdx > delEpIdx {
		t.Fatalf("expected loadbalancer deleted (idx %d) before endpoint (idx %d) during wipe, calls: %v", delLbIdx, delEpIdx, hooks.Calls)
	}

	addEpIdx := callIndex(hooks.Calls, "NetEpHostAdd:ep1")
	addLbIdx := callIndex(hooks.Calls, "NetLbRuleAdd:1.1.1.1")
	if addEpIdx < 0 || addLbIdx < 0 || addEpIdx > addLbIdx {
		t.Fatalf("expected endpoint applied (idx %d) before loadbalancer (idx %d), calls: %v", addEpIdx, addLbIdx, hooks.Calls)
	}

	// The whole delete (wipe) phase must finish before the apply phase
	// starts: every Del call index precedes every Add call index.
	if delEpIdx > addEpIdx {
		t.Fatalf("expected the wipe phase to fully precede the apply phase, calls: %v", hooks.Calls)
	}

	if len(hooks.endpoints) != 1 || hooks.endpoints[0].Name != "ep1" {
		t.Fatalf("expected final endpoints = [ep1], got %+v", hooks.endpoints)
	}
	if len(hooks.lbRules) != 1 || hooks.lbRules[0].Serv.ServIP != "1.1.1.1" {
		t.Fatalf("expected final lb rules = [1.1.1.1], got %+v", hooks.lbRules)
	}
}

// --- commit happy path ---

func TestRestoreCommitHappyPath(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "9.9.9.9", Name: "old-ep"}}
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)
	dir := t.TempDir()

	e := newTestEngine(hooks, dir)
	res, err := e.Restore(raw, RestoreOptions{
		Mode:       ModeCommit,
		Components: []string{DomainEndpoint, DomainLoadBalancer, DomainFirewall, DomainPolicy},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ResultOK, got %+v", res)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", res.Errors)
	}
	if res.PreRestoreSnapshotPersisted == "" {
		t.Fatalf("expected a pre-restore snapshot path")
	}
	if _, statErr := os.Stat(res.PreRestoreSnapshotPersisted); statErr != nil {
		t.Fatalf("pre-restore snapshot file missing on disk: %v", statErr)
	}
	if info, statErr := os.Stat(res.PreRestoreSnapshotPersisted); statErr == nil {
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected pre-restore file mode 0600, got %o", info.Mode().Perm())
		}
	}

	// Verify the persisted pre-restore file captured the OLD state (old-ep),
	// not the new one.
	persisted, rerr := os.ReadFile(res.PreRestoreSnapshotPersisted)
	if rerr != nil {
		t.Fatalf("reading pre-restore file: %v", rerr)
	}
	preDoc, derr := Decode(bytes.NewReader(persisted))
	if derr != nil {
		t.Fatalf("decoding pre-restore file: %v", derr)
	}
	if len(preDoc.Domains.Endpoint) != 1 || preDoc.Domains.Endpoint[0].Name != "old-ep" {
		t.Fatalf("pre-restore file should capture the old endpoint, got: %+v", preDoc.Domains.Endpoint)
	}

	if len(hooks.endpoints) != 1 || hooks.endpoints[0].Name != "ep1" {
		t.Fatalf("expected final live endpoints = [ep1], got %+v", hooks.endpoints)
	}
	if len(hooks.lbRules) != 1 || hooks.lbRules[0].Serv.ServIP != "1.1.1.1" {
		t.Fatalf("expected final live lb rules = [1.1.1.1], got %+v", hooks.lbRules)
	}
	if len(hooks.fwRules) != 1 {
		t.Fatalf("expected final live firewall rules = 1, got %+v", hooks.fwRules)
	}
	if len(hooks.policies) != 1 {
		t.Fatalf("expected final live policies = 1, got %+v", hooks.policies)
	}
}

// --- components filtering end-to-end ---

func TestRestoreComponentsFilteredOnlyTouchesSelectedDomains(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{
		Mode:       ModeCommit,
		Components: []string{DomainEndpoint, DomainLoadBalancer},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ResultOK, got %+v", res)
	}
	if len(res.Plan) != 2 {
		t.Fatalf("expected exactly 2 plan rows (endpoint, loadbalancer), got %d: %+v", len(res.Plan), res.Plan)
	}
	if call := containsCallSubstring(hooks.Calls, "Firewall", "Policer"); call != "" {
		t.Fatalf("components filter must exclude firewall/policy, but saw call: %s", call)
	}
	if len(hooks.fwRules) != 0 || len(hooks.policies) != 0 {
		t.Fatalf("firewall/policy from the document must remain unapplied, fw=%+v pol=%+v", hooks.fwRules, hooks.policies)
	}
	if len(hooks.endpoints) != 1 || len(hooks.lbRules) != 1 {
		t.Fatalf("expected endpoint/loadbalancer applied, got endpoints=%+v lb=%+v", hooks.endpoints, hooks.lbRules)
	}
}

// --- rollback on mid-apply failure ---

func TestRestoreRollbackOnMidApplyFailure(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "9.9.9.9", Name: "old-ep"}}
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)
	hooks.failNext("NetLbRuleAdd", errors.New("simulated forward-apply failure"))

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{
		Mode:       ModeCommit,
		Components: []string{DomainEndpoint, DomainLoadBalancer, DomainFirewall, DomainPolicy},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back, got %+v", res)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected the forward-apply error to be recorded")
	}

	// firewall/policy come after loadbalancer in apply order: since
	// loadbalancer failed, they must never have been reached at all.
	if call := containsCallSubstring(hooks.Calls, "NetFwRuleAdd", "NetPolicerAdd"); call != "" {
		t.Fatalf("apply must abort remaining domains after a mid-apply failure, but saw: %s", call)
	}

	// Rollback must restore exactly the pre-restore state: old-ep present,
	// nothing else (nothing else existed live before the restore).
	if len(hooks.endpoints) != 1 || hooks.endpoints[0].Name != "old-ep" {
		t.Fatalf("expected rollback to restore old-ep, got: %+v", hooks.endpoints)
	}
	if len(hooks.lbRules) != 0 {
		t.Fatalf("expected rollback to leave no lb rules (none existed pre-restore), got: %+v", hooks.lbRules)
	}
	if len(hooks.fwRules) != 0 || len(hooks.policies) != 0 {
		t.Fatalf("expected rollback to leave no firewall/policy (none existed pre-restore), got fw=%+v pol=%+v", hooks.fwRules, hooks.policies)
	}
}

// --- ROLLBACK-FAILED double fault ---

func TestRestoreRollbackFailedDoubleFault(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "9.9.9.9", Name: "old-ep"}}
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)

	// 1st NetLbRuleAdd (forward apply of the new rule) fails -> triggers
	// rollback. 2nd NetEpHostAdd (rollback re-applying "old-ep") also
	// fails -> double fault.
	hooks.failNext("NetLbRuleAdd", errors.New("simulated forward-apply failure"))
	hooks.failOnNthCall("NetEpHostAdd", 2, errors.New("simulated rollback re-apply failure"))

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{
		Mode:       ModeCommit,
		Components: []string{DomainEndpoint, DomainLoadBalancer},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRollbackFailed {
		t.Fatalf("expected ROLLBACK-FAILED, got %+v", res)
	}
	if res.PreRestoreSnapshotPersisted == "" {
		t.Fatalf("expected the pre-restore path to be reported for manual recovery even on double fault")
	}
	if _, statErr := os.Stat(res.PreRestoreSnapshotPersisted); statErr != nil {
		t.Fatalf("pre-restore file must still exist on disk for manual recovery: %v", statErr)
	}
	if len(res.Errors) < 2 {
		t.Fatalf("expected both the forward-apply and rollback errors recorded, got: %v", res.Errors)
	}
}

// --- VERIFY mismatch triggers rollback ---

func TestRestoreVerifyMismatchTriggersRollback(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)

	// NetLbRuleGet is called 4 times in a non-boot commit restore that
	// selects loadbalancer: PLAN, PRESERVE, the pre-apply wipe's
	// enumeration, and VERIFY (in that order). Override the 4th (VERIFY's)
	// call to report 0 items even though the apply actually added 1,
	// simulating the backend silently not persisting what it acknowledged.
	hooks.overrideGetLenAtCall("NetLbRuleGet", 4, 0)

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{
		Mode:       ModeCommit,
		Components: []string{DomainEndpoint, DomainLoadBalancer},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected a VERIFY mismatch to trigger rollback, got %+v", res)
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "verify") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a verify-mismatch error recorded, got: %v", res.Errors)
	}
}

// --- rollback idempotency: "already exists" tolerated only during rollback ---

func TestRollbackTreatsAlreadyExistsAsWarningNotFailure(t *testing.T) {
	hooks := newMockHooks()
	e := &Engine{Hooks: hooks}
	preDoc := &Document{Domains: Domains{Endpoint: []cmn.EndPointMod{{HostName: "1.1.1.1", Name: "ep1"}}}}
	selected, serr := Select([]string{DomainEndpoint})
	if serr != nil {
		t.Fatalf("Select: %v", serr)
	}

	hooks.failNext("NetEpHostAdd", errors.New("endpoint ep1 already exists"))
	errs := e.rollback(preDoc, selected)
	if len(errs) != 0 {
		t.Fatalf("expected an 'already exists' rollback re-apply error to be tolerated as a warning, got: %v", errs)
	}
}

func TestRollbackCollectsNonIdempotentErrors(t *testing.T) {
	hooks := newMockHooks()
	e := &Engine{Hooks: hooks}
	preDoc := &Document{Domains: Domains{Endpoint: []cmn.EndPointMod{{HostName: "1.1.1.1", Name: "ep1"}}}}
	selected, serr := Select([]string{DomainEndpoint})
	if serr != nil {
		t.Fatalf("Select: %v", serr)
	}

	hooks.failNext("NetEpHostAdd", errors.New("some unrelated backend failure"))
	errs := e.rollback(preDoc, selected)
	if len(errs) == 0 {
		t.Fatalf("expected a non-idempotent rollback re-apply error to be collected, not silently dropped")
	}
}

func TestIsIdempotentExists(t *testing.T) {
	if !isIdempotentExists(errors.New("Tunnel tun1 ALREADY EXISTS")) {
		t.Fatalf("expected case-insensitive match on the generic convention")
	}
	if isIdempotentExists(nil) {
		t.Fatalf("nil error must not match")
	}
	if isIdempotentExists(errors.New("some other failure")) {
		t.Fatalf("unrelated error must not match")
	}
	// The per-domain identical-item sentinels (wrapped, as the apply loop
	// sees them).
	for _, msg := range []string{
		"apply loadbalancer \"10.0.0.12\": lbrule-exists error",
		"fwrule-exists error",
		"mirr-exists error",
		"pol-exists error",
		"sess-exists error",
		"ulcl-exists error",
	} {
		if !isIdempotentExists(errors.New(msg)) {
			t.Fatalf("expected idempotent-exists match for %q", msg)
		}
	}
	// Same key but DIFFERENT config -- real conflicts, never tolerated.
	for _, msg := range []string{
		"lbrule-exist error: cant modify rule security mode",
		"lbrule-exist error: cant modify rule egress mode",
		"lbrule-exist error: cant modify fullproxy rule mode",
		"lbrule not-exists error",
	} {
		if isIdempotentExists(errors.New(msg)) {
			t.Fatalf("conflict/absence error %q must not be treated as idempotent", msg)
		}
	}
}

// --- boot variant ---

func TestRestoreBootSkipsPreserveAndWipe(t *testing.T) {
	hooks := newMockHooks() // empty -- datapath is empty at boot
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)

	e := &Engine{Hooks: hooks, GatewayVersion: "0.9.8.6-beta", Hostname: "test-host"} // no PreRestoreDir needed
	res, err := e.Restore(raw, RestoreOptions{
		Boot:       true,
		Components: []string{DomainEndpoint, DomainLoadBalancer},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Mode != "boot" {
		t.Fatalf("expected mode boot, got %q", res.Mode)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ResultOK, got %+v", res)
	}
	if res.PreRestoreSnapshotPersisted != "" {
		t.Fatalf("boot must never persist a pre-restore snapshot, got %q", res.PreRestoreSnapshotPersisted)
	}
	if call := containsCallSubstring(hooks.Calls, "Del"); call != "" {
		t.Fatalf("boot must skip the pre-apply wipe entirely (no Del calls), got: %s", call)
	}
	// Only VERIFY Gets at boot: PLAN never reads live state (empty by the
	// boot premise, and a boot-time Get can race a still-starting optional
	// subsystem), and PRESERVE plus the wipe's enumeration are skipped --
	// exactly 1 call, not 2 or 4.
	if got := hooks.callCounts["NetEpHostGet"]; got != 1 {
		t.Fatalf("expected exactly 1 NetEpHostGet call (VERIFY only) for boot, got %d", got)
	}
	if got := hooks.callCounts["NetLbRuleGet"]; got != 1 {
		t.Fatalf("expected exactly 1 NetLbRuleGet call (VERIFY only) for boot, got %d", got)
	}

	if len(hooks.endpoints) != 1 || hooks.endpoints[0].Name != "ep1" {
		t.Fatalf("expected the document applied, got endpoints=%+v", hooks.endpoints)
	}
	if len(hooks.lbRules) != 1 {
		t.Fatalf("expected the document applied, got lbRules=%+v", hooks.lbRules)
	}
}

func TestRestoreBootRollsBackOnApplyFailureWithNoPreRestoreState(t *testing.T) {
	hooks := newMockHooks() // empty at boot
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)
	hooks.failNext("NetLbRuleAdd", errors.New("simulated boot apply failure"))

	e := &Engine{Hooks: hooks, GatewayVersion: "0.9.8.6-beta", Hostname: "test-host"}
	res, err := e.Restore(raw, RestoreOptions{
		Boot:       true,
		Components: []string{DomainEndpoint, DomainLoadBalancer},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back, got %+v", res)
	}
	// Rollback for boot means: wipe whatever partially applied (ep1) and
	// re-apply the implicit empty pre-restore document -- ending up empty
	// again, matching the true pre-boot state.
	if len(hooks.endpoints) != 0 {
		t.Fatalf("expected boot rollback to leave no endpoints (nothing existed pre-boot), got: %+v", hooks.endpoints)
	}
	if len(hooks.lbRules) != 0 {
		t.Fatalf("expected boot rollback to leave no lb rules, got: %+v", hooks.lbRules)
	}
}
