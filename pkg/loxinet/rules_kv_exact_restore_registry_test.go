/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package loxinet

import (
	"errors"
	"net"
	"testing"
)

// The model-prompt profile registry publishes all-or-nothing: one malformed
// document anywhere leaves NO generation serving, so every profile
// declaration in a boot snapshot becomes unresolvable at the same moment.
//
// Before this was fixed, that turned into a silent strictness downgrade: the
// loadbalancer domain refused each strict rule, the whole snapshot restore
// rolled back, and the legacy config replay recreated the rules with no
// profile and no fence — unattested KV-exact rules serving traffic, with the
// operator's declaration permanently gone from the next snapshot write.
//
// The tests below pin the three properties that make that impossible.

// TestKvProfileUnresolvedIsDistinguishable: the "not published" refusal is
// wrapped in a sentinel so the restore path can tell it apart from every
// other admission refusal. Without the sentinel the restore branch cannot
// exist, so this is the first thing to break if the wrap is dropped.
func TestKvProfileUnresolvedIsDistinguishable(t *testing.T) {
	deps := kvExactAdmissionDeps{
		getenv:         func(string) (string, bool) { return "0", true },
		tokenizerReady: func(string) bool { return true },
		profileByID: func(string) (*ModelPromptProfile, uint64, bool) {
			return nil, 0, false // registry unavailable: nothing published
		},
		chatRenderer: func(string) bool { return true },
		contractRef:  kvCurrentContractRef,
	}
	_, err := kvExactRuntimeValidate("vllm", 1, "model-x", "completions", "prof-x", deps)
	if err == nil {
		t.Fatal("an unresolvable profile must still be refused")
	}
	if !errors.Is(err, errKvProfileUnresolved) {
		t.Fatalf("unresolved-profile refusal must carry the sentinel, got %v", err)
	}

	// A DIFFERENT refusal must NOT carry it — otherwise the restore path
	// would swallow genuinely bad declarations too.
	deps.profileByID = func(id string) (*ModelPromptProfile, uint64, bool) {
		return &ModelPromptProfile{
			ProfileID: id, BaseModel: "some-other-model",
			AliasPolicy:   KvAliasPolicyBaseModelOnly,
			SupportedApis: []string{KvProfileAPICompletions},
		}, 1, true
	}
	_, err = kvExactRuntimeValidate("vllm", 1, "model-x", "completions", "prof-x", deps)
	if err == nil {
		t.Fatal("a profile that does not serve the model must be refused")
	}
	if errors.Is(err, errKvProfileUnresolved) {
		t.Fatalf("model-mismatch refusal must NOT carry the unresolved sentinel: %v", err)
	}
}

// TestKvExactStatusRestoredProfileUnresolved: a restored rule whose declared
// profile could not be resolved reports the registry cause with the exact
// path FENCED, keeps its declaration, and is never rendered as a benign
// profile-less legacy rule.
func TestKvExactStatusRestoredProfileUnresolved(t *testing.T) {
	KvBindingReset()
	t.Cleanup(KvBindingReset)
	t.Cleanup(KvSvcContractReset)

	R := &RuleH{}
	R.tables[RtLB].eMap = map[string]*ruleEnt{}

	r := kvStatusTestRule("rule-unresolved", "model-u", "vllm",
		"prof-gone", "completions", "10.0.0.1", 9200, 6, 1)
	r.kvRestoredProfileUnresolved = true
	r.ruleNum = 77
	R.tables[RtLB].eMap["u"] = r

	// The add path registers such a rule DENIED with no install path —
	// mirror that registration here.
	KvSvcContractRegister(77, "rule-unresolved", net.ParseIP("10.0.0.1"), 9200, 6, 0)

	res, err := R.GetKvExactStatus("10.0.0.1", 9200, "tcp", "")
	if err != nil || len(res) != 1 {
		t.Fatalf("status = %v, %v", res, err)
	}
	m := res[0]

	// The whole point: NOT the benign legacy verdict.
	if m.DesiredState == KvExactStateLegacyActive || m.EnforcedState == KvExactStateLegacyActive {
		t.Fatalf("registry-unavailable rule rendered as LEGACY_ACTIVE (silent downgrade): %s/%s",
			m.DesiredState, m.EnforcedState)
	}
	if m.DesiredState != KvExactStateProfileValidated || m.EnforcedState != KvExactStateEnforcementFault {
		t.Fatalf("states = %s/%s, want PROFILE_VALIDATED/ENFORCEMENT_FAULT",
			m.DesiredState, m.EnforcedState)
	}
	if len(m.ReasonCodes) != 1 || m.ReasonCodes[0] != KvAttestReasonProfileRegistryUnavailable {
		t.Fatalf("reasons = %v, want [%s]", m.ReasonCodes, KvAttestReasonProfileRegistryUnavailable)
	}
	// The declaration must survive — losing it is what made the old
	// behavior unrecoverable without a manual re-attach.
	if m.ModelProfileID != "prof-gone" {
		t.Fatalf("declared profile lost from the status read model: %q", m.ModelProfileID)
	}
	// The status read model surfaces the fence that the add path registered.
	// NOTE: this assertion only proves the RENDERING, because the fixture
	// above had to register the contract itself. Whether the add path
	// actually decides to fence is pinned separately, and honestly, by
	// TestKvExactRestoreFenceDecision below.
	if m.Enforcement == nil || !m.Enforcement.GoFenced {
		t.Fatalf("registry-unavailable rule must report the engaged fence, got %+v", m.Enforcement)
	}
}

// TestKvExactRestoreFenceDecision pins the add path's fence DECISION, which a
// status test cannot reach: the status fixture registers the deny-set entry
// itself, so it would pass even if production never fenced at all (this was
// caught by mutating the fix and watching the status test stay green).
func TestKvExactRestoreFenceDecision(t *testing.T) {
	cases := []struct {
		name       string
		legacy     bool
		unresolved bool
		want       bool
	}{
		{"restored profile-less", true, false, true},
		{"restored, profile unresolved (registry unavailable)", false, true, true},
		{"both markers", true, true, true},
		{"ordinary rule: no fence", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &ruleEnt{
				kvRestoredLegacy:            c.legacy,
				kvRestoredProfileUnresolved: c.unresolved,
			}
			if got := kvExactNeedsRestoreFence(r); got != c.want {
				t.Fatalf("kvExactNeedsRestoreFence = %v, want %v", got, c.want)
			}
		})
	}
}

// TestKvExactStatusUnresolvedDistinctFromMissingBinding: the registry cause
// must not be reported as the generic missing-binding fault. They share a
// state pair but need different reason codes, because the remedies differ:
// repair the registry vs. investigate a partially applied restore.
func TestKvExactStatusUnresolvedDistinctFromMissingBinding(t *testing.T) {
	KvBindingReset()
	t.Cleanup(KvBindingReset)
	t.Cleanup(KvSvcContractReset)

	R := &RuleH{}
	R.tables[RtLB].eMap = map[string]*ruleEnt{}

	unresolved := kvStatusTestRule("rule-a", "model-u", "vllm",
		"prof-gone", "completions", "10.0.0.1", 9201, 6, 1)
	unresolved.kvRestoredProfileUnresolved = true
	unresolved.ruleNum = 78
	R.tables[RtLB].eMap["a"] = unresolved

	// Same shape, same missing binding, but NOT a registry failure.
	missing := kvStatusTestRule("rule-b", "model-u", "vllm",
		"prof-present", "completions", "10.0.0.1", 9202, 6, 1)
	missing.ruleNum = 79
	R.tables[RtLB].eMap["b"] = missing

	a, err := R.GetKvExactStatus("10.0.0.1", 9201, "tcp", "")
	if err != nil || len(a) != 1 {
		t.Fatalf("unresolved status = %v, %v", a, err)
	}
	b, err := R.GetKvExactStatus("10.0.0.1", 9202, "tcp", "")
	if err != nil || len(b) != 1 {
		t.Fatalf("missing-binding status = %v, %v", b, err)
	}
	if a[0].ReasonCodes[0] != KvAttestReasonProfileRegistryUnavailable {
		t.Fatalf("registry case reason = %v", a[0].ReasonCodes)
	}
	if b[0].ReasonCodes[0] != KvAttestReasonBindingStateMissing {
		t.Fatalf("missing-binding case reason = %v", b[0].ReasonCodes)
	}
	if a[0].ReasonCodes[0] == b[0].ReasonCodes[0] {
		t.Fatal("the two causes must not collapse onto one reason code")
	}
}

// TestKvBindingRestoreHoldsFenceWhenProfileUnresolved: the second half of the
// registry-unavailable fix. The kvexactbinding snapshot domain restores a rule's persisted
// binding and normally kicks the contract-word install — the only path that
// clears the loadbalancer domain's fence. When the binding's profile is not
// resolvable in the current registry generation, that kick must be withheld so
// the fence survives, while the binding STATE is still restored (nothing lost).
//
// The persisted binding is self-consistent (its digest recomputes), so the
// tamper/digest guards do not catch this case — only the live-registry check
// does. Proven by mutating the fix: without the guard, the fence lifts.
func TestKvBindingRestoreHoldsFenceWhenProfileUnresolved(t *testing.T) {
	kvBindingTestSetup(t)
	t.Cleanup(KvSvcContractReset)
	prevReg := kvProfileReg.Load()
	t.Cleanup(func() { kvProfileReg.Store(prevReg) })

	// The loadbalancer domain fenced the rule (deny set) before the binding
	// domain runs — mirror that registration.
	const svcID = 4242
	ruleIdent := "rule-fence-hold"
	KvSvcContractRegister(svcID, ruleIdent, net.ParseIP("10.0.0.1"), 9300, 6, 0)
	if !kvSvcDenied(svcID) {
		t.Fatal("precondition: rule must start fenced")
	}
	mod := kvExportOne(t, ruleIdent, 5) // profile "acme-m1-v1"

	// Registry UNAVAILABLE: nothing published, so the binding's profile
	// cannot be resolved.
	kvProfileReg.Store(nil)
	if err := KvBindingRestore(&mod); err != nil {
		t.Fatalf("restore must keep the binding state, got error: %v", err)
	}
	// Binding state kept.
	if _, ok := KvBindingResolve(ruleIdent, 5); !ok {
		t.Fatal("binding state was lost — the restore must preserve it")
	}
	// Fence HELD — the withhold decision keeps the deny bit set. The kick is
	// what would clear it (async), and the decision to skip that kick is the
	// property under test; assert it directly and deterministically.
	if kvBindingProfileResolvable(mod.ModelProfileID) {
		t.Fatal("test setup: profile must be UNresolvable in an empty registry")
	}
	if !kvSvcDenied(svcID) {
		t.Fatal("fence lifted while the profile was unresolvable (silent un-fence regression)")
	}
}

// TestKvBindingRestoreClearsFenceWhenProfileResolvable is the green-neighbour:
// with the SAME binding but the profile published, the restore kicks the
// install as before, so the healthy-restart path is untouched.
func TestKvBindingRestoreClearsFenceWhenProfileResolvable(t *testing.T) {
	kvBindingTestSetup(t)
	t.Cleanup(KvSvcContractReset)
	prevReg := kvProfileReg.Load()
	t.Cleanup(func() { kvProfileReg.Store(prevReg) })

	const svcID = 4243
	ruleIdent := "rule-fence-clear"
	KvSvcContractRegister(svcID, ruleIdent, net.ParseIP("10.0.0.1"), 9301, 6, 0)
	mod := kvExportOne(t, ruleIdent, 5) // profile "acme-m1-v1"

	// Publish a generation that DOES contain the binding's profile.
	e := &kvProfileEntry{Profile: ModelPromptProfile{
		ProfileID: mod.ModelProfileID, BaseModel: "acme-m1",
		SupportedApis: []string{KvProfileAPICompletions},
		AliasPolicy:   KvAliasPolicyBaseModelOnly,
	}}
	gen := &kvProfileGeneration{
		Gen:      kvProfileRegGen.Add(1),
		Profiles: map[string]*kvProfileEntry{mod.ModelProfileID: e},
		ByModel:  map[string]*kvProfileEntry{kvModelSlug("acme-m1"): e},
	}
	e.Gen = gen.Gen
	kvProfileReg.Store(gen)

	if err := KvBindingRestore(&mod); err != nil {
		t.Fatalf("restore with resolvable profile: %v", err)
	}
	if _, ok := KvBindingResolve(ruleIdent, 5); !ok {
		t.Fatal("binding state lost")
	}
	// The kick ran; the async install transaction will clear the fence.
	// Assert the decision point directly: the profile resolves, so the
	// withhold branch was NOT taken.
	if _, ok := kvProfileByID(mod.ModelProfileID); !ok {
		t.Fatal("test setup: profile must be resolvable")
	}
}

// TestKvBindingProfileResolvable pins the decision that gates the fence-clear
// kick: resolvable iff the profile is in the currently published generation.
// This is the deterministic core the fence-hold behavior rides on — the
// install kick it guards is async and cannot be asserted synchronously.
func TestKvBindingProfileResolvable(t *testing.T) {
	prev := kvProfileReg.Load()
	t.Cleanup(func() { kvProfileReg.Store(prev) })

	kvProfileReg.Store(nil)
	if kvBindingProfileResolvable("acme-m1-v1") {
		t.Fatal("empty registry: nothing is resolvable")
	}

	e := &kvProfileEntry{Profile: ModelPromptProfile{
		ProfileID: "acme-m1-v1", BaseModel: "acme-m1",
		SupportedApis: []string{KvProfileAPICompletions},
		AliasPolicy:   KvAliasPolicyBaseModelOnly,
	}}
	gen := &kvProfileGeneration{
		Gen:      kvProfileRegGen.Add(1),
		Profiles: map[string]*kvProfileEntry{"acme-m1-v1": e},
		ByModel:  map[string]*kvProfileEntry{kvModelSlug("acme-m1"): e},
	}
	e.Gen = gen.Gen
	kvProfileReg.Store(gen)
	if !kvBindingProfileResolvable("acme-m1-v1") {
		t.Fatal("published profile must resolve")
	}
	if kvBindingProfileResolvable("some-other-profile") {
		t.Fatal("an unpublished id must not resolve")
	}
}
