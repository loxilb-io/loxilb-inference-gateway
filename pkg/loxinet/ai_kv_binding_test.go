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
	"context"
	"errors"
	"math"
	"net"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func kvBindingTestSetup(t *testing.T) {
	t.Helper()
	KvBindingReset()
	t.Cleanup(KvBindingReset)
}

func kvTestComponents(policyGen uint32) KvExactBindingComponents {
	return KvExactBindingComponents{
		Profile:               KvModelProfileRef{ID: "acme-m1-v1", Gen: 3},
		Contract:              KvEngineContractRef{ID: "vllm-zmq-v1", Gen: 7},
		AttestationPolicyGen:  policyGen,
		RequiredEvidenceLevel: "validated",
		ConsensusPolicy:       "all_endpoints",
	}
}

func TestKvBindingAllocateMonotonic(t *testing.T) {
	kvBindingTestSetup(t)
	b1, err := KvBindingAllocate("rule-a", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if b1.BindingGen != 1 {
		t.Fatalf("first generation = %d, want 1", b1.BindingGen)
	}
	b2, err := KvBindingAllocate("rule-a", kvTestComponents(2))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if b2.BindingGen != 2 {
		t.Fatalf("second generation = %d, want 2", b2.BindingGen)
	}
	if b1.Digest == b2.Digest {
		t.Fatal("different components produced equal digests")
	}
	cur, ok := KvBindingCurrent("rule-a")
	if !ok || cur.BindingGen != 2 {
		t.Fatal("current binding is not the latest allocation")
	}
	// Both snapshots stay resolvable until retirement: a late in-flight
	// request carrying generation 1 must still resolve its exact components.
	old, ok := KvBindingResolve("rule-a", 1)
	if !ok || old.Components.AttestationPolicyGen != 1 {
		t.Fatal("superseded snapshot no longer resolves")
	}
}

// TestKvBindingRuleIsolation: allocation on one rule never moves another
// rule's generations.
func TestKvBindingRuleIsolation(t *testing.T) {
	kvBindingTestSetup(t)
	if _, err := KvBindingAllocate("rule-a", kvTestComponents(1)); err != nil {
		t.Fatal(err)
	}
	b, err := KvBindingAllocate("rule-b", kvTestComponents(1))
	if err != nil {
		t.Fatal(err)
	}
	if b.BindingGen != 1 {
		t.Fatalf("rule-b first generation = %d, want 1 (rule-scoped allocator)", b.BindingGen)
	}
}

// TestKvBindingDigestConvergesAcrossRules: two rules with EQUAL components
// — the two-node HA shape, where each node mints its own rule UUID for the
// same operator config — must allocate the SAME binding digest, or the
// §17.7 capability exchange can never converge and strict cluster
// activation is structurally impossible (found live as
// binding_not_converged_on_peer on both nodes forever). Anti-replay is the
// separate (ruleIdentity, bindingGen) pair, not the digest.
func TestKvBindingDigestConvergesAcrossRules(t *testing.T) {
	kvBindingTestSetup(t)
	ba, err := KvBindingAllocate("rule-node-a", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate a: %v", err)
	}
	bb, err := KvBindingAllocate("rule-node-b", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate b: %v", err)
	}
	if ba.Digest != bb.Digest {
		t.Fatalf("equal components diverged across rule identities: %s vs %s", ba.Digest, bb.Digest)
	}
	if ba.RuleIdent == bb.RuleIdent {
		t.Fatal("test premise broken: rule identities must differ")
	}
}

// TestKvBindingDigestCoversEveryComponent: changing any single component
// changes the digest — the digest, not the generation handle, is identity.
func TestKvBindingDigestCoversEveryComponent(t *testing.T) {
	base := kvTestComponents(1)
	baseDigest := kvBindingDigest(&base)
	mutations := map[string]KvExactBindingComponents{}

	m := base
	m.Profile.ID = "other-profile"
	mutations["profile id"] = m
	m = base
	m.Profile.Gen = 4
	mutations["profile gen"] = m
	m = base
	m.Contract.ID = "sglang-zmq-v1"
	mutations["contract id"] = m
	m = base
	m.Contract.Gen = 8
	mutations["contract gen"] = m
	m = base
	m.AttestationPolicyGen = 2
	mutations["attestation policy gen"] = m
	m = base
	m.RequiredEvidenceLevel = "candidate"
	mutations["evidence level"] = m
	m = base
	m.ConsensusPolicy = "quorum"
	mutations["consensus policy"] = m

	for name, comps := range mutations {
		if kvBindingDigest(&comps) == baseDigest {
			t.Errorf("mutating %s did not change the binding digest", name)
		}
	}
	// The digest names the composed CONTENT — the rule identity must NOT
	// participate. Equivalently-configured rules on two cluster nodes carry
	// different node-minted UUIDs, and the HA capability exchange requires
	// their binding digests to CONVERGE for strict activation; anti-replay
	// rides the separate (ruleIdentity, bindingGen) pair.
	if kvBindingDigest(&base) != baseDigest {
		t.Error("equal components must produce equal digests regardless of rule identity")
	}
}

func TestKvBindingVerify(t *testing.T) {
	kvBindingTestSetup(t)
	b, err := KvBindingAllocate("rule-v", kvTestComponents(1))
	if err != nil {
		t.Fatal(err)
	}
	if !KvBindingVerify("rule-v", b.BindingGen, b.Digest) {
		t.Fatal("matching (generation, digest) rejected")
	}
	if KvBindingVerify("rule-v", b.BindingGen, "0000") {
		t.Fatal("wrong digest accepted — the generation handle alone proved identity")
	}
	if KvBindingVerify("rule-v", b.BindingGen+1, b.Digest) {
		t.Fatal("unknown generation accepted")
	}
}

func TestKvBindingComponentValidation(t *testing.T) {
	kvBindingTestSetup(t)
	cases := []struct {
		name   string
		mutate func(*KvExactBindingComponents)
	}{
		{"empty profile id", func(c *KvExactBindingComponents) { c.Profile.ID = "" }},
		{"zero profile gen", func(c *KvExactBindingComponents) { c.Profile.Gen = 0 }},
		{"empty contract id", func(c *KvExactBindingComponents) { c.Contract.ID = "" }},
		{"zero contract gen", func(c *KvExactBindingComponents) { c.Contract.Gen = 0 }},
		{"bad evidence level", func(c *KvExactBindingComponents) { c.RequiredEvidenceLevel = "hearsay" }},
		{"empty consensus", func(c *KvExactBindingComponents) { c.ConsensusPolicy = "" }},
	}
	for _, tc := range cases {
		comps := kvTestComponents(1)
		tc.mutate(&comps)
		if _, err := KvBindingAllocate("rule-val", comps); err == nil {
			t.Errorf("%s accepted", tc.name)
		}
	}
	if _, err := KvBindingAllocate("", kvTestComponents(1)); err == nil {
		t.Error("empty rule identity accepted")
	}
}

// TestKvBindingWrapSkipsZeroAndLiveGenerations: generation 0 is reserved and
// a wrap never reissues a generation whose snapshot is still live.
func TestKvBindingWrapSkipsZeroAndLiveGenerations(t *testing.T) {
	kvBindingTestSetup(t)
	mod := kvExportOne(t, "rule-wrap", math.MaxUint32)
	if err := KvBindingRestore(&mod); err != nil {
		t.Fatalf("restore at MaxUint32: %v", err)
	}
	b, err := KvBindingAllocate("rule-wrap", kvTestComponents(9))
	if err != nil {
		t.Fatalf("allocate after wrap: %v", err)
	}
	if b.BindingGen != 1 {
		t.Fatalf("wrapped generation = %d, want 1 (0 reserved)", b.BindingGen)
	}
	// MaxUint32's snapshot is still live and must still resolve.
	if _, ok := KvBindingResolve("rule-wrap", math.MaxUint32); !ok {
		t.Fatal("pre-wrap snapshot lost")
	}
	// Wrap again: 1 is live now, so the next allocation must skip it.
	rs := func() *kvBindingRuleState {
		kvBindingMu.Lock()
		defer kvBindingMu.Unlock()
		return kvBindingRules["rule-wrap"]
	}()
	kvBindingMu.Lock()
	rs.maxAllocated = math.MaxUint32
	kvBindingMu.Unlock()
	b2, err := KvBindingAllocate("rule-wrap", kvTestComponents(10))
	if err != nil {
		t.Fatal(err)
	}
	if b2.BindingGen != 2 {
		t.Fatalf("second wrap allocated %d, want 2 (1 and MaxUint32 still live)", b2.BindingGen)
	}
}

// kvExportOne builds a valid persisted mod (digest computed by the real
// digest function) for restore-side tests.
func kvExportOne(t *testing.T, ruleIdent string, gen uint32) cmn.KvExactBindingMod {
	t.Helper()
	comps := kvTestComponents(5)
	return cmn.KvExactBindingMod{
		RuleIdent:             ruleIdent,
		ModelProfileID:        comps.Profile.ID,
		ModelProfileGen:       comps.Profile.Gen,
		EngineContractID:      comps.Contract.ID,
		EngineContractGen:     comps.Contract.Gen,
		AttestationPolicyGen:  comps.AttestationPolicyGen,
		RequiredEvidenceLevel: comps.RequiredEvidenceLevel,
		ConsensusPolicy:       comps.ConsensusPolicy,
		BindingGen:            gen,
		BindingDigest:         kvBindingDigest(&comps),
		MaxAllocatedGen:       gen,
	}
}

func TestKvBindingRestoreResumesAboveHighWaterMark(t *testing.T) {
	kvBindingTestSetup(t)
	mod := kvExportOne(t, "rule-hwm", 5)
	mod.MaxAllocatedGen = 9 // generations 6..9 were allocated pre-restart
	if err := KvBindingRestore(&mod); err != nil {
		t.Fatalf("restore: %v", err)
	}
	b, err := KvBindingAllocate("rule-hwm", kvTestComponents(6))
	if err != nil {
		t.Fatal(err)
	}
	if b.BindingGen != 10 {
		t.Fatalf("post-restore allocation = %d, want 10 (above the persisted high-water mark)", b.BindingGen)
	}
}

// TestKvBindingRestoreRejectsTamperedDigest: a persisted document whose
// components do not reproduce its digest must be refused — restore installs
// proven identities only.
func TestKvBindingRestoreRejectsTamperedDigest(t *testing.T) {
	kvBindingTestSetup(t)
	mod := kvExportOne(t, "rule-tamper", 3)
	mod.ModelProfileGen++ // component changed after the digest was computed
	if err := KvBindingRestore(&mod); err == nil {
		t.Fatal("tampered persisted binding restored")
	}
	mod = kvExportOne(t, "rule-tamper", 3)
	mod.BindingDigest = "deadbeef"
	if err := KvBindingRestore(&mod); err == nil {
		t.Fatal("corrupt digest restored")
	}
	mod = kvExportOne(t, "rule-tamper", 0)
	if err := KvBindingRestore(&mod); err == nil {
		t.Fatal("generation 0 restored (reserved)")
	}
}

func TestKvBindingExportRestoreRoundTrip(t *testing.T) {
	kvBindingTestSetup(t)
	if _, err := KvBindingAllocate("rule-r1", kvTestComponents(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := KvBindingAllocate("rule-r1", kvTestComponents(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := KvBindingAllocate("rule-r2", kvTestComponents(1)); err != nil {
		t.Fatal(err)
	}
	exported := KvBindingExport()
	if len(exported) != 2 {
		t.Fatalf("exported %d rules, want 2", len(exported))
	}

	KvBindingReset()
	for i := range exported {
		if err := KvBindingRestore(&exported[i]); err != nil {
			t.Fatalf("restore %s: %v", exported[i].RuleIdent, err)
		}
	}
	again := KvBindingExport()
	if !reflect.DeepEqual(exported, again) {
		t.Fatalf("round trip drifted:\n before %+v\n after  %+v", exported, again)
	}
	// Re-restoring the IDENTICAL proven identity is an idempotent no-op:
	// a retried boot replay re-applies the same document over the partial
	// state an earlier attempt left behind, and refusing it wedged every
	// boot retry into a self-conflict (found live; the boot loader
	// converges instead of wiping between attempts).
	if err := KvBindingRestore(&exported[0]); err != nil {
		t.Fatalf("identical re-restore refused (boot retries would self-conflict): %v", err)
	}
	if after := KvBindingExport(); !reflect.DeepEqual(again, after) {
		t.Fatalf("idempotent re-restore drifted state:\n before %+v\n after  %+v", again, after)
	}
	// A DIVERGENT identity for the same rule stays a hard conflict: two
	// documents disagreeing about a rule's binding identity is never
	// reconcilable here. (The binding digest covers components, not the
	// generation, so a bumped generation passes the digest gate and must
	// be caught by the live-state conflict check.)
	mut := exported[0]
	mut.BindingGen++
	if err := KvBindingRestore(&mut); err == nil {
		t.Fatal("divergent binding identity accepted over live state")
	}
}

// TestKvBindingRestoreRebindsSubscriberWire: a restore replay starts a
// strict rule's subscribers before the persisted binding document lands, so
// they resolve the LEGACY wire schema; installing the restored binding must
// restart those streams under the restored engine contract — otherwise every
// native event rejects as schema_mismatch and the rule can never re-attest
// past token parity after a gateway restart.
func TestKvBindingRestoreRebindsSubscriberWire(t *testing.T) {
	kvBindingTestSetup(t)
	const svcID = uint32(9107)
	const ruleIdent = "rule-restore-rebind"

	// The metrics bridge is a once-armed global; arm it with a live context
	// so the subscriber start below never captures a nil shutdown context.
	StartKvMetricsBridge(context.Background())

	KvSvcContractRegister(svcID, ruleIdent, net.ParseIP("127.0.0.1"), 9107, 6, 0)
	t.Cleanup(func() { KvSvcContractDeregister(svcID) })

	// Replay order: the LB rule replays first and starts its subscriber with
	// no binding installed yet — contractID "" (the legacy per-engine wire).
	KvSubscriberStartRank(svcID, 0, 0, "127.0.0.1", 45907, "sha256_cbor", "vllm", 16, "")
	t.Cleanup(func() { KvSubscriberStopAll(svcID) })

	argsContract := func() string {
		t.Helper()
		kvServicesMu.RLock()
		svc := kvServices[svcID]
		kvServicesMu.RUnlock()
		if svc == nil {
			t.Fatal("subscriber service state missing")
		}
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		a, ok := svc.startArgs[kvEpRankKey{epIdx: 0, rank: 0}]
		if !ok {
			t.Fatal("subscriber start args missing")
		}
		return a.contractID
	}
	if got := argsContract(); got != "" {
		t.Fatalf("pre-restore subscriber contract = %q, want legacy \"\"", got)
	}

	comps := kvTestComponents(1)
	digest := kvBindingDigest(&comps)
	err := KvBindingRestore(&cmn.KvExactBindingMod{
		RuleIdent:             ruleIdent,
		ModelProfileID:        comps.Profile.ID,
		ModelProfileGen:       comps.Profile.Gen,
		EngineContractID:      comps.Contract.ID,
		EngineContractGen:     comps.Contract.Gen,
		AttestationPolicyGen:  comps.AttestationPolicyGen,
		RequiredEvidenceLevel: comps.RequiredEvidenceLevel,
		ConsensusPolicy:       comps.ConsensusPolicy,
		BindingGen:            4,
		BindingDigest:         digest,
		MaxAllocatedGen:       4,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	if got := argsContract(); got != comps.Contract.ID {
		t.Fatalf("post-restore subscriber contract = %q, want %q (stream not rebound)", got, comps.Contract.ID)
	}

	// Converged streams are left alone: a rebind to the already-bound
	// contract must not churn the goroutines (no stop/start cycle).
	KvSubscriberRebindWire(svcID, comps.Contract.ID)
	if got := argsContract(); got != comps.Contract.ID {
		t.Fatalf("idempotent rebind changed contract to %q", got)
	}
}

func TestKvBindingRetire(t *testing.T) {
	kvBindingTestSetup(t)
	b1, _ := KvBindingAllocate("rule-ret", kvTestComponents(1))
	b2, _ := KvBindingAllocate("rule-ret", kvTestComponents(2))
	if err := KvBindingRetire("rule-ret", b2.BindingGen); err == nil {
		t.Fatal("current binding retired")
	}
	if err := KvBindingRetire("rule-ret", b1.BindingGen); err != nil {
		t.Fatalf("retire superseded generation: %v", err)
	}
	if _, ok := KvBindingResolve("rule-ret", b1.BindingGen); ok {
		t.Fatal("retired snapshot still resolves")
	}
	if err := KvBindingRetire("rule-ret", b1.BindingGen); err == nil {
		t.Fatal("double retire accepted")
	}
}

// --- engine-contract source seam ------------------------------------------

type kvStubContractSource struct {
	digests map[KvEngineContractRef]string
}

func (s *kvStubContractSource) ResolveDigest(ref KvEngineContractRef) (string, error) {
	if d, ok := s.digests[ref]; ok {
		return d, nil
	}
	return "", errors.New("unknown contract")
}

func (s *kvStubContractSource) CurrentRef(engineFamily string) (KvEngineContractRef, error) {
	for ref := range s.digests {
		if strings.HasPrefix(ref.ID, engineFamily) {
			return ref, nil
		}
	}
	return KvEngineContractRef{}, errors.New("no contract for engine family")
}

// TestKvEngineContractSourceSeam: without a registered source every resolve
// fails closed; with one, resolution is by exact (id, generation).
func TestKvEngineContractSourceSeam(t *testing.T) {
	KvRegisterEngineContractSource(nil)
	t.Cleanup(func() { KvRegisterEngineContractSource(nil) })

	ref := KvEngineContractRef{ID: "vllm-zmq-v1", Gen: 7}
	if _, err := kvResolveEngineContract(ref); !errors.Is(err, ErrKvNoContractSource) {
		t.Fatalf("resolve without source: %v, want ErrKvNoContractSource", err)
	}

	KvRegisterEngineContractSource(&kvStubContractSource{
		digests: map[KvEngineContractRef]string{ref: "digest-7"},
	})
	d, err := kvResolveEngineContract(ref)
	if err != nil || d != "digest-7" {
		t.Fatalf("resolve = (%q, %v)", d, err)
	}
	if _, err := kvResolveEngineContract(KvEngineContractRef{ID: "vllm-zmq-v1", Gen: 8}); err == nil {
		t.Fatal("wrong generation resolved")
	}
}
