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
	"math"
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

// TestKvBindingDigestCoversEveryComponent: changing any single component
// changes the digest — the digest, not the generation handle, is identity.
func TestKvBindingDigestCoversEveryComponent(t *testing.T) {
	base := kvTestComponents(1)
	baseDigest := kvBindingDigest("rule-x", &base)
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
		if kvBindingDigest("rule-x", &comps) == baseDigest {
			t.Errorf("mutating %s did not change the binding digest", name)
		}
	}
	if kvBindingDigest("rule-y", &base) == baseDigest {
		t.Error("rule identity does not participate in the digest")
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
		BindingDigest:         kvBindingDigest(ruleIdent, &comps),
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
	// Duplicate restore of the same rule is refused.
	if err := KvBindingRestore(&exported[0]); err == nil {
		t.Fatal("second restore over live binding state accepted")
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
