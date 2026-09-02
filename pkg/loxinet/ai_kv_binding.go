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

/*
 * ai_kv_binding.go — KvExactBinding: the composed identity a KV-exact rule
 * runs under, and the rule-scoped binding-generation allocator.
 *
 * One rule owns exactly one binding; a binding composes exactly one
 * ModelPromptProfile@generation (ai_kv_profile.go) with exactly one
 * KvEngineContract@generation. The contract itself is owned by the engine-
 * contract registry and is only ever REFERENCED here (KvEngineContractRef +
 * KvEngineContractSource) — this file defines zero engine semantics and
 * duplicates zero contract content.
 *
 * binding_gen is the data-plane identity: a rule-scoped monotonic uint32
 * allocated whenever any contract-sensitive component changes. The compact
 * value is a handle, never identity proof — the store retains the full
 * mapping binding_gen -> components + digest, and consumers verify the
 * digest, so a wrapped or colliding handle can never alias two different
 * component sets. Late in-flight requests resolve one immutable binding
 * snapshot by the generation they carried; mixed old-profile/new-contract
 * resolution is impossible because the snapshot is one object.
 *
 * Persistence carries the full mapping plus the per-rule allocation
 * high-water mark; a restarted allocator resumes above it so a live
 * generation is never reissued.
 */

package loxinet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	cmn "github.com/loxilb-io/loxilb/common"
)

// KvEngineContractRef references an engine contract by identity and
// generation. Scalars by design: one binding, one contract, one generation.
type KvEngineContractRef struct {
	ID  string
	Gen uint64
}

// KvEngineContractSource resolves a contract reference to its content
// digest. The engine-contract registry provides the implementation; until
// one is registered, every resolve fails and admission of contract-bearing
// bindings stays closed. This seam is the ONLY coupling to the contract
// registry — contract content never crosses it.
type KvEngineContractSource interface {
	// ResolveDigest returns the content digest of the referenced contract,
	// or an error when the contract is unknown at that generation.
	ResolveDigest(ref KvEngineContractRef) (string, error)
	// CurrentRef returns the current contract reference for an engine
	// family ("vllm", "sglang", "trtllm"), or an error when the registry
	// serves no contract for it. Identity resolution only — contract
	// content never crosses this seam.
	CurrentRef(engineFamily string) (KvEngineContractRef, error)
}

var (
	kvEngineContractSrcMu sync.RWMutex
	kvEngineContractSrc   KvEngineContractSource
)

// KvRegisterEngineContractSource installs the engine-contract resolver.
func KvRegisterEngineContractSource(s KvEngineContractSource) {
	kvEngineContractSrcMu.Lock()
	defer kvEngineContractSrcMu.Unlock()
	kvEngineContractSrc = s
}

// kvResolveEngineContract resolves ref through the registered source.
// ErrKvNoContractSource is the fail-closed answer when none is registered.
var ErrKvNoContractSource = errors.New("kv-binding: no engine-contract source registered")

func kvResolveEngineContract(ref KvEngineContractRef) (string, error) {
	kvEngineContractSrcMu.RLock()
	s := kvEngineContractSrc
	kvEngineContractSrcMu.RUnlock()
	if s == nil {
		return "", ErrKvNoContractSource
	}
	return s.ResolveDigest(ref)
}

// kvCurrentContractRef resolves the current engine-contract reference for an
// engine family through the registered source. Fail-closed: with no source
// registered, strict (profile-bound) admission cannot compose a binding.
func kvCurrentContractRef(engineFamily string) (KvEngineContractRef, error) {
	kvEngineContractSrcMu.RLock()
	s := kvEngineContractSrc
	kvEngineContractSrcMu.RUnlock()
	if s == nil {
		return KvEngineContractRef{}, ErrKvNoContractSource
	}
	return s.CurrentRef(engineFamily)
}

// KvExactBindingComponents are the contract-sensitive inputs a binding
// generation is allocated over.
type KvExactBindingComponents struct {
	Profile               KvModelProfileRef
	Contract              KvEngineContractRef
	AttestationPolicyGen  uint32
	RequiredEvidenceLevel string
	ConsensusPolicy       string
}

// KvExactBinding is one immutable binding snapshot. The Digest covers every
// component; equality of digests, never of generation handles, proves
// identity.
type KvExactBinding struct {
	RuleIdent  string
	Components KvExactBindingComponents
	BindingGen uint32
	Digest     string
}

// kvBindingRuleState is one rule's allocator + snapshot map. Single-writer:
// all mutation happens under the store lock.
type kvBindingRuleState struct {
	maxAllocated uint32
	current      *KvExactBinding
	live         map[uint32]*KvExactBinding
}

var (
	kvBindingMu    sync.RWMutex
	kvBindingRules = make(map[string]*kvBindingRuleState)
)

// kvBindingDigest computes the binding digest over a canonical
// serialization of the components. Every component field participates: two
// sets differing in ANY field produce different digests. The rule identity
// deliberately does NOT participate: the digest names the composed CONTENT,
// and the HA capability exchange requires equivalently-configured rules on
// two nodes to CONVERGE on it (a node-local UUID in the digest makes strict
// cluster activation structurally impossible). Local anti-replay protection
// is the separate (ruleIdentity, bindingGen) pair.
func kvBindingDigest(c *KvExactBindingComponents) string {
	h := sha256.New()
	fmt.Fprintf(h, "profile\x00%s\x00%d\x00contract\x00%s\x00%d\x00policy\x00%d\x00evidence\x00%s\x00consensus\x00%s\x00",
		c.Profile.ID, c.Profile.Gen, c.Contract.ID, c.Contract.Gen,
		c.AttestationPolicyGen, c.RequiredEvidenceLevel, c.ConsensusPolicy)
	return hex.EncodeToString(h.Sum(nil))
}

// kvValidateBindingComponents rejects structurally invalid component sets
// before any allocation happens.
func kvValidateBindingComponents(c *KvExactBindingComponents) error {
	if c.Profile.ID == "" || c.Profile.Gen == 0 {
		return errors.New("kv-binding: profile reference requires id and non-zero generation")
	}
	if c.Contract.ID == "" || c.Contract.Gen == 0 {
		return errors.New("kv-binding: contract reference requires id and non-zero generation")
	}
	switch c.RequiredEvidenceLevel {
	case "observed", "candidate", "validated":
	default:
		return fmt.Errorf("kv-binding: unknown evidence level %q", c.RequiredEvidenceLevel)
	}
	if c.ConsensusPolicy == "" {
		return errors.New("kv-binding: consensus policy is required")
	}
	return nil
}

// KvBindingAllocate allocates the next binding generation for ruleIdent over
// the given components and installs the snapshot as the rule's current
// binding. Generation 0 is reserved; wrap skips it and never reissues a
// generation whose snapshot is still live.
func KvBindingAllocate(ruleIdent string, comps KvExactBindingComponents) (*KvExactBinding, error) {
	if ruleIdent == "" {
		return nil, errors.New("kv-binding: rule identity is required")
	}
	if err := kvValidateBindingComponents(&comps); err != nil {
		return nil, err
	}

	kvBindingMu.Lock()
	defer kvBindingMu.Unlock()

	rs := kvBindingRules[ruleIdent]
	if rs == nil {
		rs = &kvBindingRuleState{live: make(map[uint32]*KvExactBinding)}
		kvBindingRules[ruleIdent] = rs
	}

	next := rs.maxAllocated
	for {
		next++
		if next == 0 { // wrap: 0 is reserved
			next = 1
		}
		if _, taken := rs.live[next]; !taken {
			break
		}
		if next == rs.maxAllocated {
			return nil, fmt.Errorf("kv-binding: rule %s has no free binding generation", ruleIdent)
		}
	}

	b := &KvExactBinding{
		RuleIdent:  ruleIdent,
		Components: comps,
		BindingGen: next,
		Digest:     kvBindingDigest(&comps),
	}
	rs.maxAllocated = next
	rs.current = b
	rs.live[next] = b
	return b, nil
}

// KvBindingCurrent returns the rule's current (desired) binding.
func KvBindingCurrent(ruleIdent string) (*KvExactBinding, bool) {
	kvBindingMu.RLock()
	defer kvBindingMu.RUnlock()
	rs := kvBindingRules[ruleIdent]
	if rs == nil || rs.current == nil {
		return nil, false
	}
	return rs.current, true
}

// KvBindingResolve returns the immutable snapshot for a generation a late
// in-flight request carried. The snapshot is one object: profile and
// contract resolve together or not at all.
func KvBindingResolve(ruleIdent string, gen uint32) (*KvExactBinding, bool) {
	kvBindingMu.RLock()
	defer kvBindingMu.RUnlock()
	rs := kvBindingRules[ruleIdent]
	if rs == nil {
		return nil, false
	}
	b, ok := rs.live[gen]
	return b, ok
}

// KvBindingVerify checks a (generation, digest) pair against the retained
// mapping. This is the acknowledgment-path identity check: a generation
// handle without a matching digest proves nothing and must not be trusted.
func KvBindingVerify(ruleIdent string, gen uint32, digest string) bool {
	b, ok := KvBindingResolve(ruleIdent, gen)
	return ok && b.Digest == digest
}

// KvBindingRetire drops a non-current snapshot after the data plane has
// quiesced every request that could still carry its generation. The current
// binding is never retirable.
func KvBindingRetire(ruleIdent string, gen uint32) error {
	kvBindingMu.Lock()
	defer kvBindingMu.Unlock()
	rs := kvBindingRules[ruleIdent]
	if rs == nil {
		return fmt.Errorf("kv-binding: unknown rule %s", ruleIdent)
	}
	if rs.current != nil && rs.current.BindingGen == gen {
		return fmt.Errorf("kv-binding: generation %d is the current binding of rule %s", gen, ruleIdent)
	}
	if _, ok := rs.live[gen]; !ok {
		return fmt.Errorf("kv-binding: rule %s has no live generation %d", ruleIdent, gen)
	}
	delete(rs.live, gen)
	return nil
}

// KvBindingDelete removes all binding state for a rule (rule teardown).
func KvBindingDelete(ruleIdent string) {
	kvBindingMu.Lock()
	defer kvBindingMu.Unlock()
	delete(kvBindingRules, ruleIdent)
}

// KvBindingReset clears the whole store (tests and restore wipe).
func KvBindingReset() {
	kvBindingMu.Lock()
	defer kvBindingMu.Unlock()
	kvBindingRules = make(map[string]*kvBindingRuleState)
}

// KvBindingExport serializes every rule's current binding + high-water mark
// for snapshot capture, sorted by rule identity for deterministic documents.
func KvBindingExport() []cmn.KvExactBindingMod {
	kvBindingMu.RLock()
	defer kvBindingMu.RUnlock()
	out := make([]cmn.KvExactBindingMod, 0, len(kvBindingRules))
	for ruleIdent, rs := range kvBindingRules {
		if rs.current == nil {
			continue
		}
		b := rs.current
		out = append(out, cmn.KvExactBindingMod{
			RuleIdent:             ruleIdent,
			ModelProfileID:        b.Components.Profile.ID,
			ModelProfileGen:       b.Components.Profile.Gen,
			EngineContractID:      b.Components.Contract.ID,
			EngineContractGen:     b.Components.Contract.Gen,
			AttestationPolicyGen:  b.Components.AttestationPolicyGen,
			RequiredEvidenceLevel: b.Components.RequiredEvidenceLevel,
			ConsensusPolicy:       b.Components.ConsensusPolicy,
			BindingGen:            b.BindingGen,
			BindingDigest:         b.Digest,
			MaxAllocatedGen:       rs.maxAllocated,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleIdent < out[j].RuleIdent })
	return out
}

// KvBindingRestore installs one persisted binding. The digest is recomputed
// from the restored components and must match the persisted value — a
// tampered or corrupted document fails here instead of installing an
// identity the components do not prove. The allocator resumes above the
// persisted high-water mark so restored generations are never reissued.
func KvBindingRestore(mod *cmn.KvExactBindingMod) error {
	if mod == nil || mod.RuleIdent == "" {
		return errors.New("kv-binding: restore requires a rule identity")
	}
	if mod.BindingGen == 0 {
		return fmt.Errorf("kv-binding: rule %s: binding generation 0 is reserved", mod.RuleIdent)
	}
	comps := KvExactBindingComponents{
		Profile:               KvModelProfileRef{ID: mod.ModelProfileID, Gen: mod.ModelProfileGen},
		Contract:              KvEngineContractRef{ID: mod.EngineContractID, Gen: mod.EngineContractGen},
		AttestationPolicyGen:  mod.AttestationPolicyGen,
		RequiredEvidenceLevel: mod.RequiredEvidenceLevel,
		ConsensusPolicy:       mod.ConsensusPolicy,
	}
	if err := kvValidateBindingComponents(&comps); err != nil {
		return fmt.Errorf("rule %s: %w", mod.RuleIdent, err)
	}
	digest := kvBindingDigest(&comps)
	if digest != mod.BindingDigest {
		return fmt.Errorf("kv-binding: rule %s: persisted digest %.12s… does not match recomputed %.12s… — refusing to restore an unproven identity",
			mod.RuleIdent, mod.BindingDigest, digest)
	}

	kvBindingMu.Lock()
	defer kvBindingMu.Unlock()
	if _, exists := kvBindingRules[mod.RuleIdent]; exists {
		return fmt.Errorf("kv-binding: rule %s already has binding state", mod.RuleIdent)
	}
	b := &KvExactBinding{
		RuleIdent:  mod.RuleIdent,
		Components: comps,
		BindingGen: mod.BindingGen,
		Digest:     digest,
	}
	maxAlloc := mod.MaxAllocatedGen
	if maxAlloc < mod.BindingGen {
		maxAlloc = mod.BindingGen
	}
	kvBindingRules[mod.RuleIdent] = &kvBindingRuleState{
		maxAllocated: maxAlloc,
		current:      b,
		live:         map[uint32]*KvExactBinding{b.BindingGen: b},
	}

	// The loadbalancer snapshot domain registered this strict rule
	// fenced (deny set) without a binding; now that the authoritative
	// binding exists, run the contract-word install transaction — the only
	// path that can clear the fence.
	KvSvcContractKickInstall(mod.RuleIdent)
	// The replayed rule's subscribers started before this binding existed and
	// resolved the legacy wire schema; converge them on the restored contract
	// or every native event rejects as schema_mismatch and the rule can never
	// re-attest past token parity.
	if svcID, ok := kvSvcByRuleIdent(mod.RuleIdent); ok {
		KvSubscriberRebindWire(svcID, mod.EngineContractID)
	}
	return nil
}
