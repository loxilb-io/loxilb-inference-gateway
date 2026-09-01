/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

// KV binding-dataplane contract: the Go half of the packed
// [binding_gen:32|flags:16|api_mode:8|eligible:8] contract word installed on
// the C proxy entry, plus the per-svc_id deny set that fences a strict rule
// whenever the C-side word cannot be trusted (not installed yet, entry
// rebuilt, setter fault). The deny set is authoritative: every exact scoring
// path, chat and completions alike, must cross the tokenize bridge to obtain
// tokens; a denied svc_id gets no tokens, so no hashes are computed and the
// C guard path falls back to Tier-2 regardless of C-side state.

import (
	"fmt"
	"net"
	"sync"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// Typed tokenize-bridge return codes. MIRROR of the LLB_KV_TOK_ERR_* values
// in loxilb-ebpf/common/sockproxy_kv_exact.h — the two definitions change in
// the same paired commits (twin-lockstep discipline). Request-class codes
// (-1/-2) never affect readiness; runtime-fault codes (-3..-6) are emitted
// only on strict paths (binding_gen != 0); -7 is the deny-set fence.
const (
	KvTokErrRequest     = -1
	KvTokErrUnsupported = -2
	KvTokErrProfile     = -3
	KvTokErrRenderer    = -4
	KvTokErrTokenizer   = -5
	KvTokErrUnknown     = -6
	KvTokErrNotReady    = -7
)

// Contract-word api_mode byte vocabulary. MIRROR of KV_EXACT_API_* in
// loxilb-ebpf/common/sockproxy_kv_exact.h. Zero means "both" so a word with
// no surface restriction is still non-zero through its binding_gen bits.
const (
	KvContractAPIBoth        uint8 = 0
	KvContractAPICompletions uint8 = 1
	KvContractAPIChat        uint8 = 2
)

// KvContractPack packs the data-plane contract word. MIRROR of
// KV_CONTRACT_PACK in loxilb-ebpf/common/sockproxy_kv_exact.h.
func KvContractPack(bindingGen uint32, flags uint16, apiMode, eligible uint8) uint64 {
	return uint64(bindingGen)<<32 | uint64(flags)<<16 |
		uint64(apiMode)<<8 | uint64(eligible)
}

// kvContractAPIModeByte collapses the effective (chat, completions) surface
// pair into the contract byte. A pair with neither surface cannot happen past
// admission; it degrades to completions-only (the narrower surface) rather
// than to "both", which would widen enforcement.
func kvContractAPIModeByte(chat, completions bool) uint8 {
	switch {
	case chat && completions:
		return KvContractAPIBoth
	case chat:
		return KvContractAPIChat
	default:
		return KvContractAPICompletions
	}
}

// kvSvcContract is the control plane's per-rule record of the data-plane
// contract: the identity needed to (re)install the word plus the deny flag
// that fences the rule while the word is not proven installed.
type kvSvcContract struct {
	ruleIdent string
	vip       net.IP
	port      uint16
	proto     uint8
	apiMode   uint8
	denied    bool
	fault     string // last enforcement fault reason ("" = none)
	// lastAckAt/lastApplied record the most recent full setter ACK (§7.1
	// enforced-state evidence for the status sub-resource); zero until the
	// first ACK after registration or restart.
	lastAckAt   time.Time
	lastApplied uint64
}

// KvSvcEnforcement is the status read model of a rule's enforcement position
// (plan §7.4 GET shape): the Go-fence flag, the last recorded fault, and the
// last full data-plane ACK (word + timestamp).
type KvSvcEnforcement struct {
	GoFenced    bool
	Fault       string
	LastAckAt   time.Time
	LastApplied uint64
}

// KvSvcContractEnforcement reports the enforcement position for a svc_id
// (false = the rule has no registered contract, i.e. legacy).
func KvSvcContractEnforcement(svcID uint32) (KvSvcEnforcement, bool) {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	c := kvSvcContracts[svcID]
	if c == nil {
		return KvSvcEnforcement{}, false
	}
	return KvSvcEnforcement{
		GoFenced:    c.denied,
		Fault:       c.fault,
		LastAckAt:   c.lastAckAt,
		LastApplied: c.lastApplied,
	}, true
}

// kvExactEnforcementInfo builds the status sub-resource's enforcement block
// for a strict rule (nil when the rule has no registered contract).
func kvExactEnforcementInfo(svcID uint32, desired, enforced string) *cmn.KvExactEnforcement {
	e, ok := KvSvcContractEnforcement(svcID)
	if !ok {
		return nil
	}
	out := &cmn.KvExactEnforcement{
		Desired:  desired,
		Enforced: enforced,
		Fault:    e.Fault,
		GoFenced: e.GoFenced,
	}
	if !e.LastAckAt.IsZero() {
		out.LastAckAt = e.LastAckAt.UTC().Format(time.RFC3339)
	}
	return out
}

// kvSvcContractAckStamp records a full setter ACK (word readback + digest
// half both verified by the caller).
func kvSvcContractAckStamp(svcID uint32, applied uint64) {
	kvSvcMu.Lock()
	if c := kvSvcContracts[svcID]; c != nil {
		c.lastAckAt = time.Now()
		c.lastApplied = applied
	}
	kvSvcMu.Unlock()
}

var (
	kvSvcMu        sync.RWMutex
	kvSvcContracts = make(map[uint32]*kvSvcContract)
)

// kvContractSetter is the injected data-plane setter seam (production: a
// closure over DpEbpfH.DpKvExactContractUpdate; tests: a fake). It returns
// the readback word and whether the C call itself succeeded.
type kvContractSetter func(vip net.IP, port uint16, proto uint8,
	bindingGen uint32, apiMode, eligible uint8) (applied uint64, ok bool)

var (
	kvContractSetterMu sync.RWMutex
	kvContractSetterFn kvContractSetter
)

// KvRegisterContractSetter installs the data-plane setter (called once by the
// eBPF datapath init; nil until then, which keeps every strict rule denied —
// fail-closed by construction).
func KvRegisterContractSetter(fn kvContractSetter) {
	kvContractSetterMu.Lock()
	kvContractSetterFn = fn
	kvContractSetterMu.Unlock()
}

func kvContractSetter_get() kvContractSetter {
	kvContractSetterMu.RLock()
	defer kvContractSetterMu.RUnlock()
	return kvContractSetterFn
}

// KvSvcContractRegister records a strict rule's contract identity and fences
// it (denied=true) until an install transaction ACKs — the fence-first
// discipline: the rule can never route exact traffic through a window where
// the C word is absent or unproven.
func KvSvcContractRegister(svcID uint32, ruleIdent string, vip net.IP,
	port uint16, proto uint8, apiMode uint8) {
	if svcID == 0 || ruleIdent == "" {
		return
	}
	kvSvcMu.Lock()
	kvSvcContracts[svcID] = &kvSvcContract{
		ruleIdent: ruleIdent,
		vip:       vip,
		port:      port,
		proto:     proto,
		apiMode:   apiMode,
		denied:    true,
	}
	kvSvcMu.Unlock()
}

// KvSvcContractDeregister drops all contract state for a rule (teardown).
func KvSvcContractDeregister(svcID uint32) {
	kvSvcMu.Lock()
	delete(kvSvcContracts, svcID)
	kvSvcMu.Unlock()
}

// KvSvcContractReset clears the whole store (tests).
func KvSvcContractReset() {
	kvSvcMu.Lock()
	kvSvcContracts = make(map[uint32]*kvSvcContract)
	kvSvcMu.Unlock()
}

// kvSvcDenied is the tokenize-bridge fence consult (plan §7.4). An
// unregistered svc_id is a legacy rule — never denied.
func kvSvcDenied(svcID uint32) bool {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	c := kvSvcContracts[svcID]
	return c != nil && c.denied
}

// kvSvcRuleIdent resolves the binding-store identity for a svc_id.
func kvSvcRuleIdent(svcID uint32) (string, bool) {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	c := kvSvcContracts[svcID]
	if c == nil {
		return "", false
	}
	return c.ruleIdent, true
}

// kvSvcByRuleIdent reverse-resolves a rule identity to its svc_id (used by
// the snapshot-restore kick, which only knows the persisted rule identity).
func kvSvcByRuleIdent(ruleIdent string) (uint32, bool) {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	for id, c := range kvSvcContracts {
		if c.ruleIdent == ruleIdent {
			return id, true
		}
	}
	return 0, false
}

// kvSvcContractFault reports the recorded enforcement fault ("" = none).
func kvSvcContractFault(svcID uint32) string {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	c := kvSvcContracts[svcID]
	if c == nil {
		return ""
	}
	return c.fault
}

func kvSvcContractSnapshot(svcID uint32) (kvSvcContract, bool) {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	c := kvSvcContracts[svcID]
	if c == nil {
		return kvSvcContract{}, false
	}
	return *c, true
}

func kvSvcContractOutcome(svcID uint32, denied bool, fault string) {
	kvSvcMu.Lock()
	if c := kvSvcContracts[svcID]; c != nil {
		c.denied = denied
		c.fault = fault
	}
	kvSvcMu.Unlock()
}

// kvDataplaneContractApply runs one §7.2/§7.4 contract transaction against
// the injected setter at an explicit eligibility: compute the expected word
// from the rule's CURRENT binding, call the synchronous setter, and accept
// only the full ACK — C readback == the requested word AND the binding still
// being current (digest-verified) after the readback. Only a full ACK clears
// the deny entry; every other outcome keeps the rule fenced and records the
// fault — which IS the §7.4 escalation's deny-set write (a same-process
// memory operation that cannot fail), so a rule whose C word cannot be
// trusted is always Go-fenced regardless of C-side state. Retries re-read
// the current binding each attempt, so a concurrent re-allocation converges
// on the NEWEST generation instead of ACKing a stale one (§17.3's "two
// distinct component pairs must be unacceptable under one data-plane
// generation").
//
// eligible=1 is written ONLY by the attestation controller's READY
// transition (ai_kv_attest.go); every other caller installs at eligible=0.
func kvDataplaneContractApply(svcID uint32, setter kvContractSetter,
	attempts int, backoff time.Duration, eligible uint8) error {
	if setter == nil {
		kvSvcContractOutcome(svcID, true, "no_dataplane_setter")
		return fmt.Errorf("kv-contract: svc %d: no data-plane setter registered", svcID)
	}
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 && backoff > 0 {
			time.Sleep(backoff)
		}
		snap, ok := kvSvcContractSnapshot(svcID)
		if !ok {
			// Deregistered mid-flight (rule teardown) — nothing to fence.
			return nil
		}
		b, ok := KvBindingCurrent(snap.ruleIdent)
		if !ok {
			lastErr = fmt.Errorf("kv-contract: svc %d rule %s: binding state missing", svcID, snap.ruleIdent)
			kvSvcContractOutcome(svcID, true, "binding_state_missing")
			continue
		}
		want := KvContractPack(b.BindingGen, 0, snap.apiMode, eligible)
		applied, ok := setter(snap.vip, snap.port, snap.proto,
			b.BindingGen, snap.apiMode, eligible)
		if !ok {
			lastErr = fmt.Errorf("kv-contract: svc %d rule %s: setter failed", svcID, snap.ruleIdent)
			kvSvcContractOutcome(svcID, true, "dataplane_setter_failed")
			continue
		}
		if applied != want {
			lastErr = fmt.Errorf("kv-contract: svc %d rule %s: readback 0x%x != requested 0x%x",
				svcID, snap.ruleIdent, applied, want)
			kvSvcContractOutcome(svcID, true, "dataplane_ack_mismatch")
			continue
		}
		// Digest half of the ACK: the generation we just installed must
		// still be the rule's CURRENT binding with an unchanged digest —
		// otherwise a concurrent re-allocation raced the install and the
		// word on the wire is stale; retry converges on the new generation.
		cur, ok := KvBindingCurrent(snap.ruleIdent)
		if !ok || cur.BindingGen != b.BindingGen ||
			!KvBindingVerify(snap.ruleIdent, b.BindingGen, b.Digest) {
			lastErr = fmt.Errorf("kv-contract: svc %d rule %s: binding changed during install (gen %d)",
				svcID, snap.ruleIdent, b.BindingGen)
			kvSvcContractOutcome(svcID, true, "binding_changed_during_install")
			continue
		}
		kvSvcContractOutcome(svcID, false, "")
		kvSvcContractAckStamp(svcID, want)
		tk.LogIt(tk.LogInfo, "kv-contract: svc %d rule %s gen %d api_mode %d eligible %d applied\n",
			svcID, snap.ruleIdent, b.BindingGen, snap.apiMode, eligible)
		return nil
	}
	tk.LogIt(tk.LogError, "kv-contract: svc %d apply(eligible=%d) failed after %d attempts: %v — rule stays Go-fenced (ENFORCEMENT_FAULT path)\n",
		svcID, eligible, attempts, lastErr)
	return lastErr
}

// kvDataplaneContractInstall is the install-shaped transaction (eligible=0):
// the word carries identity and surface policy and the rule stays fenced
// pending attestation — the attestation readiness ladder is the only writer that
// flips eligible to 1.
func kvDataplaneContractInstall(svcID uint32, setter kvContractSetter,
	attempts int, backoff time.Duration) error {
	return kvDataplaneContractApply(svcID, setter, attempts, backoff, 0)
}

// kvDataplaneContractInstallAsync launches the production install goroutine
// (pattern: the circuit-breaker enable retry — the proxy entry is created
// asynchronously by the DP worker, so the first attempts may miss it). A
// full install ACK hands the rule to the attestation controller, the
// only path to eligible=1.
func kvDataplaneContractInstallAsync(svcID uint32) {
	go func() {
		if kvDataplaneContractInstall(svcID, kvContractSetter_get(),
			20, 200*time.Millisecond) == nil {
			kvAttestActivate(svcID)
		}
	}()
}

// KvSvcContractKickInstall re-runs the install for a rule identified by its
// binding-store identity — the snapshot-restore path (the kvexactbinding
// domain applies after the loadbalancer domain has already registered and
// fenced the strict rule).
func KvSvcContractKickInstall(ruleIdent string) {
	if svcID, ok := kvSvcByRuleIdent(ruleIdent); ok {
		kvDataplaneContractInstallAsync(svcID)
	}
}

// kvBridgeGate is the common pre-resolution consult both tokenize bridges run
// before touching any profile or tokenizer state: the deny-set fence first
// (authoritative, plan §7.4), then immutable resolution of the binding
// generation the request carried across the CGO boundary (plan §7.3 / §17.3
// — a generation that no longer resolves is a profile_resolution_fault).
// Returns 0 to proceed.
func kvBridgeGate(svcID, bindingGen uint32) int {
	if svcID != 0 && kvSvcDenied(svcID) {
		return KvTokErrNotReady
	}
	if bindingGen != 0 {
		ident, ok := kvSvcRuleIdent(svcID)
		if !ok {
			return KvTokErrProfile
		}
		if _, ok := KvBindingResolve(ident, bindingGen); !ok {
			return KvTokErrProfile
		}
	}
	return 0
}

// kvBridgeTokenize is the typed core of the llb_ai_kv_tokenize CGO export.
// Legacy paths (bindingGen == 0) return exactly the codes the pre-contract bridge
// produced (-1 for every failure) so legacy rule behavior — and its metric
// attribution — is unchanged; strict paths classify per plan §8.
func kvBridgeTokenize(svcID, bindingGen uint32, text, model string, max int) ([]uint32, int) {
	if rc := kvBridgeGate(svcID, bindingGen); rc != 0 {
		return nil, rc
	}
	if text == "" || model == "" || max <= 0 {
		return nil, KvTokErrRequest
	}
	// Raw completions prompt: encode with specials so the id stream matches
	// vLLM's add_special_tokens=True completions tokenization (BOS included
	// on tokenizers that declare one).
	tokens := kvTokenizeWithCache(text, model, max, true)
	if len(tokens) == 0 {
		if bindingGen != 0 {
			// Admission proved this tokenizer loadable; its absence now is
			// a runtime fault, not a request problem.
			return nil, kvBridgeRuntimeFault(svcID, KvTokErrTokenizer)
		}
		return nil, KvTokErrRequest
	}
	return tokens, 0
}

// kvBridgeRuntimeFault forwards a strict path's runtime-fault code and kicks
// the rule's attestation controller (§6.3: the ladder re-runs on any
// runtime-fault signal). Request-class codes NEVER pass through here —
// readiness reacting to attacker-controllable request problems would let
// traffic degrade rules (I-12).
func kvBridgeRuntimeFault(svcID uint32, code int) int {
	KvAttestKick(svcID, KvAttestReasonRuntimeFault)
	return code
}

// kvBridgeTokenizeChat is the typed core of llb_ai_kv_tokenize_chat. Same
// legacy-compatibility contract as kvBridgeTokenize; on strict paths the
// excluded-feature detection (plan §4 vocabulary) returns request-class
// UNSUPPORTED (never readiness-affecting), a failed validated renderer is a
// runtime fault, and a missing tokenizer is a runtime fault.
func kvBridgeTokenizeChat(svcID, bindingGen uint32, body, model string, max int) ([]uint32, int) {
	if rc := kvBridgeGate(svcID, bindingGen); rc != 0 {
		return nil, rc
	}
	if body == "" || model == "" || max <= 0 {
		return nil, KvTokErrRequest
	}
	strict := bindingGen != 0
	msgs, ok := kvParseChatMessages(body)
	if !ok || len(msgs) == 0 {
		return nil, KvTokErrRequest
	}
	if strict {
		if feature := kvChatExcludedFeature(body); feature != "" {
			return nil, KvTokErrUnsupported
		}
	}
	rendered, ok := kvRenderChatTemplate(model, msgs)
	if !ok || rendered == "" {
		if strict {
			// Admission refuses a declared chat surface without a validated
			// renderer, so a strict rule reaching this branch means the
			// renderer itself failed.
			return nil, kvBridgeRuntimeFault(svcID, KvTokErrRenderer)
		}
		return nil, KvTokErrRequest
	}
	// Chat-rendered text: the template already carries its special tokens and
	// vLLM encodes the render with add_special_tokens=False.
	tokens := kvTokenizeWithCache(rendered, model, max, false)
	if len(tokens) == 0 {
		if strict {
			return nil, kvBridgeRuntimeFault(svcID, KvTokErrTokenizer)
		}
		return nil, KvTokErrRequest
	}
	return tokens, 0
}
