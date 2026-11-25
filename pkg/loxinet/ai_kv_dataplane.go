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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
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
	// kvSvcRecreating is the re-create state of the rules fenced by
	// kvStrictPoolRecreated (guarded by kvSvcMu): the generation of the
	// latest call and whether its install still runs. Only the install of
	// that generation may fence, release or clear; an older one writes
	// nothing. A failed latest install leaves the entry, not running.
	kvSvcRecreating  = make(map[uint32]*kvSvcRecreate)
	kvSvcRecreateGen uint64
	// kvSvcInstallMu serializes the contract-word installs of one rule (a
	// re-create's and attestation's), so that the check of the generation and
	// the word written stay in order (guarded by kvSvcMu).
	kvSvcInstallMu = make(map[uint32]*sync.Mutex)
)

// kvRecreateRetryNs paces the retries of a re-create's install after it
// failed for good (nanoseconds; tests shorten it).
var kvRecreateRetryNs atomic.Int64

func init() { kvRecreateRetryNs.Store(int64(30 * time.Second)) }

type kvSvcRecreate struct {
	gen     uint64
	running bool
}

var (
	errKvRecreateSuperseded = errors.New("a later re-create of the pool took over")
	errKvRecreateRunning    = errors.New("the rule's pool is being re-created; its own install releases the fence")
)

func kvSvcInstallLock(svcID uint32) *sync.Mutex {
	kvSvcMu.Lock()
	defer kvSvcMu.Unlock()
	m := kvSvcInstallMu[svcID]
	if m == nil {
		m = &sync.Mutex{}
		kvSvcInstallMu[svcID] = m
	}
	return m
}

// kvSvcRecreateCurrent: gen 0 (an install outside a re-create) is always
// current; a re-create's install only while it is the latest.
func kvSvcRecreateCurrent(svcID uint32, gen uint64) bool {
	if gen == 0 {
		return true
	}
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	st := kvSvcRecreating[svcID]
	return st != nil && st.gen == gen
}

func kvSvcRecreateRunning(svcID uint32) bool {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	st := kvSvcRecreating[svcID]
	return st != nil && st.running
}

// kvSvcContractFenceGen records a failed install: the rule stays fenced with
// the fault. A superseded re-create's install records nothing.
func kvSvcContractFenceGen(svcID uint32, gen uint64, fault string) {
	kvSvcMu.Lock()
	defer kvSvcMu.Unlock()
	if gen != 0 {
		if st := kvSvcRecreating[svcID]; st == nil || st.gen != gen {
			return
		}
	}
	if c := kvSvcContracts[svcID]; c != nil {
		c.denied = true
		c.fault = fault
	}
}

// kvSvcContractReleaseGen lifts the fence after a full ACK. A re-create's
// install releases only while it is the latest, and clears the state; any
// other install releases only while no re-create of the rule is running.
func kvSvcContractReleaseGen(svcID uint32, gen uint64) error {
	kvSvcMu.Lock()
	defer kvSvcMu.Unlock()
	st := kvSvcRecreating[svcID]
	if gen != 0 {
		if st == nil || st.gen != gen {
			return errKvRecreateSuperseded
		}
	} else if st != nil && st.running {
		return errKvRecreateRunning
	}
	delete(kvSvcRecreating, svcID)
	if c := kvSvcContracts[svcID]; c != nil {
		c.denied = false
		c.fault = ""
	}
	return nil
}

// kvSvcRecreateEnded marks the latest re-create's install as no longer
// running after it failed: the rule stays fenced, a later re-create installs
// again, and attestation may release it.
func kvSvcRecreateEnded(svcID uint32, gen uint64) {
	kvSvcMu.Lock()
	defer kvSvcMu.Unlock()
	if st := kvSvcRecreating[svcID]; st != nil && st.gen == gen {
		st.running = false
	}
}

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
	delete(kvSvcRecreating, svcID)
	kvSvcMu.Unlock()
}

// KvSvcContractReset clears the whole store (tests).
func KvSvcContractReset() {
	kvSvcMu.Lock()
	kvSvcContracts = make(map[uint32]*kvSvcContract)
	kvSvcRecreating = make(map[uint32]*kvSvcRecreate)
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
	return kvDataplaneContractApplyGen(svcID, setter, attempts, backoff, eligible, 0)
}

// kvDataplaneContractApplyGen is kvDataplaneContractApply for an install
// that belongs to re-create generation gen (0: none). Each attempt runs
// under the rule's install lock; a superseded re-create's install stops
// without writing the word or the fence.
func kvDataplaneContractApplyGen(svcID uint32, setter kvContractSetter,
	attempts int, backoff time.Duration, eligible uint8, gen uint64) error {
	if setter == nil {
		kvSvcContractFenceGen(svcID, gen, "no_dataplane_setter")
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
		lk := kvSvcInstallLock(svcID)
		lk.Lock()
		done, err := kvDataplaneContractAttempt(svcID, setter, eligible, gen)
		lk.Unlock()
		if done {
			return err
		}
		lastErr = err
	}
	tk.LogIt(tk.LogError, "kv-contract: svc %d apply(eligible=%d) failed after %d attempts: %v — rule stays Go-fenced (ENFORCEMENT_FAULT path)\n",
		svcID, eligible, attempts, lastErr)
	return lastErr
}

// kvDataplaneContractAttempt is one attempt of the install transaction,
// under the rule's install lock. done: stop retrying and return err.
func kvDataplaneContractAttempt(svcID uint32, setter kvContractSetter,
	eligible uint8, gen uint64) (done bool, err error) {
	if !kvSvcRecreateCurrent(svcID, gen) {
		return true, errKvRecreateSuperseded
	}
	if gen == 0 && kvSvcRecreateRunning(svcID) {
		// The pool is being re-created: an install outside the re-create
		// (attestation, a restore's kick) writes nothing; the re-create's
		// install writes the word and hands the rule to attestation.
		return true, errKvRecreateRunning
	}
	snap, ok := kvSvcContractSnapshot(svcID)
	if !ok {
		// Deregistered mid-flight (rule teardown) — nothing to fence.
		return true, nil
	}
	b, ok := KvBindingCurrent(snap.ruleIdent)
	if !ok {
		kvSvcContractFenceGen(svcID, gen, "binding_state_missing")
		return false, fmt.Errorf("kv-contract: svc %d rule %s: binding state missing", svcID, snap.ruleIdent)
	}
	want := KvContractPack(b.BindingGen, 0, snap.apiMode, eligible)
	applied, ok := setter(snap.vip, snap.port, snap.proto,
		b.BindingGen, snap.apiMode, eligible)
	if !ok {
		kvSvcContractFenceGen(svcID, gen, "dataplane_setter_failed")
		return false, fmt.Errorf("kv-contract: svc %d rule %s: setter failed", svcID, snap.ruleIdent)
	}
	if applied != want {
		kvSvcContractFenceGen(svcID, gen, "dataplane_ack_mismatch")
		return false, fmt.Errorf("kv-contract: svc %d rule %s: readback 0x%x != requested 0x%x",
			svcID, snap.ruleIdent, applied, want)
	}
	// Digest half of the ACK: the generation we just installed must
	// still be the rule's CURRENT binding with an unchanged digest —
	// otherwise a concurrent re-allocation raced the install and the
	// word on the wire is stale; retry converges on the new generation.
	cur, ok := KvBindingCurrent(snap.ruleIdent)
	if !ok || cur.BindingGen != b.BindingGen ||
		!KvBindingVerify(snap.ruleIdent, b.BindingGen, b.Digest) {
		kvSvcContractFenceGen(svcID, gen, "binding_changed_during_install")
		return false, fmt.Errorf("kv-contract: svc %d rule %s: binding changed during install (gen %d)",
			svcID, snap.ruleIdent, b.BindingGen)
	}
	// A full ACK releases the fence, unless a re-create of the rule's pool
	// took over meanwhile (this install's word may be on a pool that is
	// gone) or is running (its own install releases the fence).
	if err := kvSvcContractReleaseGen(svcID, gen); err != nil {
		tk.LogIt(tk.LogInfo, "kv-contract: svc %d rule %s gen %d eligible %d written, fence kept: %v\n",
			svcID, snap.ruleIdent, b.BindingGen, eligible, err)
		return true, err
	}
	kvSvcContractAckStamp(svcID, want)
	tk.LogIt(tk.LogInfo, "kv-contract: svc %d rule %s gen %d api_mode %d eligible %d applied\n",
		svcID, snap.ruleIdent, b.BindingGen, snap.apiMode, eligible)
	return true, nil
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

// kvStrictPoolRecreated is called when a replace removes a rule's data-plane
// pool, and when the undo of a refused replace creates a removed pool again.
// The new pool starts without the contract word, and a pool without the word
// is served as a rule without a contract. So a strict rule is fenced at once,
// as a new strict rule is, and the word is installed again (eligible 0) once
// the removal has reached the data plane; the install ACK lifts the fence and
// hands the rule to attestation, the only writer of eligible 1. A rule
// without a contract is left as it is, and so is a rule that is already
// fenced for a reason of its own (a restored rule waiting for migration or
// for its profile, an install not yet acknowledged, a fault): its fence is
// lifted only by the path that set it, as before. Each call takes a new
// generation; when re-creates follow each other, only the install of the
// latest may release the fence, and no other install of the rule releases
// it while that one runs.
func kvStrictPoolRecreated(svcID uint32) {
	kvSvcMu.Lock()
	c := kvSvcContracts[svcID]
	st := kvSvcRecreating[svcID]
	if c == nil || (c.denied && st == nil) {
		kvSvcMu.Unlock()
		return
	}
	kvSvcRecreateGen++
	gen := kvSvcRecreateGen
	kvSvcRecreating[svcID] = &kvSvcRecreate{gen: gen, running: true}
	c.denied, c.fault = true, ""
	kvSvcMu.Unlock()
	go func() {
		// Every data-plane work queued before this point, the removal
		// included, is done after the barrier: the install cannot land on
		// the pool that is going away. Until the new pool exists the install
		// retries. Only the latest re-create's install releases the fence.
		if mh.dp != nil {
			DpBrokerSyncBarrier(mh.dp)
		}
		if kvDataplaneContractApplyGen(svcID, kvContractSetter_get(),
			20, 200*time.Millisecond, 0, gen) == nil {
			kvAttestActivate(svcID)
			return
		}
		kvSvcRecreateEnded(svcID, gen)
		// Failed for good: the rule stays fenced. Its attestation
		// controller re-runs its fence step, which meets the same data
		// plane and publishes the fault (reason: the binding's data-plane
		// word is pending); the install is then tried again
		// on a slow pace until it takes, a later re-create supersedes it,
		// or the rule is deleted.
		KvAttestKick(svcID, KvAttestReasonBindingDataplanePending)
		kvStrictRecreateRetry(svcID, gen)
	}()
}

// kvStrictRecreateRetry tries a failed re-create's install again, one
// attempt every kvRecreateRetryNs, until it is acknowledged (the ladder
// then runs again), superseded, or the rule is gone.
func kvStrictRecreateRetry(svcID uint32, gen uint64) {
	for {
		time.Sleep(time.Duration(kvRecreateRetryNs.Load()))
		setter := kvContractSetter_get()
		if setter == nil {
			continue
		}
		lk := kvSvcInstallLock(svcID)
		lk.Lock()
		done, err := kvDataplaneContractAttempt(svcID, setter, 0, gen)
		lk.Unlock()
		if !done {
			continue
		}
		if err == nil {
			if _, ok := kvSvcContractSnapshot(svcID); ok {
				tk.LogIt(tk.LogInfo, "kv-contract: svc %d re-created pool's word installed on retry\n", svcID)
				kvAttestActivate(svcID)
			}
		}
		return
	}
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
	_, rc := kvBridgeBinding(svcID, bindingGen)
	return rc
}

// kvBridgeBinding is kvBridgeGate returning the resolved binding snapshot
// (nil on a legacy path, which carries no binding).
func kvBridgeBinding(svcID, bindingGen uint32) (*KvExactBinding, int) {
	if svcID != 0 && kvSvcDenied(svcID) {
		return nil, KvTokErrNotReady
	}
	if bindingGen == 0 {
		return nil, 0
	}
	ident, ok := kvSvcRuleIdent(svcID)
	if !ok {
		return nil, KvTokErrProfile
	}
	b, ok := KvBindingResolve(ident, bindingGen)
	if !ok {
		return nil, KvTokErrProfile
	}
	return b, 0
}

// kvBridgeEncodeCompletions encodes a strict rule's text completions prompt
// through the encoder of the engine contract its binding names. A profile or
// contract that no longer resolves, or an encoding its engine module does
// not reproduce, is a profile-resolution fault: admission proved both.
func kvBridgeEncodeCompletions(b *KvExactBinding, text, model string, max int) ([]uint32, int) {
	e, ok := kvProfileByID(b.Components.Profile.ID)
	if !ok {
		return nil, KvTokErrProfile
	}
	tokens, err := kvEncodeCompletions(kvTokenizeWithCache,
		kvCompletionsEncodingOf(&e.Profile, b.Components.Contract.ID), text, model, max)
	if err != nil {
		return nil, KvTokErrProfile
	}
	return tokens, 0
}

// kvBridgeTokenize is the typed core of the llb_ai_kv_tokenize CGO export.
// Legacy paths (bindingGen == 0) return exactly the codes the pre-contract bridge
// produced (-1 for every failure) so legacy rule behavior — and its metric
// attribution — is unchanged; strict paths classify per plan §8.
func kvBridgeTokenize(svcID, bindingGen uint32, text, model string, max int) ([]uint32, int) {
	binding, rc := kvBridgeBinding(svcID, bindingGen)
	if rc != 0 {
		return nil, rc
	}
	if text == "" || model == "" || max <= 0 {
		return nil, KvTokErrRequest
	}
	if rc := kvBridgeNulGuard(text, bindingGen != 0); rc != 0 {
		return nil, rc
	}
	var tokens []uint32
	if binding != nil {
		// Strict rule: the bound engine's encoder module decides how a text
		// completions prompt becomes ids.
		if tokens, rc = kvBridgeEncodeCompletions(binding, text, model, max); rc != 0 {
			return nil, rc
		}
	} else {
		// Legacy rule, raw completions prompt: encode with specials so the id
		// stream matches vLLM's add_special_tokens=True completions
		// tokenization (BOS included on tokenizers that declare one).
		tokens = kvTokenizeWithCache(text, model, max, true)
	}
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

// kvBridgeNulGuard refuses text carrying a NUL byte (a JSON "\u0000"
// escape decodes to one). The tokenizer binding hands the text to Rust as a C
// string, so everything after the NUL would be silently dropped and the
// gateway would hash a prefix of what the engine tokenizes. Request-class on
// both paths: strict rules report UNSUPPORTED, legacy rules the generic
// request failure they already return for unusable input.
func kvBridgeNulGuard(text string, strict bool) int {
	if strings.IndexByte(text, 0) < 0 {
		return 0
	}
	if strict {
		return KvTokErrUnsupported
	}
	return KvTokErrRequest
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
	binding, rc := kvBridgeBinding(svcID, bindingGen)
	if rc != 0 {
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
	// toolsReq is set only on the tools-aware path: LOXILB_KV_TOOLS_EXACT on
	// AND the binding is the attested target (kvToolsExactEligible). Off, or
	// for any other profile, the flow below is the previous release's.
	var toolsReq *kvChatToolsRequest
	var toolsEntry *kvProfileEntry
	if strict {
		// No profile leaves the engine default (true) to compare against;
		// the render below then faults on the missing renderer anyway.
		addGen := true
		e, hasProfile := kvProfileByModel(model)
		if hasProfile {
			addGen = e.Profile.RenderPolicy.AddGenerationPrompt
		}
		feature := kvChatExcludedFeature(body, addGen)
		if kvToolsExactLifts(feature) && hasProfile && kvToolsExactEligible(svcID, binding, e) {
			// The tools and chat_template_kwargs refusals are lifted (the
			// kwargs are allowlisted by kvChatToolsParse below); every other
			// refusal still applies.
			feature = kvChatExcludedFeatureOpts(body, addGen, true)
			if feature == "" {
				if tf := kvChatTemplateFeatureOpts(body, string(e.TemplateBytes), kvChatToolsModeledKeys); tf != "" {
					return nil, KvTokErrUnsupported
				}
				req, reason := kvChatToolsParse(body)
				if reason != "" {
					// Request class: a shape the engine refuses with 400 or
					// coerces in a way the gateway does not reproduce.
					return nil, KvTokErrUnsupported
				}
				toolsReq, toolsEntry = req, e
			}
		}
		if feature != "" {
			return nil, KvTokErrUnsupported
		}
		if toolsReq == nil && hasProfile {
			if feature := kvChatTemplateFeature(body, string(e.TemplateBytes)); feature != "" {
				return nil, KvTokErrUnsupported
			}
		}
	}
	// One instant for every render of this request: a date-printing template
	// rendered twice across midnight must not look shape-dependent.
	now := kvChatClock()
	clock := func() time.Time { return now }
	var rendered string
	var err error
	if toolsReq != nil {
		rendered, err = kvRenderChatToolsReq(toolsEntry, toolsReq, clock)
	} else {
		rendered, err = kvRenderChatTemplateReq(model, msgs, clock)
	}
	if err != nil {
		if !strict {
			return nil, KvTokErrRequest
		}
		if errors.Is(err, errKvNoChatRenderer) {
			// Admission refuses a declared chat surface without a validated
			// renderer, so a strict rule reaching this branch means the
			// renderer itself failed.
			return nil, kvBridgeRuntimeFault(svcID, KvTokErrRenderer)
		}
		// The validated template refused these messages: request-class,
		// never readiness-affecting (I-12).
		return nil, KvTokErrUnsupported
	}
	if strict && kvChatContentShapeDependent(model, body, msgs, rendered, clock) {
		// The engine's prompt depends on the content shape it hands the
		// template: request-class, like the refusals above.
		return nil, KvTokErrUnsupported
	}
	if rc := kvBridgeNulGuard(rendered, strict); rc != 0 {
		return nil, rc
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
