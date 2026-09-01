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

// ai_kv_attest_test.go — GPU-free attestation + fence suite:
// drives the readiness ladder synchronously through deterministic fake
// dependencies and asserts the §7.2 ordering guarantees the design hangs on:
// fence-ACK strictly before DEGRADED publish, eligible=1 written only by the
// READY transition, plateaus that never flip eligibility, and the §7.4
// escalation to ENFORCEMENT_FAULT.

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// attestRecorder captures every externally visible effect of a controller in
// ONE ordered event list, so ordering assertions (fence before publish) are
// direct.
type attestRecorder struct {
	mu     sync.Mutex
	events []string
	// applyErrAt maps 1-based apply-call ordinals to injected errors.
	applyErrAt map[int]error
	applyCalls int
}

func (r *attestRecorder) record(ev string) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *attestRecorder) apply(svcID uint32, eligible uint8) error {
	r.mu.Lock()
	r.applyCalls++
	n := r.applyCalls
	err := r.applyErrAt[n]
	r.events = append(r.events, fmt.Sprintf("apply:%d", eligible))
	r.mu.Unlock()
	return err
}

func (r *attestRecorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func (r *attestRecorder) indexOf(ev string) int {
	for i, e := range r.list() {
		if e == ev {
			return i
		}
	}
	return -1
}

func (r *attestRecorder) count(ev string) int {
	n := 0
	for _, e := range r.list() {
		if e == ev {
			n++
		}
	}
	return n
}

// fakeAttestAdapter answers each rung from configurable outcomes.
type fakeAttestAdapter struct {
	identity  KvAttestFinding
	parity    KvAttestFinding
	challenge KvAttestFinding
}

func (f *fakeAttestAdapter) IdentityProbe(ep KvAttestEndpoint, m *KvAttestManifest) KvAttestFinding {
	return f.identity
}
func (f *fakeAttestAdapter) TokenParityProbe(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	return f.parity
}
func (f *fakeAttestAdapter) HashChallenge(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	return f.challenge
}

func okFinding() KvAttestFinding { return KvAttestFinding{OK: true} }

type attestHarness struct {
	rec     *attestRecorder
	adapter *fakeAttestAdapter
	deps    kvAttestDeps
	info    kvAttestRuleInfo
	nowV    time.Time
	nowMu   sync.Mutex
}

func (h *attestHarness) now() time.Time {
	h.nowMu.Lock()
	defer h.nowMu.Unlock()
	return h.nowV
}

func (h *attestHarness) advance(d time.Duration) {
	h.nowMu.Lock()
	h.nowV = h.nowV.Add(d)
	h.nowMu.Unlock()
}

func newAttestHarness(t *testing.T) *attestHarness {
	t.Helper()
	h := &attestHarness{
		rec:     &attestRecorder{applyErrAt: map[int]error{}},
		adapter: &fakeAttestAdapter{identity: okFinding(), parity: okFinding(), challenge: okFinding()},
		nowV:    time.Unix(1756000000, 0),
	}
	manifest := &KvAttestManifest{ProfileID: "prof-1", ImageDigest: "sha256:img", EngineVersion: "0.27.1", Digest: "mdigest"}
	h.info = kvAttestRuleInfo{
		svcID: 77, ruleIdent: "rule-77", modelName: "m1", engine: "vllm",
		hashAlgo: "sha256_cbor", blockSize: 16, profileID: "prof-1",
		apiChat: true, apiCompl: true,
	}
	h.deps = kvAttestDeps{
		adapterFor: func(engine string) kvAttestAdapter {
			if engine == "vllm" {
				return h.adapter
			}
			return nil
		},
		endpoints: func(svcID uint32) []KvAttestEndpoint {
			return []KvAttestEndpoint{{EpIdx: 0, IP: "10.0.0.2", Port: 8000}}
		},
		apply:            h.rec.apply,
		manifest:         func(id string) (*KvAttestManifest, bool) { return manifest, true },
		peerGate:         func(info kvAttestRuleInfo) (bool, string) { return true, "" },
		now:              h.now,
		requireManifest:  true,
		probeCadence:     time.Minute,
		challengeCadence: 30 * time.Minute,
	}

	// Route the metric seams into the same ordered event list.
	prevState, prevFault, prevProbe, prevEcho := kvAttestStateGaugeFn, kvAttestFaultGaugeFn, kvAttestProbeFailFn, kvAttestEchoFn
	kvAttestStateGaugeFn = func(rule, state string) { h.rec.record("state:" + state) }
	kvAttestFaultGaugeFn = func(rule string, fault bool) {}
	kvAttestProbeFailFn = func(reason string) { h.rec.record("probefail:" + reason) }
	kvAttestEchoFn = func(result string) { h.rec.record("echo:" + result) }
	t.Cleanup(func() {
		kvAttestStateGaugeFn, kvAttestFaultGaugeFn, kvAttestProbeFailFn, kvAttestEchoFn = prevState, prevFault, prevProbe, prevEcho
	})
	return h
}

func (h *attestHarness) controller() *kvAttestController {
	return newKvAttestController(h.info, h.deps)
}

// TestKvAttestLadderReachesReady: the full happy ladder — fence(0) first,
// every rung earned, exactly one eligible=1 write, READY published last.
func TestKvAttestLadderReachesReady(t *testing.T) {
	h := newAttestHarness(t)
	c := h.controller()
	c.fenceAndReattest("activation")

	if got := c.enforced; got != KvExactStateReady {
		t.Fatalf("enforced = %s, want READY (events %v)", got, h.rec.list())
	}
	if n := h.rec.count("apply:1"); n != 1 {
		t.Fatalf("eligible=1 applied %d times, want exactly 1 (events %v)", n, h.rec.list())
	}
	// §7.2 order: the fence apply precedes the DEGRADED publish, and the
	// eligible flip precedes the READY publish.
	if h.rec.indexOf("apply:0") > h.rec.indexOf("state:"+KvExactStateDegraded) {
		t.Fatalf("fence ACK must precede DEGRADED publish: %v", h.rec.list())
	}
	if h.rec.indexOf("apply:1") > h.rec.indexOf("state:"+KvExactStateReady) {
		t.Fatalf("eligible flip must precede READY publish: %v", h.rec.list())
	}
	// Receipts: identity + parity + echo for the single endpoint.
	recs := c.receipts
	if len(recs) != 3 {
		t.Fatalf("receipts = %d, want 3", len(recs))
	}
	for _, r := range recs {
		if !r.OK || r.Digest == "" || r.ManifestDigest != "mdigest" {
			t.Fatalf("bad receipt: %+v", r)
		}
	}
}

// TestKvAttestParityFailureHoldsFenced: a token-parity failure keeps the rule
// at PROFILE_VALIDATED with its typed reason; eligible=1 is never written.
func TestKvAttestParityFailureHoldsFenced(t *testing.T) {
	h := newAttestHarness(t)
	h.adapter.parity = KvAttestFinding{Reason: KvAttestReasonTokenMismatch, Detail: "token[3]"}
	c := h.controller()
	c.fenceAndReattest("activation")

	if c.enforced != KvExactStateProfileValidated {
		t.Fatalf("enforced = %s, want PROFILE_VALIDATED", c.enforced)
	}
	if len(c.reasons) == 0 || c.reasons[0] != KvAttestReasonTokenMismatch {
		t.Fatalf("reasons = %v", c.reasons)
	}
	if h.rec.count("apply:1") != 0 {
		t.Fatalf("eligible=1 must never be written on a failed ladder: %v", h.rec.list())
	}
	if h.rec.count("probefail:"+KvAttestReasonTokenMismatch) != 1 {
		t.Fatalf("probe-fail metric missing: %v", h.rec.list())
	}
}

// TestKvAttestIdentityMismatchHoldsFenced: manifest-vs-endpoint inconsistency
// is an attestation failure, not a warning (§6.4).
func TestKvAttestIdentityMismatchHoldsFenced(t *testing.T) {
	h := newAttestHarness(t)
	h.adapter.identity = KvAttestFinding{Reason: KvAttestReasonIdentityMismatch}
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateProfileValidated || h.rec.count("apply:1") != 0 {
		t.Fatalf("enforced = %s, applies = %v", c.enforced, h.rec.list())
	}
}

// TestKvAttestChallengeFailureHoldsAtTokenParity: the echo challenge failing
// leaves the rule at TOKEN_PARITY_VERIFIED, fenced.
func TestKvAttestChallengeFailureHoldsAtTokenParity(t *testing.T) {
	h := newAttestHarness(t)
	h.adapter.challenge = KvAttestFinding{Reason: KvAttestReasonChallengeTimeout}
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateTokenParity {
		t.Fatalf("enforced = %s, want TOKEN_PARITY_VERIFIED", c.enforced)
	}
	if h.rec.count("apply:1") != 0 {
		t.Fatalf("eligible=1 written on failed challenge: %v", h.rec.list())
	}
	if h.rec.count("echo:fail") != 1 {
		t.Fatalf("echo fail metric missing: %v", h.rec.list())
	}
}

// TestKvAttestManifestMissingPlateaus: requireManifest (default) without a
// manifest plateaus at ENGINE_HASH_ATTESTED with manifest_missing — exact
// stays bypassed (§6.4).
func TestKvAttestManifestMissingPlateaus(t *testing.T) {
	h := newAttestHarness(t)
	h.deps.manifest = func(id string) (*KvAttestManifest, bool) { return nil, false }
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateHashAttested {
		t.Fatalf("enforced = %s, want ENGINE_HASH_ATTESTED", c.enforced)
	}
	if len(c.reasons) == 0 || c.reasons[0] != KvAttestReasonManifestMissing {
		t.Fatalf("reasons = %v", c.reasons)
	}
	if h.rec.count("apply:1") != 0 {
		t.Fatalf("manifest-less rule flipped eligible: %v", h.rec.list())
	}
}

// TestKvAttestFunctionalOnlyOptIn: BOTH knobs lowered ⇒ manifest-less READY
// surfaces distinctly as READY_FUNCTIONAL_ONLY.
func TestKvAttestFunctionalOnlyOptIn(t *testing.T) {
	h := newAttestHarness(t)
	h.deps.manifest = func(id string) (*KvAttestManifest, bool) { return nil, false }
	h.deps.requireManifest = false
	h.deps.functionalOnly = true
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateReadyFunctional {
		t.Fatalf("enforced = %s, want READY_FUNCTIONAL_ONLY", c.enforced)
	}
	if h.rec.count("apply:1") != 1 {
		t.Fatalf("functional-only READY must still flip eligible: %v", h.rec.list())
	}
}

// TestKvAttestLoneOptInKnobStaysFenced: functionalOnly without lowering
// requireManifest documents intent but lifts nothing.
func TestKvAttestLoneOptInKnobStaysFenced(t *testing.T) {
	h := newAttestHarness(t)
	h.deps.manifest = func(id string) (*KvAttestManifest, bool) { return nil, false }
	h.deps.functionalOnly = true // requireManifest stays true
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateHashAttested || h.rec.count("apply:1") != 0 {
		t.Fatalf("lone opt-in knob lifted the plateau: %s %v", c.enforced, h.rec.list())
	}
}

// TestKvAttestPeerGateBlocksReady: §17.7 — any peer mismatch prohibits the
// flip; the rule plateaus at ENGINE_HASH_ATTESTED.
func TestKvAttestPeerGateBlocksReady(t *testing.T) {
	h := newAttestHarness(t)
	h.deps.peerGate = func(info kvAttestRuleInfo) (bool, string) {
		return false, "profile_set_digest_mismatch"
	}
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateHashAttested {
		t.Fatalf("enforced = %s, want ENGINE_HASH_ATTESTED", c.enforced)
	}
	if len(c.reasons) != 2 || c.reasons[0] != KvAttestReasonPeerMismatch {
		t.Fatalf("reasons = %v", c.reasons)
	}
	if h.rec.count("apply:1") != 0 {
		t.Fatalf("peer-blocked rule flipped eligible: %v", h.rec.list())
	}
}

// TestKvAttestFenceFailureIsEnforcementFault: an unACKable fence escalates
// per §7.4 — ENFORCEMENT_FAULT, never a silent normal state. (The apply
// transaction itself has already written the deny set; that half is pinned
// by the dataplane contract tests.)
func TestKvAttestFenceFailureIsEnforcementFault(t *testing.T) {
	h := newAttestHarness(t)
	h.rec.applyErrAt[1] = errors.New("setter down")
	c := h.controller()
	c.fenceAndReattest(KvAttestReasonRuntimeFault)
	if c.enforced != KvExactStateEnforcementFault {
		t.Fatalf("enforced = %s, want ENFORCEMENT_FAULT", c.enforced)
	}
	// The DEGRADED publish must NOT have happened — publish comes only
	// after a fence ACK.
	if h.rec.indexOf("state:"+KvExactStateDegraded) != -1 {
		t.Fatalf("DEGRADED published despite failed fence: %v", h.rec.list())
	}
}

// TestKvAttestEligibleFlipFailureIsEnforcementFault: the READY-transition
// apply failing is the same escalation.
func TestKvAttestEligibleFlipFailureIsEnforcementFault(t *testing.T) {
	h := newAttestHarness(t)
	h.rec.applyErrAt[2] = errors.New("flip lost") // 1=fence, 2=flip
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateEnforcementFault {
		t.Fatalf("enforced = %s, want ENFORCEMENT_FAULT (events %v)", c.enforced, h.rec.list())
	}
}

// TestKvAttestNoEndpointsHoldsFenced / adapter-less engines stay fenced at
// PROFILE_VALIDATED (TRT-LLM until its adapter lands; SGLang gained
// its adapter — the production mapping is pinned by
// TestKvSglangAdapterSelected, this harness fake only knows vllm).
func TestKvAttestNoEndpointsAndNoAdapterHoldFenced(t *testing.T) {
	h := newAttestHarness(t)
	h.deps.endpoints = func(svcID uint32) []KvAttestEndpoint { return nil }
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateProfileValidated || c.reasons[0] != KvAttestReasonNoEndpoints {
		t.Fatalf("state %s reasons %v", c.enforced, c.reasons)
	}

	h2 := newAttestHarness(t)
	h2.info.engine = "trtllm"
	c2 := h2.controller()
	c2.fenceAndReattest("activation")
	if c2.enforced != KvExactStateProfileValidated || c2.reasons[0] != KvAttestReasonAdapterUnavailable {
		t.Fatalf("state %s reasons %v", c2.enforced, c2.reasons)
	}
	if h2.rec.count("apply:1") != 0 {
		t.Fatalf("adapter-less engine flipped eligible")
	}
}

// TestKvAttestStalenessFences: §6.3 — a READY rule whose receipts age past
// 2× cadence is fenced and re-earns the ladder.
func TestKvAttestStalenessFences(t *testing.T) {
	h := newAttestHarness(t)
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateReady {
		t.Fatalf("precondition: READY, got %s", c.enforced)
	}
	base := h.rec.count("apply:0")

	h.advance(3 * h.deps.probeCadence) // > 2× probe cadence
	c.cadenceCheck()

	if got := h.rec.count("apply:0"); got <= base {
		t.Fatalf("staleness did not fence (apply:0 count %d -> %d)", base, got)
	}
	// The ladder re-ran and re-earned READY (probes still green).
	if c.enforced != KvExactStateReady {
		t.Fatalf("enforced after stale re-attest = %s", c.enforced)
	}
}

// TestKvAttestCadenceProbeFailureFences: a READY rule whose re-probe fails
// on the cadence is fenced (fence-first) and holds below READY.
func TestKvAttestCadenceProbeFailureFences(t *testing.T) {
	h := newAttestHarness(t)
	c := h.controller()
	c.fenceAndReattest("activation")
	h.adapter.parity = KvAttestFinding{Reason: KvAttestReasonTokenMismatch}

	h.advance(h.deps.probeCadence) // within freshness, probes re-run
	c.cadenceCheck()

	if c.enforced != KvExactStateProfileValidated {
		t.Fatalf("enforced = %s, want PROFILE_VALIDATED after drift", c.enforced)
	}
	if h.rec.count("apply:1") != 1 {
		t.Fatalf("drifted rule must not re-flip eligible: %v", h.rec.list())
	}
}

// TestKvAttestArtifactDriftFencesAndRecovers: a READY rule whose registry
// artifacts drift on disk is fenced within one cadence with the typed
// profile-resolution reason, the ladder holds fenced while the drift
// persists, and restoring the bytes re-earns READY without operator kicks.
func TestKvAttestArtifactDriftFencesAndRecovers(t *testing.T) {
	h := newAttestHarness(t)
	var freshErr error
	var freshMu sync.Mutex
	h.deps.profileFreshness = func(profileID string) error {
		if profileID != "prof-1" {
			t.Errorf("freshness probed wrong profile %q", profileID)
		}
		freshMu.Lock()
		defer freshMu.Unlock()
		return freshErr
	}
	c := h.controller()
	c.fenceAndReattest("activation")
	if c.enforced != KvExactStateReady {
		t.Fatalf("precondition: READY, got %s", c.enforced)
	}
	baseFences := h.rec.count("apply:0")

	freshMu.Lock()
	freshErr = fmt.Errorf("tokenizer bytes drifted")
	freshMu.Unlock()
	h.advance(h.deps.probeCadence)
	c.cadenceCheck()

	if c.enforced != KvExactStateProfileValidated {
		t.Fatalf("enforced = %s, want PROFILE_VALIDATED under drift", c.enforced)
	}
	if len(c.reasons) == 0 || c.reasons[0] != KvAttestReasonProfileResolution {
		t.Fatalf("reasons = %v, want [%s ...]", c.reasons, KvAttestReasonProfileResolution)
	}
	if got := h.rec.count("apply:0"); got <= baseFences {
		t.Fatalf("drift did not fence (apply:0 count %d -> %d)", baseFences, got)
	}
	if h.rec.count("probefail:"+KvAttestReasonProfileResolution) == 0 {
		t.Fatalf("probe-fail metric missing: %v", h.rec.list())
	}
	if h.rec.count("apply:1") != 1 {
		t.Fatalf("drifted rule must not re-flip eligible: %v", h.rec.list())
	}

	// Still drifted on the next cadence: the retry holds fenced.
	h.advance(h.deps.probeCadence)
	c.cadenceCheck()
	if c.enforced != KvExactStateProfileValidated {
		t.Fatalf("enforced = %s, want PROFILE_VALIDATED while drift persists", c.enforced)
	}
	if h.rec.count("apply:1") != 1 {
		t.Fatalf("eligible re-flipped while drifted: %v", h.rec.list())
	}

	// Bytes restored: the cadence retry re-earns the full ladder.
	freshMu.Lock()
	freshErr = nil
	freshMu.Unlock()
	h.advance(h.deps.probeCadence)
	c.cadenceCheck()
	if c.enforced != KvExactStateReady {
		t.Fatalf("enforced = %s, want READY after restore", c.enforced)
	}
	if h.rec.count("apply:1") != 2 {
		t.Fatalf("restore must re-flip eligible exactly once more: %v", h.rec.list())
	}
}

// TestKvAttestControllerLifecycle: Start/Kick/Stop through the registry with
// the production goroutine — the ladder re-runs on a kick, and Stop tears
// down the state gauge and the controller entry.
func TestKvAttestControllerLifecycle(t *testing.T) {
	h := newAttestHarness(t)
	ladders := make(chan struct{}, 16)
	baseApply := h.deps.apply
	h.deps.apply = func(svcID uint32, eligible uint8) error {
		err := baseApply(svcID, eligible)
		if eligible == 1 {
			select {
			case ladders <- struct{}{}:
			default:
			}
		}
		return err
	}
	c := KvAttestStart(h.info, h.deps)
	// The seam-restoring harness cleanup must not race the loop goroutine:
	// wait for the controller to fully exit before cleanups run.
	t.Cleanup(func() {
		KvAttestReset()
		c.wg.Wait()
	})

	waitLadder := func(what string) {
		select {
		case <-ladders:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s (events %v)", what, h.rec.list())
		}
	}
	waitLadder("activation ladder")

	// The apply signal fires inside the transaction, before the READY
	// publish — poll the status read-model rather than racing it.
	waitState := func(want string) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, enforced, _, ok := KvAttestStatus(h.info.svcID); ok && enforced == want {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		_, enforced, _, ok := KvAttestStatus(h.info.svcID)
		t.Fatalf("status never reached %s (ok=%v enforced=%s)", want, ok, enforced)
	}
	waitState(KvExactStateReady)

	KvAttestKick(h.info.svcID, "profile_reload")
	waitLadder("kicked ladder")

	KvAttestStop(h.info.svcID)
	if _, _, _, ok := KvAttestStatus(h.info.svcID); ok {
		t.Fatalf("controller survives Stop")
	}
	c.wg.Wait() // loop exit also clears the rule's metric series
}

// TestKvAttestApplyEligibleStampsAck: the refactored contract-apply at
// eligible=1 packs the eligible byte into the ACKed word and stamps the
// enforcement read-model (lastAckAt / lastApplied).
func TestKvAttestApplyEligibleStampsAck(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(9, "rule-9", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-9", kvTestComponents(1))
	if err != nil {
		t.Fatal(err)
	}
	var gotWord uint64
	if err := kvDataplaneContractApply(9, func(vip net.IP, port uint16, proto uint8,
		gen uint32, apiMode, eligible uint8) (uint64, bool) {
		w := KvContractPack(gen, 0, apiMode, eligible)
		gotWord = w
		return w, true
	}, 1, 0, 1); err != nil {
		t.Fatalf("apply(eligible=1): %v", err)
	}
	want := KvContractPack(b.BindingGen, 0, KvContractAPIBoth, 1)
	if gotWord != want {
		t.Fatalf("applied word 0x%x, want 0x%x", gotWord, want)
	}
	enf, found := KvSvcContractEnforcement(9)
	if !found || enf.GoFenced || enf.LastAckAt.IsZero() || enf.LastApplied != want {
		t.Fatalf("enforcement read-model after ACK: %+v (found=%v)", enf, found)
	}
}

// TestKvAttestStartReplacesOnInfoChange: a rule UPDATE re-registers changed
// attestation identity (e.g. kvDpRankCount) and re-activates through
// KvAttestStart. The running controller must be replaced — kicking it would
// re-earn every ladder against the stale declaration (live signature: dp=2
// sims + dp=2 rule read-back, yet every climb fails engine_geometry_mismatch
// because the controller still holds dpRanks=1).
func TestKvAttestStartReplacesOnInfoChange(t *testing.T) {
	h := newAttestHarness(t)
	c1 := KvAttestStart(h.info, h.deps)
	t.Cleanup(func() {
		KvAttestReset()
		c1.wg.Wait()
	})

	// Same identity re-activation keeps the controller (kick path).
	if c := KvAttestStart(h.info, h.deps); c != c1 {
		t.Fatalf("same-info re-activation must return the running controller")
	}

	// Updated identity (dpRanks 0->2) must REPLACE it.
	updated := h.info
	updated.dpRanks = 2
	c2 := KvAttestStart(updated, h.deps)
	t.Cleanup(func() {
		KvAttestReset()
		c2.wg.Wait()
	})
	if c2 == c1 {
		t.Fatalf("info change must start a fresh controller, got the stale one kicked")
	}
	if !c2.info.equal(updated) {
		t.Fatalf("replacement controller info = %+v, want %+v", c2.info, updated)
	}
	select {
	case <-c1.stop:
	case <-time.After(2 * time.Second):
		t.Fatalf("stale controller was not stopped on replacement")
	}
}

// TestKvAttestTypedReasonSurvivesReclimb: a rule held below READY re-runs
// the ladder every probe tick. The transitional hash_attestation_pending
// must be published only on ARRIVAL at TOKEN_PARITY_VERIFIED — a re-climb
// that republished it would erase the typed rung-2 verdict for all but a
// sliver of each cycle (live signature: T4/T5/T6 pollers reading
// hash_attestation_pending for 120s+ while every challenge timed out).
func TestKvAttestTypedReasonSurvivesReclimb(t *testing.T) {
	h := newAttestHarness(t)
	h.adapter.challenge = KvAttestFinding{Reason: KvAttestReasonChallengeTimeout,
		Detail: "expected hashes not observed within 15s"}
	c := h.controller()

	countTP := func() int {
		n := 0
		for _, e := range h.rec.list() {
			if e == "state:"+KvExactStateTokenParity {
				n++
			}
		}
		return n
	}

	c.runLadder() // arrival: pending publish + typed verdict publish
	if got := countTP(); got != 2 {
		t.Fatalf("first climb: %d TOKEN_PARITY publishes, want 2 (pending + verdict)", got)
	}
	if c.enforced != KvExactStateTokenParity || len(c.reasons) != 1 ||
		c.reasons[0] != KvAttestReasonChallengeTimeout {
		t.Fatalf("first climb verdict: state=%s reasons=%v", c.enforced, c.reasons)
	}

	c.runLadder() // re-climb: verdict publish ONLY — no transient in between
	if got := countTP(); got != 3 {
		t.Fatalf("re-climb: %d TOKEN_PARITY publishes total, want 3 (re-climb must not republish pending)", got)
	}
	if len(c.reasons) != 1 || c.reasons[0] != KvAttestReasonChallengeTimeout {
		t.Fatalf("re-climb erased the typed verdict: reasons=%v", c.reasons)
	}
}
