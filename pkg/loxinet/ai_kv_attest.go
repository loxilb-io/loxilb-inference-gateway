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

// ai_kv_attest.go — KV-exact runtime attestation: the engine-neutral
// readiness ladder that decides whether a strict rule's data-plane
// contract word may carry eligible=1.
//
// Ladder (plan §6.1, one rung earned at a time, per endpoint, consensus =
// every endpoint):
//
//   PROFILE_VALIDATED → TOKEN_PARITY_VERIFIED → ENGINE_HASH_ATTESTED → READY
//
// Exact routing is possible ONLY in READY (invariant I-13): the attestation
// controller is the single writer that ever applies the contract word with
// eligible=1, and it does so only after every rung has fresh receipts, the
// deployment-manifest trust root is satisfied (§6.4), and every eligible HA
// peer agrees on the composed identity (§17.7). Everything else in the
// gateway installs at eligible=0.
//
// Degradation is fence-FIRST (§7.2): on drift, fault, or staleness the
// controller fences the data plane (eligible=0, full ACK required) BEFORE
// publishing DEGRADED, then re-earns the ladder from the bottom. A fence
// that cannot be ACKed escalates per §7.4: the apply transaction has already
// written the Go deny set (same-process, cannot fail), the rule is marked
// ENFORCEMENT_FAULT, and the KvExactEnforcementFault alert fires from the
// enforcement-fault gauge.
//
// The controller is a single-writer state machine: one goroutine per rule
// consumes kicks (activation, profile reload, endpoint change, runtime
// fault, cadence) and runs ladder transitions inline. Tests drive the same
// transitions synchronously through deterministic injected dependencies.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	log "github.com/sirupsen/logrus"
)

// Attestation ladder states beyond the admission vocabulary (rules.go defines
// LEGACY_ACTIVE_UNATTESTED / PROFILE_VALIDATED / PENDING_DATAPLANE_CONTRACT /
// ENFORCEMENT_FAULT).
const (
	KvExactStateTokenParity = "TOKEN_PARITY_VERIFIED"
	// TOKEN_PARITY_NOT_AVAILABLE_WITH_APPROVED_ORACLE is the §6.1 alternate
	// second rung for engines without a tokenize endpoint (TRT-LLM);
	// the vLLM adapter never reports it.
	KvExactStateTokenParityNoOracle = "TOKEN_PARITY_NOT_AVAILABLE_WITH_APPROVED_ORACLE"
	KvExactStateHashAttested        = "ENGINE_HASH_ATTESTED"
	KvExactStateReady               = "READY"
	// READY_FUNCTIONAL_ONLY: manifest-less READY through the §6.4
	// privileged/audited/expiring opt-in — functionally attested, identity
	// trust root absent, exposed distinctly so the risk acceptance is
	// visible in status.
	KvExactStateReadyFunctional   = "READY_FUNCTIONAL_ONLY"
	KvExactStateDegrading         = "DEGRADING"
	KvExactStateDegraded          = "DEGRADED"
	KvExactStateRequiresMigration = "REQUIRES_MIGRATION"
)

// Typed attestation reason codes (bounded vocabulary; surfaced in status
// ReasonCodes and metric labels).
const (
	KvAttestReasonNoEndpoints        = "no_endpoints"
	KvAttestReasonAdapterUnavailable = "adapter_unavailable"
	KvAttestReasonIdentityMismatch   = "identity_mismatch"
	KvAttestReasonProbeSchema        = "probe_schema_mismatch"
	KvAttestReasonTokenMismatch      = "token_mismatch"
	KvAttestReasonEndpointUnreach    = "endpoint_unreachable"
	KvAttestReasonChallengeFailed    = "challenge_failed"
	KvAttestReasonChallengeTimeout   = "challenge_timeout"
	KvAttestReasonManifestMissing    = "manifest_missing"
	KvAttestReasonStale              = "attestation_stale"
	KvAttestReasonProfileResolution  = "profile_resolution_fault"
	KvAttestReasonPeerMismatch       = "peer_capability_mismatch"
	KvAttestReasonEnforcementFault   = "enforcement_fault"
	KvAttestReasonRuntimeFault       = "runtime_fault"
	// A profile-less KV-exact rule that arrived via restore: exact routing
	// is fenced (strict bypass) until a profile is attached by rule replace.
	KvAttestReasonRequiresMigration = "restored_profile_less_requires_migration"
)

// KvAttestManifest is the §6.4 deployment-manifest trust root: operator- or
// deploy-pipeline-provisioned identity of what SHOULD be running behind the
// rule. Its digest rides every receipt. Enforcement stays with the probes and
// the echo challenge — declared identity without functional proof is as
// insufficient as functional proof without identity.
type KvAttestManifest struct {
	ProfileID         string   `yaml:"profileId"`
	ImageDigest       string   `yaml:"imageDigest"`
	EngineVersion     string   `yaml:"engineVersion"`
	ModelRevision     string   `yaml:"modelRevision,omitempty"`
	TokenizerRevision string   `yaml:"tokenizerRevision,omitempty"`
	TemplateDigest    string   `yaml:"templateDigest,omitempty"`
	ServeArgs         []string `yaml:"serveArgs,omitempty"`
	// Digest is the sha256 of the manifest file bytes (computed at load,
	// never declared in the file).
	Digest string `yaml:"-"`
}

// KvAttestReceipt records one attestation observation. Receipts are the
// evidence chain behind runtimeAttested — bounded per controller, exposed
// through status, digested so a receipt can be cited immutably.
type KvAttestReceipt struct {
	Kind           string // "identity" | "token_parity" | "hash_echo"
	EndpointID     string
	OK             bool
	Reason         string // typed reason code ("" when OK)
	Detail         string
	At             time.Time
	ManifestDigest string
	Digest         string // sha256 over the canonical receipt content
}

// KvAttestEndpoint identifies one attestable endpoint of a rule: the
// inference-serving address plus the subscriber's endpoint index (the echo
// challenge correlates BlockStored events per epIdx).
type KvAttestEndpoint struct {
	EpIdx int
	IP    string
	Port  uint16
}

// ID returns the receipt/endpoint identity string.
func (e KvAttestEndpoint) ID() string {
	return fmt.Sprintf("%s:%d", e.IP, e.Port)
}

// KvAttestFinding is one probe/challenge outcome.
type KvAttestFinding struct {
	OK     bool
	Reason string // typed reason code on failure
	Detail string
}

// kvAttestRuleInfo is the immutable identity the controller attests against.
type kvAttestRuleInfo struct {
	svcID     uint32
	ruleIdent string
	modelName string
	engine    string // effective engine family ("vllm", "sglang", ...)
	hashAlgo  string // effective kvHashAlgo ("sha256_cbor" | "xxhash_cbor")
	blockSize uint32
	profileID string
	apiChat   bool
	apiCompl  bool
	// SGLang event-plane declaration (geometry preflight + DP-rank
	// challenge coverage); zero values take the engine defaults downstream.
	dpRanks uint16 // kvDpRankCount (0 => 1)
	zmqPort uint16 // kvZmqPort (0 => 5557)
	// SGLang P/D pair-challenge context (mode-1 rules): a disaggregation-mode
	// prefill engine refuses bootstrap-less inference, so the echo challenge
	// dispatches as a (prefill, decode) pair carrying the bootstrap triple.
	pdMode          bool
	pdBootstrapPort uint16             // 0 => engine default downstream
	decodeEPs       []KvAttestEndpoint // ep_role 2 counterparts for the pair
}

// equal is the controller-identity comparison (== is unavailable once the
// info carries the decode endpoint slice; a changed counterpart set must
// replace the controller like any other identity change).
func (a kvAttestRuleInfo) equal(b kvAttestRuleInfo) bool {
	return reflect.DeepEqual(a, b)
}

// kvAttestAdapter is the per-engine attestation surface (§16.5). The vLLM
// adapter lives in ai_kv_attest_vllm.go / ai_kv_attest_echo.go; SGLang and
// TRT-LLM adapters follow the same surface.
type kvAttestAdapter interface {
	// IdentityProbe verifies the running endpoint's self-reported identity
	// against the manifest (§6.4: /version + /v1/models consistency). Called
	// only when a manifest is present.
	IdentityProbe(ep KvAttestEndpoint, manifest *KvAttestManifest) KvAttestFinding
	// TokenParityProbe runs the §5 byte-exact fixture probes.
	TokenParityProbe(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding
	// HashChallenge runs the §6.2 nonce-unique echo challenge.
	HashChallenge(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding
}

// kvAttestDeps carries every external effect of the controller so the GPU-free
// suite can drive the machine deterministically. Production deps come from
// kvAttestProductionDeps().
type kvAttestDeps struct {
	adapterFor       func(engine string) kvAttestAdapter
	endpoints        func(svcID uint32) []KvAttestEndpoint
	apply            func(svcID uint32, eligible uint8) error
	manifest         func(profileID string) (*KvAttestManifest, bool)
	profileFreshness func(profileID string) error
	peerGate         func(info kvAttestRuleInfo) (bool, string)
	now              func() time.Time
	requireManifest  bool
	functionalOnly   bool
	probeCadence     time.Duration
	challengeCadence time.Duration
}

// kvAttestController is the single-writer per-rule readiness machine.
type kvAttestController struct {
	info kvAttestRuleInfo
	deps kvAttestDeps

	mu           sync.Mutex
	desired      string
	enforced     string
	reasons      []string
	receipts     []KvAttestReceipt
	lastProbeOK  time.Time
	lastEchoOK   time.Time
	manifestSeen string // digest of the manifest the current rungs attest to

	stop chan struct{}
	kick chan string
	wg   sync.WaitGroup
}

const kvAttestReceiptCap = 32

var (
	kvAttestMu          sync.RWMutex
	kvAttestControllers = make(map[uint32]*kvAttestController)
)

// Metric seams (kvColdSeedCounterFn precedent): defaults are the real
// Prometheus surface; unit tests override.
var (
	kvAttestStateGaugeFn = prom.SetKvAttestState
	kvAttestFaultGaugeFn = prom.SetKvAttestEnforcementFault
	kvAttestProbeFailFn  = prom.IncKvAttestProbeFail
	kvAttestEchoFn       = prom.IncKvAttestEcho
)

// ---- environment knobs (init-time reads, kvColdSeedN pattern) ----

var (
	kvAttestEnvOnce         sync.Once
	kvAttestProbeCadenceV   = 60 * time.Second
	kvAttestChallengeCadV   = 30 * time.Minute
	kvAttestRequireManifest = true
	kvAttestFunctionalOnly  = false
)

func kvAttestEnv() (time.Duration, time.Duration, bool, bool) {
	kvAttestEnvOnce.Do(func() {
		if v := os.Getenv("LOXILB_KV_ATTEST_PROBE_CADENCE_S"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				kvAttestProbeCadenceV = time.Duration(n) * time.Second
			} else {
				log.Warnf("[KV_ATTEST] invalid LOXILB_KV_ATTEST_PROBE_CADENCE_S=%q, using default %v", v, kvAttestProbeCadenceV)
			}
		}
		if v := os.Getenv("LOXILB_KV_ATTEST_CHALLENGE_CADENCE_S"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				kvAttestChallengeCadV = time.Duration(n) * time.Second
			} else {
				log.Warnf("[KV_ATTEST] invalid LOXILB_KV_ATTEST_CHALLENGE_CADENCE_S=%q, using default %v", v, kvAttestChallengeCadV)
			}
		}
		// requireManifest defaults TRUE (§6.4); lowering it is the audited
		// opt-in to challenge-only READY_FUNCTIONAL_ONLY. Both knobs must be
		// set for the plateau to lift — a lone "false" only documents intent.
		if v := os.Getenv("LOXILB_KV_ATTEST_REQUIRE_MANIFEST"); v == "false" || v == "0" {
			kvAttestRequireManifest = false
		}
		if v := os.Getenv("LOXILB_KV_ATTEST_FUNCTIONAL_ONLY_OPTIN"); v == "true" || v == "1" {
			kvAttestFunctionalOnly = true
			log.Warnf("[KV_ATTEST] READY_FUNCTIONAL_ONLY opt-in ACTIVE — manifest-less rules may reach functional READY (risk acceptance is on the operator)")
		}
	})
	return kvAttestProbeCadenceV, kvAttestChallengeCadV, kvAttestRequireManifest, kvAttestFunctionalOnly
}

// ---- controller registry ----

// KvAttestStart creates and launches the readiness machine for a strict rule
// whose data-plane contract word has been installed (fenced). Idempotent per
// svc_id: a second start for a live controller only kicks it.
func KvAttestStart(info kvAttestRuleInfo, deps kvAttestDeps) *kvAttestController {
	kvAttestMu.Lock()
	old := kvAttestControllers[info.svcID]
	if old != nil && old.info.equal(info) {
		kvAttestMu.Unlock()
		old.Kick("re-activation")
		return old
	}
	// A live controller with a DIFFERENT identity means the rule was updated
	// in place (dpRanks/zmqPort/profile/... changed without delete+recreate).
	// Kicking it would re-earn the ladder against the stale declaration —
	// e.g. a dpRanks bump would fail every climb as engine_geometry_mismatch
	// while the rule itself reads back the new value. Replace it instead;
	// the replacement re-earns from the bottom under the updated identity.
	if old != nil {
		delete(kvAttestControllers, info.svcID)
	}
	c := newKvAttestController(info, deps)
	kvAttestControllers[info.svcID] = c
	kvAttestMu.Unlock()
	if old != nil {
		close(old.stop)
	}

	c.wg.Add(1)
	go c.loop()
	c.Kick("activation")
	return c
}

// KvAttestStop tears down a rule's controller (rule delete). The contract
// word and deny set are handled by the caller's teardown path. Non-blocking
// for the caller: a ladder mid-probe can hold the loop goroutine for up to
// the probe/challenge timeout, and the rule-delete path must not wait on
// that — the loop goroutine clears the rule's metric series itself on exit,
// strictly after its last possible publish.
func KvAttestStop(svcID uint32) {
	kvAttestMu.Lock()
	c := kvAttestControllers[svcID]
	delete(kvAttestControllers, svcID)
	kvAttestMu.Unlock()
	if c != nil {
		close(c.stop)
	}
}

// KvAttestKick asks a rule's controller to fence and re-earn the ladder
// (profile reload, endpoint-set change, runtime-fault signal §8).
func KvAttestKick(svcID uint32, reason string) {
	kvAttestMu.RLock()
	c := kvAttestControllers[svcID]
	kvAttestMu.RUnlock()
	if c != nil {
		c.Kick(reason)
	}
}

// KvAttestReset stops every controller (tests, shutdown).
func KvAttestReset() {
	kvAttestMu.Lock()
	cs := kvAttestControllers
	kvAttestControllers = make(map[uint32]*kvAttestController)
	kvAttestMu.Unlock()
	for _, c := range cs {
		close(c.stop)
		c.wg.Wait()
	}
}

// KvAttestStatus reports a rule's ladder position for the status
// sub-resource ("" strings when no controller exists).
func KvAttestStatus(svcID uint32) (desired, enforced string, reasons []string, ok bool) {
	kvAttestMu.RLock()
	c := kvAttestControllers[svcID]
	kvAttestMu.RUnlock()
	if c == nil {
		return "", "", nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.desired, c.enforced, append([]string(nil), c.reasons...), true
}

// KvAttestReceipts returns a copy of a rule's receipt chain.
func KvAttestReceipts(svcID uint32) []KvAttestReceipt {
	kvAttestMu.RLock()
	c := kvAttestControllers[svcID]
	kvAttestMu.RUnlock()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]KvAttestReceipt(nil), c.receipts...)
}

func newKvAttestController(info kvAttestRuleInfo, deps kvAttestDeps) *kvAttestController {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.probeCadence <= 0 || deps.challengeCadence <= 0 {
		pc, cc, _, _ := kvAttestEnv()
		if deps.probeCadence <= 0 {
			deps.probeCadence = pc
		}
		if deps.challengeCadence <= 0 {
			deps.challengeCadence = cc
		}
	}
	return &kvAttestController{
		info:     info,
		deps:     deps,
		desired:  KvExactStateReady,
		enforced: KvExactStateProfileValidated,
		reasons:  []string{"attestation_pending"},
		stop:     make(chan struct{}),
		kick:     make(chan string, 4),
	}
}

// Kick requests a fence + re-attest cycle (non-blocking; coalesces).
func (c *kvAttestController) Kick(reason string) {
	select {
	case c.kick <- reason:
	default:
	}
}

// loop is the production single-writer: kicks and cadence ticks both land
// here, so every transition runs on one goroutine. A backlog of kicks
// coalesces into one fence+re-attest cycle — a runtime-fault storm cannot
// queue more ladders than it can trigger fresh ones.
func (c *kvAttestController) loop() {
	defer c.wg.Done()
	// Teardown clears this rule's metric series HERE, on the loop goroutine,
	// after the last possible publish — Stop itself stays non-blocking and
	// nothing can resurrect a cleared series.
	defer func() {
		kvAttestStateGaugeFn(c.info.ruleIdent, "")
		kvAttestFaultGaugeFn(c.info.ruleIdent, false)
	}()
	t := time.NewTicker(c.deps.probeCadence)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case reason := <-c.kick:
			c.drainKicks()
			c.fenceAndReattest(reason)
		case <-t.C:
			c.cadenceCheck()
		}
	}
}

func (c *kvAttestController) drainKicks() {
	for {
		select {
		case <-c.kick:
		default:
			return
		}
	}
}

// publish updates the machine's visible state (status + metrics). It is the
// ONLY state writer, and callers on the fence path invoke it strictly AFTER
// the fence ACK (§7.2 order: fence first, publish after). A stopped
// controller publishes nothing — teardown's series clear must be the final
// metric write (the Stop waiter clears AFTER the loop exits, so the last
// racing publish is still swept).
func (c *kvAttestController) publish(enforced string, reasons ...string) {
	c.mu.Lock()
	c.enforced = enforced
	c.reasons = reasons
	c.mu.Unlock()
	select {
	case <-c.stop:
		return
	default:
	}
	kvAttestStateGaugeFn(c.info.ruleIdent, enforced)
	kvAttestFaultGaugeFn(c.info.ruleIdent, enforced == KvExactStateEnforcementFault)
}

func (c *kvAttestController) addReceipt(r KvAttestReceipt) {
	r.Digest = kvSha256Hex([]byte(fmt.Sprintf("%s|%s|%t|%s|%s|%d|%s",
		r.Kind, r.EndpointID, r.OK, r.Reason, r.Detail, r.At.UnixNano(), r.ManifestDigest)))
	c.mu.Lock()
	c.receipts = append(c.receipts, r)
	if len(c.receipts) > kvAttestReceiptCap {
		c.receipts = c.receipts[len(c.receipts)-kvAttestReceiptCap:]
	}
	c.mu.Unlock()
	// Failed probes must be debuggable from the operator log alone: the
	// receipt detail names the exact disagreement (which geometry axis,
	// which rank set), while the status API carries only the reason code.
	if !r.OK {
		log.Warnf("kv-attest: rule %s %s probe ep %s failed: %s (%s)",
			c.info.ruleIdent, r.Kind, r.EndpointID, r.Reason, r.Detail)
	}
}

// fenceAndReattest is the §7.2 fence-first transaction: fence the data plane
// (eligible=0, full ACK), publish the degraded position only after the ACK,
// then re-earn the ladder from the bottom. The initial activation kick runs
// the same path — the fence is then a re-install of the already-fenced word,
// which is idempotent and re-verifies the binding digest.
func (c *kvAttestController) fenceAndReattest(reason string) {
	c.mu.Lock()
	c.desired = KvExactStateDegrading
	c.mu.Unlock()

	if err := c.deps.apply(c.info.svcID, 0); err != nil {
		// §7.4 escalation: the apply transaction has already written the Go
		// deny set (deny-on-failure is unconditional in
		// kvDataplaneContractApply) — exact is fenced regardless of C-side
		// state. Mark the fault and raise the alert gauge.
		c.mu.Lock()
		c.desired = KvExactStateReady
		c.mu.Unlock()
		c.publish(KvExactStateEnforcementFault, KvAttestReasonEnforcementFault, reason)
		log.Errorf("kv-attest: rule %s fence failed (%v) — Go deny set is the standing fence, rule marked ENFORCEMENT_FAULT", c.info.ruleIdent, err)
		return
	}
	c.publish(KvExactStateDegraded, reason)

	c.mu.Lock()
	c.desired = KvExactStateReady
	c.mu.Unlock()
	c.runLadder()
}

// runLadder earns the ladder bottom-up against the CURRENT endpoint set and
// binding generation. Precondition: the contract word is installed and
// fenced (eligible=0).
func (c *kvAttestController) runLadder() {
	info := c.info
	now := c.deps.now

	eps := c.deps.endpoints(info.svcID)
	if len(eps) == 0 {
		c.publish(KvExactStateProfileValidated, KvAttestReasonNoEndpoints)
		return
	}
	ad := c.deps.adapterFor(info.engine)
	if ad == nil {
		// No attestation adapter for this engine family yet: the rule
		// holds at PROFILE_VALIDATED, fenced.
		c.publish(KvExactStateProfileValidated, KvAttestReasonAdapterUnavailable)
		return
	}
	// The ladder is only earnable while the on-disk registry still matches
	// the loaded generation; a drifted artifact holds the rule fenced until
	// the operator restores the bytes or republishes the registry.
	if c.deps.profileFreshness != nil && info.profileID != "" {
		if err := c.deps.profileFreshness(info.profileID); err != nil {
			log.Errorf("kv-attest: rule %s profile artifacts unresolvable on disk (%v) — holding fenced", info.ruleIdent, err)
			c.publish(KvExactStateProfileValidated, KvAttestReasonProfileResolution)
			return
		}
	}

	manifest, haveManifest := c.deps.manifest(info.profileID)
	manifestDigest := ""
	if haveManifest {
		manifestDigest = manifest.Digest
	}
	c.mu.Lock()
	c.manifestSeen = manifestDigest
	c.mu.Unlock()

	// Rung 1 — TOKEN_PARITY_VERIFIED: identity consistency (when a manifest
	// names the expected identity) plus §5 byte-exact fixture probes, every
	// endpoint.
	for _, ep := range eps {
		if haveManifest {
			f := ad.IdentityProbe(ep, manifest)
			c.addReceipt(KvAttestReceipt{Kind: "identity", EndpointID: ep.ID(), OK: f.OK,
				Reason: f.Reason, Detail: f.Detail, At: now(), ManifestDigest: manifestDigest})
			if !f.OK {
				kvAttestProbeFailFn(f.Reason)
				c.publish(KvExactStateProfileValidated, f.Reason)
				return
			}
		}
		f := ad.TokenParityProbe(ep, info)
		c.addReceipt(KvAttestReceipt{Kind: "token_parity", EndpointID: ep.ID(), OK: f.OK,
			Reason: f.Reason, Detail: f.Detail, At: now(), ManifestDigest: manifestDigest})
		if !f.OK {
			kvAttestProbeFailFn(f.Reason)
			c.publish(KvExactStateProfileValidated, f.Reason)
			return
		}
	}
	c.mu.Lock()
	c.lastProbeOK = now()
	alreadyTokenParity := c.enforced == KvExactStateTokenParity
	c.mu.Unlock()
	// First arrival at rung 1 publishes the transitional reason; re-climbs
	// of a rule already holding here must NOT — the retry ladder runs every
	// probe tick, and republishing the transient would erase the typed
	// rung-2 verdict (challenge_timeout, engine_geometry_mismatch, ...) for
	// all but a sliver of each cycle, leaving status readers with a
	// permanent "pending" and no cause.
	if !alreadyTokenParity {
		c.publish(KvExactStateTokenParity, "hash_attestation_pending")
	}

	// Rung 2 — ENGINE_HASH_ATTESTED: the §6.2 echo challenge, every endpoint.
	for _, ep := range eps {
		f := ad.HashChallenge(ep, info)
		c.addReceipt(KvAttestReceipt{Kind: "hash_echo", EndpointID: ep.ID(), OK: f.OK,
			Reason: f.Reason, Detail: f.Detail, At: now(), ManifestDigest: manifestDigest})
		if !f.OK {
			kvAttestEchoFn("fail")
			c.publish(KvExactStateTokenParity, f.Reason)
			return
		}
		kvAttestEchoFn("ok")
	}
	c.mu.Lock()
	c.lastEchoOK = now()
	c.mu.Unlock()

	// Rung 3 — trust root (§6.4) and cluster capability (§17.7).
	ready := KvExactStateReady
	if !haveManifest {
		if c.deps.requireManifest || !c.deps.functionalOnly {
			c.publish(KvExactStateHashAttested, KvAttestReasonManifestMissing)
			return
		}
		ready = KvExactStateReadyFunctional
	}
	if c.deps.peerGate != nil {
		if ok, reason := c.deps.peerGate(c.info); !ok {
			c.publish(KvExactStateHashAttested, KvAttestReasonPeerMismatch, reason)
			return
		}
	}

	// READY — the one place in the gateway that writes eligible=1.
	if err := c.deps.apply(info.svcID, 1); err != nil {
		c.publish(KvExactStateEnforcementFault, KvAttestReasonEnforcementFault)
		log.Errorf("kv-attest: rule %s eligible-flip failed (%v) — Go deny set fences, rule marked ENFORCEMENT_FAULT", info.ruleIdent, err)
		return
	}
	c.publish(ready)
	log.Infof("kv-attest: rule %s READY (state=%s, manifest=%.12s) — exact eligibility enabled", info.ruleIdent, ready, manifestDigest)
}

// cadenceCheck runs on the probe cadence while the controller is live
// (§6.3): READY rules re-probe on every tick, re-challenge on the slow
// cadence, and fence on receipt staleness. Non-READY rules retry the ladder
// (the endpoint may have become reachable).
func (c *kvAttestController) cadenceCheck() {
	c.mu.Lock()
	enforced := c.enforced
	lastProbe := c.lastProbeOK
	lastEcho := c.lastEchoOK
	c.mu.Unlock()

	switch enforced {
	case KvExactStateReady, KvExactStateReadyFunctional:
		now := c.deps.now()
		if !lastProbe.IsZero() && now.Sub(lastProbe) > 2*c.deps.probeCadence {
			c.fenceAndReattest(KvAttestReasonStale)
			return
		}
		if !lastEcho.IsZero() && now.Sub(lastEcho) > 2*c.deps.challengeCadence {
			c.fenceAndReattest(KvAttestReasonStale)
			return
		}
		if !c.probeSweep() {
			// probeSweep already fenced.
			return
		}
		if now.Sub(lastEcho) > c.deps.challengeCadence {
			c.fenceAndReattest("challenge_cadence")
		}
	case KvExactStateEnforcementFault:
		// Only an explicit kick (setter recovering, operator action) retries
		// a fault — cadence retries would flap the alert.
	default:
		c.runLadder()
	}
}

// probeSweep re-runs the identity + token-parity probes against every
// endpoint of a READY rule. A failure fences (fence-first) and returns
// false.
func (c *kvAttestController) probeSweep() bool {
	info := c.info
	eps := c.deps.endpoints(info.svcID)
	if len(eps) == 0 {
		c.fenceAndReattest(KvAttestReasonNoEndpoints)
		return false
	}
	ad := c.deps.adapterFor(info.engine)
	if ad == nil {
		c.fenceAndReattest(KvAttestReasonAdapterUnavailable)
		return false
	}
	// §6.3 freshness covers the trust inputs on disk, not just the probes:
	// a READY rule whose registry artifacts no longer match the loaded
	// generation is serving from bytes an auditor can no longer trace.
	if c.deps.profileFreshness != nil && info.profileID != "" {
		if err := c.deps.profileFreshness(info.profileID); err != nil {
			log.Errorf("kv-attest: rule %s profile artifacts drifted on disk (%v) — fencing", info.ruleIdent, err)
			kvAttestProbeFailFn(KvAttestReasonProfileResolution)
			c.fenceAndReattest(KvAttestReasonProfileResolution)
			return false
		}
	}
	manifest, haveManifest := c.deps.manifest(info.profileID)
	c.mu.Lock()
	seen := c.manifestSeen
	c.mu.Unlock()
	manifestDigest := ""
	if haveManifest {
		manifestDigest = manifest.Digest
	}
	if manifestDigest != seen {
		// Trust root changed under a READY rule — full re-attest.
		c.fenceAndReattest("manifest_changed")
		return false
	}
	for _, ep := range eps {
		if haveManifest {
			if f := ad.IdentityProbe(ep, manifest); !f.OK {
				kvAttestProbeFailFn(f.Reason)
				c.fenceAndReattest(f.Reason)
				return false
			}
		}
		if f := ad.TokenParityProbe(ep, info); !f.OK {
			kvAttestProbeFailFn(f.Reason)
			c.fenceAndReattest(f.Reason)
			return false
		}
	}
	c.mu.Lock()
	c.lastProbeOK = c.deps.now()
	c.mu.Unlock()
	return true
}

// ---- §6.4 manifest loading (profile-registry trust discipline) ----

// kvAttestManifestMaxBytes caps a manifest document.
const kvAttestManifestMaxBytes = 64 * 1024

// kvAttestManifestLoad reads manifests/<profileId>.yaml beneath the profile
// registry root with the same secure-open rules as profile documents
// (beneath-only resolution, no symlinks, trusted owner/mode, size cap). A
// missing manifest is (nil, false); a PRESENT but untrusted/unparseable
// manifest is also (nil, false) after a loud log — fail-closed either way,
// because §6.4 treats "no trust root" and "broken trust root" identically
// (the rule plateaus at ENGINE_HASH_ATTESTED).
func kvAttestManifestLoad(profileID string) (*KvAttestManifest, bool) {
	root := kvAttestManifestRoot()
	rootFd, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	defer unix.Close(rootFd)

	rel := "manifests/" + profileID + ".yaml"
	raw, _, err := kvReadTrustedFile(rootFd, rel, kvAttestManifestMaxBytes)
	if err != nil {
		// %w-wrapped unix errors need errors.Is, not os.IsNotExist.
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
			log.Warnf("kv-attest: manifest %s unreadable/untrusted: %v (rule will plateau at %s)",
				rel, err, KvExactStateHashAttested)
		}
		return nil, false
	}
	var m KvAttestManifest
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		log.Warnf("kv-attest: manifest %s parse error: %v (rule will plateau at %s)",
			rel, err, KvExactStateHashAttested)
		return nil, false
	}
	if m.ProfileID != profileID {
		log.Warnf("kv-attest: manifest %s declares profileId %q (want %q) — refused",
			rel, m.ProfileID, profileID)
		return nil, false
	}
	if m.ImageDigest == "" || m.EngineVersion == "" {
		log.Warnf("kv-attest: manifest %s missing imageDigest/engineVersion — refused", rel)
		return nil, false
	}
	m.Digest = kvSha256Hex(raw)
	return &m, true
}

// kvAttestManifestRoot resolves the trusted root manifests load beneath: the
// SAME root the published profile generation came from, so a registry pointed
// at a test root (or a future alternate root) keeps profiles and manifests
// coherent. Falls back to the default registry dir before the first publish.
func kvAttestManifestRoot() string {
	if gen := kvProfileCurrent(); gen != nil && gen.SourceRoot != "" {
		return gen.SourceRoot
	}
	return KvProfileDir
}

// ---- production wiring ----

// kvAttestReg is a strict rule's registered attestation identity plus its
// attestable endpoint set. The endpoint set mirrors the SUBSCRIBER target
// set (mode-1: prefill EPs; single-role: every EP) with the subscriber's own
// epIdx values — event bridges exist only on subscribed endpoints, so echo
// consensus is scoped to them (probing beyond that set is a live-leg
// refinement).
type kvAttestReg struct {
	info kvAttestRuleInfo
	eps  []KvAttestEndpoint
}

var (
	kvAttestRegMu sync.RWMutex
	kvAttestRegs  = make(map[uint32]kvAttestReg)
)

// KvAttestRegister records a strict rule's attestation identity (AddLbRule,
// before the async contract install that will activate the controller).
func kvAttestRegisterRule(info kvAttestRuleInfo, eps []KvAttestEndpoint) {
	kvAttestRegMu.Lock()
	kvAttestRegs[info.svcID] = kvAttestReg{info: info, eps: eps}
	kvAttestRegMu.Unlock()
}

// kvAttestDeregisterRule drops registration state and stops the controller
// (rule teardown).
func kvAttestDeregisterRule(svcID uint32) {
	kvAttestRegMu.Lock()
	delete(kvAttestRegs, svcID)
	kvAttestRegMu.Unlock()
	KvAttestStop(svcID)
}

// kvAttestActivate launches the readiness machine for an installed rule
// (called by the install goroutine after its full ACK). A rule without a
// registration (legacy, or racing teardown) activates nothing.
func kvAttestActivate(svcID uint32) {
	kvAttestRegMu.RLock()
	reg, ok := kvAttestRegs[svcID]
	kvAttestRegMu.RUnlock()
	if !ok {
		return
	}
	KvAttestStart(reg.info, kvAttestProductionDeps())
}

// kvRuleAttestEndpoints resolves a rule's registered attestable endpoints.
func kvRuleAttestEndpoints(svcID uint32) []KvAttestEndpoint {
	kvAttestRegMu.RLock()
	defer kvAttestRegMu.RUnlock()
	return append([]KvAttestEndpoint(nil), kvAttestRegs[svcID].eps...)
}

// KvAttestKickAll fences and re-attests every live controller (profile
// registry republish — every strict rule's trust inputs may have moved).
func KvAttestKickAll(reason string) {
	kvAttestMu.RLock()
	ids := make([]uint32, 0, len(kvAttestControllers))
	for id := range kvAttestControllers {
		ids = append(ids, id)
	}
	kvAttestMu.RUnlock()
	for _, id := range ids {
		KvAttestKick(id, reason)
	}
}

// kvAttestProductionDeps builds the controller dependencies used by the live
// gateway.
func kvAttestProductionDeps() kvAttestDeps {
	pc, cc, reqManifest, funcOnly := kvAttestEnv()
	return kvAttestDeps{
		adapterFor: kvAttestAdapterFor,
		endpoints:  kvRuleAttestEndpoints,
		apply: func(svcID uint32, eligible uint8) error {
			return kvDataplaneContractApply(svcID, kvContractSetter_get(),
				3, 200*time.Millisecond, eligible)
		},
		manifest:         kvAttestManifestLoad,
		profileFreshness: KvProfileVerifyDisk,
		peerGate:         kvClusterCapabilityGate,
		now:              time.Now,
		requireManifest:  reqManifest,
		functionalOnly:   funcOnly,
		probeCadence:     pc,
		challengeCadence: cc,
	}
}

// kvAttestAdapterFor maps an effective engine family to its attestation
// adapter. vLLM and SGLang exist; TRT-LLM returns nil until its adapter lands
// (rules hold fenced at PROFILE_VALIDATED — fail-closed, never inferred
// from another engine's evidence).
func kvAttestAdapterFor(engine string) kvAttestAdapter {
	switch engine {
	case "", "vllm":
		return kvVllmAdapter()
	case "sglang":
		return kvSglangAdapter()
	default:
		return nil
	}
}
