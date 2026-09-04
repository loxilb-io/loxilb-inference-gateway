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

// ai_kv_attest_trtllm_test.go — GPU-free suite for the TRT-LLM attestation
// adapter (§16.5 TRT row): /server_info self-describing identity (the rc24+
// versionSelector arm, with the tokens_per_block + hash-mode read-back),
// the approved-oracle token-parity path (no engine tokenize surface), the
// drain re-hash echo challenge, and the ladder's oracle parity-state
// publication. The engine-neutral echo machinery is covered by
// ai_kv_attest_echo_test.go; this file reuses its harness seams.
//
// NOTE: pkg/loxinet is a CGO package — these tests are AUTHORED here and
// validated on the remote GPU testbed; darwin-local verification is
// structural only (gofmt + grep).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- harness ----

// kvTrtTestConf parameterizes the fake TRT-LLM endpoint (the pinned
// /server_info + /v1/models + /v1/completions surface the adapter consumes;
// shapes from trtllmFixtureServerInfo and the trtllm-serve OpenAI routes).
type kvTrtTestConf struct {
	model          string
	hashAlgo       string // kv_cache_hash_algo ("" => field omitted)
	tokensPerBlock int    // 0 => field omitted
	// legacyShape serves the pre-rc24 /server_info (no kv fields at all).
	legacyShape bool
	// serverInfoRaw, when non-empty, is served verbatim (schema mutations).
	serverInfoRaw string
	// completionsStatus for /v1/completions (0 => 200).
	completionsStatus int
	// lastCompletionsBody, when non-nil, captures the most recent
	// /v1/completions request body ("" until one arrives).
	lastCompletionsBody *string
}

func kvTrtTestServer(t *testing.T, conf kvTrtTestConf) (*httptest.Server, KvAttestEndpoint) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server_info":
			if conf.serverInfoRaw != "" {
				fmt.Fprint(w, conf.serverInfoRaw)
				return
			}
			si := map[string]interface{}{
				// unconsumed fields the pinned decoder must tolerate
				// (live shape: trtllmFixtureServerInfo).
				"disaggregated_params": nil,
				"max_batch_size":       2048,
			}
			if !conf.legacyShape {
				if conf.hashAlgo != "" {
					si["kv_cache_hash_algo"] = conf.hashAlgo
				}
				if conf.tokensPerBlock != 0 {
					si["tokens_per_block"] = conf.tokensPerBlock
				}
			}
			json.NewEncoder(w).Encode(si)
		case "/v1/models":
			fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"object":"model"}]}`, conf.model)
		case "/v1/completions":
			body, _ := io.ReadAll(r.Body)
			if conf.lastCompletionsBody != nil {
				*conf.lastCompletionsBody = string(body)
			}
			st := conf.completionsStatus
			if st == 0 {
				st = 200
			}
			w.WriteHeader(st)
			fmt.Fprint(w, `{}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, kvTestEndpoint(t, ts)
}

// kvTrtTestHasher accepts only the TRT algo binding (the challenge must ask
// for blockhash_trtllm, never a vLLM/SGLang algo); deterministic chaining.
func kvTrtTestHasher(algo string, blockSize uint32, tokens []uint32) ([]uint64, bool) {
	if algo != "blockhash_trtllm" {
		return nil, false
	}
	nBlocks := len(tokens) / int(blockSize)
	out := make([]uint64, 0, nBlocks)
	var h uint64 = 14695981039346656037
	for b := 0; b < nBlocks; b++ {
		for i := 0; i < int(blockSize); i++ {
			h = (h ^ uint64(tokens[b*int(blockSize)+i])) * 1099511628211
		}
		out = append(out, h)
	}
	return out, true
}

func kvTrtTestSetup(t *testing.T) {
	t.Helper()
	prevTok := kvChallengeTokenizeFn
	kvChallengeTokenizeFn = kvEchoTestTokenizer
	KvRegisterChallengeHasher(kvTrtTestHasher)
	prevTimeout := kvChallengeTimeoutV
	kvChallengeTimeoutV = 2 * time.Second
	t.Cleanup(func() {
		kvChallengeTokenizeFn = prevTok
		KvRegisterChallengeHasher(nil)
		kvChallengeTimeoutV = prevTimeout
	})
}

func kvTrtInfo() kvAttestRuleInfo {
	return kvAttestRuleInfo{
		svcID: 47, ruleIdent: "rule-47", modelName: "m-trt", engine: "trtllm",
		hashAlgo: "blockhash_trtllm", blockSize: kvEchoTestBS, profileID: "prof-trt",
		apiCompl: true,
	}
}

// kvTrtGoodConf returns a server conf coherent with kvTrtInfo defaults.
func kvTrtGoodConf() kvTrtTestConf {
	return kvTrtTestConf{
		model: "m-trt", hashAlgo: kvTrtllmHashAlgoV1, tokensPerBlock: kvEchoTestBS,
	}
}

// kvWriteTrtllmProbeFixture writes a fixture pair into the TRT-scoped
// subdirectory probefixtures/<profileID>/trtllm with an explicit api shape.
func kvWriteTrtllmProbeFixture(t *testing.T, root, profileID, name, api string, request []byte, tokens []int64) {
	t.Helper()
	dir := filepath.Join(root, "probefixtures", profileID, kvTrtllmFixtureSub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(request)
	exp := map[string]interface{}{
		"requestSha256":    hex.EncodeToString(sum[:]),
		"expectedTokenIds": tokens,
		"api":              api,
	}
	expRaw, _ := json.Marshal(exp)
	if err := os.WriteFile(filepath.Join(dir, name+".request.json"), request, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".expect.json"), expRaw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// kvTrtOracleSeam installs a deterministic oracle encode and returns a
// pointer to the addSpecials value the last call carried.
func kvTrtOracleSeam(t *testing.T, out []uint32) *bool {
	t.Helper()
	lastSpecials := new(bool)
	prev := kvTrtllmOracleEncodeFn
	kvTrtllmOracleEncodeFn = func(text, model string, max int, addSpecials bool) []uint32 {
		*lastSpecials = addSpecials
		return append([]uint32(nil), out...)
	}
	t.Cleanup(func() { kvTrtllmOracleEncodeFn = prev })
	return lastSpecials
}

// ---- adapter selection ----

func TestKvTrtllmAdapterSelected(t *testing.T) {
	if kvAttestAdapterFor("trtllm") == nil {
		t.Fatal("trtllm must resolve an attestation adapter")
	}
	if kvAttestAdapterFor("llamacpp") != nil {
		t.Fatal("llamacpp must stay adapter-less (no event plane — §16.5)")
	}
}

// ---- identity (rc24+ self-description) ----

func TestKvTrtllmIdentityProbe(t *testing.T) {
	manifest := &KvAttestManifest{ProfileID: "prof-trt", EngineVersion: "1.3.0rc24", Digest: "mdig"}

	t.Run("live-shape-ok-with-readback", func(t *testing.T) {
		_, ep := kvTrtTestServer(t, kvTrtGoodConf())
		f := newKvTrtllmAttest().IdentityProbe(ep, manifest)
		if !f.OK {
			t.Fatalf("identity failed: %s %s", f.Reason, f.Detail)
		}
		if !strings.Contains(f.Detail, "tokens_per_block=") ||
			!strings.Contains(f.Detail, "kv_cache_hash_algo="+kvTrtllmHashAlgoV1) {
			t.Fatalf("identity detail must record the read-back, got %q", f.Detail)
		}
	})
	t.Run("legacy-shape-fails-identity", func(t *testing.T) {
		conf := kvTrtGoodConf()
		conf.legacyShape = true
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().IdentityProbe(ep, manifest)
		if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
			t.Fatalf("pre-rc24 shape must fail identity under a manifest: OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("v2-hash-mode-fails-identity", func(t *testing.T) {
		conf := kvTrtGoodConf()
		conf.hashAlgo = "v2_sha256"
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().IdentityProbe(ep, manifest)
		if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
			t.Fatalf("v2 hash mode must fail identity: OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("unparseable-schema", func(t *testing.T) {
		conf := kvTrtGoodConf()
		conf.serverInfoRaw = `not json`
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().IdentityProbe(ep, manifest)
		if f.OK || f.Reason != KvAttestReasonProbeSchema {
			t.Fatalf("want probe_schema_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
}

// ---- token parity (approved-oracle path) ----

func TestKvTrtllmTokenParityOracle(t *testing.T) {
	info := kvTrtInfo()
	req := []byte(`{"model":"m-trt","prompt":"oracle parity probe"}`)
	want := []int64{101, 202, 303, 404}
	oracleOut := []uint32{101, 202, 303, 404}
	_, ep := kvTrtTestServer(t, kvTrtGoodConf()) // never consulted; asserts no-crash addressing

	t.Run("green-oracle-marked", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteTrtllmProbeFixture(t, root, info.profileID, "basic", "completions", req, want)
		lastSpecials := kvTrtOracleSeam(t, oracleOut)
		f := newKvTrtllmAttest().TokenParityProbe(ep, info)
		if !f.OK {
			t.Fatalf("oracle parity failed: %s %s", f.Reason, f.Detail)
		}
		if !f.Oracle {
			t.Fatal("a TRT parity finding must be Oracle-marked (§16.5) — TOKEN_PARITY_VERIFIED would overstate the evidence")
		}
		if !*lastSpecials {
			t.Fatal("completions oracle encode must add special tokens (kvBridgeTokenize contract)")
		}
	})
	t.Run("vllm-flat-dir-does-not-satisfy-trtllm", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteProbeFixture(t, root, info.profileID, "basic", req, want)
		kvTrtOracleSeam(t, oracleOut)
		f := newKvTrtllmAttest().TokenParityProbe(ep, info)
		if f.OK || f.Reason != KvAttestReasonFixturesMissing {
			t.Fatalf("vLLM flat-dir fixtures must not attest trtllm parity: OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("oracle-token-mismatch", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteTrtllmProbeFixture(t, root, info.profileID, "basic", "completions", req, want)
		kvTrtOracleSeam(t, []uint32{101, 202, 303, 999})
		f := newKvTrtllmAttest().TokenParityProbe(ep, info)
		if f.OK || f.Reason != KvAttestReasonTokenMismatch {
			t.Fatalf("want token_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("fixture-model-mismatch-refused", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		other := []byte(`{"model":"m-other","prompt":"oracle parity probe"}`)
		kvWriteTrtllmProbeFixture(t, root, info.profileID, "basic", "completions", other, want)
		kvTrtOracleSeam(t, oracleOut)
		f := newKvTrtllmAttest().TokenParityProbe(ep, info)
		if f.OK || f.Reason != KvAttestReasonProbeSchema {
			t.Fatalf("foreign-model fixture must refuse: OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("declared-chat-surface-uncovered-refused", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteTrtllmProbeFixture(t, root, info.profileID, "basic", "completions", req, want)
		kvTrtOracleSeam(t, oracleOut)
		chatInfo := info
		chatInfo.apiChat = true
		f := newKvTrtllmAttest().TokenParityProbe(ep, chatInfo)
		if f.OK || f.Reason != KvAttestReasonFixturesMissing {
			t.Fatalf("chat surface without chat fixtures must refuse: OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("chat-fixture-renders-and-encodes-without-specials", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		chatReq := []byte(`{"model":"m-trt","messages":[{"role":"user","content":"hi"}]}`)
		kvWriteTrtllmProbeFixture(t, root, info.profileID, "chat", "chat", chatReq, want)
		lastSpecials := kvTrtOracleSeam(t, oracleOut)
		// A static template renders "rendered" for any message list — the
		// same stub the registry seam used to provide, now through the
		// profile-driven render path.
		kvTestPublishChatProfile(t, info.modelName, "rendered",
			KvRenderPolicy{AddGenerationPrompt: true})
		chatInfo := info
		chatInfo.apiChat, chatInfo.apiCompl = true, false
		f := newKvTrtllmAttest().TokenParityProbe(ep, chatInfo)
		if !f.OK || !f.Oracle {
			t.Fatalf("chat oracle parity failed: OK=%v Oracle=%v %s %s", f.OK, f.Oracle, f.Reason, f.Detail)
		}
		if *lastSpecials {
			t.Fatal("chat oracle encode must NOT add special tokens (kvBridgeTokenizeChat contract)")
		}
	})
	t.Run("chat-fixture-without-renderer-is-trust-fault", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		chatReq := []byte(`{"model":"m-trt","messages":[{"role":"user","content":"hi"}]}`)
		kvWriteTrtllmProbeFixture(t, root, info.profileID, "chat", "chat", chatReq, want)
		kvTrtOracleSeam(t, oracleOut)
		chatInfo := info
		chatInfo.apiChat, chatInfo.apiCompl = true, false
		f := newKvTrtllmAttest().TokenParityProbe(ep, chatInfo)
		if f.OK || f.Reason != KvAttestReasonProfileResolution {
			t.Fatalf("missing renderer must be a trust-input fault: OK=%v %s", f.OK, f.Reason)
		}
	})
}

// ---- drain re-hash echo challenge ----

// kvTrtFeedEcho answers the next armed challenge for (svcID, epIdx) from a
// single stream (rank 0 — the TRT drain has no rank identity), optionally
// corrupting the echoed token list (mutateTok >= 0).
func kvTrtFeedEcho(t *testing.T, svcID uint32, epIdx int, mutateTok int) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			kvHashWatchMu.RLock()
			ws := kvHashWatches[kvHashWatchKey(svcID, epIdx)]
			kvHashWatchMu.RUnlock()
			if len(ws) > 0 {
				hashes, tokens := kvEchoWatchExpectation(ws[0])
				if mutateTok >= 0 && mutateTok < len(tokens) {
					tokens[mutateTok] ^= 0x5555
				}
				kvHashWatchObserve(svcID, epIdx, 0,
					kvEvent{Type: kvEventBlockStored, Hashes: hashes, Tokens: tokens})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
}

func TestKvTrtllmHashChallenge(t *testing.T) {
	t.Run("green-with-readback", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		_, ep := kvTrtTestServer(t, kvTrtGoodConf())
		kvTrtFeedEcho(t, info.svcID, ep.EpIdx, -1)
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if !f.OK {
			t.Fatalf("challenge failed: %s %s", f.Reason, f.Detail)
		}
		if !strings.Contains(f.Detail, "tokens_per_block=") {
			t.Fatalf("echo detail must record the geometry read-back, got %q", f.Detail)
		}
	})
	t.Run("geometry-mismatch-refused-before-inference", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		conf := kvTrtGoodConf()
		conf.tokensPerBlock = int(kvEchoTestBS) * 2
		last := new(string)
		conf.lastCompletionsBody = last
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonGeometryMismatch {
			t.Fatalf("want engine_geometry_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
		if *last != "" {
			t.Fatal("a geometry-refused endpoint must never receive challenge inference")
		}
	})
	t.Run("v2-hash-mode-refused", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		conf := kvTrtGoodConf()
		conf.hashAlgo = "v2_sha256"
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonGeometryMismatch {
			t.Fatalf("want geometry refusal on v2 hash mode, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("model-not-served", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		conf := kvTrtGoodConf()
		conf.model = "m-other"
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
			t.Fatalf("want identity_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("inference-5xx", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		conf := kvTrtGoodConf()
		conf.completionsStatus = 500
		_, ep := kvTrtTestServer(t, conf)
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonChallengeFailed {
			t.Fatalf("want challenge_failed, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("timeout-when-drain-silent", func(t *testing.T) {
		kvTrtTestSetup(t)
		kvChallengeTimeoutV = 300 * time.Millisecond
		info := kvTrtInfo()
		_, ep := kvTrtTestServer(t, kvTrtGoodConf())
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonChallengeTimeout {
			t.Fatalf("want challenge_timeout, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("echoed-token-mismatch-fails-wire-check", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		_, ep := kvTrtTestServer(t, kvTrtGoodConf())
		kvTrtFeedEcho(t, info.svcID, ep.EpIdx, 1)
		f := newKvTrtllmAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonChallengeFailed {
			t.Fatalf("a token-mutated echo must fail the §6.2 wire check: OK=%v %s", f.OK, f.Reason)
		}
	})
}

// ---- ladder parity-state publication ----

// TestKvAttestLadderOracleParityState pins the §16.5 state contract: a rule
// whose parity evidence is oracle-class must publish
// TOKEN_PARITY_NOT_AVAILABLE_WITH_APPROVED_ORACLE — never
// TOKEN_PARITY_VERIFIED — both on the climb and when rung 2 holds it there.
func TestKvAttestLadderOracleParityState(t *testing.T) {
	t.Run("climb-publishes-oracle-state", func(t *testing.T) {
		h := newAttestHarness(t)
		h.adapter.parity = KvAttestFinding{OK: true, Oracle: true}
		c := h.controller()
		c.fenceAndReattest("activation")
		if got := c.enforced; got != KvExactStateReady {
			t.Fatalf("enforced = %s, want READY (events %v)", got, h.rec.list())
		}
		if h.rec.indexOf("state:"+KvExactStateTokenParityNoOracle) < 0 {
			t.Fatalf("oracle parity state never published: %v", h.rec.list())
		}
		if h.rec.indexOf("state:"+KvExactStateTokenParity) >= 0 {
			t.Fatalf("TOKEN_PARITY_VERIFIED published on oracle-class evidence: %v", h.rec.list())
		}
	})
	t.Run("held-at-oracle-state-on-echo-failure", func(t *testing.T) {
		h := newAttestHarness(t)
		h.adapter.parity = KvAttestFinding{OK: true, Oracle: true}
		h.adapter.challenge = KvAttestFinding{Reason: KvAttestReasonChallengeTimeout, Detail: "silent drain"}
		c := h.controller()
		c.fenceAndReattest("activation")
		if got := c.enforced; got != KvExactStateTokenParityNoOracle {
			t.Fatalf("enforced = %s, want %s (events %v)", got, KvExactStateTokenParityNoOracle, h.rec.list())
		}
	})
}

// ---- committed chat fixture pairs (the banked oracle derivation) ----

// TestKvTrtllmCommittedChatFixturesParity replays the COMMITTED chat probe
// fixtures (cicd/common/kv_hash/fixtures/probefixtures/<profile>/trtllm,
// generated by gen_chat_probe_fixtures.py from the HF render-parity goldens)
// through the production oracle chain: kvParseChatMessages over the exact
// committed request bytes, the profile-driven executor render over the
// banked template artifact, then kvTrtllmOracleFixtureCheck's full-array
// token comparison. The encode seam maps ONLY the goldens' rendered bytes to
// the goldens' templated ids (the encode leg the goldens proved HF-side via
// encode_rendered_matches_templated), so a render or fixture drift fails the
// check instead of being absorbed by a permissive stub.
func TestKvTrtllmCommittedChatFixturesParity(t *testing.T) {
	for _, tc := range []struct {
		slug, profileDir, servedModel string
	}{
		{"Qwen__Qwen3-0.6B", "qwen3-06b-completions-v1", "Qwen/Qwen3-0.6B"},
		{"NousResearch__Meta-Llama-3.1-8B-Instruct", "llama31-8b-completions-v1",
			"NousResearch/Meta-Llama-3.1-8B-Instruct"},
	} {
		t.Run(tc.slug, func(t *testing.T) {
			kvCommittedChatFixturesParity(t, tc.slug, tc.profileDir, kvTrtllmFixtureSub, tc.servedModel)
		})
	}
}

// TestKvSharedRootCommittedChatFixturesParity replays the committed chat
// fixtures at the profile ROOT — the fixture home the vLLM adapter loads
// directly and the sglang cicd suite stages into the sglang subdirectory —
// through the same production oracle chain. Unlike the trtllm set, these
// request bytes are ALSO posted verbatim to a live engine tokenize route by
// TokenParityProbe, so the banked ids were live-verified against the
// engine's messages-form defaults before banking (P9d six-leg record).
func TestKvSharedRootCommittedChatFixturesParity(t *testing.T) {
	for _, tc := range []struct {
		slug, profileDir, servedModel string
	}{
		{"Qwen__Qwen3-0.6B", "qwen3-06b-completions-v1", "Qwen/Qwen3-0.6B"},
		{"NousResearch__Meta-Llama-3.1-8B-Instruct", "llama31-8b-completions-v1",
			"NousResearch/Meta-Llama-3.1-8B-Instruct"},
		{"LGAI-EXAONE__EXAONE-3.5-7.8B-Instruct", "exaone35-78b-completions-v1",
			"LGAI-EXAONE/EXAONE-3.5-7.8B-Instruct"},
	} {
		t.Run(tc.slug, func(t *testing.T) {
			kvCommittedChatFixturesParity(t, tc.slug, tc.profileDir, "", tc.servedModel)
		})
	}
}

func kvCommittedChatFixturesParity(t *testing.T, slug, profileDir, fixtureSub, servedModel string) {
	goldens := loadRenderParityFixture(t)
	model, ok := goldens.Models[slug]
	if !ok {
		t.Fatalf("render-parity goldens carry no model %s", slug)
	}
	src, err := os.ReadFile(kvHashFixturePath(t, "templates", slug, "chat_template.jinja"))
	if err != nil {
		t.Fatalf("banked template missing for %s: %v", slug, err)
	}
	kvTestPublishChatProfile(t, servedModel, string(src), KvRenderPolicy{
		AddGenerationPrompt: true, BosToken: model.BosToken, EosToken: model.EosToken})

	renderedToIDs := make(map[string][]int, len(model.Cases))
	for _, c := range model.Cases {
		renderedToIDs[c.Rendered] = c.TemplatedIds
	}
	prevEnc := kvTrtllmOracleEncodeFn
	kvTrtllmOracleEncodeFn = func(text, m string, max int, addSpecials bool) []uint32 {
		if addSpecials { // the render carries its own specials (kvBridgeTokenizeChat contract)
			return nil
		}
		ids, ok := renderedToIDs[text]
		if !ok {
			return nil
		}
		out := make([]uint32, 0, len(ids))
		for _, id := range ids {
			out = append(out, uint32(id))
		}
		return out
	}
	t.Cleanup(func() { kvTrtllmOracleEncodeFn = prevEnc })

	dir := kvHashFixturePath(t, "probefixtures", profileDir, fixtureSub)
	loadPair := func(t *testing.T, base string) kvProbeFixture {
		t.Helper()
		expRaw, err := os.ReadFile(filepath.Join(dir, base+".expect.json"))
		if err != nil {
			t.Fatalf("fixture %s: %v", base, err)
		}
		var exp kvProbeExpect
		dec := json.NewDecoder(strings.NewReader(string(expRaw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&exp); err != nil {
			t.Fatalf("fixture %s: strict parse: %v", base, err)
		}
		reqRaw, err := os.ReadFile(filepath.Join(dir, base+".request.json"))
		if err != nil {
			t.Fatalf("fixture %s: request: %v", base, err)
		}
		sum := sha256.Sum256(reqRaw)
		if hex.EncodeToString(sum[:]) != strings.ToLower(exp.RequestSha256) {
			t.Fatalf("fixture %s: committed request bytes drifted from pinned sha256", base)
		}
		return kvProbeFixture{Name: base, RequestBytes: reqRaw,
			RequestSha256: exp.RequestSha256, ExpectedIDs: exp.ExpectedTokenIds, API: exp.API}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("committed fixture dir missing: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "chat-") || !strings.HasSuffix(name, ".expect.json") {
			continue
		}
		base := strings.TrimSuffix(name, ".expect.json")
		caseName := strings.TrimPrefix(base, "chat-")
		if _, ok := model.Cases[caseName]; !ok {
			t.Fatalf("fixture %s has no golden case %q — regenerate fixtures and goldens together", base, caseName)
		}
		fx := loadPair(t, base)
		if fx.API != "chat" {
			t.Fatalf("fixture %s: api %q, want chat", base, fx.API)
		}
		if f := kvTrtllmOracleFixtureCheck(fx, servedModel); !f.OK {
			t.Fatalf("fixture %s failed the oracle chain: %s %s", base, f.Reason, f.Detail)
		}
		checked++
	}
	if checked != len(model.Cases) {
		t.Fatalf("checked %d committed chat fixtures, want one per golden case (%d)", checked, len(model.Cases))
	}

	t.Run("banked-id-drift-detected", func(t *testing.T) {
		fx := loadPair(t, "chat-user-only")
		fx.ExpectedIDs = append([]int64(nil), fx.ExpectedIDs...)
		fx.ExpectedIDs[len(fx.ExpectedIDs)-1]++
		f := kvTrtllmOracleFixtureCheck(fx, servedModel)
		if f.OK || f.Reason != KvAttestReasonTokenMismatch {
			t.Fatalf("drifted banked ids must fail token comparison: OK=%v %s", f.OK, f.Reason)
		}
	})
}
