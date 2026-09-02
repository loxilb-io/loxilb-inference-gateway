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
 * ai_kv_attest_trtllm.go — TensorRT-LLM attestation adapter (§16.5 TRT row).
 *
 * The engine has NO tokenize endpoint on any known tuple, so rung 1 cannot
 * run the byte-exact engine probe the vLLM/SGLang adapters use. The TRT
 * parity path is the APPROVED-ORACLE construction:
 *
 *   - The pinned oracle is the gateway's own profile tokenizer chain — the
 *     same digest-pinned artifacts and render/encode semantics the serving
 *     bridges (kvBridgeTokenize / kvBridgeTokenizeChat) hash requests with.
 *     TokenParityProbe re-derives every committed fixture's banked token IDs
 *     through that chain; any divergence means the loaded tokenizer/renderer
 *     no longer reproduces the reviewed vectors.
 *   - The LIVE cross-check is the drain echo: TRT stored events always carry
 *     full token lists, and the §6.2 watch (kvHashWatchObserve) compares
 *     every challenge block's event tokens against the gateway's own
 *     encoding. A green HashChallenge is therefore also the live half of the
 *     oracle parity evidence.
 *
 *   The rule's ladder consequently holds at
 *   TOKEN_PARITY_NOT_AVAILABLE_WITH_APPROVED_ORACLE instead of
 *   TOKEN_PARITY_VERIFIED (KvAttestFinding.Oracle), keeping the evidence
 *   class visible to status readers per §16.5.
 *
 * Identity (versionSelector rc24+ arm): the engine serves GET /server_info,
 * and from 1.3.0rc24 the response self-describes the KV event contract
 * (kv_cache_hash_algo, tokens_per_block — live-captured; see
 * trtllmFixtureServerInfo). The engine exposes NO version string at runtime
 * on any probed tuple, so the numeric tuple pin stays a deploy-time control
 * (manifest imageDigest/serveArgs); what IdentityProbe attests is the
 * rc24+ self-description itself: a manifest-pinned rule must be talking to
 * a self-describing endpoint whose hash mode is the v1 contract. The
 * pre-rc24 legacy shape (no kv fields) FAILS identity under a manifest —
 * that is the 1.2.x-vs-rc24+ selector split of §18.2 finding 4.
 *
 * The tokens_per_block + kv_cache_hash_algo read-back is recorded in the
 * identity and hash_echo receipt details (§16.5 "read-back recorded").
 *
 * Hash attestation is the drain re-hash echo: nonce prompt → the SUBSCRIBER's
 * own drain stream carries the stored token lists → the decoder re-hashes
 * them with the self-owned chained-SHA256 (blockhash_trtllm — both sides
 * ours, the engine's native hash never enters) → the watch compares against
 * the request-side chain. Geometry is preflighted against the endpoint's own
 * /server_info answer with the SAME rules the admission gate applies
 * (kvTrtllmAdmissionEvaluate) so attestation can never pass a contract the
 * poller would refuse.
 *
 * §17.4 boundary: a green challenge is functional evidence ONLY. Drain
 * ownership (DEC-007) is enforced by the ladder itself — runLadder/probeSweep
 * consult the ownership receipt before this adapter is ever asked — so
 * nothing here may be read as a sole-consumer proof (the RD-B03 withdrawal).
 *
 * NOTE: pkg/loxinet is a CGO package — validated on the remote GPU testbed;
 * darwin-local verification is structural only (gofmt + grep).
 */

package loxinet

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// kvTrtllmFixtureSub scopes the TRT fixture set beneath the profile
	// (probefixtures/<profileId>/trtllm) — same engine-scoped discipline as
	// the SGLang set; a vLLM flat-dir set never satisfies a TRT binding.
	kvTrtllmFixtureSub = "trtllm"

	// kvTrtllmOracleMaxTokens caps one oracle encode (same bound as the
	// challenge builder's — fixtures are short by construction).
	kvTrtllmOracleMaxTokens = 4096
)

// kvTrtllmOracleEncodeFn is the oracle encode seam: the SAME cache path the
// serving bridges hash requests with (attesting parity with anything else
// would attest the wrong tokenizer). Tests override.
var kvTrtllmOracleEncodeFn = func(text, model string, max int, addSpecials bool) []uint32 {
	return kvTokenizeWithCache(text, model, max, addSpecials)
}

// kvTrtllmAttest implements kvAttestAdapter for the TensorRT-LLM family.
type kvTrtllmAttest struct {
	client *http.Client
}

var (
	kvTrtllmAdapterOnce sync.Once
	kvTrtllmAdapterInst *kvTrtllmAttest
)

// kvTrtllmAdapter returns the process-wide TRT-LLM attestation adapter.
func kvTrtllmAdapter() kvAttestAdapter {
	kvTrtllmAdapterOnce.Do(func() {
		kvTrtllmAdapterInst = newKvTrtllmAttest()
	})
	return kvTrtllmAdapterInst
}

func newKvTrtllmAttest() *kvTrtllmAttest {
	return &kvTrtllmAttest{
		client: &http.Client{
			Timeout: kvProbeTimeout(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("kv-attest: probe redirect refused")
			},
		},
	}
}

// ---- identity / geometry ----

// serverInfo fetches and parses the endpoint's /server_info self-description
// (kvTrtllmServerInfo — the same pinned surface the admission gate consumes).
func (a *kvTrtllmAttest) serverInfo(ep KvAttestEndpoint) (*kvTrtllmServerInfo, KvAttestFinding) {
	body, f := kvAttestGetCapped(a.client, fmt.Sprintf("http://%s:%d/server_info", ep.IP, ep.Port))
	if !f.OK {
		return nil, f
	}
	var si kvTrtllmServerInfo
	if err := json.Unmarshal(body, &si); err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/server_info unparseable: %v", err)}
	}
	return &si, KvAttestFinding{OK: true}
}

// kvTrtllmReadback renders the receipt read-back fragment (§16.5).
func kvTrtllmReadback(si *kvTrtllmServerInfo) string {
	tpb := "absent"
	if si.TokensPerBlock != nil {
		tpb = fmt.Sprintf("%d", *si.TokensPerBlock)
	}
	algo := si.KvCacheHashAlgo
	if algo == "" {
		algo = "absent"
	}
	return fmt.Sprintf("tokens_per_block=%s kv_cache_hash_algo=%s", tpb, algo)
}

// IdentityProbe attests the rc24+ self-describing identity (file header): a
// manifest-pinned rule must reach a /server_info that self-describes the KV
// event contract on the v1 hash mode. The legacy 1.2.x shape (no kv fields)
// fails identity here — its geometry is only manifest-sourced and belongs to
// the other versionSelector arm, which no manifest on this path pins.
func (a *kvTrtllmAttest) IdentityProbe(ep KvAttestEndpoint, manifest *KvAttestManifest) KvAttestFinding {
	si, f := a.serverInfo(ep)
	if !f.OK {
		return f
	}
	if si.KvCacheHashAlgo == "" && si.TokensPerBlock == nil {
		return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
			Detail: fmt.Sprintf("/server_info self-describes no KV contract (pre-rc24 legacy shape) — manifest engineVersion %q pins the self-describing line",
				manifest.EngineVersion)}
	}
	if si.KvCacheHashAlgo != "" && si.KvCacheHashAlgo != kvTrtllmHashAlgoV1 {
		return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
			Detail: fmt.Sprintf("endpoint kv_cache_hash_algo %q is not the attested %q contract",
				si.KvCacheHashAlgo, kvTrtllmHashAlgoV1)}
	}
	return KvAttestFinding{OK: true, Detail: kvTrtllmReadback(si)}
}

// kvTrtllmModelServed checks /v1/models for the attested model (same OpenAI
// list surface the vLLM adapter consumes; live on trtllm-serve).
func (a *kvTrtllmAttest) kvTrtllmModelServed(ep KvAttestEndpoint, model string) KvAttestFinding {
	body, f := kvAttestGetCapped(a.client, fmt.Sprintf("http://%s:%d/v1/models", ep.IP, ep.Port))
	if !f.OK {
		return f
	}
	var mr struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &mr); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/v1/models unparseable: %v", err)}
	}
	for _, m := range mr.Data {
		if m.ID == model {
			return KvAttestFinding{OK: true}
		}
	}
	return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
		Detail: fmt.Sprintf("model %q not served by endpoint", model)}
}

// ---- token parity (§16.5 approved-oracle path) ----

// kvTrtllmFixtureReq pins the fixture request fields the oracle consumes.
type kvTrtllmFixtureReq struct {
	Model    string          `json:"model"`
	Prompt   *string         `json:"prompt"`
	Messages json.RawMessage `json:"messages"`
}

// TokenParityProbe runs the approved-oracle parity check (file header): every
// committed TRT fixture's banked token IDs must be reproduced by the
// gateway's own render/encode chain — completions encode with specials (the
// kvBridgeTokenize contract), chat renders through the validated template
// and encodes without (the kvBridgeTokenizeChat contract). The endpoint is
// not consulted (it has no tokenize surface); its live cross-check is the
// echo challenge's token comparison. The green finding is Oracle-marked so
// the ladder publishes the §16.5 oracle parity state, never
// TOKEN_PARITY_VERIFIED.
func (a *kvTrtllmAttest) TokenParityProbe(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	fixtures, err := kvProbeFixturesLoadDir("probefixtures/" + info.profileID + "/" + kvTrtllmFixtureSub)
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonFixturesMissing, Detail: err.Error()}
	}
	if f := kvFixtureSurfaceCheck(fixtures, info); !f.OK {
		return f
	}
	for _, fx := range fixtures {
		if f := kvTrtllmOracleFixtureCheck(fx, info.modelName); !f.OK {
			return f
		}
	}
	return KvAttestFinding{OK: true, Oracle: true,
		Detail: fmt.Sprintf("oracle path: %d fixtures reproduced by the pinned tokenizer chain (no engine tokenize surface; live cross-check = drain echo token comparison)", len(fixtures))}
}

// kvTrtllmOracleFixtureCheck re-derives one fixture through the oracle chain
// and compares the FULL token array against the banked expectation.
func kvTrtllmOracleFixtureCheck(fx kvProbeFixture, model string) KvAttestFinding {
	var req kvTrtllmFixtureReq
	if err := json.Unmarshal(fx.RequestBytes, &req); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: request unparseable: %v", fx.Name, err)}
	}
	if req.Model != model {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s declares model %q, rule attests %q", fx.Name, req.Model, model)}
	}

	var got []uint32
	switch fx.API {
	case "chat":
		msgs, ok := kvParseChatMessages(string(fx.RequestBytes))
		if !ok || len(msgs) == 0 {
			return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
				Detail: fmt.Sprintf("fixture %s: chat fixture carries no parseable messages", fx.Name)}
		}
		rendered, ok := kvRenderChatTemplate(model, msgs)
		if !ok || rendered == "" {
			// Admission refuses a declared chat surface without a validated
			// renderer; reaching this means the renderer registry no longer
			// covers the attested model — a trust-input fault, not a
			// request problem.
			return KvAttestFinding{Reason: KvAttestReasonProfileResolution,
				Detail: fmt.Sprintf("fixture %s: no validated chat renderer for model %q", fx.Name, model)}
		}
		// Chat renders carry their own special tokens (encode-mode
		// contract, kvBridgeTokenizeChat).
		got = kvTrtllmOracleEncodeFn(rendered, model, kvTrtllmOracleMaxTokens, false)
	case "completions":
		if req.Prompt == nil {
			return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
				Detail: fmt.Sprintf("fixture %s: completions fixture carries no prompt", fx.Name)}
		}
		got = kvTrtllmOracleEncodeFn(*req.Prompt, model, kvTrtllmOracleMaxTokens, true)
	default:
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: unknown api %q", fx.Name, fx.API)}
	}
	if len(got) == 0 {
		return KvAttestFinding{Reason: KvAttestReasonProfileResolution,
			Detail: fmt.Sprintf("fixture %s: oracle tokenizer produced no tokens for model %q", fx.Name, model)}
	}
	if len(got) != len(fx.ExpectedIDs) {
		return KvAttestFinding{Reason: KvAttestReasonTokenMismatch,
			Detail: fmt.Sprintf("fixture %s: oracle count %d != banked %d", fx.Name, len(got), len(fx.ExpectedIDs))}
	}
	for i := range got {
		if int64(got[i]) != fx.ExpectedIDs[i] {
			return KvAttestFinding{Reason: KvAttestReasonTokenMismatch,
				Detail: fmt.Sprintf("fixture %s: oracle token[%d]=%d != banked %d", fx.Name, i, got[i], fx.ExpectedIDs[i])}
		}
	}
	return KvAttestFinding{OK: true}
}

// ---- drain re-hash echo challenge (§6.2 machinery, §16.5 TRT semantics) ----

// HashChallenge runs the drain re-hash echo against one endpoint: geometry
// preflight from the endpoint's own /server_info (same rules as the
// admission gate), model preflight, then one nonce-unique §6.2 challenge
// resolved by this endpoint's drain stream — the decoder re-hashes the
// stored token lists (blockhash_trtllm) and the watch compares chain AND
// token IDs against the request side.
func (a *kvTrtllmAttest) HashChallenge(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	si, f := a.serverInfo(ep)
	if !f.OK {
		return f
	}
	blockSize := info.blockSize
	if blockSize == 0 {
		blockSize = 16
	}
	if verdict, admitted := kvTrtllmAdmissionEvaluate(si, int(blockSize)); !admitted {
		return KvAttestFinding{Reason: KvAttestReasonGeometryMismatch, Detail: verdict}
	}
	if f := a.kvTrtllmModelServed(ep, info.modelName); !f.OK {
		return f
	}
	hasher := kvChallengeHasherGet()
	if hasher == nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: "no challenge hasher registered (datapath not initialized)"}
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed, Detail: "nonce: " + err.Error()}
	}
	nonceHex := hex.EncodeToString(nonce[:])

	prompt, wantTokens, err := kvChallengeBuildPrompt(info.modelName, nonceHex, blockSize)
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed, Detail: err.Error()}
	}
	expected, ok := hasher(info.hashAlgo, blockSize, wantTokens)
	if !ok || len(expected) < 2 {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("expected-chain computation failed (algo=%s, %d hashes)", info.hashAlgo, len(expected))}
	}

	w := kvHashWatchRegister(info.svcID, ep.EpIdx, expected, wantTokens, blockSize)
	defer kvHashWatchUnregister(w)

	url := fmt.Sprintf("http://%s:%d/v1/completions", ep.IP, ep.Port)
	reqBody := fmt.Sprintf(`{"model":%q,"prompt":%q,"max_tokens":1,"temperature":0}`,
		info.modelName, prompt)
	resp, err := a.client.Post(url, "application/json", strings.NewReader(reqBody))
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: "challenge inference: " + err.Error()}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("challenge inference HTTP %d", resp.StatusCode)}
	}

	select {
	case <-w.done:
		if reason, detail := w.result(); reason != "" {
			return KvAttestFinding{Reason: reason, Detail: detail}
		}
		return KvAttestFinding{OK: true,
			Detail: fmt.Sprintf("drain re-hash echo ok (%d blocks; %s)", len(expected), kvTrtllmReadback(si))}
	case <-time.After(kvChallengeTimeout()):
		return KvAttestFinding{Reason: KvAttestReasonChallengeTimeout,
			Detail: fmt.Sprintf("expected re-hash chain not observed on the drain within %v", kvChallengeTimeout())}
	}
}
